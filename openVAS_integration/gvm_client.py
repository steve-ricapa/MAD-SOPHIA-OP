from __future__ import annotations

import os
import re
import socket
import ssl
import xml.etree.ElementTree as ET
from typing import Optional
from xml.sax.saxutils import escape


def _env_int(name: str, default: int) -> int:
    v = os.getenv(name)
    if v is None or v.strip() == "":
        return default
    try:
        return int(v.strip())
    except ValueError:
        return default


def _env_bool(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    vv = v.strip().lower()
    if vv in {"1", "true", "yes", "y", "on"}:
        return True
    if vv in {"0", "false", "no", "n", "off"}:
        return False
    return default


def _normalize_transport(raw_transport: str, socket_path: str) -> str:
    transport = (raw_transport or "").strip().lower()
    if transport == "tcp":
        transport = "plain"
    if not transport:
        transport = "unix" if (socket_path or "").strip() else "tls"
    return transport


def _gmp_status(xml_text: str) -> tuple[str | None, str | None]:
    try:
        root = ET.fromstring(xml_text)
        return root.attrib.get("status"), root.attrib.get("status_text")
    except Exception:
        return None, None


class GVMClient:
    def __init__(
        self,
        host: str,
        port: int,
        user: str,
        password: str,
        socket_path: str = "",
        *,
        transport: str = "",
        cafile: str = "",
        certfile: str = "",
        keyfile: str = "",
        timeout: int = 30,
        debug: bool = False,
    ):
        self.host = host
        self.port = int(port)
        self.user = user
        self.password = password
        self.socket_path = (socket_path or "").strip()
        self.transport = _normalize_transport(transport, self.socket_path)

        self.cafile = (cafile or "").strip()
        self.certfile = (certfile or "").strip()
        self.keyfile = (keyfile or "").strip()
        self.timeout = int(timeout) if int(timeout) > 0 else 30
        self.debug = debug

        self._err: Optional[Exception] = None
        self._TLSConnection = None
        self._UnixSocketConnection = None
        self._GMP = None

        self.connection = None
        self._gmp_cm = None
        self.gmp = None
        self._plain_sock: socket.socket | None = None

        if self.transport in {"tls", "unix"}:
            try:
                from gvm.connections import TLSConnection, UnixSocketConnection  # type: ignore
                from gvm.protocols.gmp import GMP  # type: ignore

                self._TLSConnection = TLSConnection
                self._UnixSocketConnection = UnixSocketConnection
                self._GMP = GMP
            except Exception as e:
                self._err = e

    def __enter__(self):
        if self.transport not in {"unix", "tls", "plain"}:
            raise ValueError("GVM_TRANSPORT inválido. Usa 'unix', 'tls' o 'plain'.")

        if self.transport == "plain":
            self._plain_connect_and_auth()
            return self

        if self._GMP is None or (self._TLSConnection is None and self._UnixSocketConnection is None):
            raise ModuleNotFoundError(
                "python-gvm no está disponible en este entorno. "
                f"Detalle: {type(self._err).__name__}: {self._err}"
            )

        if self.transport == "unix":
            if not self.socket_path:
                raise RuntimeError("GVM_TRANSPORT=unix requiere GVM_SOCKET no vacío.")
            self.connection = self._UnixSocketConnection(path=self.socket_path, timeout=self.timeout)  # type: ignore
        else:
            kwargs = {"hostname": self.host, "port": self.port, "timeout": self.timeout}
            if self.cafile:
                kwargs["cafile"] = self.cafile
            if self.certfile:
                kwargs["certfile"] = self.certfile
            if self.keyfile:
                kwargs["keyfile"] = self.keyfile
            self.connection = self._TLSConnection(**kwargs)  # type: ignore

        self._gmp_cm = self._GMP(connection=self.connection)  # type: ignore

        try:
            self.gmp = self._gmp_cm.__enter__()
            self.gmp.authenticate(self.user, self.password)
            return self
        except ssl.SSLError as e:
            try:
                self._gmp_cm.__exit__(type(None), None, None)
            except Exception:
                pass
            raise RuntimeError(
                "Fallo handshake TLS contra GMP. "
                "Si el destino no habla TLS, usa GVM_TRANSPORT=plain (con GVM_ALLOW_PLAIN_TCP=true) "
                "o GVM_TRANSPORT=unix con GVM_SOCKET local."
            ) from e
        except Exception:
            try:
                self._gmp_cm.__exit__(type(None), None, None)
            except Exception:
                pass
            raise

    def __exit__(self, exc_type, exc, tb):
        try:
            if self._gmp_cm is not None:
                self._gmp_cm.__exit__(exc_type, exc, tb)
        except Exception:
            pass
        if self._plain_sock is not None:
            try:
                self._plain_sock.close()
            except Exception:
                pass
            self._plain_sock = None

    def _read_until_response(self, response_tag: str) -> str:
        if self._plain_sock is None:
            raise RuntimeError("Socket GMP plain no inicializado")

        self._plain_sock.settimeout(self.timeout)
        data = b""
        closing_tag = f"</{response_tag}>"
        self_closing = re.compile(rf"<{response_tag}\\b[^>]*/>")

        while True:
            chunk = self._plain_sock.recv(65535)
            if not chunk:
                break
            data += chunk
            text = data.decode("utf-8", errors="replace")
            if closing_tag in text or self_closing.search(text):
                return text
        return data.decode("utf-8", errors="replace")

    def _send_plain_gmp(self, xml_request: str, expected_response: str) -> str:
        if self._plain_sock is None:
            raise RuntimeError("Socket GMP plain no inicializado")
        if self.debug:
            print(f"[GVMClient] >>> SEND ({len(xml_request)} bytes): {xml_request[:500]}")
            if len(xml_request) > 500:
                print(f"[GVMClient] >>> ... (truncated, total {len(xml_request)} bytes)")
        self._plain_sock.sendall(xml_request.encode("utf-8"))
        response = self._read_until_response(expected_response)
        if self.debug:
            print(f"[GVMClient] <<< RECV ({len(response)} bytes): {response[:1000]}")
            if len(response) > 1000:
                print(f"[GVMClient] <<< ... (truncated, total {len(response)} bytes)")
        return response

    def _plain_connect_and_auth(self) -> None:
        allow_plain = _env_bool("GVM_ALLOW_PLAIN_TCP", False)
        if not allow_plain:
            raise RuntimeError("GVM_TRANSPORT=plain requiere GVM_ALLOW_PLAIN_TCP=true")

        self._plain_sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        version_xml = self._send_plain_gmp("<get_version/>", "get_version_response")
        version_status, _ = _gmp_status(version_xml)
        if version_status != "200":
            raise RuntimeError("get_version no respondió status=200 en GMP plain")

        auth_xml = (
            "<authenticate><credentials>"
            f"<username>{escape(self.user)}</username>"
            f"<password>{escape(self.password)}</password>"
            "</credentials></authenticate>"
        )
        auth_response = self._send_plain_gmp(auth_xml, "authenticate_response")
        auth_status, auth_status_text = _gmp_status(auth_response)
        if auth_status != "200":
            raise RuntimeError(f"Autenticación GMP plain falló: status={auth_status} {auth_status_text or ''}".strip())

    def get_tasks(self) -> str:
        if self.transport == "plain":
            return self._send_plain_gmp("<get_tasks/>", "get_tasks_response")
        try:
            return self.gmp.get_tasks(ignore_pagination=True)  # type: ignore
        except TypeError:
            return self.gmp.get_tasks()  # type: ignore

    def get_report(self, report_id: str) -> str:
        if self.transport == "plain":
            report_id_escaped = escape(report_id or "")
            rows = min(1000, max(250, _env_int("TOP_N", 50) * 5))
            request = (
                f"<get_report report_id=\"{report_id_escaped}\" "
                f"details=\"1\" "
                f"filter=\"rows={rows} first=1 sort-reverse=severity levels=chmlgio details=1 notes=1 overrides=1\"/>"
            )
            return self._send_plain_gmp(request, "get_report_response")

        top_n = _env_int("TOP_N", 50)

        rows_default = min(1000, max(250, top_n * 5))
        rows = _env_int("GVM_REPORT_ROWS", rows_default)
        rows = max(1, min(int(rows), 2000))

        default_filter = f"rows={rows} first=1 sort-reverse=severity levels=chmlgio details=1 notes=1 overrides=1"
        filter_string = (os.getenv("GVM_REPORT_FILTER", default_filter) or default_filter).strip()

        ignore_pagination = _env_bool("GVM_IGNORE_PAGINATION", False)

        kwargs = {
            "report_id": report_id,
            "details": True,
            "filter_string": filter_string,
        }
        if ignore_pagination:
            kwargs["ignore_pagination"] = True

        return self.gmp.get_report(**kwargs)  # type: ignore
