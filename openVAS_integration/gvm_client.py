from __future__ import annotations

import os
import ssl
from typing import Optional


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
    ):
        self.host = host
        self.port = int(port)
        self.user = user
        self.password = password
        self.socket_path = (socket_path or "").strip()

        self.transport = (transport or "").strip().lower()
        if not self.transport:
            self.transport = "unix" if self.socket_path else "tls"

        self.cafile = (cafile or "").strip()
        self.certfile = (certfile or "").strip()
        self.keyfile = (keyfile or "").strip()
        self.timeout = int(timeout) if int(timeout) > 0 else 30

        self._err: Optional[Exception] = None
        self._TLSConnection = None
        self._UnixSocketConnection = None
        self._GMP = None

        self.connection = None
        self._gmp_cm = None
        self.gmp = None

        try:
            from gvm.connections import TLSConnection, UnixSocketConnection  # type: ignore
            from gvm.protocols.gmp import GMP  # type: ignore
            self._TLSConnection = TLSConnection
            self._UnixSocketConnection = UnixSocketConnection
            self._GMP = GMP
        except Exception as e:
            self._err = e

    def __enter__(self):
        if self._GMP is None or (self._TLSConnection is None and self._UnixSocketConnection is None):
            raise ModuleNotFoundError(
                "python-gvm no está disponible en este entorno. "
                f"Detalle: {type(self._err).__name__}: {self._err}"
            )

        if self.transport not in {"unix", "tls"}:
            raise ValueError("GVM_TRANSPORT inválido. Usa 'unix' o 'tls'.")

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
                "Si el destino no habla TLS, usa GVM_TRANSPORT=unix con GVM_SOCKET local. "
                "Alternativamente habilita endpoint GMP TLS válido en gvmd."
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

    def get_tasks(self) -> str:
        try:
            return self.gmp.get_tasks(ignore_pagination=True)  # type: ignore
        except TypeError:
            return self.gmp.get_tasks()  # type: ignore

    def get_report(self, report_id: str) -> str:
        top_n = _env_int("TOP_N", 50)

        rows_default = min(1000, max(250, top_n * 5))
        rows = _env_int("GVM_REPORT_ROWS", rows_default)
        rows = max(1, min(int(rows), 2000))

        default_filter = f"rows={rows} first=1 sort-reverse=severity levels=chml details=1 notes=1 overrides=1"
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
