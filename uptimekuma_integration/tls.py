"""TLS trust for the Kuma source only; backend delivery is unaffected."""

from pathlib import Path
from typing import Mapping


def metrics_tls_verify(env: Mapping[str, str], repo: Path) -> bool | str:
    raw_verify = env.get("UPTIME_VERIFY_SSL", env.get("VERIFY_SSL", "true"))
    verify = str(raw_verify).strip().lower() in {"1", "true", "yes", "on"}
    bundle = (env.get("UPTIME_KUMA_CA_BUNDLE") or "").strip()
    if not bundle:
        return verify
    if not verify:
        raise ValueError("UPTIME_KUMA_CA_BUNDLE requiere UPTIME_VERIFY_SSL=true")
    path = Path(bundle)
    if not path.is_absolute():
        path = repo / path
    if not path.is_file():
        raise ValueError("UPTIME_KUMA_CA_BUNDLE debe ser un archivo CA existente")
    with path.open("rb"):
        pass
    return str(path)
