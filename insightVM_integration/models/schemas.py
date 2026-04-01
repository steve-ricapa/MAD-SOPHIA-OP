from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Literal

Source = Literal["insightvm"]
Severity = Literal["info", "low", "medium", "high", "critical", "unknown"]


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def to_dict(obj: Any) -> Any:
    if hasattr(obj, "__dataclass_fields__"):
        return asdict(obj)
    if isinstance(obj, list):
        return [to_dict(x) for x in obj]
    if isinstance(obj, dict):
        return {k: to_dict(v) for k, v in obj.items()}
    return obj


@dataclass
class AgentError:
    source: Source
    message: str
    where: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


@dataclass
class Asset:
    id: str
    source: Source = "insightvm"
    hostname: Optional[str] = None
    ip: Optional[str] = None
    os: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Finding:
    id: str
    source: Source = "insightvm"
    asset_id: Optional[str] = None
    title: str = ""
    severity: Severity = "unknown"
    cve: Optional[str] = None
    cvss: Optional[float] = None
    risk_score: Optional[float] = None
    impact: str = ""
    raw: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SourceResult:
    source: Source = "insightvm"
    collected_at: str = field(default_factory=utc_now_iso)
    assets: List[Asset] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    errors: List[AgentError] = field(default_factory=list)
    meta: Dict[str, Any] = field(default_factory=dict)


@dataclass
class UnifiedReport:
    generated_at: str = field(default_factory=utc_now_iso)
    insightvm: Optional[SourceResult] = None

    def as_dict(self) -> Dict[str, Any]:
        return to_dict(self)
