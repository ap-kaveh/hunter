from datetime import datetime, timezone
from hashlib import sha256
from typing import Literal
from uuid import NAMESPACE_URL, uuid5

from pydantic import Field

from .config import StrictModel


def utc(value: str | float | int) -> datetime:
    try:
        if isinstance(value, (int, float)) or str(value).replace(".", "", 1).isdigit():
            return datetime.fromtimestamp(float(value), timezone.utc)
        result = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if result.tzinfo is None:
            raise ValueError("Timezone offset is required")
        return result.astimezone(timezone.utc)
    except (ValueError, OverflowError, OSError) as exc:
        raise ValueError("Invalid timestamp; use ISO 8601 with an explicit UTC offset") from exc


def fingerprint(*values) -> str:
    return sha256("\x00".join(str(v) for v in values).encode()).hexdigest()


class Event(StrictModel):
    id: str
    timestamp: datetime
    source: Literal["waf", "firewall"]
    device: str = "unknown"
    src: str = "unknown"
    original_src: str = "unknown"
    dst: str = "unknown"
    dst_port: int = 0
    application: str = "unknown"
    path: str = "/"
    query_keys: list[str] = Field(default_factory=list)
    method: str = "unknown"
    status: int = 0
    action: str = "unknown"
    attack_type: str = ""
    signature: str = ""
    severity: str = "unknown"
    event_type: str = "traffic"
    bytes_out: int = 0
    bytes_in: int = 0
    session_id: str = ""
    subtype: str = ""
    auth_status: str = ""
    config_path: str = ""
    vdom: str = "unknown"
    warnings: list[str] = Field(default_factory=list)


class Bucket(StrictModel):
    source: Literal["waf", "firewall"] = "waf"
    device: str = "unknown"
    vdom: str = "unknown"
    timestamp: datetime
    src: str
    application: str
    count: int
    paths: int
    errors: int
    attacks: int
    attack_types: list[str] = Field(default_factory=list)
    signatures: list[str] = Field(default_factory=list)
    sensitive: int = 0
    high: int = 0
    sample_paths: list[str] = Field(default_factory=list)
    traffic_count: int = 0
    traffic_paths: int = 0
    client_errors: int = 0
    server_errors: int = 0
    auth_rejects: int = 0
    alert_only: int = 0
    ports: int = 0
    destinations: int = 0
    denied: int = 0
    ips_high: int = 0
    malware: int = 0
    admin_failures: int = 0
    config_changes: int = 0


class Candidate(StrictModel):
    ruleset: str = "legacy"
    source: Literal["waf", "firewall"] = "waf"
    device: str = "unknown"
    vdom: str = "unknown"
    key: str
    hunts: list[str]
    src: str
    application: str
    severity: Literal["low", "medium", "high"]
    signals: list[str]
    priority: int


class Claim(StrictModel):
    text: str = Field(min_length=1, max_length=1000)
    evidence_ids: list[str] = Field(min_length=1, max_length=20)


class Assessment(StrictModel):
    assessment: Literal["likely_true_positive", "likely_false_positive", "inconclusive"]
    outcome: Literal["apparently_blocked", "suspicious_activity_allowed", "evidence_of_compromise", "unknown"]
    summary: str = Field(min_length=1, max_length=2000)
    claims: list[Claim] = Field(min_length=1, max_length=10)
    alternatives: list[str] = Field(min_length=1, max_length=10)
    gaps: list[str] = Field(min_length=1, max_length=100)
    next_steps: list[str] = Field(min_length=1, max_length=10)


class Decision(StrictModel):
    action: Literal["finish", "waf_source", "firewall_source"]
    report: Assessment | None = None


class Finding(StrictModel):
    id: str
    run_id: str
    candidate: Candidate
    evidence: list[Event]
    report: Assessment
    synthetic: bool
    window_start: datetime
    window_end: datetime
    review_state: str = "open"
    model: str

    @staticmethod
    def stable_id(candidate: Candidate, start: datetime, end: datetime, synthetic: bool):
        return str(uuid5(NAMESPACE_URL, fingerprint(candidate.key, start, end, synthetic)))
