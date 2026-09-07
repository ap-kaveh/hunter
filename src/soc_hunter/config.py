import re
import ssl
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Endpoint(StrictModel):
    url: str
    token_file: str | None = None
    ca_file: str | None = None
    timeout_seconds: int = Field(default=30, ge=1, le=600)

    @field_validator("url")
    @classmethod
    def secure_url(cls, value):
        parsed = urlsplit(value)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("Use an HTTPS URL without embedded credentials")
        if parsed.query or parsed.fragment or parsed.path not in ("", "/"):
            raise ValueError("Use the service origin, without a path, query or fragment")
        return value.rstrip("/")


class SplunkConfig(Endpoint):
    indexes: dict[str, str] = Field(default_factory=lambda: {"firewall": "fw", "waf": "fwb"})
    web_url: str | None = None
    page_size: int = Field(default=500, ge=1, le=5000)
    max_results: int = Field(default=20000, ge=10, le=200000)
    search_timeout_seconds: int = Field(default=300, ge=10, le=3600)
    poll_seconds: float = Field(default=2, ge=0.1, le=30)
    timestamp_validated: bool = False

    @field_validator("indexes")
    @classmethod
    def valid_indexes(cls, value):
        if set(value) != {"firewall", "waf"}:
            raise ValueError("Exactly firewall and waf index mappings are required")
        if not all(re.fullmatch(r"[A-Za-z0-9_-]+", v) for v in value.values()):
            raise ValueError("Index names must be literal names without SPL or wildcards")
        return value

    @field_validator("web_url")
    @classmethod
    def valid_web_url(cls, value):
        return Endpoint.secure_url(value) if value else None


class ModelConfig(StrictModel):
    mode: Literal["mock", "live"] = "mock"
    base_url: str = "http://127.0.0.1:8000/v1"
    name: str = "Qwen/Qwen3.6-27B-FP8"
    api_key_file: str | None = None
    ca_file: str | None = None
    timeout_seconds: int = Field(default=180, ge=1, le=1800)
    max_tokens: int = Field(default=2048, ge=256, le=8192)
    max_input_chars: int = Field(default=24000, ge=4000, le=48000)

    @field_validator("base_url")
    @classmethod
    def valid_model_url(cls, value):
        parsed = urlsplit(value)
        if (
            parsed.scheme not in ("http", "https")
            or not parsed.hostname
            or parsed.username
            or parsed.password
        ):
            raise ValueError("Model URL must be HTTP(S), without embedded credentials")
        if parsed.scheme == "http" and parsed.hostname not in (
            "localhost",
            "127.0.0.1",
            "::1",
            "model-server",
        ):
            raise ValueError("Use HTTPS for remote inference; HTTP is limited to loopback/model-server")
        return value.rstrip("/")


class PostgresConfig(StrictModel):
    host: str = "PG_PRIMARY_ENDPOINT"
    port: int = Field(default=5432, ge=1, le=65535)
    database: str = "soc_hunter"
    username: str = "soc_hunter"
    password_file: str = "/run/secrets/postgres_password"
    sslmode: Literal["verify-full"] = "verify-full"
    ca_file: str = "/etc/soc-hunter/certs/postgres-ca.pem"


class ZammadConfig(Endpoint):
    enabled: bool = False
    group_id: int = Field(default=1, ge=1)
    customer_id: int | None = Field(default=None, ge=1)
    tier2_role_ids: list[int] = Field(default_factory=list)
    approval_enforcement_verified: bool = False


class HuntConfig(StrictModel):
    disabled_rules: list[str] = Field(default_factory=list)
    firewall_enabled: bool = True
    fw_scan_min_ports: int = Field(default=20, ge=2)
    fw_scan_min_destinations: int = Field(default=20, ge=2)
    fw_scan_min_events: int = Field(default=30, ge=2)
    fw_deny_min_events: int = Field(default=100, ge=2)
    fw_admin_fail_min_events: int = Field(default=5, ge=2)
    waf_error_min_events: int = Field(default=30, ge=2)
    waf_error_min_ratio: float = Field(default=0.8, ge=0.1, le=1)
    waf_server_error_min_events: int = Field(default=20, ge=2)
    waf_auth_reject_min_events: int = Field(default=20, ge=2)
    waf_alert_min_events: int = Field(default=3, ge=1)
    max_window_hours: int = Field(default=12, ge=1, le=24)
    baseline_days: int = Field(default=14, ge=1, le=30)
    max_candidates: int = Field(default=20, ge=1, le=100)
    evidence_per_candidate: int = Field(default=20, ge=1, le=50)
    max_followups: int = Field(default=2, ge=0, le=2)
    scan_min_paths: int = Field(default=20, ge=2)
    scan_min_requests: int = Field(default=30, ge=2)
    multi_attack_min_events: int = Field(default=6, ge=1)
    sensitive_min_requests: int = Field(default=30, ge=2)
    campaign_min_sources: int = Field(default=5, ge=2)
    rate_multiplier: float = Field(default=5, ge=1)
    rate_min_requests: int = Field(default=50, ge=2)
    sensitive_paths: list[str] = Field(
        default_factory=lambda: ["/otp/", "/captcha", "/startpay", "/result.mellat"]
    )

    @field_validator("disabled_rules")
    @classmethod
    def known_rules(cls, value):
        from .rules import RULES

        if set(value) - set(RULES):
            raise ValueError("Unknown disabled rule ID")
        return sorted(set(value))


class Config(StrictModel):
    splunk: SplunkConfig = Field(default_factory=lambda: SplunkConfig(url="https://sh3:8089"))
    model: ModelConfig = Field(default_factory=ModelConfig)
    postgres: PostgresConfig = Field(default_factory=PostgresConfig)
    zammad: ZammadConfig = Field(default_factory=lambda: ZammadConfig(url="https://ZAMMAD_HOST"))
    hunts: HuntConfig = Field(default_factory=HuntConfig)
    data_dir: str = "data"


def load_config(path: str) -> Config:
    with open(path, encoding="utf-8") as handle:
        return Config.model_validate(yaml.safe_load(handle))


def secret(path: str | None) -> str:
    if not path:
        raise ValueError("A secret file must be configured")
    value = Path(path).read_text(encoding="utf-8").strip()
    if not value or "\n" in value or "\r" in value:
        raise ValueError("Secret file must contain one nonempty line")
    return value


def tls_context(ca_file: str | None):
    return ssl.create_default_context(cafile=ca_file)
