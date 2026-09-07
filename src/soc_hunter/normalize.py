"""Allowlisted normalization. Raw payloads, headers and bodies never leave this module."""

import json
import re
import shlex
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from hashlib import sha256
from ipaddress import ip_address
from urllib.parse import parse_qsl, urlsplit
from zoneinfo import ZoneInfo

from .domain import Bucket, Event, utc


def safe_text(value, max_length=200):
    text = str(value or "")
    text = re.sub(r"[\x00-\x1f\x7f]", " ", text)
    text = re.sub(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", "[email]", text)
    text = re.sub(r"(?<![A-Za-z0-9])\+?\d[\d -]{8,}\d(?![A-Za-z0-9])", "[identifier]", text)
    text = re.sub(r"[A-Za-z0-9_-]{24,}", "[opaque-id]", text)
    return text[:max_length]


def safe_ip(value):
    try:
        return str(ip_address(str(value)))
    except ValueError:
        return "unknown"


def integer(value):
    try:
        return max(0, int(value or 0))
    except (ValueError, TypeError):
        return 0


def parse_raw(raw: str) -> dict:
    marker = raw.find("{")
    if marker >= 0:
        return json.loads(raw[marker:])
    return dict(token.split("=", 1) for token in shlex.split(raw) if "=" in token)


def event_time(fields):
    if fields.get("_time"):
        return utc(fields["_time"]), []
    value = str(fields.get("eventtime", ""))
    if value.isdigit():
        number = Decimal(value)
        if len(value) >= 18:
            number /= 1_000_000_000
        elif len(value) >= 15:
            number /= 1_000_000
        elif len(value) >= 12:
            number /= 1000
        return utc(float(number)), ["Timestamp derived from device eventtime; Splunk _time not provided"]
    stamp = datetime.strptime(f"{fields['date']} {fields['time']}", "%Y-%m-%d %H:%M:%S")
    offset = str(fields.get("tz", ""))
    if re.fullmatch(r"[+-]\d{4}", offset):
        minutes = int(offset[1:3]) * 60 + int(offset[3:])
        zone = timezone(timedelta(minutes=minutes * (-1 if offset[0] == "-" else 1)))
    elif "Tehran" in str(fields.get("timezone", "")):
        zone = ZoneInfo("Asia/Tehran")
    else:
        raise ValueError("No reliable timezone for event")
    return stamp.replace(tzinfo=zone).astimezone(timezone.utc), [
        "Timestamp derived from device date/time; epoch absent or masked; alignment unverified"
    ]


def normalize(record: dict, source: str) -> Event:
    fields = parse_raw(record["_raw"]) if record.get("_raw") else {}
    fields.update({k: v for k, v in record.items() if k != "_raw" and v is not None})
    timestamp, warnings = event_time(fields)
    url = urlsplit(str(fields.get("http_url", fields.get("url", "/"))))
    query_keys = sorted({safe_text(k, 60) for k, _ in parse_qsl(url.query)})[:30]
    device = str(fields.get("device_id", fields.get("devid", "unknown")))
    app = fields.get("http_host") or fields.get("hostname") or fields.get("policy") or "unknown"
    # Identity hashing uses the original event, while persisted/model evidence is allowlisted.
    identifier = sha256(json.dumps(record, sort_keys=True, default=str).encode()).hexdigest()[:24]
    if fields.get("packet") or fields.get("packet.packet"):
        warnings.append("Request headers/body omitted; matched payload requires a sanitized analyst review")
    if source == "firewall":
        app = "firewall"
    return Event(
        id=identifier,
        timestamp=timestamp,
        source=source,
        device=safe_text(device),
        src=safe_ip(fields.get("srcip") or fields.get("src") or fields.get("remip")),
        original_src=safe_ip(fields.get("original_src")),
        dst=safe_ip(fields.get("dst", fields.get("dest", fields.get("dstip")))),
        dst_port=integer(fields.get("dst_port", fields.get("dstport"))),
        application=safe_text(app),
        path=safe_text(url.path or "/", 400),
        query_keys=query_keys,
        method=safe_text(fields.get("http_method", fields.get("method", "unknown"))).upper(),
        status=integer(fields.get("http_retcode")),
        action=safe_text(fields.get("action", "unknown")),
        attack_type=safe_text(fields.get("attack_type", "")),
        signature=safe_text(
            fields.get("signature_subclass")
            or fields.get("attack")
            or fields.get("virus")
            or fields.get("virusid")
            or ""
        ),
        severity=safe_text(
            fields.get("severity") or fields.get("severity_level") or fields.get("level", "unknown")
        ).lower(),
        event_type=safe_text(fields.get("type", "traffic")),
        bytes_out=integer(fields.get("sentbyte", fields.get("http_request_bytes"))),
        bytes_in=integer(fields.get("rcvdbyte", fields.get("http_response_bytes"))),
        session_id=safe_text(fields.get("sessionid", fields.get("msg_id", ""))),
        subtype=safe_text(fields.get("subtype", "")).lower(),
        auth_status=safe_text(fields.get("status", "")).lower(),
        config_path=safe_text(fields.get("cfgpath", "")),
        vdom=safe_text(fields.get("vd", "unknown")),
        warnings=warnings,
    )


def aggregate(events: list[Event], sensitive_paths: list[str]) -> list[Bucket]:
    groups = defaultdict(list)
    for event in events:
        if event.source != "waf":
            continue
        timestamp = datetime.fromtimestamp(int(event.timestamp.timestamp()) // 300 * 300, timezone.utc)
        groups[(timestamp, event.src, event.application)].append(event)
    return [
        Bucket(
            timestamp=key[0],
            src=key[1],
            application=key[2],
            count=len(rows),
            paths=len({e.path for e in rows}),
            errors=sum(e.status >= 400 for e in rows),
            attacks=sum(e.event_type == "attack" for e in rows),
            attack_types=sorted({e.attack_type for e in rows if e.attack_type}),
            signatures=sorted({e.signature for e in rows if e.signature}),
            high=sum(e.event_type == "attack" and e.severity in ("high", "critical") for e in rows),
            sensitive=sum(any(p in e.path.lower() for p in sensitive_paths) for e in rows),
            sample_paths=sorted({e.path for e in rows})[:30],
            traffic_count=sum(e.event_type == "traffic" for e in rows),
            traffic_paths=len({e.path for e in rows if e.event_type == "traffic"}),
            client_errors=sum(e.event_type == "traffic" and 400 <= e.status < 500 for e in rows),
            server_errors=sum(e.event_type == "traffic" and 500 <= e.status < 600 for e in rows),
            auth_rejects=sum(e.event_type == "traffic" and e.status in (401, 403) for e in rows),
            alert_only=sum(e.event_type == "attack" and e.action.lower() == "alert" for e in rows),
        )
        for key, rows in groups.items()
    ]


def aggregate_firewall(events: list[Event]) -> list[Bucket]:
    groups = defaultdict(list)
    for event in events:
        if event.source == "firewall":
            stamp = datetime.fromtimestamp(int(event.timestamp.timestamp()) // 300 * 300, timezone.utc)
            groups[(stamp, event.src, event.device, event.vdom)].append(event)
    result = []
    for (stamp, src, device, vdom), rows in groups.items():
        traffic = [e for e in rows if e.event_type == "traffic"]
        result.append(
            Bucket(
                source="firewall",
                timestamp=stamp,
                src=src,
                application="firewall",
                device=device,
                vdom=vdom,
                count=len(rows),
                paths=0,
                errors=0,
                attacks=0,
                traffic_count=len(traffic),
                ports=len({e.dst_port for e in traffic if e.dst_port}),
                destinations=len({e.dst for e in traffic if e.dst != "unknown"}),
                denied=sum(e.action.lower() == "deny" for e in traffic),
                ips_high=sum(e.subtype == "ips" and e.severity in ("high", "critical") for e in rows),
                malware=sum(e.subtype == "virus" and bool(e.signature) for e in rows),
                admin_failures=sum(
                    e.event_type == "event"
                    and e.subtype == "system"
                    and e.action.lower() == "login"
                    and e.auth_status == "failed"
                    for e in rows
                ),
                config_changes=sum(
                    e.event_type == "event"
                    and bool(e.config_path)
                    and e.action.lower() in ("add", "edit", "delete")
                    for e in rows
                ),
            )
        )
    return result
