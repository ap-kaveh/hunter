"""Entirely synthetic TEST-NET addresses and example.invalid applications."""

from datetime import timedelta

from .domain import utc


def demo_records():
    start = utc("2026-01-15T00:00:00Z")
    records = []

    def add(timestamp, src, path, **extra):
        row = {
            "_time": timestamp.isoformat(),
            "device_id": "DEMO-WAF",
            "type": "traffic",
            "src": src,
            "dst": "192.0.2.20",
            "dst_port": 443,
            "http_host": "payments.example.invalid",
            "http_url": path,
            "http_method": "GET",
            "http_retcode": 200,
            "msg_id": str(len(records)),
        }
        row.update(extra)
        records.append(row)

    for day in range(1, 15):
        for n in range(5):
            add(start - timedelta(days=day) + timedelta(seconds=n), "198.51.100.10", "/health")
    for n in range(60):
        add(start + timedelta(seconds=n), "198.51.100.10", f"/probe/path-{n}", http_retcode=404)
    for n in range(35):
        add(start + timedelta(minutes=15, seconds=n), "198.51.100.11", "/api/otp/request", http_method="POST")
    for n in range(8):
        add(
            start + timedelta(minutes=25, seconds=n),
            "198.51.100.12",
            "/search",
            type="attack",
            attack_type="SQL Injection" if n % 2 else "Cross Site Scripting",
            action="alert",
            signature_subclass="demo-signature",
            severity="high",
        )
    for n in range(5):
        add(
            start + timedelta(minutes=35, seconds=n),
            f"203.0.113.{n + 1}",
            "/demo-probe",
            type="attack",
            attack_type="Protocol violation",
            signature_subclass="shared-demo-signature",
            severity="medium",
        )
    for n in range(12):
        add(start + timedelta(minutes=50, seconds=n), "198.51.100.99", "/assets/style.css")
    return records, start, start + timedelta(hours=12)
