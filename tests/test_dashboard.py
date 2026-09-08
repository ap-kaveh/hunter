import json

import pytest
import yaml
from fastapi.testclient import TestClient

from soc_hunter.config import Config, ModelConfig
from soc_hunter.dashboard import create_app, init_admin
from soc_hunter.fixtures import demo_records
from soc_hunter.model import Investigator
from soc_hunter.runner import hunt
from soc_hunter.storage import FileStore


@pytest.fixture
def dashboard(tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(Config().model_dump()))
    ui = tmp_path / "ui"
    password = init_admin(ui).read_text().strip()
    app = create_app(config_path, ui, secure_cookie=False)
    with TestClient(app) as client:
        yield client, password, config_path, ui


def login(client, password):
    response = client.post("/api/login", json={"username": "admin", "password": password})
    assert response.status_code == 200
    return {"X-CSRF-Token": response.json()["csrf"]}


def test_dashboard_requires_authentication(dashboard):
    client, *_ = dashboard
    assert client.get("/").status_code == 200
    assert client.get("/api/config").status_code == 401
    assert client.get("/api/jobs").status_code == 401
    assert client.get("/api/rules").status_code == 401
    assert client.get("/api/monitor").status_code == 401
    assert client.get("/assets/../../admin.json").status_code == 404


def test_rule_catalog_tracks_saved_controls(dashboard):
    client, password, *_ = dashboard
    headers = login(client, password)
    rules = client.get("/api/rules").json()["rules"]
    assert len(rules) == 17 and sum(r["source"] == "firewall" for r in rules) == 7
    data = client.get("/api/config").json()["config"]
    data["hunts"]["disabled_rules"] = ["waf_error_probe"]
    data["hunts"]["firewall_enabled"] = False
    assert client.put("/api/config", json={"yaml": json.dumps(data)}, headers=headers).status_code == 200
    rules = client.get("/api/rules").json()["rules"]
    assert all(not r["enabled"] for r in rules if r["source"] == "firewall" or r["id"] == "waf_error_probe")
    data["hunts"]["disabled_rules"] = ["typo"]
    assert client.put("/api/config", json={"yaml": json.dumps(data)}, headers=headers).status_code == 400


def test_login_and_logout(dashboard):
    client, password, *_ = dashboard
    headers = login(client, password)
    assert client.get("/api/session").status_code == 200
    assert client.post("/api/logout", headers=headers).status_code == 200
    assert client.get("/api/config").status_code == 401


def test_monitor_requires_login_and_returns_metrics(dashboard):
    client, password, *_ = dashboard
    login(client, password)
    response = client.get("/api/monitor")
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    data = response.json()
    assert {"gpu", "cpu", "memory", "network", "disk_io", "history"} <= data.keys()
    assert data["refresh_seconds"] == 5


def test_csrf_and_foreign_origin_blocked(dashboard):
    client, password, *_ = dashboard
    headers = login(client, password)
    assert client.post("/api/jobs", json={"mode": "demo"}).status_code == 403
    headers["Origin"] = "https://evil.example.invalid"
    assert client.post("/api/jobs", json={"mode": "demo"}, headers=headers).status_code == 403


def test_config_validates_and_persists(dashboard):
    client, password, path, *_ = dashboard
    headers = login(client, password)
    data = client.get("/api/config").json()["config"]
    data["hunts"]["max_candidates"] = 3
    assert client.put("/api/config", json={"yaml": json.dumps(data)}, headers=headers).status_code == 200
    assert yaml.safe_load(path.read_text())["hunts"]["max_candidates"] == 3
    data["splunk"]["url"] = "http://sh3:8089"
    assert client.put("/api/config", json={"yaml": json.dumps(data)}, headers=headers).status_code == 400


def test_secret_is_saved_but_never_returned(dashboard):
    client, password, path, ui = dashboard
    headers = login(client, password)
    response = client.put(
        "/api/secrets/splunk", json={"value": "EXAMPLE-SECRET-DO-NOT-RETURN"}, headers=headers
    )
    assert response.status_code == 200
    assert "EXAMPLE-SECRET" not in response.text
    assert "EXAMPLE-SECRET" not in client.get("/api/config").text
    assert (ui / "secrets" / "splunk").read_text() == "EXAMPLE-SECRET-DO-NOT-RETURN"
    assert yaml.safe_load(path.read_text())["splunk"]["token_file"] == str(ui / "secrets" / "splunk")


def test_live_start_requires_live_model(dashboard):
    client, password, *_ = dashboard
    headers = login(client, password)
    response = client.post(
        "/api/jobs",
        headers=headers,
        json={"mode": "live", "start": "2026-01-01T00:00:00Z", "end": "2026-01-01T12:00:00Z"},
    )
    assert response.status_code == 400
    assert "live model" in response.text


def test_mock_connection_check_is_honest(dashboard):
    client, password, *_ = dashboard
    response = client.post("/api/check/model", headers=login(client, password))
    assert response.status_code == 200 and response.json()["ok"] is False


def test_invalid_password_rate_limit(dashboard):
    client, *_ = dashboard
    for _ in range(5):
        assert client.post("/api/login", json={"username": "admin", "password": "wrong"}).status_code == 401
    assert client.post("/api/login", json={"username": "admin", "password": "wrong"}).status_code == 429


def test_resume_preserves_completed_findings(tmp_path):
    class InterruptedModel:
        def __init__(self):
            self.count = 0

        def decide(self, *args):
            self.count += 1
            if self.count == 3:
                raise KeyboardInterrupt()
            return Investigator(ModelConfig()).decide(*args)

    store = FileStore(tmp_path)
    records, start, end = demo_records()
    with pytest.raises(KeyboardInterrupt):
        hunt(Config(), start, end, store, fixture=records, investigator=InterruptedModel())
    stopped = json.loads((tmp_path / "run.json").read_text())
    saved = store.findings(stopped["id"])
    assert len(saved) == 2 and stopped["status"] == "interrupted"
    run, findings = hunt(Config(), start, end, store, fixture=records, resume_id=stopped["id"])
    assert run["id"] == stopped["id"] and len(findings) == 8 and run["resume_count"] == 1
    assert {f.id for f in saved}.issubset({f.id for f in findings})
    assert len(store.findings(run["id"])) == 8


def test_resume_rejects_changed_hunt_settings(tmp_path):
    store = FileStore(tmp_path)
    records, start, end = demo_records()
    run, _ = hunt(Config(), start, end, store, fixture=records)
    changed = Config()
    changed.hunts.baseline_days = 7
    with pytest.raises(ValueError, match="original"):
        hunt(changed, start, end, store, fixture=records, resume_id=run["id"])
