import json
from datetime import timedelta

import httpx
import pytest
from pydantic import ValidationError

from soc_hunter.config import Config, Endpoint, ModelConfig, SplunkConfig
from soc_hunter.detect import detect
from soc_hunter.domain import utc
from soc_hunter.fixtures import demo_records
from soc_hunter.model import Investigator
from soc_hunter.normalize import aggregate, normalize
from soc_hunter.runner import hunt
from soc_hunter.splunk import Splunk, evidence_query
from soc_hunter.storage import FileStore
from soc_hunter.zammad import Zammad, publish


def sample(**extra):
    row = {
        "_time": "2026-01-15T00:00:01Z",
        "src": "198.51.100.10",
        "dst": "192.0.2.1",
        "http_host": "payments.example.invalid",
        "http_url": "/normal",
        "type": "traffic",
    }
    row.update(extra)
    return row


def demo_case(tmp_path):
    records, start, end = demo_records()
    return hunt(Config(), start, end, FileStore(tmp_path), fixture=records)


def test_demo_has_expected_candidates_and_never_confirms_attack(tmp_path):
    run, findings = demo_case(tmp_path)
    assert run["candidate_failures"] == []
    assert len(findings) == 8
    assert all(f.synthetic and f.report.assessment == "inconclusive" for f in findings)
    assert {h for f in findings for h in f.candidate.hunts} == {
        "path_enumeration",
        "historical_rate_deviation",
        "sensitive_endpoint_volume",
        "multiple_attack_types",
        "high_severity_detection",
        "shared_signature_cluster",
        "waf_error_probe",
        "waf_alert_only_detection",
    }


def test_normal_traffic_does_not_create_candidate():
    events = [normalize(sample(), "waf")]
    config = Config()
    assert detect(aggregate(events, config.hunts.sensitive_paths), [], config.hunts, False) == []


def test_missing_baseline_does_not_claim_anomaly():
    rows, start, end = demo_records()
    config = Config()
    current = aggregate(
        [normalize(r, "waf") for r in rows if utc(r["_time"]) >= start], config.hunts.sensitive_paths
    )
    results = detect(current, [], config.hunts, False)
    assert all("historical_rate_deviation" not in c.hunts for c in results)


def test_normalization_removes_headers_bodies_and_query_values():
    value = sample(
        http_url="/otp?token=SECRET-QUERY&phone=989123456789",
        packet={"packet": "Cookie: SECRET-COOKIE\r\nAuthorization: SECRET-AUTH\r\n\r\nSECRET-BODY"},
    )
    event = normalize(value, "waf")
    serialized = event.model_dump_json()
    assert "SECRET" not in serialized
    assert "989123456789" not in serialized
    assert event.query_keys == ["phone", "token"]
    assert event.warnings


def test_prefixed_json_normalizes():
    event = normalize({"_raw": "Jan 15 00:00:01 192.0.2.1 " + json.dumps(sample())}, "waf")
    assert event.src == "198.51.100.10"


def test_fortigate_epoch_and_timezone():
    event = normalize(
        {
            "_raw": "Sep 6 17:41:04 fw date=2026-09-06 time=18:41:04 "
            'eventtime=1788703864501879218 tz="+0430" srcip=192.0.2.1 dstip=192.0.2.2 '
            'sessionid=5 action="server-rst"'
        },
        "firewall",
    )
    assert event.timestamp.isoformat().startswith("2026-09-06T14:11:04")
    assert event.action == "server-rst"


def test_splunk_time_takes_precedence():
    event = normalize(sample(eventtime="1788703864501879218"), "waf")
    assert event.timestamp == utc("2026-01-15T00:00:01Z")


def test_masked_epoch_fallback_is_explicit():
    row = sample()
    row.pop("_time")
    row.update(date="2026-09-06", time="17:54:22", eventtime="$16XXXXX", timezone="(GMT+3:30)Tehran")
    event = normalize(row, "waf")
    assert event.timestamp == utc("2026-09-06T14:24:22Z")
    assert "unverified" in event.warnings[0]


@pytest.mark.parametrize("url", ["http://sh3:8089", "https://root:secret@sh3:8089", "https://sh3:8089/foo"])
def test_insecure_service_urls_rejected(url):
    with pytest.raises(ValidationError):
        Endpoint(url=url)


def test_index_injection_rejected():
    with pytest.raises(ValidationError):
        SplunkConfig(url="https://sh3:8089", indexes={"waf": "fwb | delete", "firewall": "fw"})


def test_source_injection_rejected():
    with pytest.raises(ValueError):
        evidence_query(Config().splunk, "waf", '1.2.3.4" | delete')


def test_application_is_quoted_as_eval_literal():
    query = evidence_query(Config().splunk, "waf", "192.0.2.1", 'app" | delete')
    assert 'hunter_app="app\\" | delete"' in query
    assert "_raw" not in query
    assert "packet" not in query


def test_naive_timestamp_rejected():
    with pytest.raises(ValueError):
        utc("2026-01-15T00:00:00")


def test_overlong_window_rejected(tmp_path):
    records, start, end = demo_records()
    with pytest.raises(ValueError):
        hunt(Config(), start, end + timedelta(hours=1), FileStore(tmp_path), fixture=records)


def test_deduplication_id_is_stable_between_runs(tmp_path):
    _, first = demo_case(tmp_path / "one")
    _, second = demo_case(tmp_path / "two")
    assert {f.id for f in first} == {f.id for f in second}
    assert first[0].run_id != second[0].run_id


def test_evidence_budget_is_visible(tmp_path):
    _, findings = demo_case(tmp_path)
    result = next(f for f in findings if f.candidate.src == "198.51.100.10")
    assert len(result.evidence) == 20
    assert any("bounded" in gap for gap in result.report.gaps)


def test_splunk_pagination_and_truncation():
    requests = []

    def handler(request):
        requests.append(request)
        if request.method == "POST":
            return httpx.Response(201, json={"sid": "abc"})
        if request.url.path.endswith("/results"):
            offset = int(request.url.params["offset"])
            count = int(request.url.params["count"])
            return httpx.Response(200, json={"results": [{"n": i} for i in range(offset, offset + count)]})
        return httpx.Response(
            200, json={"entry": [{"content": {"dispatchState": "DONE", "resultCount": 12}}]}
        )

    config = SplunkConfig(url="https://sh3:8089", page_size=4, max_results=10)
    client = Splunk(config, httpx.Client(base_url=config.url, transport=httpx.MockTransport(handler)))
    result = client.search(
        "search index=fwb | stats count", utc("2026-01-01T00:00:00Z"), utc("2026-01-01T01:00:00Z")
    )
    assert len(result.rows) == 10 and result.truncated and result.total == 12
    assert [int(r.url.params["offset"]) for r in requests if r.url.path.endswith("results")] == [0, 4, 8]
    assert all(r.url.host == "sh3" for r in requests)


def test_failed_search_cancels():
    requests = []

    def handler(request):
        requests.append(request)
        if request.url.path.endswith("control"):
            return httpx.Response(200, json={})
        if request.method == "POST":
            return httpx.Response(201, json={"sid": "abc"})
        return httpx.Response(200, json={"entry": [{"content": {"dispatchState": "FAILED"}}]})

    client = Splunk(
        Config().splunk, httpx.Client(base_url="https://sh3:8089", transport=httpx.MockTransport(handler))
    )
    with pytest.raises(RuntimeError):
        client.search("search index=fwb", utc("2026-01-01T00:00:00Z"), utc("2026-01-01T01:00:00Z"))
    assert requests[-1].url.path.endswith("control")


def test_model_fabricated_evidence_is_rejected(tmp_path):
    _, findings = demo_case(tmp_path)
    finding = findings[0]
    report = finding.report.model_dump()
    report["claims"][0]["evidence_ids"] = ["invented"]
    transport = httpx.MockTransport(
        lambda r: httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {"content": json.dumps({"action": "finish", "report": report})},
                    }
                ]
            },
        )
    )
    investigator = Investigator(
        ModelConfig(mode="live"), httpx.Client(base_url="http://localhost/v1/", transport=transport)
    )
    with pytest.raises(ValueError, match="cited"):
        investigator.decide(finding.candidate, finding.evidence, [], [])


def test_model_cannot_invent_tools(tmp_path):
    _, findings = demo_case(tmp_path)
    transport = httpx.MockTransport(
        lambda r: httpx.Response(
            200,
            json={
                "choices": [
                    {"finish_reason": "stop", "message": {"content": '{"action":"shell","report":null}'}}
                ]
            },
        )
    )
    investigator = Investigator(
        ModelConfig(mode="live"), httpx.Client(base_url="http://localhost/v1/", transport=transport)
    )
    with pytest.raises(ValidationError):
        investigator.decide(findings[0].candidate, findings[0].evidence, [], [])


def test_mock_cannot_run_live_hunt(tmp_path):
    _, start, end = demo_records()
    with pytest.raises(ValueError, match="live model"):
        hunt(Config(), start, end, FileStore(tmp_path))


def test_synthetic_findings_never_create_tickets(tmp_path):
    _, findings = demo_case(tmp_path)
    client = Zammad(Config().zammad, httpx.Client())
    with pytest.raises(ValueError, match="Synthetic"):
        client.create(findings[0])


def test_tier2_enforcement_gate(tmp_path):
    _, findings = demo_case(tmp_path)
    finding = findings[0].model_copy(update={"synthetic": False})
    config = Config().zammad.model_copy(update={"enabled": True, "customer_id": 1})
    with pytest.raises(ValueError, match="Tier 2"):
        Zammad(config, httpx.Client()).create(finding)


def test_publication_note_is_internal(tmp_path):
    _, findings = demo_case(tmp_path)
    payloads = []

    def handler(request):
        payloads.append(json.loads(request.content))
        return httpx.Response(201, json={"id": 123})

    config = Config().zammad.model_copy(
        update={
            "enabled": True,
            "customer_id": 1,
            "tier2_role_ids": [5],
            "approval_enforcement_verified": True,
        }
    )
    client = Zammad(config, httpx.Client(base_url="https://zammad", transport=httpx.MockTransport(handler)))
    assert client.create(findings[0].model_copy(update={"synthetic": False})) == 123
    assert payloads[0]["article"]["internal"] is True
    assert payloads[0]["article"]["type"] == "note"
    assert "email" not in payloads[0]["article"]


def test_uncertain_delivery_is_not_reposted(tmp_path):
    from contextlib import nullcontext

    class Store:
        def delivery_lock(self, finding_id):
            return nullcontext()

        def delivery(self, finding_id):
            return {"state": "unknown"}

    class Client:
        def create(self, finding):
            raise AssertionError("Must not POST again")

    _, findings = demo_case(tmp_path)
    result = publish(Store(), Client(), findings[:1])
    assert result["needs_reconciliation"] == 1


def test_empty_window_is_successful_without_findings(tmp_path):
    _, start, end = demo_records()
    run, findings = hunt(Config(), start, end, FileStore(tmp_path), fixture=[])
    assert not findings
    assert run["status"] == "complete"
    assert run["candidate_count"] == 0


def test_candidate_budget_reports_deferred_work(tmp_path):
    config = Config()
    config.hunts.max_candidates = 1
    records, start, end = demo_records()
    run, findings = hunt(config, start, end, FileStore(tmp_path), fixture=records)
    assert len(findings) == 1
    assert any("7 deferred" in gap for gap in run["coverage_gaps"])


def test_followup_is_bounded_and_evidence_accumulates(tmp_path):
    from soc_hunter.domain import Decision

    class Model:
        def __init__(self):
            self.calls = []

        def decide(self, candidate, evidence, available, gaps):
            self.calls.append(list(available))
            if available:
                return Decision(action=available[0])
            return Investigator(ModelConfig()).decide(candidate, evidence, [], gaps)

    config = Config()
    config.hunts.max_candidates = 1
    config.splunk.timestamp_validated = True
    model = Model()
    records, start, end = demo_records()
    run, findings = hunt(config, start, end, FileStore(tmp_path), fixture=records, investigator=model)
    assert len(findings) == 1
    assert model.calls == [["waf_source", "firewall_source"], ["firewall_source"], []]
    assert not run["candidate_failures"]


def test_model_failure_is_recorded_not_silently_mocked(tmp_path):
    class Broken:
        def decide(self, *args):
            raise RuntimeError("Do not expose this raw payload")

    config = Config()
    config.hunts.max_candidates = 1
    records, start, end = demo_records()
    run, findings = hunt(config, start, end, FileStore(tmp_path), fixture=records, investigator=Broken())
    assert not findings and run["status"] == "partial"
    assert run["candidate_failures"][0]["error_type"] == "RuntimeError"
    assert "raw payload" not in json.dumps(run)


def test_splunk_finalization_exposes_coverage_gap():
    def handler(request):
        if request.method == "POST":
            return httpx.Response(201, json={"sid": "abc"})
        return httpx.Response(
            200,
            json={"entry": [{"content": {"dispatchState": "DONE", "resultCount": 0, "isFinalized": True}}]},
        )

    client = Splunk(
        Config().splunk, httpx.Client(base_url="https://sh3:8089", transport=httpx.MockTransport(handler))
    )
    result = client.search("search index=fwb", utc("2026-01-01T00:00:00Z"), utc("2026-01-01T01:00:00Z"))
    assert result.warnings


def test_splunk_timeout_attempts_cancellation(monkeypatch):
    requests = []

    def handler(request):
        requests.append(request)
        if request.method == "POST":
            return httpx.Response(201, json={"sid": "abc"})
        return httpx.Response(200, json={"entry": [{"content": {"dispatchState": "RUNNING"}}]})

    clock = iter([0, 10000])
    monkeypatch.setattr("soc_hunter.splunk.time.monotonic", lambda: next(clock))
    client = Splunk(
        Config().splunk, httpx.Client(base_url="https://sh3:8089", transport=httpx.MockTransport(handler))
    )
    with pytest.raises(TimeoutError):
        client.search("search index=fwb", utc("2026-01-01T00:00:00Z"), utc("2026-01-01T01:00:00Z"))
    assert requests[-1].url.path.endswith("control")


def test_model_context_reduction_cannot_cite_dropped_evidence(tmp_path):
    _, findings = demo_case(tmp_path)
    finding = next(f for f in findings if len(f.evidence) == 20)
    report = finding.report.model_dump()
    report["claims"][0]["evidence_ids"] = [finding.evidence[-1].id]
    transport = httpx.MockTransport(
        lambda r: httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {"content": json.dumps({"action": "finish", "report": report})},
                    }
                ]
            },
        )
    )
    investigator = Investigator(
        ModelConfig(mode="live", max_input_chars=4000),
        httpx.Client(base_url="http://localhost/v1/", transport=transport),
    )
    with pytest.raises(ValueError, match="cited"):
        investigator.decide(finding.candidate, finding.evidence, [], [])


def test_truncated_model_response_rejected(tmp_path):
    _, findings = demo_case(tmp_path)
    transport = httpx.MockTransport(
        lambda r: httpx.Response(
            200, json={"choices": [{"finish_reason": "length", "message": {"content": "{}"}}]}
        )
    )
    investigator = Investigator(
        ModelConfig(mode="live"), httpx.Client(base_url="http://localhost/v1/", transport=transport)
    )
    with pytest.raises(ValueError, match="truncated"):
        investigator.decide(findings[0].candidate, findings[0].evidence, [], [])
