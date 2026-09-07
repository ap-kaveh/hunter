from datetime import timedelta

import pytest
from pydantic import ValidationError

from soc_hunter.config import Config, HuntConfig
from soc_hunter.detect import detect
from soc_hunter.domain import Bucket, utc
from soc_hunter.model import Investigator
from soc_hunter.normalize import aggregate, aggregate_firewall, normalize
from soc_hunter.rules import RULES, RULESET_VERSION
from soc_hunter.runner import hunt
from soc_hunter.splunk import SearchResult, buckets, evidence_query, firewall_summary_query, summary_query
from soc_hunter.storage import FileStore

START = utc("2026-01-15T00:00:00Z")


def bucket(**values):
    return Bucket(
        **dict(
            timestamp=START,
            src="198.51.100.10",
            application="app",
            count=100,
            paths=0,
            errors=0,
            attacks=0,
            **values,
        )
    )


def fw_record(**values):
    return dict(
        _time=START.isoformat(),
        source="firewall",
        devid="FGT-TEST",
        vd="root",
        srcip="198.51.100.10",
        dstip="192.0.2.1",
        dstport=443,
        **values,
    )


CASES = [
    ("fw_many_ports", "ports", 20, dict(traffic_count=30)),
    ("fw_many_destinations", "destinations", 20, dict(traffic_count=30)),
    ("fw_deny_burst", "denied", 100, {}),
    ("fw_ips_high", "ips_high", 1, {}),
    ("fw_malware_detection", "malware", 1, {}),
    ("fw_admin_failures", "admin_failures", 5, {}),
    ("fw_config_change", "config_changes", 1, {}),
    ("waf_error_probe", "client_errors", 30, dict(traffic_count=30, traffic_paths=20)),
    ("waf_server_error_burst", "server_errors", 20, {}),
    ("waf_auth_rejection_burst", "auth_rejects", 20, {}),
    ("waf_alert_only_detection", "alert_only", 3, {}),
]


@pytest.mark.parametrize("name,metric,threshold,other", CASES)
def test_threshold_and_below_threshold(name, metric, threshold, other):
    row = bucket(source=RULES[name]["source"], device="FGT-TEST", **{metric: threshold}, **other)
    found = detect([row], [], HuntConfig(), False)
    assert name in {rule for candidate in found for rule in candidate.hunts}
    row = row.model_copy(update={metric: threshold - 1})
    assert name not in {
        rule for candidate in detect([row], [], HuntConfig(), False) for rule in candidate.hunts
    }


@pytest.mark.parametrize("name,metric,threshold,other", CASES)
def test_each_new_rule_can_be_disabled(name, metric, threshold, other):
    row = bucket(source=RULES[name]["source"], device="FGT-TEST", **{metric: threshold}, **other)
    assert name not in {
        rule for c in detect([row], [], HuntConfig(disabled_rules=[name]), False) for rule in c.hunts
    }


def test_reject_unknown_disabled_rule():
    with pytest.raises(ValidationError):
        HuntConfig(disabled_rules=["misspelled_rule"])


def test_device_and_vdom_candidates_do_not_merge():
    a = bucket(source="firewall", device="FGT-A", vdom="one", ips_high=1)
    b = a.model_copy(update={"device": "FGT-B"})
    c = a.model_copy(update={"vdom": "two"})
    assert len(detect([a, b, c], [], HuntConfig(), False)) == 3
    assert detect([a], [], HuntConfig(firewall_enabled=False), False) == []


def test_unknown_device_does_not_trigger_firewall_rule():
    assert detect([bucket(source="firewall", ips_high=1)], [], HuntConfig(), False) == []


def test_unknown_sources_do_not_become_scans_but_config_is_reviewable():
    row = bucket(source="firewall", device="FGT", traffic_count=100, ports=30, config_changes=1)
    row.src = "unknown"
    assert detect([row], [], HuntConfig(), False)[0].hunts == ["fw_config_change"]


@pytest.mark.parametrize("action", ["accept", "close", "server-rst", "client-rst", "timeout", "start"])
def test_reset_or_end_of_session_is_not_a_deny(action):
    events = [normalize(fw_record(type="traffic", action=action), "firewall") for _ in range(100)]
    assert detect(aggregate_firewall(events), [], HuntConfig(), False) == []


def test_normalized_firewall_security_and_admin_events():
    records = [
        fw_record(type="utm", subtype="ips", severity="high", attack="Example IPS"),
        fw_record(type="utm", subtype="virus", virus="EICAR-Test-File"),
        fw_record(type="event", subtype="system", action="Edit", cfgpath="firewall.policy"),
    ]
    records += [fw_record(type="event", subtype="system", action="login", status="failed")] * 5
    rows = aggregate_firewall([normalize(r, "firewall") for r in records])
    assert set(detect(rows, [], HuntConfig(), False)[0].hunts) == {
        "fw_ips_high",
        "fw_malware_detection",
        "fw_admin_failures",
        "fw_config_change",
    }
    serialized = normalize(
        fw_record(type="event", cfgattr="password=SECRET", cfgpath="system.admin"), "firewall"
    ).model_dump_json()
    assert "SECRET" not in serialized and "cfgattr" not in serialized


def test_waf_attack_logs_do_not_inflate_http_failure_counts():
    records = [
        dict(
            _time=START.isoformat(),
            src="198.51.100.10",
            http_host="app",
            http_retcode=403,
            type="attack",
            action="Alert_Deny",
        )
    ] * 40
    row = aggregate([normalize(r, "waf") for r in records], [])[0]
    assert row.auth_rejects == row.client_errors == row.alert_only == 0
    records[0] = dict(records[0], type="traffic", http_retcode=503)
    row = aggregate([normalize(r, "waf") for r in records], [])[0]
    assert row.server_errors == row.traffic_count == 1


def test_client_error_ratio_filters_mostly_normal_traffic():
    row = bucket(client_errors=30, traffic_count=100, traffic_paths=30)
    assert "waf_error_probe" not in {r for c in detect([row], [], HuntConfig(), False) for r in c.hunts}


def test_live_firewall_query_scope_and_allowlist():
    config = Config()
    query = firewall_summary_query(config.splunk)
    assert "index=fw" in query and "span=5m" in query
    assert "hunter_device hunter_vdom" in query
    q = evidence_query(config.splunk, "firewall", "unknown", device="FGT", vdom="root")
    assert 'hunter_src="unknown"' in q and 'hunter_device="FGT"' in q
    assert "cfgattr" not in q and "_raw" not in q and " packet" not in q
    with pytest.raises(ValueError):
        evidence_query(config.splunk, "firewall", "unknown")
    q = summary_query(config.splunk, config.hunts)
    assert 'type="traffic" AND hunter_status' in q


def test_result_conversion_preserves_new_metrics():
    result = SearchResult(
        "test",
        [
            dict(
                _time=START.timestamp(),
                hunter_src="198.51.100.10",
                hunter_source="firewall",
                hunter_app="firewall",
                hunter_device="FGT",
                hunter_vdom="root",
                count="100",
                denied="100",
                ports="1",
            )
        ],
        1,
        False,
        [],
    )
    candidate = detect(buckets(result), [], HuntConfig(), False)[0]
    assert candidate.source == "firewall" and candidate.hunts == ["fw_deny_burst"]


def test_firewall_candidate_gets_firewall_evidence_without_cross_source_permission(tmp_path):
    config = Config()
    records = [fw_record(type="utm", subtype="ips", severity="high", attack="Example")]
    seen = []

    class Model:
        def decide(self, candidate, evidence, available, gaps):
            seen.append((candidate.source, {e.source for e in evidence}, available))
            return Investigator(config.model).decide(candidate, evidence, [], gaps)

    run, findings = hunt(
        config, START, START + timedelta(hours=1), FileStore(tmp_path), fixture=records, investigator=Model()
    )
    assert not run["candidate_failures"] and len(findings) == 1
    assert seen == [("firewall", {"firewall"}, ["firewall_source"])]
    assert run["config"]["ruleset"] == RULESET_VERSION
    assert len(run["rule_catalog"]) == 17


def test_device_only_config_change_gets_evidence(tmp_path):
    record = fw_record(type="event", subtype="system", action="Edit", cfgpath="firewall.policy")
    record.pop("srcip")
    run, findings = hunt(Config(), START, START + timedelta(hours=1), FileStore(tmp_path), fixture=[record])
    assert not run["candidate_failures"] and findings[0].candidate.hunts == ["fw_config_change"]


def test_live_runner_searches_firewall_and_records_incomplete_coverage(tmp_path):
    class Splunk:
        history = []
        queries = []

        def search(self, query, *args):
            self.queries.append(query)
            if "index=fw " in query and "stats count" in query:
                return SearchResult(
                    "fw",
                    [
                        dict(
                            _time=START.timestamp(),
                            hunter_src="198.51.100.10",
                            hunter_source="firewall",
                            hunter_app="firewall",
                            hunter_device="FGT-TEST",
                            hunter_vdom="root",
                            count=1,
                            ips_high=1,
                        )
                    ],
                    2,
                    True,
                    [],
                )
            if "index=fw " in query:
                return SearchResult(
                    "evidence",
                    [fw_record(type="utm", subtype="ips", severity="high", attack="test")],
                    1,
                    False,
                    [],
                )
            return SearchResult("waf", [], 0, False, [])

    config = Config()
    config.model.mode = "live"
    splunk = Splunk()
    # Inject a deterministic investigator only in this test; runtime forbids mock live hunts.
    run, findings = hunt(
        config,
        START,
        START + timedelta(hours=1),
        FileStore(tmp_path),
        splunk=splunk,
        investigator=Investigator(Config().model),
    )
    assert len(findings) == 1 and run["status"] == "partial"
    assert any("Firewall aggregation is incomplete" in gap for gap in run["coverage_gaps"])
    assert 'hunter_device="FGT-TEST"' in splunk.queries[-1]
