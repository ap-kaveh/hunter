from collections import defaultdict

from .config import HuntConfig
from .domain import Bucket, Candidate, fingerprint
from .rules import RULESET_VERSION


def detect(
    current: list[Bucket], baseline: list[Bucket], config: HuntConfig, baseline_complete: bool
) -> list[Candidate]:
    """Explainable candidates, not confirmed attacks. Rules merge per source/application."""
    candidates = {}
    normal_peaks = defaultdict(int)
    for row in baseline:
        key = (row.src, row.application)
        normal_peaks[key] = max(normal_peaks[key], row.count)

    def add(row, hunt, signal, priority=50):
        if hunt in config.disabled_rules:
            return
        key = (
            (row.source, row.device, row.vdom, row.src, row.application)
            if row.source == "firewall"
            else (row.src, row.application)
        )
        if (row.src == "unknown" and row.source == "waf") or row.application == "unknown":
            return
        if key not in candidates:
            candidates[key] = Candidate(
                key=fingerprint(RULESET_VERSION, *key),
                ruleset=RULESET_VERSION,
                hunts=[],
                src=row.src,
                application=row.application,
                severity="medium",
                signals=[],
                priority=priority,
                source=row.source,
                device=row.device,
                vdom=row.vdom,
            )
        candidate = candidates[key]
        if hunt not in candidate.hunts:
            candidate.hunts.append(hunt)
        if signal not in candidate.signals and len(candidate.signals) < 12:
            candidate.signals.append(signal)
        candidate.priority = max(candidate.priority, priority)
        if priority >= 80:
            candidate.severity = "high"

    campaigns = defaultdict(list)
    for row in current:
        if row.source == "firewall":
            if not config.firewall_enabled or row.device == "unknown":
                continue
            checks = [
                (
                    row.traffic_count >= config.fw_scan_min_events and row.ports >= config.fw_scan_min_ports,
                    "fw_many_ports",
                    f"{row.ports} destination ports across {row.traffic_count} traffic logs",
                    60,
                ),
                (
                    row.traffic_count >= config.fw_scan_min_events
                    and row.destinations >= config.fw_scan_min_destinations,
                    "fw_many_destinations",
                    f"{row.destinations} destinations across {row.traffic_count} traffic logs",
                    60,
                ),
                (
                    row.denied >= config.fw_deny_min_events,
                    "fw_deny_burst",
                    f"{row.denied} explicit deny logs",
                    50,
                ),
                (
                    row.ips_high > 0,
                    "fw_ips_high",
                    f"{row.ips_high} high/critical IPS detections; outcome unverified",
                    85,
                ),
                (
                    row.malware > 0,
                    "fw_malware_detection",
                    f"{row.malware} antivirus detections; execution unproven",
                    85,
                ),
                (
                    row.admin_failures >= config.fw_admin_fail_min_events,
                    "fw_admin_failures",
                    f"{row.admin_failures} failed administrator login events",
                    75,
                ),
                (
                    row.config_changes > 0,
                    "fw_config_change",
                    f"{row.config_changes} configuration changes; authorization unverified",
                    65,
                ),
            ]
            for triggered, name, signal, priority in checks:
                if row.src == "unknown" and name not in (
                    "fw_config_change",
                    "fw_ips_high",
                    "fw_malware_detection",
                ):
                    continue
                if triggered:
                    add(row, name, signal + " in five minutes", priority)
            continue
        if (
            row.client_errors >= config.waf_error_min_events
            and row.traffic_count
            and row.client_errors / row.traffic_count >= config.waf_error_min_ratio
            and row.traffic_paths >= config.scan_min_paths
        ):
            add(
                row,
                "waf_error_probe",
                f"{row.client_errors}/{row.traffic_count} traffic logs have 4xx status across {row.traffic_paths} paths in five minutes",
                65,
            )
        if row.server_errors >= config.waf_server_error_min_events:
            add(
                row,
                "waf_server_error_burst",
                f"{row.server_errors} HTTP 5xx traffic logs in five minutes; availability issue or attack",
                60,
            )
        if row.auth_rejects >= config.waf_auth_reject_min_events:
            add(
                row,
                "waf_auth_rejection_burst",
                f"{row.auth_rejects} HTTP 401/403 traffic logs in five minutes; authentication attack unproven",
                65,
            )
        if row.alert_only >= config.waf_alert_min_events:
            add(
                row,
                "waf_alert_only_detection",
                f"{row.alert_only} alert-only attack logs in five minutes; other controls may still block",
                75,
            )
        if row.paths >= config.scan_min_paths and row.count >= config.scan_min_requests:
            add(
                row,
                "path_enumeration",
                f"{row.paths} distinct paths / {row.count} events in a five-minute bucket",
            )
        if row.attacks >= config.multi_attack_min_events and len(row.attack_types) >= 2:
            add(
                row,
                "multiple_attack_types",
                f"{row.attacks} attack events covering {len(row.attack_types)} types",
                70,
            )
        if row.high:
            add(
                row,
                "high_severity_detection",
                f"{row.high} high/critical vendor detections; accuracy unverified",
                80,
            )
        if row.sensitive >= config.sensitive_min_requests:
            add(
                row,
                "sensitive_endpoint_volume",
                f"{row.sensitive} sensitive-endpoint events in five minutes",
                60,
            )
        peak = normal_peaks[(row.src, row.application)]
        if (
            baseline_complete
            and peak
            and row.count >= config.rate_min_requests
            and row.count > peak * config.rate_multiplier
        ):
            add(
                row,
                "historical_rate_deviation",
                f"Five-minute count {row.count} exceeds historical observed peak {peak} by configured factor",
                65,
            )
        for signature in row.signatures:
            campaigns[(row.timestamp, row.application, signature)].append(row)
    for (stamp, app, signature), rows in campaigns.items():
        source_count = len({row.src for row in rows if row.src != "unknown"})
        if source_count >= config.campaign_min_sources:
            for row in rows:
                add(
                    row,
                    "shared_signature_cluster",
                    f"{source_count} sources share a vendor signature on this application in five minutes; coordination unproven",
                    65,
                )
    return sorted(candidates.values(), key=lambda c: (-c.priority, c.key))
