from collections import defaultdict

from .config import HuntConfig
from .domain import Bucket, Candidate, fingerprint


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
        key = (row.src, row.application)
        if row.src == "unknown" or row.application == "unknown":
            return
        if key not in candidates:
            candidates[key] = Candidate(
                key=fingerprint(*key),
                hunts=[],
                src=row.src,
                application=row.application,
                severity="medium",
                signals=[],
                priority=priority,
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
