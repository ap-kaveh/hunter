from datetime import timedelta
from pathlib import Path
from uuid import uuid4

from . import __version__
from .detect import detect
from .domain import Finding
from .model import Investigator
from .normalize import aggregate, aggregate_firewall, normalize
from .rules import RULES, RULESET_VERSION, catalog
from .splunk import buckets, evidence_query, firewall_summary_query, summary_query
from .storage import now
from .zammad import ticket_text


def hunt(
    config,
    start,
    end,
    store,
    *,
    fixture=None,
    splunk=None,
    investigator=None,
    resume_id=None,
    progress=None,
    demo_delay=0,
):
    if end <= start or (end - start).total_seconds() > config.hunts.max_window_hours * 3600:
        raise ValueError("Hunt window must be positive and within the configured maximum")
    synthetic = fixture is not None
    if not synthetic and config.model.mode != "live":
        raise ValueError("Real hunts require a live model; mock is restricted to synthetic demo")
    run = {
        "id": str(uuid4()),
        "status": "running",
        "started_at": now(),
        "window_start": start.isoformat(),
        "window_end": end.isoformat(),
        "synthetic": synthetic,
        "model": config.model.name if not synthetic else "mock",
        "config": {"hunts": config.hunts.model_dump(), "version": __version__, "ruleset": RULESET_VERSION},
        "rule_catalog": catalog(config.hunts),
        "coverage_gaps": [],
        "finding_count": 0,
        "candidate_failures": [],
        "searches": [],
    }
    findings = []
    if resume_id:
        previous = store.get_run(resume_id)
        if (
            previous["window_start"] != start.isoformat()
            or previous["window_end"] != end.isoformat()
            or previous["synthetic"] != synthetic
            or previous["config"]["hunts"] != config.hunts.model_dump()
            or previous["model"] != run["model"]
            or previous["config"].get("ruleset") != RULESET_VERSION
        ):
            raise ValueError("Resume requires the original window, model and hunt settings")
        run["id"] = resume_id
        run["started_at"] = previous["started_at"]
        run["resume_count"] = previous.get("resume_count", 0) + 1
        findings = store.findings(resume_id)
        run["finding_count"] = len(findings)
    completed = {f.candidate.key for f in findings}

    def checkpoint(stage):
        run["stage"] = stage
        run["updated_at"] = now()
        run["searches"] = splunk.history if splunk else []
        store.save_run(run)
        if progress:
            progress(run)

    checkpoint("preparing")
    baseline_start = start - timedelta(days=config.hunts.baseline_days)
    try:
        investigator = investigator or Investigator(config.model)
        events = []
        baseline_complete = True
        if synthetic:
            checkpoint("reading_demo")
            for record in fixture:
                try:
                    events.append(normalize(record, record.get("source", "waf")))
                except (ValueError, KeyError, TypeError):
                    run["coverage_gaps"].append("An event could not be normalized and was excluded")
            current = aggregate(
                [e for e in events if start <= e.timestamp < end], config.hunts.sensitive_paths
            )
            baseline = aggregate(
                [e for e in events if baseline_start <= e.timestamp < start], config.hunts.sensitive_paths
            )
            if config.hunts.firewall_enabled:
                current += aggregate_firewall([e for e in events if start <= e.timestamp < end])
            run["coverage_gaps"].append("Synthetic fixture only; no real-world coverage or AI verdict")
        else:
            if not config.splunk.timestamp_validated:
                run["coverage_gaps"].append(
                    "Splunk timestamps are unvalidated; cross-source follow-up disabled"
                )
            query = summary_query(config.splunk, config.hunts)
            checkpoint("searching_current_window")
            recent = splunk.search(query, start, end)
            checkpoint("searching_baseline")
            history = splunk.search(query, baseline_start, start)
            current, baseline = buckets(recent), buckets(history)
            if recent.truncated or recent.warnings:
                run["coverage_gaps"].append(
                    "Current-window aggregation is incomplete; candidates may be missed"
                )
            if history.truncated or history.warnings:
                baseline_complete = False
                run["coverage_gaps"].append(
                    "Baseline aggregation is incomplete; rate-deviation rule disabled"
                )
            if not baseline:
                baseline_complete = False
                run["coverage_gaps"].append("No baseline returned; rate-deviation rule disabled")
            if config.hunts.firewall_enabled:
                checkpoint("searching_firewall")
                firewall = splunk.search(firewall_summary_query(config.splunk), start, end)
                current += buckets(firewall)
                if firewall.truncated or firewall.warnings:
                    run["coverage_gaps"].append(
                        "Firewall aggregation is incomplete; firewall candidates may be missed"
                    )
                if not firewall.rows:
                    run["coverage_gaps"].append(
                        "No firewall buckets returned; check collection and permissions before interpreting coverage"
                    )
            else:
                run["coverage_gaps"].append("Firewall screening disabled by configuration")
        if any(row.source == "firewall" and row.device == "unknown" for row in current):
            run["coverage_gaps"].append("Firewall buckets without a device ID are excluded from detection")
        if any(row.src == "unknown" or row.application == "unknown" for row in current):
            run["coverage_gaps"].append(
                "Missing source/application fields limit entity detection; device-scoped security/configuration events may still be reviewed"
            )
        all_candidates = detect(current, baseline, config.hunts, baseline_complete)
        run["candidate_count"] = len(all_candidates)
        run["current_buckets"] = len(current)
        run["baseline_buckets"] = len(baseline)
        if len(all_candidates) > config.hunts.max_candidates:
            run["coverage_gaps"].append(
                f"Candidate budget reached: {len(all_candidates) - config.hunts.max_candidates} deferred"
            )
        run["coverage_gaps"].append(
            "Rules identify hypotheses, not confirmed attacks. Missing event categories/fields can hide detections; validate collection."
        )
        run["candidate_budget"] = min(len(all_candidates), config.hunts.max_candidates)
        checkpoint("investigating")
        for candidate in all_candidates[: config.hunts.max_candidates]:
            if candidate.key in completed:
                continue
            try:
                run["active_candidate"] = {"source": candidate.src, "application": candidate.application}
                checkpoint("gathering_evidence")
                if synthetic and demo_delay:
                    import time

                    time.sleep(demo_delay)
                gaps = list(run["coverage_gaps"])

                def fetch(source, application=None):
                    scoped = source == "firewall" and candidate.source == "firewall"
                    if synthetic:
                        selected = [
                            e
                            for e in events
                            if e.source == source
                            and start <= e.timestamp < end
                            and (e.src == candidate.src or (source == "firewall" and e.dst == candidate.src))
                            and (not application or e.application == application)
                            and (not scoped or (e.device == candidate.device and e.vdom == candidate.vdom))
                        ]
                        selected.sort(key=lambda e: (e.event_type != "attack", e.timestamp))
                        if len(selected) > config.hunts.evidence_per_candidate:
                            gaps.append("Evidence is a bounded selection, not every matching event")
                        return selected[: config.hunts.evidence_per_candidate]
                    result = splunk.search(
                        evidence_query(
                            config.splunk,
                            source,
                            candidate.src,
                            application,
                            candidate.device if scoped else None,
                            candidate.vdom if scoped else None,
                        ),
                        start,
                        end,
                        config.hunts.evidence_per_candidate,
                    )
                    if result.truncated or result.warnings:
                        gaps.append(
                            "Evidence search is limited; selected events do not establish full coverage"
                        )
                    selected = [normalize(row, source) for row in result.rows]
                    gaps.append("Raw request headers and bodies were not retrieved")
                    if not selected:
                        gaps.append(
                            f"No events returned for {source} follow-up; this is not proof of absence"
                        )
                    return selected

                evidence = fetch(
                    candidate.source, candidate.application if candidate.source == "waf" else None
                )
                tools = [candidate.source + "_source"]
                if config.splunk.timestamp_validated and candidate.src != "unknown":
                    tools.append("firewall_source" if candidate.source == "waf" else "waf_source")
                report = None
                for step in range(config.hunts.max_followups + 1):
                    checkpoint("analyzing_evidence")
                    available = tools if step < config.hunts.max_followups else []
                    decision = investigator.decide(candidate, evidence, available, gaps)
                    if decision.action == "finish":
                        report = decision.report
                        break
                    tools.remove(decision.action)
                    additional = fetch("waf" if decision.action == "waf_source" else "firewall")
                    evidence = list({e.id: e for e in evidence + additional}.values())
                if report is None:
                    raise ValueError("Investigation ended without a valid final report")
                # Preserve limitations even when the model omits them.
                report.alternatives = list(
                    dict.fromkeys(
                        report.alternatives + [RULES[name]["alternatives"] for name in candidate.hunts]
                    )
                )
                report.gaps = list(
                    dict.fromkeys(report.gaps + gaps + [w for e in evidence for w in e.warnings])
                )
                finding = Finding(
                    id=Finding.stable_id(candidate, start, end, synthetic),
                    run_id=run["id"],
                    candidate=candidate,
                    evidence=evidence,
                    report=report,
                    synthetic=synthetic,
                    window_start=start,
                    window_end=end,
                    model=run["model"],
                )
                store.save_finding(finding)
                findings.append(finding)
                run["finding_count"] += 1
            except Exception as exc:
                run["candidate_failures"].append(
                    {"candidate_key": candidate.key, "error_type": type(exc).__name__}
                )
            checkpoint("investigating")
        run["status"] = (
            "partial"
            if run["candidate_failures"] or (not synthetic and len(run["coverage_gaps"]) > 1)
            else "complete"
        )
        run["finished_at"] = now()
        run.pop("active_candidate", None)
        checkpoint("finished")
        return run, findings
    except BaseException as exc:
        run.update(
            status="interrupted" if isinstance(exc, KeyboardInterrupt) else "failed",
            error_type=type(exc).__name__,
            finished_at=now(),
        )
        checkpoint("stopped" if isinstance(exc, KeyboardInterrupt) else "failed")
        raise


def write_report(directory, run, findings):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    lines = [
        "# SOC Hunter run",
        "",
        f"Run: {run['id']}",
        f"Status: {run['status']}",
        f"Window: {run['window_start']} to {run['window_end']}",
        f"Candidates: {run.get('candidate_count', 0)}; findings: {run['finding_count']}",
        "",
        "SYNTHETIC DEMO — no AI security verdict and no live tickets."
        if run["synthetic"]
        else "AI findings require analyst review.",
        "",
        "## Coverage",
        "",
    ]
    lines += ["- " + gap for gap in run["coverage_gaps"]]
    for finding in findings:
        lines += ["", "## Finding " + finding.id, "", "```text", ticket_text(finding), "```"]
    (directory / "report.md").write_text("\n".join(lines), encoding="utf-8")
