from datetime import timedelta
from pathlib import Path
from uuid import uuid4

from .detect import detect
from .domain import Finding
from .model import Investigator
from .normalize import aggregate, normalize
from .splunk import buckets, evidence_query, summary_query
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
        "config": {"hunts": config.hunts.model_dump(), "version": "0.1.0"},
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
        if any(row.src == "unknown" or row.application == "unknown" for row in current):
            run["coverage_gaps"].append(
                "Events with missing source/application cannot generate entity candidates"
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
            "Phase one screens WAF events; firewall is contextual enrichment, not a full firewall hunt"
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
                    if synthetic:
                        selected = [
                            e
                            for e in events
                            if e.source == source
                            and start <= e.timestamp < end
                            and (e.src == candidate.src or (source == "firewall" and e.dst == candidate.src))
                            and (not application or e.application == application)
                        ]
                        selected.sort(key=lambda e: (e.event_type != "attack", e.timestamp))
                        if len(selected) > config.hunts.evidence_per_candidate:
                            gaps.append("Evidence is a bounded selection, not every matching event")
                        return selected[: config.hunts.evidence_per_candidate]
                    result = splunk.search(
                        evidence_query(config.splunk, source, candidate.src, application),
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

                evidence = fetch("waf", candidate.application)
                tools = ["waf_source"]
                if config.splunk.timestamp_validated:
                    tools.append("firewall_source")
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
