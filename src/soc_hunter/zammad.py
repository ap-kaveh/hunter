import httpx

from .config import ZammadConfig, secret, tls_context
from .domain import Finding


def ticket_text(finding: Finding):
    report = finding.report
    lines = [
        f"Finding ID: {finding.id}",
        f"Run ID: {finding.run_id}",
        f"Window: {finding.window_start.isoformat()} to {finding.window_end.isoformat()} (end exclusive)",
        f"Application: {finding.candidate.application}",
        f"Source: {finding.candidate.src}",
        f"Hunts: {', '.join(finding.candidate.hunts)}",
        f"Model: {finding.model}",
        "AI recommendation — UNREVIEWED",
        f"Assessment: {report.assessment}",
        f"Outcome: {report.outcome}",
        "",
        report.summary,
        "",
        "Evidence-backed claims:",
    ]
    lines += [f"- {claim.text} [events: {', '.join(claim.evidence_ids)}]" for claim in report.claims]
    for title, items in [
        ("Alternative explanations", report.alternatives),
        ("Evidence gaps", report.gaps),
        ("Next steps", report.next_steps),
    ]:
        lines += ["", title + ":"] + ["- " + item for item in items]
    lines += ["", "Selected evidence (sanitized; this is not full traffic coverage):"]
    for event in finding.evidence:
        lines.append(
            f"- {event.id} | {event.timestamp.isoformat()} | {event.source} | "
            f"{event.src} -> {event.dst}:{event.dst_port} | {event.method} {event.path} | "
            f"HTTP {event.status} | action={event.action} | signature={event.signature}"
        )
    lines += [
        "",
        "Tier 1 may propose false positive. Tier 2 must approve closure with rationale.",
        "Closing this finding does not authorize WAF rule changes or future suppression.",
    ]
    return "\n".join(lines)


class Zammad:
    def __init__(self, config: ZammadConfig, client=None):
        self.config = config
        self.client = client or httpx.Client(
            base_url=config.url,
            headers={"Authorization": f"Token token={secret(config.token_file)}"},
            verify=tls_context(config.ca_file),
            timeout=config.timeout_seconds,
            follow_redirects=False,
        )

    def check(self):
        response = self.client.get("/api/v1/users/me")
        response.raise_for_status()
        user = response.json()
        return {"reachable": True, "user_id": user["id"], "role_ids": user.get("role_ids", [])}

    def create(self, finding: Finding):
        if finding.synthetic:
            raise ValueError("Synthetic findings cannot be published")
        if not self.config.enabled or not self.config.customer_id:
            raise ValueError("Configure and enable Zammad with an internal customer ID first")
        if not self.config.approval_enforcement_verified or not self.config.tier2_role_ids:
            raise ValueError("Tier 2 closure enforcement must be verified before live publication")
        marker = "soc-hunter:" + finding.id
        response = self.client.post(
            "/api/v1/tickets",
            json={
                "title": f"[AI hunt][{finding.candidate.severity}] {finding.candidate.application} — {finding.candidate.src}",
                "group_id": self.config.group_id,
                "customer_id": self.config.customer_id,
                "priority_id": 3 if finding.candidate.severity == "high" else 2,
                "tags": "soc-hunter,ai-unreviewed," + marker,
                "article": {
                    "subject": "Automated investigation",
                    "body": ticket_text(finding),
                    "type": "note",
                    "internal": True,
                    "content_type": "text/plain",
                },
            },
        )
        response.raise_for_status()
        return int(response.json()["id"])


def publish(store, zammad, findings):
    result = {"created": 0, "already_sent": 0, "needs_reconciliation": 0}
    for finding in findings:
        with store.delivery_lock(finding.id):
            existing = store.delivery(finding.id)
            if existing:
                if existing["state"] == "sent":
                    result["already_sent"] += 1
                else:
                    # A timeout/crash may have occurred AFTER Zammad created the ticket.
                    # Never blindly POST again: reconcile using the finding marker first.
                    result["needs_reconciliation"] += 1
                continue
            if finding.synthetic:
                raise ValueError("Synthetic findings cannot enter the delivery queue")
            store.mark_delivery(finding.id, "sending")
            try:
                ticket_id = zammad.create(finding)
            except Exception:
                store.mark_delivery(finding.id, "unknown")
                raise
            store.mark_delivery(finding.id, "sent", ticket_id)
            result["created"] += 1
    return result
