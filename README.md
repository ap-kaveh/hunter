# SOC Hunter — phase-one development pilot

An on-premises, manually initiated investigation service for FortiGate/FortiWeb logs in Splunk.
Includes a local operations dashboard. No scheduler, run tickets, automatic WAF changes, or automatic false-positive closure.

## Current scope

- YAML configuration; secrets in separate files; verified TLS for Splunk, PostgreSQL and Zammad.
- Direct Splunk search-job API connection to `sh3`. Submit, poll and paginated retrieval stay on that member.
- Five-minute WAF aggregation over a bounded hunt window (maximum 12 hours by default).
- Six explainable candidate rules: path enumeration, multiple attack types, high-severity detections,
  sensitive-endpoint volume, historical rate deviation, and shared-signature source clusters.
- Approved WAF/firewall evidence lookups. The model cannot execute arbitrary SPL, shell commands or URLs.
- Structured model output with supplied-event citation validation. Citation existence is checked;
  factual correctness still requires analyst review.
- PostgreSQL run/finding persistence and a separate Zammad publication command.
- Entirely synthetic demo with simulated model output; synthetic findings cannot create tickets.
- Authenticated HTTPS dashboard: start/stop/resume hunts, inspect progress, edit configuration,
  save secret files, test connections, download reports and publish eligible findings.
- Durable run checkpoints. Resume keeps completed findings, re-runs bounded initial searches and
  continues unfinished candidates using the original configuration snapshot.

This is a pilot, not a validated production detector. Thresholds are starting values, not learned PSP baselines.
There is no claim that the selected model fits or performs adequately until it is tested on the RTX 5880.

## VM development

The development VM is AlmaLinux 9.8. Source lives at `/opt/soc-hunter`.

```bash
cd /opt/soc-hunter
python3.12 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/pytest -q
.venv/bin/soc-hunter --config config.demo.yaml demo
```

Read `data/demo/report.md` for the synthetic report and `data/demo/run.json` for coverage/progress.
The demo has eight candidate groups, including normal background traffic that should not generate findings.

## Web dashboard

The development dashboard is served at `https://hunter.example.internal:8443` by `soc-hunter.service`.
It runs as the dedicated `soc-hunter` OS account, not root. Firewall access is limited to the laptop's
observed address `<operator-laptop-IP>`. Its development TLS certificate is self-signed; replace it with an
internal-CA certificate for deployment.

- Username: `admin`. Initial password is in `/var/lib/soc-hunter/ui/initial-password.txt` (owner-only).
- Configuration: `/var/lib/soc-hunter/config.yaml`.
- Dashboard run checkpoints and immutable config snapshots: `/var/lib/soc-hunter/ui/jobs/`.
- Dashboard-managed secrets: `/var/lib/soc-hunter/ui/secrets/`.
- Changing endpoint/hunt settings affects new runs; resume uses the saved snapshot. Rotated secret files
  referenced by that snapshot are read again. The UI prevents secret rotation while a hunt is active.
- One worker runs at a time. Stop interrupts the worker and attempts to cancel its active Splunk job.
- An interrupted in-progress candidate is retried on resume; its completed predecessors are retained.
- Dashboard restarts invalidate login sessions. Worker loss is surfaced as stopped/failed, not success.
- The development login is an operator account. This is not the SOC analyst RBAC/SSO system; analysts
  continue to review findings in Zammad. Production SSO and password-management integration remain pending.
- Demo investigations have a short per-candidate delay so stop/resume can be exercised.

For another installation:

```bash
soc-hunter --config /var/lib/soc-hunter/config.yaml ui-init --ui-dir /var/lib/soc-hunter/ui
soc-hunter --config /var/lib/soc-hunter/config.yaml serve \
  --ui-dir /var/lib/soc-hunter/ui --host 0.0.0.0 --port 8443 \
  --tls-cert /path/to/cert.pem --tls-key /path/to/key.pem
```

Non-loopback serving requires TLS. Sessions use HttpOnly/SameSite cookies, CSRF protection and
login rate limiting. The dashboard serves all CSS/JS locally; there are no CDN/font dependencies.

## Configuration and live operation

Copy `config.example.yaml` to `config.yaml`. Fill hostnames, actual IDs and mounted secret/CA locations.
The example contains placeholders, not working service settings. Do not commit `config.yaml` or secrets.

```bash
soc-hunter --config config.yaml validate-config
soc-hunter --config config.yaml plan
soc-hunter --config config.yaml check splunk
soc-hunter --config config.yaml check postgres
soc-hunter --config config.yaml check model
soc-hunter --config config.yaml check zammad
```

The Splunk check reads server information; some restricted accounts may be denied that endpoint while
still having search permission. A short pilot search is needed to verify `fw`/`fwb` permissions and extraction.
The PostgreSQL check rejects a replica endpoint. Use your HA cluster's designated writable endpoint.

Initialize the dedicated schema in the configured database. The command creates only `soc_hunter` objects.
The DBA must provision the database/account and grant appropriate privileges first.

```bash
soc-hunter --config config.yaml db-init
soc-hunter --config config.yaml hunt \
  --start 2026-09-06T00:00:00+03:30 \
  --end 2026-09-06T12:00:00+03:30
```

Windows are start-inclusive, end-exclusive, with explicit timezone offsets. The service uses UTC internally.
`model.mode: live` is mandatory for real hunts. Model/API failures are recorded as incomplete investigations,
not silently replaced with simulated results. No tickets are created by `hunt`.

After reviewing the saved run and configuring the SOC ticket workflow:

```bash
soc-hunter --config config.yaml publish --run-id RUN_UUID
```

Only findings create tickets. Publication requires `zammad.enabled`, a real internal customer/group,
Tier 2 role IDs, and `approval_enforcement_verified: true`. This last setting is an operator attestation
that the Zammad workflow was tested; it does NOT configure or enforce Zammad permissions by itself.
Do not set it until both UI and API closure paths have been tested for Tier 1 and Tier 2 accounts.

Tickets are internal note articles. Ensure the SOC group does not have triggers that send sensitive notes
to external recipients. Zammad remains authoritative for human review; automatic review synchronization,
and Tier 2 approval integration are not yet implemented in this development slice.

## Duplicate and failed-delivery behavior

A finding has a stable identity for its source/application and exact hunt window. Repeating the exact
window reuses the finding. First saved evidence/report is retained. Publication is serialized per finding
using PostgreSQL advisory locks.

If Zammad times out after a POST, the service marks delivery `unknown` and refuses to blindly repost.
Find the ticket using the `soc-hunter:UUID` tag or finding ID, then reconcile the delivery mapping before
retrying. An interrupted `sending` row is treated the same way. This prevents automatic duplicate retries
but needs an operator reconciliation step. Correlation/updating across overlapping or different windows
is not yet implemented; avoid publishing repeated overlapping hunts in the pilot.

## Evidence and coverage limitations

- Full raw payloads, request headers/bodies, cookies and query values are omitted. Only allowlisted fields
  are persisted or sent to the model. Field text also masks common identifier/email patterns, but this is
  not a general-purpose DLP guarantee. Sensitive data embedded in unusual path formats requires policy review.
- Attack payload inspection is therefore limited. Findings must acknowledge that limitation.
- WAF buckets count log events, not guaranteed distinct HTTP requests; traffic and attack logs may describe
  the same request. Validate shared identifiers before using these counts as request counts.
- All six rules screen WAF data. Firewall source-address lookups add context; they do not yet implement
  outbound anomaly/beaconing algorithms or WAF backend NAT correlation.
- Source/application normalization and attack fields need validation with real attack logs.
- The shared-signature rule finds clusters; a common signature alone does not prove coordinated activity.
- The baseline compares five-minute activity against the maximum observed historical source/application
  bucket. It does not adjust for weekdays, service deployments, missing ingestion periods or seasonality.
- Missing/truncated baselines disable the historical rule. Splunk result limits, candidate limits and
  failed investigations are visible in run records. Search warnings/finalization are treated conservatively.
- `timestamp_validated: false` disables cross-source follow-up. Confirm Splunk `_time` alignment first.
- Existing traffic sample actions such as `server-rst` are preserved without inventing a block/success verdict.
- A successful run means the configured pipeline ran; it is not a certification that the window was threat-free.
- Automatic retention cleanup, cross-window campaign tracking, asset enrichment,
  review synchronization, and a dedicated evaluation dataset remain later implementation work.

## Containers

Build on the VM after installing the locked dependencies:

```bash
podman build -t localhost/soc-hunter:0.1.0 -f Containerfile .
podman run --rm --network=none \
  --tmpfs /var/lib/soc-hunter:rw,mode=1777 \
  localhost/soc-hunter:0.1.0 \
  --config /app/config.demo.yaml demo --output /var/lib/soc-hunter/demo
```

The service image runs as UID 10001. For live runs, mount readable config/secret/CA files and a writable
data directory for that UID; use appropriate SELinux labels (`:Z` for a dedicated bind mount).
Run `validate-config` before adding network access. Do not use `--privileged` or disable SELinux.
Use internal DNS/network routing appropriate to your VLAN. The model server is a separate GPU container
on the deployment server and is not bundled into this CPU development image.

```bash
podman save --format oci-archive -o soc-hunter-0.1.0.oci.tar localhost/soc-hunter:0.1.0
# On the server:
podman load -i soc-hunter-0.1.0.oci.tar
```

Before disconnected deployment, also stage the exact tested vLLM image, model/tokenizer files, and any
GPU runtime packages. Pin their versions/digests after hardware validation. Runtime must use local model
paths and be tested with internet blocked. The small Alpine test image is not an application dependency.

## Optional disposable PostgreSQL test

`tests/test_postgres.py` is skipped unless `HUNTER_TEST_PG_DSN` points to a disposable database.
Do not point it at the production HA cluster. It creates test runs and synthetic findings.

## Next acceptance gates

1. Validate extraction and timestamps with sanitized attack/administration events and Splunk metadata.
2. Measure bounded SPL search cost on sh3 over a short window, then increase scope.
3. Verify PostgreSQL TLS and schema permissions using the designated writable endpoint.
4. Benchmark the pinned model/vLLM combination on the RTX 5880 using reviewed incidents.
5. Configure and verify Zammad 6.5.2 Tier 2 closure permissions before enabling publication.
6. Implement and test review synchronization, retention and cross-window ticket updates.
