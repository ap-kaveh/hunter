# Fortinet hunting rules — 2026.09.07.1

This release has **17 screening rules: 7 FortiGate and 10 FortiWeb**. Eleven are new.
The rules follow documented log semantics and established detection practices. They are not
vendor-certified detections or universal thresholds. Every hit is an investigation candidate;
the agent must gather evidence and Tier 2 must approve false-positive closure.

## FortiGate

All counts are per source, device and VDOM in a five-minute bucket. These are log events,
not deduplicated connections: start/end/periodic logs may repeat a session. Distinct port and
destination counters reduce that effect for scan screening. Device identifiers must be present.

| Rule ID | Default trigger | Review before judging |
| --- | --- | --- |
| fw_many_ports | At least 20 destination ports and 30 traffic events | Approved scanners, NAT, P2P and service behavior; this is fan-out screening, not proof of a vertical scan |
| fw_many_destinations | At least 20 destinations and 30 traffic events | Proxies, NAT, service discovery, scanners; establish internal/external direction separately |
| fw_deny_burst | At least 100 explicit `action=deny` traffic events | Background internet noise and configuration errors |
| fw_ips_high | Any high/critical IPS detection | Signature accuracy, enforcement action, asset vulnerability, actual outcome |
| fw_malware_detection | Any `subtype=virus` event with virus name/ID | Blocked transfer, EICAR/security testing; detection does not establish execution |
| fw_admin_failures | At least 5 system administrator login events with failed status | Broken automation and administrator errors; not VPN/password-spray coverage |
| fw_config_change | Any event with a configuration path and Add/Edit/Delete action | Approved change record and administrator context; no automatic claim of policy weakening |

Configuration logs often lack source IP. Those changes and IPS/AV detections can be investigated
as device-scoped events with `src=unknown`; they cannot create a scan hypothesis or cross-source lookup.
The application never exports `cfgattr`, which may contain secrets. Configuration review is limited
to path/action and requires an authorized analyst to inspect the detailed change separately.

Firewall traffic, UTM/IPS/antivirus, and system event logging must actually be collected in `fw`.
Missing categories or fields do not establish a clean environment. A device/VDOM boundary is kept
when collecting initial and follow-up firewall evidence. Cross-source IP matching is context only;
it does not resolve NAT or establish that firewall and WAF events describe the same request.

## FortiWeb

Grouped per source and application in five-minute buckets.

| Rule ID | Trigger |
| --- | --- |
| path_enumeration | At least 20 paths and 30 events |
| multiple_attack_types | At least 6 attack events across two or more attack types |
| high_severity_detection | Any high/critical attack detection |
| sensitive_endpoint_volume | At least 30 events on configured sensitive paths |
| historical_rate_deviation | At least 50 events and more than 5 times the source/application's historical peak bucket; complete nonempty baseline required |
| shared_signature_cluster | At least 5 sources sharing a signature/application/bucket; coordination unproven |
| waf_error_probe (new) | At least 30 HTTP 4xx traffic events, at least 80% of traffic events, across at least 20 traffic paths |
| waf_server_error_burst (new) | At least 20 HTTP 5xx traffic events |
| waf_auth_rejection_burst (new) | At least 20 HTTP 401/403 traffic events |
| waf_alert_only_detection (new) | At least 3 attack events with action exactly Alert, case-insensitive |

New HTTP counters use traffic records only, so duplicate attack records cannot inflate them.
HTTP 401/403 can mean forbidden resources or WAF enforcement, not necessarily failed authentication.
Application login events are needed to establish credential stuffing or password guessing.
HTTP 5xx can mean an outage. Alert-only identifies monitoring detections; other enforcement layers
may still block the request. No rule interprets HTTP 200 as proof of successful exploitation.

## Tuning and operation

The dashboard's **Hunting rules** page displays required fields, effective thresholds, enabled state
and common alternatives. Configuration → Advanced YAML exposes all settings. Example:

```yaml
hunts:
  firewall_enabled: true
  disabled_rules: []
  fw_scan_min_ports: 20
  fw_scan_min_destinations: 20
  fw_scan_min_events: 30
  fw_deny_min_events: 100
  fw_admin_fail_min_events: 5
  waf_error_min_events: 30
  waf_error_min_ratio: 0.8
  waf_server_error_min_events: 20
  waf_auth_reject_min_events: 20
  waf_alert_min_events: 3
```

Merge these keys into your existing `hunts` mapping; preserve your other settings. For example,
`disabled_rules: [fw_config_change]` disables that candidate signal for future runs. It is not a
false-positive approval or a change to appliance enforcement. Misspelled rule IDs are rejected.
Common benign explanations are retained in findings even if the model omits them.

Each new run records the ruleset version and effective catalog. Restarted hunts can resume only
under the same ruleset/settings. Runs saved by 0.1.0 remain readable; start a new hunt after this
upgrade rather than trying to resume an old run under changed detection logic.
Finding identity includes the ruleset version to prevent a new analysis silently reusing an old
saved verdict. Re-running a previously published window after an upgrade can therefore create a
new finding; review existing tickets before publication across versions.

Start with a short known window on sh3, inspect extraction and search cost, then test the 12-hour
window. The existing maximum candidates budget is shared by WAF and firewall. Deferred candidates
and incomplete searches remain visible. There are no guaranteed per-source investigation quotas.

Use confirmed incidents, authorized scans, maintenance windows, payment peaks, and routine traffic
as a review set. Record detection coverage and false positives per rule before tuning. Never
silently discard an entire signature category just because previous events were benign.

## Sources and limits

- [FortiOS 7.2.12 Log Reference](https://fortinetweb.s3.amazonaws.com/docs.fortinet.com/v2/attachments/3b0ab1d1-8467-11f0-9bfd-6af4c3636dc7/FortiOS_7.2.12_Log_Reference.pdf): field semantics; administrator login failure message 32002; configuration path/object/attribute messages 44544–44547. Appliance extraction must still be validated.
- [FortiWeb logging guidance](https://docs.fortinet.com/document/fortiweb/7.6.0/administration-guide/303842/logging): traffic/attack visibility and policy-dependent logging. This is 7.6-family guidance, not validation on your exact 7.6.6 build.
- [MITRE ATT&CK T1046](https://attack.mitre.org/techniques/T1046/): service discovery as a hypothesis for network fan-out, not attribution or confirmed technique execution.
- [OWASP logging guidance](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html): authentication failures, security events, operational context and sensitive-data exclusion.
- [OWASP credential-stuffing prevention](https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html): application context needed beyond raw HTTP status counts.

Deferred: beacon timing, exfiltration baselines, denied-then-allowed session correlation, VPN abuse,
distributed authentication attacks, FortiWeb administrative change rules, NAT-aware correlation,
asset inventory and threat intelligence. Implementing those reliably needs additional validated
fields, identity/direction context or historical models. No live Splunk or GPU accuracy claim is made.
