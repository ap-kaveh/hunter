# SOC Hunter 0.2.0 development pilot

Adds eleven detection rules: seven FortiGate rules and four FortiWeb rules, bringing the total to 17.
See RULES.md for logic, thresholds, required fields, source references, tuning and limitations.

Firewall candidates now receive firewall evidence directly, scoped to device and VDOM. Unknown-source
configuration changes can be reviewed by device. Timestamp validation still gates cross-source lookup.
The dashboard includes an authenticated Hunting rules page. Rules can be disabled individually in YAML;
firewall screening also has a form checkbox. Each run records its ruleset and effective rule settings.
Common benign explanations are preserved in findings. Tier 2 approval requirements are unchanged.

This release also fixes model evidence trimming to account for the added context-reduction notice.

## Upgrade

Source: /opt/soc-hunter
Configuration: /var/lib/soc-hunter/config.yaml
State: /var/lib/soc-hunter/ui
Service: soc-hunter.service
Container: localhost/soc-hunter:0.2.0

Existing configuration uses defaults for the new thresholds. Firewall screening defaults to enabled.
Old saved reports remain readable. Start a new hunt after upgrading; do not resume a 0.1.0 hunt
under the changed ruleset. Back up source before upgrade and keep state and secrets outside it.

Real Splunk field extraction and query execution, production PostgreSQL, Zammad and GPU inference
still need site validation. No real tickets are created by tests. The demo uses synthetic data.
