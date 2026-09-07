# SOC Hunter 0.1.0 development pilot

Dashboard: https://hunter.example.internal:8443 (development certificate).
The service is enabled at boot and currently restricted to the laptop address <operator-laptop-IP>.
Username: admin. Initial password is stored only on the VM at /var/lib/soc-hunter/ui/initial-password.txt.

Implemented: authenticated web dashboard, manual windows up to 12 hours, synthetic demo,
progress/history/reports, stop and resume, configuration editor, secret replacement, connection tests,
six WAF screening rules, bounded model investigation, PostgreSQL storage, and guarded findings-only
Zammad publication. Demo results are synthetic and cannot be published.

Verification: 46 tests passed, including disposable PostgreSQL integration. The final container
passed both a CLI demo and dashboard/login/worker/report checks with networking disabled.
Stop/resume was tested against the running HTTPS service. Automated browser visual inspection
was blocked by the development certificate; the user opened the dashboard independently.

This is a development pilot. Live Splunk, production PostgreSQL, Zammad and GPU inference have
not been validated. No real tickets were created. Tier 2 permission enforcement must be configured
and tested in Zammad; review synchronization is not implemented. Timestamp alignment and field
extraction require validation before cross-source hunts. See README.md for coverage limitations.

## Files and service

Source: /opt/soc-hunter
Configuration: /var/lib/soc-hunter/config.yaml
State and secrets: /var/lib/soc-hunter/ui
Service: soc-hunter.service
Container archive: /opt/soc-hunter-release/soc-hunter-0.1.0.oci.tar
Image ID: a6a451714e07d87e61f337ac969be31d5842fc33b2712ae00905404b4a8c7ba7

Use Connections to enter service secrets and test each integration, and Configuration to set
endpoints and hunt settings. Saved configuration applies to new hunts. Resume retains the
original run configuration. Start with Run demo; it needs no external service.

For disconnected deployment, load the application OCI archive using Podman. Model weights,
vLLM and NVIDIA container runtime are separate dependencies and are not included. Follow the
README deployment steps and benchmark the model on the RTX 5880 before live use.
