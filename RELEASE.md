# SOC Hunter 0.3.0 development pilot

Adds an authenticated Monitoring page with GPU, CPU, memory, disk space, disk I/O, network and
cgroup readings plus short in-memory activity charts. See MONITORING.md for scope and setup.
Unsupported sensors remain unavailable. Queries are cached and the NVIDIA command has a timeout.
No extra Python dependency, telemetry database, log ingestion or external monitoring service is added.

The 17 hunting rules and ruleset version are unchanged from 0.2.0. Existing 0.2.0 run checkpoints
remain compatible when original hunt settings/model/window are preserved. Live service and GPU
inference validation remain pending. Monitoring the local environment does not monitor remote hosts.

Configuration: /var/lib/soc-hunter/config.yaml
State: /var/lib/soc-hunter/ui
Service: soc-hunter.service
Container: localhost/soc-hunter:0.3.0

The development VM has no exposed GPU. NVIDIA telemetry requires the utility, driver and device
access on the deployment host/container. See MONITORING.md; no privileged container is required.
