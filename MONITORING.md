# Monitoring

Open **Monitoring** in the dashboard. Authenticated operators can see:

- Per-GPU utilization, VRAM usage/capacity, temperature and power draw/limit.
- CPU busy percentage, logical CPU count and CPU I/O-wait percentage.
- RAM availability/usage and swap usage.
- Free/used space for the app-state and root filesystems.
- Per-device disk read/write bytes per second, IOPS and busy milliseconds per second.
- Per-interface network receive/send rates, error rates and dropped-packet rates.
- Current cgroup v2 memory usage and locally visible memory/CPU quotas, when exposed.
- Recent CPU/RAM/GPU charts, limited to 120 samples in app memory.

The page requests samples every five seconds while visible. The backend shares a five-second
cache across viewers and serializes collection. GPU queries time out after two seconds. Rates
need two samples; first readings, unsupported sensors and counter resets are **unavailable**,
not zero. A failed browser request marks displayed readings stale.

This is an interactive operations view, not a persistent monitoring/alerting platform. Metrics
are not stored in PostgreSQL or on disk. Collection stops when nobody requests the page;
history resets with the dashboard process. Long gaps break chart lines. No alerts, email,
notifications or automated remediation are configured.

## Scope and deployment

Readings describe the environment visible to the app. On the development VM they describe
that VM. They do not measure the Windows Hyper-V host or a separate model/database server.
In a container, Linux CPU/RAM/disk counters can describe the host/VM while network counters
describe the container's network namespace. The page labels this explicitly. Cgroup readings
are presented separately; ancestor quotas may impose tighter effective limits.

GPU usage includes all workloads visible on each exposed device; it is not attribution to a
specific hunt or model. The CPU-only development VM is expected to show no GPU telemetry.
On the RTX 5880 deployment host, `nvidia-smi` and driver/device access must be available to the
app's service account or container. Use the supported NVIDIA Container Toolkit/CDI setup for
the deployment environment. Installing this page does not install a driver or start GPU inference.
Keep the existing non-root service and SELinux protections; privileged containers are unnecessary.

Counters come from `/proc`, `/sys` and a fixed read-only NVIDIA query. The API accepts no paths,
shell commands or remote targets. It does not read logs, environment variables, process command
lines, request payloads, service passwords or model prompts.

Filesystem figures may represent the same filesystem twice; they are not additive. Partition
and loop-device disk counters are excluded, but device-mapper and backing devices may overlap.
Do not sum them. Disk busy time is an activity measure, not reliable NVMe saturation or latency.
Network totals include non-hunt traffic in the visible namespace; they are not Splunk transfer metrics.

## References

- [NVIDIA System Management Interface](https://docs.nvidia.com/deploy/nvidia-smi/index.html)
- [Linux block statistics and 512-byte sectors](https://cdn.kernel.org/doc/html/latest/block/stat.html)
- [Linux cgroup v2 interfaces](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html)

Remote GPU telemetry, PostgreSQL/Splunk performance dashboards, persistent retention and
threshold notifications can be added separately if operational requirements call for them.
