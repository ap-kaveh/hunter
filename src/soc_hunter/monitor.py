"""Read-only Linux/NVIDIA telemetry. No log data or persistent metric storage."""

import csv
import math
import os
import shutil
import subprocess
import threading
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path


def number(value):
    try:
        result = float(value)
        return result if math.isfinite(result) and result >= 0 else None
    except (TypeError, ValueError):
        return None


def gpu_snapshot():
    executable = shutil.which("nvidia-smi")
    if not executable:
        return {
            "status": "unavailable",
            "message": "NVIDIA monitoring is not exposed to this app. No GPU or driver utility is visible.",
            "devices": [],
        }
    try:
        result = subprocess.run(
            [
                executable,
                "--query-gpu=index,name,utilization.gpu,memory.used,memory.total,temperature.gpu,power.draw,power.limit",
                "--format=csv,noheader,nounits",
            ],
            capture_output=True,
            text=True,
            timeout=2,
            check=True,
        )
        devices = []
        for row in csv.reader(result.stdout.splitlines()):
            if len(row) != 8:
                raise ValueError("Unexpected GPU response")
            devices.append(
                dict(
                    index=row[0].strip(),
                    name=row[1].strip()[:120],
                    **dict(
                        zip(
                            (
                                "utilization_pct",
                                "memory_used_mib",
                                "memory_total_mib",
                                "temperature_c",
                                "power_w",
                                "power_limit_w",
                            ),
                            map(number, row[2:]),
                        )
                    ),
                )
            )
        return {
            "status": "available" if devices else "unavailable",
            "message": "Visible GPU devices; usage includes all workloads on each device.",
            "devices": devices,
        }
    except (OSError, subprocess.SubprocessError, ValueError):
        return {
            "status": "unavailable",
            "message": "NVIDIA query failed or timed out; check driver and device access.",
            "devices": [],
        }


def read(path):
    try:
        return path.read_text()
    except OSError:
        return ""


def counters(proc, sys):
    cpu = next(
        (line.split()[1:9] for line in read(proc / "stat").splitlines() if line.startswith("cpu ")), []
    )
    disks = {}
    for line in read(proc / "diskstats").splitlines():
        fields = line.split()
        if len(fields) < 14:
            continue
        name = fields[2]
        if name.startswith(("loop", "ram")) or (sys / "class/block" / name / "partition").exists():
            continue
        disks[name] = {
            "read_bytes": int(fields[5]) * 512,
            "write_bytes": int(fields[9]) * 512,
            "read_ops": int(fields[3]),
            "write_ops": int(fields[7]),
            "busy_ms": int(fields[12]),
        }
    network = {}
    for line in read(proc / "net/dev").splitlines():
        if ":" not in line:
            continue
        name, raw = line.split(":", 1)
        fields = raw.split()
        if len(fields) >= 16 and name.strip() != "lo":
            network[name.strip()] = {
                "rx_bytes": int(fields[0]),
                "tx_bytes": int(fields[8]),
                "rx_errors": int(fields[2]),
                "tx_errors": int(fields[10]),
                "rx_drops": int(fields[3]),
                "tx_drops": int(fields[11]),
            }
    return {"cpu": list(map(int, cpu)), "disks": disks, "network": network}


def rates(current, previous, seconds):
    if not previous or seconds <= 0:
        return {key: None for key in current}
    return {
        key: round((value - previous[key]) / seconds, 2)
        if key in previous and value >= previous[key]
        else None
        for key, value in current.items()
    }


def memory(proc):
    values = {}
    for line in read(proc / "meminfo").splitlines():
        key, _, value = line.partition(":")
        fields = value.split()
        if fields:
            values[key] = int(fields[0]) * 1024
    total, available = values.get("MemTotal"), values.get("MemAvailable")
    swap, free = values.get("SwapTotal"), values.get("SwapFree")
    return dict(
        total_bytes=total,
        available_bytes=available,
        used_pct=round(100 * (1 - available / total), 1) if total and available is not None else None,
        swap_total_bytes=swap,
        swap_used_bytes=swap - free if swap is not None and free is not None else None,
    )


def cgroup(proc, sys):
    root = sys / "fs/cgroup"
    relative = next(
        (line[3:] for line in read(proc / "self/cgroup").splitlines() if line.startswith("0::")), None
    )
    if relative is None:
        return None
    # In a cgroup namespace the current group is often mounted directly at the root.
    candidate = (root / relative.lstrip("/")).resolve()
    if not candidate.is_relative_to(root.resolve()):
        return None
    if not (candidate / "memory.current").exists():
        return None
    quota = read(candidate / "cpu.max").split()
    return dict(
        memory_used_bytes=number(read(candidate / "memory.current").strip()),
        memory_limit_bytes=number(read(candidate / "memory.max").strip()),
        cpu_quota_cores=(number(quota[0]) / float(quota[1]))
        if len(quota) == 2 and number(quota[0]) is not None and float(quota[1]) > 0
        else None,
    )


class Monitor:
    interval = 5

    def __init__(
        self, state_dir, *, proc=Path("/proc"), sys=Path("/sys"), clock=time.monotonic, gpu=gpu_snapshot
    ):
        self.state_dir = Path(state_dir)
        self.proc, self.sys, self.clock, self.gpu = proc, sys, clock, gpu
        self.lock = threading.Lock()
        self.previous = None
        self.last_at = None
        self.cached = None
        self.history = deque(maxlen=120)

    def snapshot(self):
        with self.lock:
            now = self.clock()
            if self.cached is not None and now - self.last_at < self.interval:
                return self.cached
            elapsed = now - self.last_at if self.last_at is not None else 0
            raw = counters(self.proc, self.sys)
            old = self.previous or {}
            cpu, oldcpu = raw["cpu"], old.get("cpu", [])
            busy, wait = None, None
            if len(cpu) >= 5 and len(oldcpu) == len(cpu):
                delta = [a - b for a, b in zip(cpu, oldcpu)]
                if sum(delta) > 0 and all(d >= 0 for d in delta):
                    busy = round(100 * (sum(delta) - delta[3] - delta[4]) / sum(delta), 1)
                    wait = round(100 * delta[4] / sum(delta), 1)
            mem = memory(self.proc)
            disk = []
            for label, path in (("App state filesystem", self.state_dir), ("Root filesystem", Path("/"))):
                try:
                    usage = shutil.disk_usage(path)
                    disk.append(
                        dict(
                            label=label,
                            total_bytes=usage.total,
                            free_bytes=usage.free,
                            used_pct=round(100 * usage.used / usage.total, 1),
                        )
                    )
                except OSError:
                    disk.append(dict(label=label, total_bytes=None, free_bytes=None, used_pct=None))
            gpu = self.gpu()
            stamp = datetime.now(timezone.utc).isoformat()
            sample = dict(
                timestamp=stamp,
                cpu_pct=busy,
                memory_pct=mem["used_pct"],
                gpu_pct={d["index"]: d["utilization_pct"] for d in gpu["devices"]},
            )
            self.history.append(sample)
            self.cached = dict(
                timestamp=stamp,
                refresh_seconds=self.interval,
                scope="Local app environment only. CPU/RAM/disk counters reflect the visible Linux host or VM; network counters reflect its network namespace. Remote model servers are not monitored.",
                cpu=dict(busy_pct=busy, iowait_pct=wait, logical_cpus=os.cpu_count()),
                memory=mem,
                cgroup=cgroup(self.proc, self.sys),
                filesystems=disk,
                gpu=gpu,
                disk_io=[
                    dict(device=name, **rates(values, old.get("disks", {}).get(name), elapsed))
                    for name, values in raw["disks"].items()
                ],
                network=[
                    dict(interface=name, **rates(values, old.get("network", {}).get(name), elapsed))
                    for name, values in raw["network"].items()
                ],
                history=list(self.history),
                notes=[
                    "Rates need two samples. Missing metrics are unavailable, never assumed zero.",
                    "Disk rates are bytes/s and operations/s. busy_ms is milliseconds busy per second, not a saturation verdict. Device-mapper and backing disks can overlap; do not sum them.",
                    "History retains up to 120 requested samples in memory; collection pauses when nobody views this page.",
                ],
            )
            self.previous, self.last_at = raw, now
            return self.cached
