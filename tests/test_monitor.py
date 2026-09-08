import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from soc_hunter.monitor import Monitor, cgroup, counters, gpu_snapshot, memory, number, rates


def put(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value)


def linux(tmp_path, multiplier=1):
    proc, sys = tmp_path / "proc", tmp_path / "sys"
    put(
        proc / "stat",
        f"cpu {10 * multiplier} 0 {10 * multiplier} {70 * multiplier} {10 * multiplier} 0 0 0 0 0\n",
    )
    put(proc / "meminfo", "MemTotal: 1000 kB\nMemAvailable: 250 kB\nSwapTotal: 200 kB\nSwapFree: 150 kB\n")
    line = f"8 0 sda {10 * multiplier} 0 {20 * multiplier} 0 {30 * multiplier} 0 {40 * multiplier} 0 0 {50 * multiplier} 0\n"
    put(proc / "diskstats", line + line.replace("sda", "sda1") + line.replace("sda", "loop0"))
    put(sys / "class/block/sda1/partition", "1")
    put(
        proc / "net/dev",
        f"eth0: {100 * multiplier} 0 0 0 0 0 0 0 {200 * multiplier} 0 0 0 0 0 0 0\nlo: 1 0 0 0 0 0 0 0 2 0 0 0 0 0 0 0\n",
    )
    return proc, sys


def test_linux_counters_and_memory(tmp_path):
    proc, sys = linux(tmp_path)
    result = counters(proc, sys)
    assert set(result["disks"]) == {"sda"}
    assert result["disks"]["sda"]["read_bytes"] == 20 * 512
    assert result["disks"]["sda"]["write_bytes"] == 40 * 512
    assert set(result["network"]) == {"eth0"}
    assert result["network"]["eth0"]["tx_bytes"] == 200
    assert memory(proc)["used_pct"] == 75
    assert memory(proc)["swap_used_bytes"] == 50 * 1024


def test_sampler_rates_cache_and_history(tmp_path):
    proc, sys = linux(tmp_path)
    clock = iter([0, 2, 5, 10])
    calls = []

    def gpu():
        calls.append(1)
        return {"status": "unavailable", "devices": []}

    monitor = Monitor(tmp_path, proc=proc, sys=sys, clock=lambda: next(clock), gpu=gpu)
    first = monitor.snapshot()
    assert first["cpu"]["busy_pct"] is None
    assert first["network"][0]["rx_bytes"] is None
    assert monitor.snapshot() is first and len(calls) == 1
    linux(tmp_path, 2)
    second = monitor.snapshot()
    assert second["cpu"]["busy_pct"] == 20
    assert second["cpu"]["iowait_pct"] == 10
    assert second["network"][0]["rx_bytes"] == 20
    assert second["disk_io"][0]["read_bytes"] == 2048
    assert len(second["history"]) == 2
    linux(tmp_path, 1)  # Reset counters cannot appear as negative activity.
    assert monitor.snapshot()["network"][0]["rx_bytes"] is None


def test_rate_missing_reset_and_zero():
    assert rates({"n": 5}, None, 5) == {"n": None}
    assert rates({"n": 5}, {"n": 6}, 5) == {"n": None}
    assert rates({"n": 5}, {"n": 5}, 5) == {"n": 0}


def test_missing_linux_metrics_are_not_zero(tmp_path):
    monitor = Monitor(
        tmp_path,
        proc=tmp_path / "missing",
        sys=tmp_path / "absent",
        gpu=lambda: {"status": "unavailable", "devices": []},
    )
    result = monitor.snapshot()
    assert result["memory"]["used_pct"] is None
    assert result["disk_io"] == [] and result["cgroup"] is None


def test_cgroup_scope_and_limits(tmp_path):
    proc, sys = linux(tmp_path)
    put(proc / "self/cgroup", "0::/service\n")
    group = sys / "fs/cgroup/service"
    put(group / "memory.current", "1048576")
    put(group / "memory.max", "max")
    put(group / "cpu.max", "200000 100000")
    result = cgroup(proc, sys)
    assert result["memory_used_bytes"] == 1048576
    assert result["memory_limit_bytes"] is None
    assert result["cpu_quota_cores"] == 2
    put(proc / "self/cgroup", "0::/../../elsewhere\n")
    assert cgroup(proc, sys) is None


def test_gpu_csv_multiple_devices_and_unsupported_values(monkeypatch):
    monkeypatch.setattr("soc_hunter.monitor.shutil.which", lambda name: "/usr/bin/nvidia-smi")

    def run(command, **kwargs):
        assert command[0] == "/usr/bin/nvidia-smi" and kwargs["timeout"] == 2
        assert kwargs.get("shell", False) is False
        return SimpleNamespace(
            stdout="0, RTX 5880, 70, 24000, 49152, 65, 180.5, 285\n1, RTX 6000 Ada, N/A, 0, 49152, 35, [Not Supported], 300\n"
        )

    monkeypatch.setattr("soc_hunter.monitor.subprocess.run", run)
    result = gpu_snapshot()
    assert result["status"] == "available" and len(result["devices"]) == 2
    assert result["devices"][0]["utilization_pct"] == 70
    assert result["devices"][1]["utilization_pct"] is None
    assert result["devices"][1]["memory_used_mib"] == 0
    assert result["devices"][1]["power_w"] is None


@pytest.mark.parametrize("error", [subprocess.TimeoutExpired("nvidia-smi", 2), OSError("private detail")])
def test_gpu_failures_are_unavailable_and_sanitized(monkeypatch, error):
    monkeypatch.setattr("soc_hunter.monitor.shutil.which", lambda name: "nvidia-smi")

    def fail(*args, **kwargs):
        raise error

    monkeypatch.setattr("soc_hunter.monitor.subprocess.run", fail)
    result = gpu_snapshot()
    assert result["status"] == "unavailable" and "private detail" not in str(result)


def test_missing_gpu_binary(monkeypatch):
    monkeypatch.setattr("soc_hunter.monitor.shutil.which", lambda name: None)
    assert gpu_snapshot()["devices"] == []


@pytest.mark.parametrize("value", ["N/A", "[Not Supported]", "nan", "inf", "-1", None])
def test_invalid_measurements_are_null(value):
    assert number(value) is None


def test_history_is_bounded(tmp_path):
    monitor = Monitor(
        tmp_path,
        proc=Path("/missing"),
        sys=Path("/missing"),
        clock=iter(range(0, 1000, 5)).__next__,
        gpu=lambda: {"status": "unavailable", "devices": []},
    )
    for _ in range(130):
        result = monitor.snapshot()
    assert len(result["history"]) == 120
