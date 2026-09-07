"""Single-worker dashboard supervisor. Each job owns its immutable configuration snapshot."""

import json
import os
import signal
import subprocess
import sys
import threading
from pathlib import Path
from uuid import UUID, uuid4

import yaml

from .config import load_config
from .domain import utc
from .storage import now


def atomic_json(path, value):
    path = Path(path)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, indent=2), encoding="utf-8")
    os.chmod(temporary, 0o600)
    temporary.replace(path)


class Jobs:
    def __init__(self, directory, config_path):
        self.directory = Path(directory).resolve()
        self.directory.mkdir(parents=True, exist_ok=True)
        self.config_path = Path(config_path).resolve()
        self.processes = {}
        self.lock = threading.RLock()

    def path(self, job_id):
        return self.directory / str(UUID(job_id))

    def get(self, job_id):
        with self.lock:
            path = self.path(job_id)
            job = json.loads((path / "job.json").read_text())
            process = self.processes.get(job_id)
            progress_path = path / "progress.json"
            progress = json.loads(progress_path.read_text()) if progress_path.exists() else {}
            job["progress"] = progress
            if process and process.poll() is None:
                job["status"] = "stopping" if job.get("stop_requested") else "running"
            elif progress.get("status") in ("complete", "partial", "failed", "interrupted"):
                job["status"] = "stopped" if progress["status"] == "interrupted" else progress["status"]
            elif job.get("status") == "running":
                job["status"] = "stopped"  # dashboard/worker interruption; checkpoints survive
            if process and process.poll() is not None:
                job["exit_code"] = process.returncode
            return job

    def list(self):
        result = []
        for path in self.directory.glob("*/job.json"):
            try:
                result.append(self.get(path.parent.name))
            except (ValueError, OSError):
                continue
        return sorted(result, key=lambda job: job["created_at"], reverse=True)

    def busy(self):
        return any(process.poll() is None for process in self.processes.values())

    def launch(self, job, resume=False):
        if self.busy():
            raise ValueError("One hunt is already active; stop it or wait for completion")
        path = self.path(job["id"])
        job.update(status="running", stop_requested=False, resumed_at=now() if resume else None)
        job.pop("progress", None)
        job.pop("exit_code", None)
        atomic_json(path / "job.json", job)
        command = [
            sys.executable,
            "-m",
            "soc_hunter.worker",
            "--job",
            str(path),
            "--parent-pid",
            str(os.getpid()),
        ]
        if resume:
            command.append("--resume")
        with (path / "worker.log").open("a") as log:
            self.processes[job["id"]] = subprocess.Popen(
                command, stdout=log, stderr=log, stdin=subprocess.DEVNULL, start_new_session=True
            )
        return self.get(job["id"])

    def start(self, mode, start=None, end=None):
        with self.lock:
            if mode not in ("demo", "live"):
                raise ValueError("Choose demo or live")
            if self.busy():
                raise ValueError("One hunt is already active")
            config = load_config(str(self.config_path))
            if mode == "live":
                first, last = utc(start), utc(end)
                if last <= first or (last - first).total_seconds() > config.hunts.max_window_hours * 3600:
                    raise ValueError("Invalid time window; maximum is configured in hunts.max_window_hours")
                if config.model.mode != "live":
                    raise ValueError("Configure a live model before starting a real hunt")
            else:
                config.model.mode = "mock"
            identifier = str(uuid4())
            path = self.path(identifier)
            path.mkdir(mode=0o700)
            snapshot = path / "config.yaml"
            snapshot.write_text(yaml.safe_dump(config.model_dump()), encoding="utf-8")
            os.chmod(snapshot, 0o600)
            job = {
                "id": identifier,
                "mode": mode,
                "start": start,
                "end": end,
                "created_at": now(),
                "status": "starting",
            }
            return self.launch(job)

    def stop(self, job_id):
        with self.lock:
            job = self.get(job_id)
            process = self.processes.get(job_id)
            if process is None or process.poll() is not None:
                raise ValueError("This hunt is not running")
            job.pop("progress", None)
            job["stop_requested"] = True
            atomic_json(self.path(job_id) / "job.json", job)
            process.send_signal(signal.SIGINT)
            return self.get(job_id)

    def resume(self, job_id):
        with self.lock:
            job = self.get(job_id)
            if job["status"] not in ("stopped", "failed", "partial"):
                raise ValueError("Only stopped, failed or partial hunts can be resumed")
            return self.launch(job, resume=True)

    def close(self):
        for process in self.processes.values():
            if process.poll() is None:
                process.send_signal(signal.SIGINT)
        for process in self.processes.values():
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.terminate()
