import argparse
import fcntl
import json
import os
import signal
import threading
import time
from pathlib import Path

from .config import load_config
from .domain import utc
from .fixtures import demo_records
from .jobs import atomic_json
from .runner import hunt, write_report
from .splunk import Splunk
from .storage import FileStore, PostgresStore, connect


def work(path, resume=False):
    path = Path(path)
    job = json.loads((path / "job.json").read_text())
    config = load_config(str(path / "config.yaml"))
    progress_path = path / "progress.json"
    previous = json.loads(progress_path.read_text()) if resume and progress_path.exists() else {}
    resume_id = previous.get("id")

    def progress(run):
        atomic_json(progress_path, run)

    if job["mode"] == "demo":
        records, start, end = demo_records()
        run, findings = hunt(
            config,
            start,
            end,
            FileStore(path),
            fixture=records,
            resume_id=resume_id,
            progress=progress,
            demo_delay=1.0,
        )
    else:
        with connect(config.postgres) as connection:
            run, findings = hunt(
                config,
                utc(job["start"]),
                utc(job["end"]),
                PostgresStore(connection),
                splunk=Splunk(config.splunk),
                resume_id=resume_id,
                progress=progress,
            )
    write_report(path, run, findings)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--job", required=True)
    parser.add_argument("--parent-pid", type=int, required=True)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    path = Path(args.job)

    def parent_watch():
        while True:
            time.sleep(2)
            if os.getppid() != args.parent_pid:
                os.kill(os.getpid(), signal.SIGINT)
                return

    threading.Thread(target=parent_watch, daemon=True).start()
    try:
        with (path.parent / "worker.lock").open("w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            work(path, args.resume)
    except BaseException as exc:
        progress_path = path / "progress.json"
        result = json.loads(progress_path.read_text()) if progress_path.exists() else {}
        result.update(
            status="interrupted" if isinstance(exc, KeyboardInterrupt) else "failed",
            stage="stopped" if isinstance(exc, KeyboardInterrupt) else "failed",
            error_type=type(exc).__name__,
        )
        atomic_json(progress_path, result)
        return 130 if isinstance(exc, KeyboardInterrupt) else 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
