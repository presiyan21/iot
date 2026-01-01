# src/utils/logger.py

from __future__ import annotations
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any, Dict

# Default log location: artifacts/run_log.ndjson
_ARTIFACTS_DIR = Path(__file__).resolve().parents[2] / "artifacts"
_LOGFILE = _ARTIFACTS_DIR / "run_log.ndjson"
_lock = Lock()


def _ensure_artifacts_dir() -> None:
    if not _ARTIFACTS_DIR.exists():
        _ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)


def log(entry: Dict[str, Any]) -> None:
    # Append a JSON object to the run log (ndjson)
    if not isinstance(entry, dict):
        raise TypeError("log() expects a dict")

    now_ts = int(time.time())
    now_iso = datetime.fromtimestamp(now_ts, tz=timezone.utc).isoformat()

    payload = dict(entry)  # copy to avoid modifying caller
    payload.setdefault("ts", now_ts)
    payload.setdefault("ts_iso", now_iso)

    line = json.dumps(payload, separators=(",", ":"))

    _ensure_artifacts_dir()

    # Write safely with lock to prevent race conditions
    with _lock:
        with _LOGFILE.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")


if __name__ == "__main__":
    log({"event": "logger_test", "detail": "logger initialized from __main__"})
    print(f"Wrote sample log entry to {_LOGFILE}")

