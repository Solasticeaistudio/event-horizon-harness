from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Any

from .canonical import digest


class ExternalRecorder:
    """Append-only hash-chained JSONL recorder.

    In v0.2 this is a separate local path. Production deployment must place it
    outside the hostile host behind a one-way transport.
    """

    def __init__(self, path: str | os.PathLike[str]):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._tip = self._load_tip()

    def _load_tip(self) -> str:
        if not self.path.exists():
            return "0" * 64
        tip = "0" * 64
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if line.strip():
                    tip = json.loads(line)["event_hash"]
        return tip

    def append(self, event_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            event = {
                "sequence": self.count() + 1,
                "timestamp": time.time(),
                "event_type": event_type,
                "payload": payload,
                "previous_hash": self._tip,
            }
            event["event_hash"] = digest(event)
            encoded = json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            self._tip = event["event_hash"]
            return event

    def count(self) -> int:
        if not self.path.exists():
            return 0
        with self.path.open("r", encoding="utf-8") as handle:
            return sum(1 for line in handle if line.strip())

    def verify(self) -> tuple[bool, str]:
        previous = "0" * 64
        if not self.path.exists():
            return True, previous
        with self.path.open("r", encoding="utf-8") as handle:
            for index, line in enumerate(handle, 1):
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    return False, f"invalid JSON at line {index}"
                claimed = event.pop("event_hash", None)
                if event.get("previous_hash") != previous:
                    return False, f"chain linkage failure at line {index}"
                actual = digest(event)
                if claimed != actual:
                    return False, f"event digest failure at line {index}"
                previous = claimed
        return True, previous

    def events(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        with self.path.open("r", encoding="utf-8") as handle:
            return [json.loads(line) for line in handle if line.strip()]
