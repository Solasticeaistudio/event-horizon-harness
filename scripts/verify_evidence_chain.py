#!/usr/bin/env python3
"""Verify a persisted Event Horizon evidence hash chain without its private key."""

from __future__ import annotations

import argparse
from pathlib import Path

from event_horizon.recorder import ExternalRecorder, RecorderIntegrityError


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify an Event Horizon evidence chain")
    parser.add_argument("events", type=Path)
    args = parser.parse_args()
    try:
        recorder = ExternalRecorder(args.events)
        valid, detail = recorder.verify()
    except (OSError, ValueError, RecorderIntegrityError) as exc:
        print(f"evidence chain: INVALID ({exc})")
        return 1
    if not valid:
        print(f"evidence chain: INVALID ({detail})")
        return 1
    print(f"evidence chain: VERIFIED ({detail})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
