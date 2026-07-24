from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from event_horizon.certificate import ContainmentCertificateBuilder


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify an Event Horizon containment certificate")
    parser.add_argument("certificate", type=Path)
    args = parser.parse_args(argv)
    try:
        certificate = json.loads(
            args.certificate.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        print(f"containment certificate: INVALID ({exc})")
        return 1
    if not isinstance(certificate, dict) or not ContainmentCertificateBuilder.verify(certificate):
        print("containment certificate: INVALID (signature or envelope mismatch)")
        return 1
    print(
        "containment certificate: VERIFIED "
        f"({certificate['algorithm']}, {certificate['key_id']})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
