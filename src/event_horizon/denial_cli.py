from __future__ import annotations

import argparse
import json
from pathlib import Path

from .denial_certificate import DenialCertificateVerifier


def _bounded_read(path: Path, maximum: int = 1_048_576) -> bytes:
    if path.stat().st_size > maximum:
        raise ValueError("input exceeds the denial certificate size limit")
    with path.open("rb") as handle:
        value = handle.read(maximum + 1)
    if len(value) > maximum:
        raise ValueError("input exceeds the denial certificate size limit")
    return value


def _object_without_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify an Event Horizon denial certificate")
    parser.add_argument("certificate", type=Path)
    parser.add_argument("--trusted-signer", required=True, type=Path)
    parser.add_argument("--trusted-recorder", type=Path)
    args = parser.parse_args(argv)
    try:
        envelope = json.loads(
            _bounded_read(args.certificate).decode("utf-8"),
            object_pairs_hook=_object_without_duplicates,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON number: {value}")
            ),
        )
        signer = _bounded_read(args.trusted_signer, 16_384).decode("ascii")
        recorder = (
            _bounded_read(args.trusted_recorder, 16_384).decode("ascii")
            if args.trusted_recorder is not None
            else None
        )
        result = DenialCertificateVerifier(
            signer,
            trusted_recorder_public_key=recorder,
        ).verify(envelope)
    except (OSError, UnicodeError, TypeError, ValueError) as exc:
        print(f"denial certificate: INVALID ({exc})")
        return 1
    if not result.valid:
        print(f"denial certificate: INVALID ({result.reason})")
        return 1
    print(
        "denial certificate: VERIFIED "
        f"({result.certificate_id}, {result.effect_state})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
