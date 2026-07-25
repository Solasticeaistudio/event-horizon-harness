#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from event_horizon.canonical import canonical_bytes
from event_horizon.remote_replay import (
    ReferenceReplayService,
    ReplayClientPolicy,
    ReplayHttpServer,
    ReplayRequestSigner,
)


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="event-horizon-replay-interop-") as directory:
        temporary = Path(directory)
        server_key = Ed25519PrivateKey.generate()
        client_key = Ed25519PrivateKey.generate()
        signer = ReplayRequestSigner(client_key, "event-horizon-replay")
        policy = ReplayClientPolicy.create(
            signer.public_key_pem,
            operations={"nonce-create", "nonce-consume", "nonce-inspect"},
            partitions={"attestation.nonces"},
        )
        service = ReferenceReplayService(
            temporary / "replay.sqlite3",
            service_id="event-horizon-replay",
            epoch=1,
            signing_key=server_key,
            clients={policy.key_id: policy},
        )
        http = ReplayHttpServer(service)
        http.start()
        try:
            configuration = {
                "url": http.url,
                "serviceId": "event-horizon-replay",
                "epoch": 1,
                "partition": "attestation.nonces",
                "clientPrivateKeyPem": client_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                ).decode("ascii"),
                "serverPublicKeyPem": service.public_key_pem,
            }
            configuration_path = temporary / "interop.json"
            configuration_path.write_bytes(canonical_bytes(configuration))
            completed = subprocess.run(
                ["node", "scripts/verify_remote_replay_interop.mjs", str(configuration_path)],
                cwd=root,
                check=True,
                capture_output=True,
                text=True,
                timeout=30,
            )
            result = json.loads(completed.stdout)
            if result != {
                "accepted": True,
                "replay": "consumed",
                "state": "consumed",
                "checkpoint": 4,
            }:
                raise RuntimeError(f"unexpected cross-language replay result: {result!r}")
            epoch, checkpoint, _checkpoint_digest = service.checkpoint()
            if (epoch, checkpoint) != (1, 4):
                raise RuntimeError("Python replay service checkpoint did not match Node transitions")
        finally:
            http.close()
            service.close()
    print("remote replay interoperability: PASS (Python service / Node client)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
