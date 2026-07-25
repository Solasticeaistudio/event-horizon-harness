from __future__ import annotations

import multiprocessing
import os
import queue
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from event_horizon.protected_boundary import (
    AuthorizationReplayError,
    ProtectedRequestSigner,
    ProtectedRequestVerifier,
    SqliteAuthorizationReplayStore,
    load_private_seed,
    provision_private_seed,
)
from event_horizon.protocol import ProtocolError


FIXED_NOW = 1_767_225_600.0


def protected_request() -> dict:
    return {
        "type": "append",
        "request_id": "protected-request-1",
        "deadline_ms": int(FIXED_NOW * 1000) + 5_000,
        "body": {"event_type": "synthetic", "payload": {"ok": True}},
    }


def _authorization_race_worker(
    database_path,
    public_key_pem,
    key_id,
    request,
    authorization,
    start_event,
    results,
):
    store = None
    try:
        store = SqliteAuthorizationReplayStore(
            database_path,
            namespace="protected-race",
            audience="evidence-recorder",
            busy_timeout_ms=10_000,
        )
        verifier = ProtectedRequestVerifier(
            public_key_pem,
            key_id,
            "evidence-recorder",
            store,
            now=lambda: FIXED_NOW,
        )
        start_event.wait(timeout=10)
        verifier.authorize(request, authorization)
        results.put("accepted")
    except ProtocolError as exc:
        results.put(exc.code)
    except Exception as exc:
        results.put(f"error:{type(exc).__name__}:{exc}")
    finally:
        if store is not None:
            store.close()


class ProtectedBoundaryTests(unittest.TestCase):
    def signer(self, seed: bytes = b"A" * 32) -> ProtectedRequestSigner:
        return ProtectedRequestSigner(
            seed,
            "evidence-recorder",
            now=lambda: FIXED_NOW,
        )

    def verifier(self, signer, store, *, now=FIXED_NOW, audience="evidence-recorder"):
        return ProtectedRequestVerifier(
            signer.public_key_pem,
            signer.key_id,
            audience,
            store,
            now=lambda: now,
        )

    def test_valid_authorization_is_exactly_one_use_and_survives_restart(self):
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "authorization.sqlite3"
            signer = self.signer()
            request = protected_request()
            authorization = signer.authorize(request)
            first = SqliteAuthorizationReplayStore(
                database,
                namespace="restart-test",
                audience="evidence-recorder",
            )
            self.verifier(signer, first).authorize(request, authorization)
            first.close()

            second = SqliteAuthorizationReplayStore(
                database,
                namespace="restart-test",
                audience="evidence-recorder",
            )
            with self.assertRaises(ProtocolError) as replay:
                self.verifier(signer, second).authorize(request, authorization)
            self.assertEqual(replay.exception.code, "authorization_replay")
            second.close()

    def test_request_mutation_audience_key_algorithm_and_signature_substitution_fail(self):
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "authorization.sqlite3"
            signer = self.signer()
            request = protected_request()
            authorization = signer.authorize(request)

            mutated = {**request, "body": {**request["body"], "payload": {"ok": False}}}
            store = SqliteAuthorizationReplayStore(
                database,
                namespace="substitution-test",
                audience="evidence-recorder",
            )
            verifier = self.verifier(signer, store)
            with self.assertRaises(ProtocolError) as changed_request:
                verifier.authorize(mutated, authorization)
            self.assertEqual(changed_request.exception.code, "authorization_denied")

            wrong_audience = dict(authorization)
            wrong_audience["audience"] = "capability-signer"
            with self.assertRaises(ProtocolError) as audience:
                verifier.authorize(request, wrong_audience)
            self.assertEqual(audience.exception.code, "authorization_denied")

            wrong_algorithm = dict(authorization)
            wrong_algorithm["algorithm"] = "none"
            with self.assertRaises(ProtocolError) as algorithm:
                verifier.authorize(request, wrong_algorithm)
            self.assertEqual(algorithm.exception.code, "authorization_denied")

            wrong_signature = dict(authorization)
            wrong_signature["signature"] = "A" * 86
            with self.assertRaises(ProtocolError) as signature:
                verifier.authorize(request, wrong_signature)
            self.assertEqual(signature.exception.code, "authorization_denied")

            other = self.signer(b"B" * 32)
            other_store = SqliteAuthorizationReplayStore(
                database,
                namespace="other-key-test",
                audience="evidence-recorder",
            )
            with self.assertRaises(ProtocolError) as key:
                self.verifier(other, other_store).authorize(request, authorization)
            self.assertEqual(key.exception.code, "authorization_denied")
            store.close()
            other_store.close()

    def test_expired_future_unknown_and_unavailable_authorization_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "authorization.sqlite3"
            signer = self.signer()
            request = protected_request()
            authorization = signer.authorize(request)
            store = SqliteAuthorizationReplayStore(
                database,
                namespace="failure-test",
                audience="evidence-recorder",
            )
            with self.assertRaises(ProtocolError) as expired:
                self.verifier(signer, store, now=FIXED_NOW + 6).authorize(
                    request, authorization
                )
            self.assertEqual(expired.exception.code, "authorization_expired")

            future_signer = ProtectedRequestSigner(
                b"C" * 32,
                "evidence-recorder",
                now=lambda: FIXED_NOW + 10,
            )
            future_request = dict(request)
            future_request["deadline_ms"] += 20_000
            future_authorization = future_signer.authorize(future_request)
            future_store = SqliteAuthorizationReplayStore(
                database,
                namespace="future-test",
                audience="evidence-recorder",
            )
            with self.assertRaises(ProtocolError) as future:
                self.verifier(future_signer, future_store).authorize(
                    future_request, future_authorization
                )
            self.assertEqual(future.exception.code, "authorization_denied")

            unknown = dict(authorization)
            unknown["extra"] = True
            with self.assertRaises(ProtocolError) as unknown_field:
                self.verifier(signer, store).authorize(request, unknown)
            self.assertEqual(unknown_field.exception.code, "authorization_invalid")

            store.close()
            with self.assertRaises(ProtocolError) as unavailable:
                self.verifier(signer, store).authorize(request, authorization)
            self.assertEqual(unavailable.exception.code, "authorization_unavailable")
            future_store.close()

    def test_concurrent_protected_service_replicas_accept_one_authorization(self):
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "authorization.sqlite3"
            signer = self.signer()
            request = protected_request()
            authorization = signer.authorize(request)
            initializer = SqliteAuthorizationReplayStore(
                database,
                namespace="protected-race",
                audience="evidence-recorder",
            )
            initializer.close()
            context = multiprocessing.get_context("spawn")
            start_event = context.Event()
            results = context.Queue()
            processes = [
                context.Process(
                    target=_authorization_race_worker,
                    args=(
                        str(database),
                        signer.public_key_pem,
                        signer.key_id,
                        request,
                        authorization,
                        start_event,
                        results,
                    ),
                )
                for _ in range(16)
            ]
            for process in processes:
                process.start()
            start_event.set()
            for process in processes:
                process.join(timeout=20)
                if process.is_alive():
                    process.terminate()
                    process.join(timeout=5)
                self.assertEqual(process.exitcode, 0)
            outcomes = []
            for _ in processes:
                try:
                    outcomes.append(results.get(timeout=5))
                except queue.Empty:
                    self.fail("a protected service replica returned no result")
            self.assertEqual(outcomes.count("accepted"), 1)
            self.assertEqual(outcomes.count("authorization_replay"), 15)

    def test_private_seed_files_are_exact_non_overwritable_and_restricted(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "protected" / "signing.seed"
            seed = b"D" * 32
            self.assertEqual(provision_private_seed(path, seed), path.resolve())
            self.assertEqual(load_private_seed(path), seed)
            with self.assertRaises(FileExistsError):
                provision_private_seed(path, b"E" * 32)
            self.assertEqual(load_private_seed(path), seed)
            with self.assertRaises(ValueError):
                provision_private_seed(Path(temporary) / "short.seed", b"short")
            if os.name != "nt":
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                path.chmod(0o644)
                with self.assertRaisesRegex(RuntimeError, "permissions"):
                    load_private_seed(path)

    def test_corrupt_incompatible_and_colliding_replay_state_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            corrupt = Path(temporary) / "corrupt.sqlite3"
            corrupt.write_bytes(b"not a sqlite database")
            with self.assertRaisesRegex(AuthorizationReplayError, "initialization"):
                SqliteAuthorizationReplayStore(
                    corrupt,
                    namespace="failure-test",
                    audience="evidence-recorder",
                )

            schema_path = Path(temporary) / "schema.sqlite3"
            schema_store = SqliteAuthorizationReplayStore(
                schema_path,
                namespace="failure-test",
                audience="evidence-recorder",
            )
            schema_store.close()
            with closing(sqlite3.connect(schema_path)) as database:
                database.execute(
                    """
                    UPDATE event_horizon_replay_schema SET version = 2
                    WHERE component = 'protected-request'
                    """
                )
                database.commit()
            with self.assertRaisesRegex(AuthorizationReplayError, "schema version"):
                SqliteAuthorizationReplayStore(
                    schema_path,
                    namespace="failure-test",
                    audience="evidence-recorder",
                )

            collision_path = Path(temporary) / "collision.sqlite3"
            collision = SqliteAuthorizationReplayStore(
                collision_path,
                namespace="failure-test",
                audience="evidence-recorder",
            )
            nonce = self.signer().authorize(protected_request())["nonce"]
            self.assertTrue(collision.consume(nonce, "a" * 64, 10, 1))
            with self.assertRaisesRegex(AuthorizationReplayError, "collided"):
                collision.consume(nonce, "b" * 64, 10, 2)
            collision.close()


if __name__ == "__main__":
    unittest.main()
