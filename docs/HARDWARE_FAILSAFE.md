# Optional hardware fail-safe

## Threat model and protocol

The optional external switch controls only a certified low-voltage power-enable line, managed network isolation port, or equivalent safe control input. It must not directly switch household mains voltage. The hostile host is not trusted to cooperate after heartbeat loss.

The simulator implements a challenge-bound Ed25519 protocol. Each signed message binds device, one-use random challenge, monotonic sequence, issue/expiry, heartbeat policy, recorder evidence-chain digest, action, action payload, and key identity. The switch pins its verification key and policy independently. Invalid signature, malformed/stale/replayed/reordered message, policy/evidence mismatch, timeout, explicit kill, or restart enters the tripped safe state. Resumed heartbeats never re-arm it; a separately authorized signed `rearm` action and explicit trusted-rearm input are both required.

Key rotation is signed by the current key and binds the replacement PEM/key ID. A host restart must restore its monotonic sequence from trusted state; resetting it trips the switch. Canary and behavioral systems can request signed kill actions, but the simulator does not yet connect those event sources automatically.

## Simulator and tests

Run `make test-hardware-sim`. Tests cover heartbeat, loss/delay, replay/reorder/forgery, rotation, host/recorder/microcontroller assumptions, serial loss by timeout, invalid evidence, canary/behavioral kill, explicit kill/re-arm, and failures while tripped.

## Physical integration boundary

No physical hardware was available or tested. A hardware-in-the-loop suite, microcontroller target, firmware port, secure provisioning procedure, independent verifier/recorder deployment, tamper-resistant key storage, monotonic storage endurance analysis, electrical design review, and certified low-voltage isolation hardware are still required. Because no target board is selected, this repository does not ship untested board-specific firmware or a prescriptive bill of materials.

A safe demonstration would use a separately powered microcontroller development board with Ed25519 support and a certified managed network switch or low-voltage relay module whose control ratings match the lab device. A qualified engineer must review wiring and fail-safe polarity. Never connect prototype GPIO or relay boards directly to mains power.
