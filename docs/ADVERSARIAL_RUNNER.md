# Bounded synthetic adversarial runner

`event_horizon.adversarial_runner` is a collision interface for future authorized campaign engines. It is not an offensive platform and has no real-infrastructure connector.

The public types are `AdversarialRunner`, `CampaignObjective`, `ActionProposal`, `Observation`, and `CampaignResult`. A strict `CampaignManifest` binds the campaign ID, declared `synthetic-range/...` identifier, deterministic seed, objective, adapter mode, and maximum turns, commands, wall time, bytes, and concurrency.

The shipped `BoundedSyntheticAdversarialRunner` accepts only predeclared range IDs. Proposals must use one of five harmless actions and a fixture target inside that range. URLs, IP addresses, arbitrary hosts, raw commands, and unknown action types are rejected. The only shipped adapter is simulated. A caller-supplied adapter marked non-simulated cannot run without an explicit human-approval callback.

Each proposal and bound observation is recorded before the next turn. The transcript digest excludes wall-clock data and can be regenerated with `replay()`. Byte, turn, command, wall-time, and concurrency limits fail closed.

The example manifest is [examples/synthetic-campaign/manifest.json](../examples/synthetic-campaign/manifest.json). It demonstrates discovery of a synthetic honey credential followed by denied credential replay, denied executor transfer, denied prohibited network use, and detected evidence modification. It does not dump real credentials, exploit a system, evade controls, compile payloads, cause denial of service, or contact a network.
