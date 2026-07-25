# Adaptive adversarial evaluation

Deterministic scripted adversaries remain the default. An optional controller-side OpenAI-compatible client supports local llama.cpp, Ollama, vLLM, or explicitly configured compatible services through `EH_ADVERSARY_BASE_URL`, `EH_ADVERSARY_API_KEY`, `EH_ADVERSARY_MODEL`, `EH_ADVERSARY_TEMPERATURE`, `EH_ADVERSARY_MAX_STEPS`, `EH_ADVERSARY_MAX_TOKENS`, and `EH_ADVERSARY_SEED`.

The model sees only the campaign objective, a declared synthetic range, the fixed safe action catalogue, and bounded prior observations. Every output must be one strict `ActionProposal`; unknown actions, arbitrary URLs/IP addresses, out-of-range targets, malformed JSON, unbounded responses, timeout, or service failure stop the campaign. API credentials remain in the outside controller and are not included in prompts, observations, or hostile tools.

The model's prose or self-reported outcome is never success evidence. `AdaptiveCampaignEvaluation` is computed outside the model from adapter-bound observations. Default CI uses a deterministic scripted model control and no network or paid API.

This interface does not put an actual model process inside Firecracker in the default test topology. It exercises the real bounded hostile tool interface, but stronger OS isolation and configured endpoint evaluation remain separate workflows.
