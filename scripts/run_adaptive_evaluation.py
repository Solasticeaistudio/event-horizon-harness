#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from event_horizon.adaptive_adversary import (
    AdaptiveLLMAdversarialRunner,
    AdversaryModelConfig,
    OpenAICompatibleAdversaryModel,
)
from event_horizon.adversarial_runner import CampaignManifest


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a configured synthetic adaptive campaign")
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    manifest = CampaignManifest.from_dict(json.loads(args.manifest.read_text(encoding="utf-8")))
    model = OpenAICompatibleAdversaryModel(AdversaryModelConfig.from_environment())
    result, evaluation = AdaptiveLLMAdversarialRunner([manifest.range_id], model).run(manifest)
    payload = {
        "result": result.to_dict(),
        "trusted_evaluation": {
            **evaluation.__dict__,
            "boundary_violations": list(evaluation.boundary_violations),
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 1 if evaluation.trusted_success else 0


if __name__ == "__main__":
    raise SystemExit(main())
