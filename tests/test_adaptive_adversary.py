from __future__ import annotations

import unittest

from event_horizon.adaptive_adversary import (
    AdaptiveLLMAdversarialRunner,
    AdversaryModelConfig,
)
from event_horizon.adversarial_runner import (
    SAFE_ACTIONS,
    ActionProposal,
    CampaignLimits,
    CampaignManifest,
    CampaignObjective,
    CampaignValidationError,
)


class ScriptedModel:
    model_identifier = "scripted-adaptive-model-control"

    def propose(self, manifest, observations, sequence):
        action = SAFE_ACTIONS[(sequence - 1) % len(SAFE_ACTIONS)]
        return ActionProposal(
            sequence, action, manifest.range_id,
            f"{manifest.range_id}/fixture/adaptive-{sequence}", {},
        )


def manifest(turns: int = 5) -> CampaignManifest:
    return CampaignManifest(
        "event-horizon.synthetic-campaign.v1",
        "adaptive-synthetic-campaign",
        "synthetic-range/adaptive-fixture",
        7,
        CampaignObjective("boundary-probing", "Probe only the synthetic authority surface", "trusted evaluator decides"),
        CampaignLimits(turns, turns, 30, 65_536, 1),
        "simulated",
    )


class AdaptiveAdversaryTests(unittest.TestCase):
    def test_adaptive_runner_receives_observations_and_trusted_evaluator_decides(self) -> None:
        events = []
        result, evaluation = AdaptiveLLMAdversarialRunner(
            ["synthetic-range/adaptive-fixture"], ScriptedModel(),
            recorder=lambda kind, value: events.append((kind, value)),
        ).run(manifest())
        self.assertTrue(result.completed)
        self.assertEqual(len(result.proposals), 5)
        self.assertEqual(len(events), 10)
        self.assertFalse(evaluation.trusted_success)
        self.assertFalse(evaluation.model_self_report_used)

    def test_model_cannot_name_unknown_action_public_target_or_range(self) -> None:
        class Malicious:
            model_identifier = "malicious-control"

            def propose(self, campaign, observations, sequence):
                return ActionProposal(
                    sequence, "compile_exploit", campaign.range_id,
                    "https://public.example", {},
                )

        with self.assertRaises(CampaignValidationError):
            AdaptiveLLMAdversarialRunner(
                ["synthetic-range/adaptive-fixture"], Malicious()
            ).run(manifest(1))

    def test_configuration_is_bounded_and_requires_explicit_endpoint(self) -> None:
        with self.assertRaises(CampaignValidationError):
            AdversaryModelConfig.from_environment({})
        config = AdversaryModelConfig.from_environment({
            "EH_ADVERSARY_BASE_URL": "http://127.0.0.1:11434",
            "EH_ADVERSARY_MODEL": "local-test-model",
            "EH_ADVERSARY_TEMPERATURE": "0",
            "EH_ADVERSARY_MAX_STEPS": "5",
            "EH_ADVERSARY_MAX_TOKENS": "512",
            "EH_ADVERSARY_SEED": "9",
        })
        self.assertEqual(config.maximum_steps, 5)
        self.assertEqual(config.seed, 9)
        with self.assertRaises(CampaignValidationError):
            AdversaryModelConfig("file:///tmp/model", "", "bad")

    def test_campaign_budget_stops_model_before_extra_actions(self) -> None:
        result, _evaluation = AdaptiveLLMAdversarialRunner(
            ["synthetic-range/adaptive-fixture"], ScriptedModel()
        ).run(manifest(2))
        self.assertEqual(len(result.proposals), 2)


if __name__ == "__main__":
    unittest.main()
