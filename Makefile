.PHONY: demo verify-denial test test-security test-policy test-property test-concurrency test-chaos test-canary test-denial-certificates test-behavioral-guardian test-decay test-adversary test-positive-controls adversary-eval literature-check test-hardware-sim

test:
	python -m unittest discover -s tests -v

test-security: test-policy test-property test-concurrency test-chaos test-canary test-denial-certificates test-behavioral-guardian test-decay test-adversary test-positive-controls test-hardware-sim

test-policy:
	python -m unittest tests.test_task_policy_ceiling tests.test_authoritative_trust -v

test-property:
	python -m unittest tests.test_protocol_properties tests.test_capability_stateful -v

test-concurrency:
	python -m unittest tests.test_concurrent_redemption -v

test-chaos:
	python -m unittest tests.test_chaos -v

test-canary:
	python -m unittest tests.test_canary_capabilities -v

test-denial-certificates:
	python -m unittest tests.test_denial_certificates -v

test-behavioral-guardian:
	python -m unittest tests.test_behavioral_guardian -v

test-decay:
	python -m unittest tests.test_trust_decay -v

test-adversary:
	python -m unittest tests.test_adversarial_campaigns tests.test_adversarial_runner_interface tests.test_adaptive_adversary -v

test-positive-controls:
	python -m unittest tests.test_positive_controls tests.test_concurrent_redemption.ConcurrentRedemptionTests.test_positive_control_detects_non_atomic_double_redemption -v

adversary-eval: test-adversary

literature-check:
	python scripts/check_literature_feed.py

test-hardware-sim:
	python -m unittest tests.test_hardware_failsafe -v

demo:
	npm run build
	python -m event_horizon.public_demo

verify-denial:
	@test -n "$(CERT)" || (echo "CERT is required" && exit 2)
	@test -n "$(TRUSTED_SIGNER)" || (echo "TRUSTED_SIGNER is required" && exit 2)
	python scripts/verify_denial_certificate.py "$(CERT)" --trusted-signer "$(TRUSTED_SIGNER)" $(if $(TRUSTED_RECORDER),--trusted-recorder "$(TRUSTED_RECORDER)")
