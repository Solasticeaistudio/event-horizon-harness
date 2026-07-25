.PHONY: demo verify-denial

demo:
	npm run build
	python -m event_horizon.public_demo

verify-denial:
	@test -n "$(CERT)" || (echo "CERT is required" && exit 2)
	@test -n "$(TRUSTED_SIGNER)" || (echo "TRUSTED_SIGNER is required" && exit 2)
	python scripts/verify_denial_certificate.py "$(CERT)" --trusted-signer "$(TRUSTED_SIGNER)" $(if $(TRUSTED_RECORDER),--trusted-recorder "$(TRUSTED_RECORDER)")
