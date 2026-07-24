.PHONY: demo

demo:
	npm run build
	python -m event_horizon.public_demo
