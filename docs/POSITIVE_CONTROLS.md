# Vulnerable positive controls

The test-only positive-control catalogue contains non-atomic redemption, unenforced trust, synthesizer-direct authority, additive guardian authority, unsigned arguments, replay, missing workload binding, canary effect routing, and decay reset. Each control has a usable synthetic tool and one forbidden effect observed by a trusted external oracle.

Vulnerable mode requires the exact environment setting `EH_ENABLE_VULNERABLE_CONTROL=1` and emits a loud runtime warning. It is never enabled by a default application path. CI runs each campaign twice: the secure configuration must produce zero forbidden effects, while the isolated vulnerable configuration must produce a detectable violation. The concurrency suite additionally tests a real deliberately non-atomic consumption race.

These controls validate that the harness can recognize the modeled vulnerabilities. They do not establish completeness against unknown vulnerabilities.
