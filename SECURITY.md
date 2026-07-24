# Security policy

## Private reporting

Please report a suspected containment bypass through [GitHub private vulnerability reporting](https://github.com/Solasticeaistudio/event-horizon-harness/security/advisories/new). Do not open a public issue until the maintainer confirms that coordinated disclosure is appropriate. If GitHub does not offer the private form, email [solsticestudioai@gmail.com](mailto:solsticestudioai@gmail.com) with the subject `Event Horizon security report` and include only enough information to establish a secure follow-up channel.

Include the affected commit, environment, exact reproduction steps, the expected invariant, the observed result, and minimal synthetic evidence. Remove credentials, personal information, production identifiers, and unrelated data. Maintainers will acknowledge a usable report when practical; this research project does not promise a commercial response SLA or bounty.

## Valid security issues

A valid report demonstrates or plausibly identifies a failure of a documented security boundary, including:

- authority outside the deterministic static-policy ceiling;
- capability replay, scope widening, or transfer across a bound executor or session;
- accepted attestation without an issued one-use nonce or verified provider result;
- simulator evidence accepted as hardware trust;
- static-policy or required-guardian failure that permits execution;
- undetected alteration of the authoritative evidence chain or certificate;
- verified teardown that leaves reusable authority or declared persistence.

Availability failures without authority gain, behavior already listed in `KNOWN_LIMITATIONS.md`, unsupported deployment changes, and generic dependency scanner output without an exploitable path may be closed as non-security issues.

## Authorized testing only

Test only environments, accounts, data, and synthetic ranges you own or are explicitly authorized to use. Real-world targets and public infrastructure are out of scope. Destructive actions, denial of service, credential abuse, persistence on systems outside the synthetic fixture, unauthorized access, social engineering, and attempts to hide activity are prohibited.

The repository contains no authorization to test third parties. Use the bounded scripted adversary and `synthetic://` fixtures for public reproductions.

## Supported versions

Security fixes target the current `main` branch and latest tagged public release. Historical research snapshots are retained for reproducibility but are not maintained security branches.
