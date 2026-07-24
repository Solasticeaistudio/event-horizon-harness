from __future__ import annotations

import argparse
import json
import tempfile
from dataclasses import asdict
from pathlib import Path

from .adversarial import ScriptedAdversarialCampaignRunner
from .process_harness import ProcessSeparatedHarness


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Run the bounded scripted synthetic adversarial range')
    parser.add_argument('--workdir', type=Path)
    args = parser.parse_args(argv)
    workdir = args.workdir or Path(tempfile.mkdtemp(prefix='event-horizon-adversarial-'))
    harness = ProcessSeparatedHarness(workdir, inject_permissive_guardian=True).start()
    try:
        root_probe = harness.root_probe()
        results = ScriptedAdversarialCampaignRunner(harness).run_all()
        teardown = harness.teardown_executor()
        contained = all(result.contained for result in results)
        certificate = harness.build_certificate(
            run_id='scripted-adversarial-synthetic-run-v0.4',
            session_id='adversarial-session',
            assertions={
                'all_scripted_adversarial_campaigns_contained': contained,
                'authoritative_event_chain_intact': harness.call('recorder', 'verify', {})['valid'],
                'no_transferable_credential': not root_probe['ambient_authority_environment_hits'],
                'no_unauthorized_egress': harness.egress_evidence['unauthorized_egress_attempts_succeeded'] == 0,
                'teardown_verified': teardown['verified'],
            },
        )
        result_path = workdir / 'adversarial-results.json'
        certificate_path = workdir / 'adversarial-containment-certificate.json'
        result_path.write_text(
            json.dumps([asdict(result) for result in results], indent=2, sort_keys=True),
            encoding='utf-8',
        )
        certificate_path.write_text(json.dumps(certificate, indent=2, sort_keys=True), encoding='utf-8')
        print('EVENT HORIZON - BOUNDED SCRIPTED SYNTHETIC ADVERSARIAL RANGE')
        for result in results:
            print(f'[{"PASS" if result.contained else "FAIL"}] {result.name}')
        print(f'results: {result_path}')
        print(f'certificate: {certificate_path}')
        return 0 if contained and teardown['verified'] else 1
    finally:
        harness.close()


if __name__ == '__main__':
    raise SystemExit(main())
