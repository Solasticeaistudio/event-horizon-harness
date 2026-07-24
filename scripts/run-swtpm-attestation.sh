#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_DIR="$(mktemp -d "${TMPDIR:-/tmp}/attestation-swtpm.XXXXXX")"
SERVER_PORT="${EH_ATTESTATION_SWTPM_PORT:-2321}"
CONTROL_PORT="$((SERVER_PORT + 1))"
SWTPM_PID=""

cleanup() {
  if [[ -n "$SWTPM_PID" ]] && kill -0 "$SWTPM_PID" 2>/dev/null; then
    kill "$SWTPM_PID"
    wait "$SWTPM_PID" 2>/dev/null || true
  fi
  case "$RUN_DIR" in
    "${TMPDIR:-/tmp}"/attestation-swtpm.*) rm -rf -- "$RUN_DIR" ;;
    *) echo "refusing to remove unexpected path: $RUN_DIR" >&2 ;;
  esac
}
trap cleanup EXIT INT TERM

for command in swtpm tpm2_startup tpm2_getrandom tpm2_getcap tpm2_createek tpm2_createak tpm2_evictcontrol tpm2_flushcontext tpm2_quote node npm; do
  command -v "$command" >/dev/null || {
    echo "missing required command: $command" >&2
    exit 2
  }
done

mkdir -m 700 "$RUN_DIR/state" "$RUN_DIR/ak"
swtpm socket \
  --tpm2 \
  --tpmstate "dir=$RUN_DIR/state" \
  --server "type=tcp,port=$SERVER_PORT" \
  --ctrl "type=tcp,port=$CONTROL_PORT" \
  --flags not-need-init \
  --pid "file=$RUN_DIR/swtpm.pid" \
  --daemon
SWTPM_PID="$(cat "$RUN_DIR/swtpm.pid")"

TCTI="swtpm:host=127.0.0.1,port=$SERVER_PORT"
tpm2_startup -T "$TCTI" -c

cd "$ROOT/attestation"
EH_ATTESTATION_REAL_TPM=1 \
EH_ATTESTATION_TPM_TCTI="$TCTI" \
EH_ATTESTATION_TPM_WORKDIR="$RUN_DIR/ak" \
EH_ATTESTATION_TPM_PROVISION_AK=1 \
npm test
