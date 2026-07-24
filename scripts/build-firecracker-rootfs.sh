#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
default_output="${repo_root}/firecracker/build"
output_dir="${1:-${default_output}}"
output_dir="$(readlink -m "${output_dir}")"
allowed_root="$(readlink -m "${repo_root}/firecracker")"

case "${output_dir}" in
  "${allowed_root}"/*) ;;
  *) echo "output must stay under ${allowed_root}" >&2; exit 2 ;;
esac

for command in gcc truncate mkfs.ext4 install mktemp sha256sum; do
  command -v "${command}" >/dev/null || { echo "missing dependency: ${command}" >&2; exit 3; }
done

mkdir -p "${output_dir}"
staging="$(mktemp -d "${output_dir}/rootfs.stage.XXXXXX")"
temporary_image="${output_dir}/rootfs.ext4.tmp"
final_image="${output_dir}/rootfs.ext4"

cleanup() {
  case "${staging}" in
    "${output_dir}"/rootfs.stage.*) rm -rf -- "${staging}" ;;
    *) echo "refusing to remove unexpected staging path: ${staging}" >&2 ;;
  esac
  rm -f -- "${temporary_image}"
}
trap cleanup EXIT INT TERM

install -d -m 0555 "${staging}/proc" "${staging}/sys"
install -d -m 0755 "${staging}/dev"
install -d -m 0700 "${staging}/scratch"
gcc -static -Os -s -Wall -Wextra -Werror \
  -o "${staging}/init" "${repo_root}/firecracker/guest/guest_agent.c"

truncate -s 64M "${temporary_image}"
mkfs.ext4 -q -F -d "${staging}" -L EH_ROOT "${temporary_image}"
mv -f -- "${temporary_image}" "${final_image}"
sha256sum "${final_image}" >"${output_dir}/SHA256SUMS"
trap - EXIT INT TERM
cleanup

echo "built ${final_image}"
echo "the rootfs contains one static PID-1 agent and is mounted read-only by Firecracker"
