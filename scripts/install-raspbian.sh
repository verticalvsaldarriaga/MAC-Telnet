#!/usr/bin/env bash
set -euo pipefail
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if ! command -v apt-get >/dev/null 2>&1; then
	echo "This installer is for Raspberry Pi OS / Debian and requires apt-get." >&2
	exit 1
fi
exec "$script_dir/install-linux.sh" "$@"
