#!/usr/bin/env bash
set -euo pipefail
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if ! command -v pacman >/dev/null 2>&1; then
	echo "This installer is for Arch Linux and requires pacman." >&2
	exit 1
fi
exec "$script_dir/install-linux.sh" "$@"
