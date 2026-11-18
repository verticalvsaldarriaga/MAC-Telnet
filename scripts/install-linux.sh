#!/usr/bin/env bash
set -euo pipefail

usage() {
	cat <<'EOF'
Usage: install-linux.sh [--no-deps]

Build and install MAC-Telnet/MAC-SSH on Linux. Supports apt (including
Raspberry Pi OS), pacman (Arch Linux), dnf, zypper, and apk.
Run as root. --no-deps skips package installation when dependencies are
already installed.
EOF
}

install_deps=1
while (($#)); do
	case "$1" in
		--no-deps) install_deps=0 ;;
		-h|--help) usage; exit 0 ;;
		*) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
	esac
	shift
done

if ((EUID != 0)); then
	echo "Run this installer as root (for example: sudo $0)." >&2
	exit 1
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
src_dir=$(dirname -- "$script_dir")
cd "$src_dir"

if ((install_deps)); then
	if command -v apt-get >/dev/null 2>&1; then
		apt-get update
		DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential openssh-server
	elif command -v pacman >/dev/null 2>&1; then
		pacman -S --needed --noconfirm base-devel openssh
	elif command -v dnf >/dev/null 2>&1; then
		dnf install -y gcc make openssh-server
	elif command -v zypper >/dev/null 2>&1; then
		zypper --non-interactive install gcc make openssh
	elif command -v apk >/dev/null 2>&1; then
		apk add build-base openssh-server
	else
		echo "No supported package manager found. Install a C compiler and make, then rerun with --no-deps." >&2
		exit 1
	fi
fi

make -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')"
make install PREFIX=/usr

if [[ -d /run/systemd/system ]] && command -v systemctl >/dev/null 2>&1; then
	install -m 0644 config/macsshd.service /etc/systemd/system/macsshd.service
	systemctl daemon-reload
	systemctl enable --now macsshd.service
	systemctl restart macsshd.service
	cat <<'EOF'
Installed and started macsshd.service. It forwards MAC-SSH sessions to
127.0.0.1:22. Ensure the system SSH server is installed and listening there.
EOF
else
	cat <<'EOF'
Installed the binaries. This system does not appear to use systemd, so
macsshd was not enabled as a service. Run /usr/sbin/mactelnetd -S -f under
your init system and ensure SSH is listening on 127.0.0.1:22.
EOF
fi
