#!/bin/sh
# Install or upgrade the Xunara control plane on a systemd host.
#
#   sudo ./deploy/install.sh /path/to/xunarad [/path/to/xunara] [/path/to/xunara-agent]
#
# The script is idempotent: it installs the binary (keeping the previous one
# for rollback), the service account, the state directory and the unit file,
# then enables and restarts the service. Re-running it is the upgrade path.
#
# Extra binaries are installed next to the daemon under the same prefix: the
# admin CLI (xunara) and the native client (xunara-agent).
set -eu

BIN=${1:-}
if [ -z "$BIN" ] || [ ! -f "$BIN" ]; then
	echo "usage: $0 <path to the xunarad binary>" >&2
	exit 2
fi
if [ "$(id -u)" -ne 0 ]; then
	echo "error: run as root (the service is a system unit)" >&2
	exit 2
fi

here=$(cd "$(dirname "$0")" && pwd)
prefix=${XUNARA_PREFIX:-/opt/xunara}
state=${XUNARA_STATE:-/var/lib/xunara}
conf=/etc/xunara

# A dedicated, unprivileged account: the control plane must not run as root.
if ! id xunara >/dev/null 2>&1; then
	useradd --system --home-dir "$state" --shell /usr/sbin/nologin \
		--comment "Xunara control plane" xunara
fi

install -d -o root -g root -m 0755 "$prefix/bin"
install -d -o root -g root -m 0755 "$conf"
install -d -o xunara -g xunara -m 0700 "$state"

# Keep the running binary so a bad upgrade is one `mv` away from a rollback.
if [ -f "$prefix/bin/xunarad" ]; then
	cp -p "$prefix/bin/xunarad" "$prefix/bin/xunarad.previous"
fi
if [ "$(readlink -f "$BIN")" != "$(readlink -f "$prefix/bin/xunarad" 2>/dev/null)" ]; then
	install -o root -g root -m 0755 "$BIN" "$prefix/bin/xunarad"
fi

shift
for extra in "$@"; do
	[ -f "$extra" ] || { echo "error: $extra is not a file" >&2; exit 2; }
	install -o root -g root -m 0755 "$extra" "$prefix/bin/$(basename "$extra")"
	echo "installed $prefix/bin/$(basename "$extra")"
done

install -o root -g root -m 0644 "$here/systemd/xunarad.service" \
	/etc/systemd/system/xunarad.service
if [ ! -f "$conf/xunarad.env" ]; then
	install -o root -g root -m 0600 "$here/xunarad.env.example" "$conf/xunarad.env"
	echo "wrote $conf/xunarad.env (mode 0600); add secrets there, not on the command line"
fi

systemctl daemon-reload
systemctl enable xunarad >/dev/null
systemctl restart xunarad
sleep 1
systemctl --no-pager --lines=0 status xunarad || true

echo
echo "installed $( "$prefix/bin/xunarad" -version 2>/dev/null || echo "$BIN")"
echo "state: $state   config: $conf   unit: /etc/systemd/system/xunarad.service"
