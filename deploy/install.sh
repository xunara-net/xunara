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
# admin CLI (xunara), the native client (xunara-agent) and the DERP relay
# (xunara-veil).
#
# Set XUNARA_DERP_HOST to the name or address clients dial the relay with and
# the script also deploys Xunara Veil, generates its self-signed certificate
# and wires the control plane to the resulting DERP map:
#
#   sudo XUNARA_DERP_HOST=derp.example.com ./deploy/install.sh \
#       ./xunarad ./xunara ./xunara-agent ./xunara-veil
#
# Optional: XUNARA_DERP_PORT (default 9091), XUNARA_CONTROL_ADDR (default
# 127.0.0.1:9090), XUNARA_STUN_PORT (enables STUN on that UDP port; off by
# default because it needs its own port mapping to be useful).
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
veil_state=/var/lib/xunara-veil
veil_map=$veil_state/derp.json
derp_port=${XUNARA_DERP_PORT:-9091}
control_addr=${XUNARA_CONTROL_ADDR:-127.0.0.1:9090}

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

# The DERP relay is optional: it needs a port clients can reach, which not
# every deployment has. Everything below happens only when it is asked for.
if [ -n "${XUNARA_DERP_HOST:-}" ]; then
	if [ ! -x "$prefix/bin/xunara-veil" ]; then
		echo "error: XUNARA_DERP_HOST is set but $prefix/bin/xunara-veil is missing" >&2
		exit 2
	fi
	if [ -n "${XUNARA_STUN_PORT:-}" ]; then
		stun_args="-stun -stun-port $XUNARA_STUN_PORT"
	else
		stun_args="-stun=false"
	fi

	install -d -o xunara -g xunara -m 0700 "$veil_state"
	sed -e "s|@XUNARA_DERP_HOST@|$XUNARA_DERP_HOST|" \
		-e "s|@XUNARA_DERP_PORT@|$derp_port|" \
		-e "s|@XUNARA_CONTROL_ADDR@|$control_addr|" \
		-e "s|@XUNARA_STUN_ARGS@|$stun_args|" \
		"$here/systemd/xunara-veil.service" >/etc/systemd/system/xunara-veil.service
	chmod 0644 /etc/systemd/system/xunara-veil.service

	# Generate the certificate, the relay key and the DERP map before the
	# services start, so the control plane always finds a map to serve. The
	# relay rewrites the same map on every start, and the pin only changes
	# when the certificate does.
	"$prefix/bin/xunara-veil" -listen "127.0.0.1:$derp_port" \
		-hostname "$XUNARA_DERP_HOST" -state-dir "$veil_state" \
		-cert-mode selfsigned -cert-dir "$veil_state/certs" \
		-derp-map-out "$veil_map" -derp-map-only
	chown -R xunara:xunara "$veil_state"

	# The control plane reads the relay's map from its own unit, added here so
	# a deployment without a relay keeps the stock unit.
	install -o root -g root -m 0644 "$here/systemd/xunarad.service" \
		/etc/systemd/system/xunarad.service
	sed -i "/^ *-grpc-listen/a\\    -derp-map $veil_map \\\\" \
		/etc/systemd/system/xunarad.service
	systemctl daemon-reload
	systemctl enable xunara-veil >/dev/null
	echo "installed Xunara Veil: DERP on :$derp_port as $XUNARA_DERP_HOST, map $veil_map"
else
	install -o root -g root -m 0644 "$here/systemd/xunarad.service" \
		/etc/systemd/system/xunarad.service
fi

if [ ! -f "$conf/xunarad.env" ]; then
	install -o root -g root -m 0600 "$here/xunarad.env.example" "$conf/xunarad.env"
	echo "wrote $conf/xunarad.env (mode 0600); add secrets there, not on the command line"
fi

systemctl daemon-reload
systemctl enable xunarad >/dev/null
systemctl restart xunarad
sleep 1
systemctl --no-pager --lines=0 status xunarad || true

# The relay binds the public DERP port, which the control plane may still have
# held (its previous -grpc-listen), so it starts only after xunarad restarted.
if [ -n "${XUNARA_DERP_HOST:-}" ]; then
	systemctl restart xunara-veil
	sleep 1
	systemctl --no-pager --lines=0 status xunara-veil || true
fi

echo
echo "installed $( "$prefix/bin/xunarad" -version 2>/dev/null || echo "$BIN")"
echo "state: $state   config: $conf   unit: /etc/systemd/system/xunarad.service"
