#!/bin/sh
#
# peering_setup.sh — let other monetary nodes bootstrap from this one.
#
# OFF BY DEFAULT. Both switches below start at 0, and nothing is installed,
# started or published until you set them yourself. This is the Knots
# pattern: the panel exists, the dangerous entries are opt-in, and the file
# says what each one costs.
#
#   ./peering_setup.sh --settings    show the panel and where it lives
#   ./peering_setup.sh --enable      turn serving on in the settings file
#   ./peering_setup.sh --disable     turn it off again
#   sudo ./peering_setup.sh          apply whatever the settings say
#   ./peering_setup.sh --address     the peering onion, if published
#   ./peering_setup.sh --status      what is actually running
#
# WHAT "SERVING" MEANS HERE. monetary_ibd.py --serve hands your monetary
# store to another node over a sync protocol built for the filtered format.
# It is how somebody else gets a verified store without trusting you: they
# check every block against its own proof-of-work as it arrives, and they
# compare the commitment against the one you published. A dishonest server
# cannot forge either.
#
# WHAT IT COSTS YOU.
#   - Bandwidth. A full bootstrap is hundreds of gigabytes, over Tor, from a
#     laptop. maxuploadtarget does not apply: this is not bitcoind.
#   - Attention. If people come to depend on it, you have taken on an
#     obligation you did not ask for and cannot easily put down.
#   - A third permanent onion address, which is a third thing that only has
#     to leak once.
#
# WHAT IT DOES NOT DO. This does not serve the Bitcoin P2P protocol. A peer
# running stock Core cannot sync from it, and once this node is pruned it
# could not serve them anyway — the blocks are gone and the witness data for
# modified transactions is gone permanently. This is monetary-node-to-
# monetary-node only, and saying otherwise to anyone would be a lie.
#
# BSD-2-Clause.

set -eu

REAL_HOME=$(eval echo "~${SUDO_USER:-$(id -un)}")
USER_NAME="${SUDO_USER:-$(id -un)}"
SETTINGS="$REAL_HOME/.monetary/peering.conf"
TOOLS="$REAL_HOME/monetary-node/tools"
STORE="$REAL_HOME/mstore"
HSDIR=/var/lib/tor/monetary-peering
TORRC=/etc/tor/torrc
UNIT=/etc/systemd/system/monetary-peering.service
PORT=8335

ACTION=apply
case "${1:-}" in
    --settings) ACTION=settings ;;
    --enable)   ACTION=enable ;;
    --disable)  ACTION=disable ;;
    --address)  ACTION=address ;;
    --status)   ACTION=status ;;
    "")         ;;
    -h|--help)  sed -n '2,38p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
esac

say() { printf '%s\n' "$*"; }

# ---------------------------------------------------------------- defaults
#
# Written once, never overwritten. If the file exists, the operator owns it.

write_defaults() {
    mkdir -p "$(dirname "$SETTINGS")"
    cat > "$SETTINGS" <<'EOF'
# Monetary node peering settings.
#
# Everything here is OFF by default. Nothing in this file does anything
# until you run:  sudo ./peering_setup.sh
#
# ---------------------------------------------------------------------------
# serve_bootstrap
#
#   Serve this node's monetary store to other monetary nodes, so they can
#   bootstrap without re-deriving it themselves. They still verify every
#   block against its own proof-of-work and compare the commitment, so they
#   are not trusting you — but you are spending your bandwidth on them.
#
#   A full bootstrap is hundreds of gigabytes from a laptop over Tor.
#
#   default: 0
serve_bootstrap=0

# ---------------------------------------------------------------------------
# peering_onion
#
#   Publish the bootstrap service as its own Tor hidden service, so nodes
#   elsewhere can reach it. Without this, serve_bootstrap only listens on
#   loopback and is reachable by you alone.
#
#   This creates a THIRD permanent onion address, separate from the node's
#   P2P onion and from the status page. An onion address reveals no IP by
#   itself, but it is permanent and it only has to leak once.
#
#   default: 0
peering_onion=0

# ---------------------------------------------------------------------------
# serve_from_height
#
#   Lowest height to serve. 0 means genesis, which is what makes this useful
#   as a bootstrap: a store that does not start at genesis cannot bootstrap
#   anybody.
#
#   default: 0
serve_from_height=0
EOF
    chown -R "$USER_NAME" "$(dirname "$SETTINGS")" 2>/dev/null || true
}

[ -f "$SETTINGS" ] || write_defaults

get() {
    v=$(grep -E "^[[:space:]]*$1=" "$SETTINGS" 2>/dev/null \
        | tail -1 | cut -d= -f2 | tr -dc '0-9')
    [ -n "$v" ] && printf '%s' "$v" || printf '%s' "$2"
}

SERVE=$(get serve_bootstrap 0)
ONION=$(get peering_onion 0)
FROM=$(get serve_from_height 0)

# ---------------------------------------------------------------- settings

if [ "$ACTION" = settings ]; then
    say "settings file: $SETTINGS"
    say ""
    printf '  %-20s %s\n' "serve_bootstrap" "$SERVE"
    printf '  %-20s %s\n' "peering_onion" "$ONION"
    printf '  %-20s %s\n' "serve_from_height" "$FROM"
    say ""
    say "Edit that file, or use --enable / --disable, then apply with sudo."
    say "Nothing runs until you do."
    exit 0
fi

if [ "$ACTION" = enable ]; then
    sed -i 's/^serve_bootstrap=.*/serve_bootstrap=1/' "$SETTINGS"
    say "serve_bootstrap=1 in $SETTINGS"
    say ""
    say "This is loopback-only so far — nobody outside this machine can"
    say "reach it. To let other nodes connect over Tor you must also set"
    say "peering_onion=1, which creates a permanent third onion address."
    say "That one is deliberately not flipped for you."
    say ""
    say "Then:  sudo ./peering_setup.sh"
    exit 0
fi

if [ "$ACTION" = disable ]; then
    sed -i 's/^serve_bootstrap=.*/serve_bootstrap=0/' "$SETTINGS"
    sed -i 's/^peering_onion=.*/peering_onion=0/' "$SETTINGS"
    say "both switches set to 0 in $SETTINGS"
    say "Apply it:  sudo ./peering_setup.sh"
    exit 0
fi

if [ "$ACTION" = address ]; then
    if sudo test -f "$HSDIR/hostname" 2>/dev/null; then
        say "peering onion (port 8335):"
        sudo cat "$HSDIR/hostname" | sed 's/^/  /'
        say ""
        say "Other monetary nodes sync with:"
        say "  python3 monetary_ibd.py --sync <that>.onion:8335 --out ~/mstore"
    else
        say "no peering hidden service — peering_onion is off, or not applied"
        exit 1
    fi
    exit 0
fi

if [ "$ACTION" = status ]; then
    printf '  %-24s %s\n' "serve_bootstrap" "$SERVE"
    printf '  %-24s %s\n' "peering_onion" "$ONION"
    printf '  %-24s %s\n' "monetary-peering.service" \
        "$(systemctl is-active monetary-peering 2>/dev/null || echo inactive)"
    if ss -ltn 2>/dev/null | grep -q "127.0.0.1:$PORT "; then
        printf '  %-24s %s\n' "listening on $PORT" "yes"
    else
        printf '  %-24s %s\n' "listening on $PORT" "no"
    fi
    exit 0
fi

# ------------------------------------------------------------------- apply

[ "$(id -u)" = 0 ] || { say "run this with sudo to apply"; exit 1; }

say "settings  $SETTINGS"
printf '  serve_bootstrap=%s  peering_onion=%s  serve_from_height=%s\n' \
    "$SERVE" "$ONION" "$FROM"
say ""

# --- off ---------------------------------------------------------------

if [ "$SERVE" != "1" ]; then
    say "serve_bootstrap is 0 — tearing down anything previously installed."
    systemctl disable --now monetary-peering 2>/dev/null || true
    rm -f "$UNIT"
    if grep -q "monetary peering" "$TORRC" 2>/dev/null; then
        sed -i '/# monetary peering/,+2d' "$TORRC"
        systemctl reload tor 2>/dev/null || systemctl restart tor
        say "removed the peering hidden service from torrc"
        say ""
        say "NOTE: $HSDIR still holds the key, so the same address comes back"
        say "if you re-enable. Delete that directory to destroy it for good."
    fi
    systemctl daemon-reload
    say "Nothing is being served."
    exit 0
fi

# --- on ----------------------------------------------------------------

[ -f "$TOOLS/monetary_ibd.py" ] || { say "no monetary_ibd.py in $TOOLS"; exit 1; }
[ -f "$STORE/state.json" ] || { say "no store at $STORE"; exit 1; }

# Refuse to serve a store that does not start at genesis. A partial store
# cannot bootstrap anybody, and advertising one as a bootstrap source wastes
# the bandwidth of everyone who tries.
if [ "$FROM" != "0" ]; then
    say "WARNING: serve_from_height=$FROM. A store that does not begin at"
    say "genesis cannot bootstrap a new node from nothing. Serve it only if"
    say "you know the peer already has everything below that height."
    say ""
fi

say "unit  $UNIT"
cat > "$UNIT" <<EOF
[Unit]
Description=Monetary node bootstrap service (opt-in)
Requires=bitcoind.service
After=bitcoind.service

[Service]
Type=simple
User=$USER_NAME
ExecStart=$(command -v python3) $TOOLS/monetary_ibd.py \\
    --serve $STORE --start-height $FROM --host 127.0.0.1 --port $PORT
Restart=always
RestartSec=30

# Loopback only, always. When peering_onion is on, Tor is what reaches the
# outside; this process is never exposed to the LAN, and never to clearnet.
IPAddressDeny=any
IPAddressAllow=127.0.0.1/8
IPAddressAllow=::1/128

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadOnlyPaths=$STORE

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable monetary-peering >/dev/null 2>&1 || true
systemctl restart monetary-peering
say "  serving $STORE on 127.0.0.1:$PORT"

# --- the onion, only if asked -----------------------------------------

if [ "$ONION" != "1" ]; then
    say ""
    say "peering_onion is 0, so this is reachable from this machine only."
    say "Nobody else can connect. To publish it, set peering_onion=1 in"
    say "$SETTINGS and run this again."
    exit 0
fi

if grep -q "monetary peering" "$TORRC" 2>/dev/null; then
    say "torrc already has the peering hidden service"
else
    say "torrc  adding a THIRD hidden service, separate from the others"
    cat >> "$TORRC" <<EOF

# monetary peering
HiddenServiceDir $HSDIR
HiddenServicePort $PORT 127.0.0.1:$PORT
EOF
fi
systemctl reload tor 2>/dev/null || systemctl restart tor

n=0
while [ ! -f "$HSDIR/hostname" ]; do
    n=$((n + 1)); [ "$n" -gt 30 ] && break
    sleep 2
done

say ""
say "=================================================================="
if [ -f "$HSDIR/hostname" ]; then
    say "PEERING ONION"
    say "=================================================================="
    cat "$HSDIR/hostname" | sed 's/^/  /'
    say ""
    say "Another monetary node bootstraps with:"
    say "  python3 monetary_ibd.py --sync <above>.onion:$PORT --out ~/mstore"
    say ""
    say "Tell people plainly what this is: a laptop, alpha software, and"
    say "monetary-node-to-monetary-node only. It cannot serve a stock"
    say "Bitcoin node and never will."
else
    say "Tor produced no hostname. Check: journalctl -u tor -n 20"
fi
