#!/bin/sh
#
# tor_setup.sh — make Tor the permanent default for a Bitcoin node.
#
# Configures Tor, points bitcoind at it with onlynet=onion, and installs a
# systemd unit so the setting survives reboots, upgrades and a forgetful
# operator. Idempotent: safe to run repeatedly, and it will tell you what it
# changed rather than silently rewriting your config.
#
# The distinction this exists to enforce: `proxy` ALONE IS NOT ENOUGH. With
# proxy set and onlynet unset, bitcoind still dials clearnet peers -- it just
# routes some of them through Tor. Your IP stays visible. Only onlynet=onion
# stops it.
#
#   ./tor_setup.sh            configure, then verify
#   ./tor_setup.sh --verify   check only, change nothing
#
# Needs sudo for apt, torrc and systemd. Does not touch your chain data.
#
# BSD-2-Clause.

set -eu

DATADIR="${DATADIR:-$HOME/.bitcoin}"
CONF="$DATADIR/bitcoin.conf"
TORRC=/etc/tor/torrc
UNIT=/etc/systemd/system/bitcoind.service
USERNAME="$(id -un)"
VERIFY_ONLY=0
[ "${1:-}" = "--verify" ] && VERIFY_ONLY=1

say()  { printf '%s\n' "$*"; }
head_() { say ""; say "=================================================="; say "$*"; say "=================================================="; }
ok()   { say "  [ok  ] $*"; }
bad()  { say "  [FAIL] $*"; FAILED=1; }
warn() { say "  [warn] $*"; }
FAILED=0

# ------------------------------------------------------------- verify

verify() {
    head_ "VERIFY"

    if systemctl is-active --quiet tor 2>/dev/null; then
        ok "tor service running"
    else
        bad "tor service not running"
    fi

    if grep -qs '^ControlPort 9051' "$TORRC"; then
        ok "tor control port enabled"
    else
        bad "tor ControlPort 9051 missing from $TORRC"
    fi

    if id -nG "$USERNAME" | tr ' ' '\n' | grep -qx debian-tor; then
        ok "$USERNAME is in debian-tor (can read the control cookie)"
    else
        bad "$USERNAME not in debian-tor — log out and back in after setup"
    fi

    for line in "proxy=127.0.0.1:9050" "onlynet=onion" "listen=1" \
                "torcontrol=127.0.0.1:9051"; do
        if grep -qxF "$line" "$CONF" 2>/dev/null; then
            ok "bitcoin.conf: $line"
        else
            bad "bitcoin.conf missing: $line"
        fi
    done

    # The setting that actually matters, checked against a running node
    # rather than against the file that is supposed to produce it.
    if command -v bitcoin-cli >/dev/null 2>&1 \
       && bitcoin-cli -rpcwait -rpcclienttimeout=10 getblockcount >/dev/null 2>&1
    then
        clear_peers=$(bitcoin-cli getpeerinfo 2>/dev/null \
            | grep -o '"network": *"[a-z0-9]*"' \
            | grep -cv 'onion\|i2p' || true)
        total=$(bitcoin-cli getpeerinfo 2>/dev/null | grep -c '"addr"' || true)
        if [ "${clear_peers:-0}" -eq 0 ] && [ "${total:-0}" -gt 0 ]; then
            ok "all $total connected peers are onion"
        elif [ "${total:-0}" -eq 0 ]; then
            warn "node has no peers yet — recheck in a few minutes"
        else
            bad "$clear_peers of $total peers are CLEARNET — onlynet is not in force"
        fi
    else
        warn "node not reachable; peer check skipped"
    fi

    head_ "RESULT"
    if [ "$FAILED" -eq 0 ]; then
        say "Tor is the default. Your IP is not visible to peers."
    else
        say "NOT Tor-only. Fix the failures above before treating this node"
        say "as private. Note that anything already learned by peers on a"
        say "clearnet connection cannot be retracted."
    fi
    return "$FAILED"
}

if [ "$VERIFY_ONLY" -eq 1 ]; then
    verify
    exit $?
fi

# ------------------------------------------------------------- install

head_ "TOR"
if command -v tor >/dev/null 2>&1; then
    ok "tor already installed"
else
    say "  installing tor..."
    sudo apt-get update -qq
    sudo apt-get install -y -qq tor
    ok "tor installed"
fi

# Append only what is missing. Rewriting torrc wholesale would clobber
# anything else the machine relies on.
for line in "ControlPort 9051" "CookieAuthentication 1" \
            "CookieAuthFileGroupReadable 1"; do
    if grep -qxF "$line" "$TORRC"; then
        ok "torrc: $line"
    else
        printf '%s\n' "$line" | sudo tee -a "$TORRC" >/dev/null
        say "  added to torrc: $line"
    fi
done

if id -nG "$USERNAME" | tr ' ' '\n' | grep -qx debian-tor; then
    ok "$USERNAME already in debian-tor"
else
    sudo usermod -aG debian-tor "$USERNAME"
    warn "added $USERNAME to debian-tor — LOG OUT AND BACK IN for this to apply"
fi

sudo systemctl restart tor
sudo systemctl enable tor >/dev/null 2>&1 || true
ok "tor restarted and enabled at boot"

# ------------------------------------------------------------- bitcoin.conf

head_ "BITCOIN.CONF"
mkdir -p "$DATADIR"
touch "$CONF"
cp "$CONF" "$CONF.bak.$(date +%s)"
ok "backed up $CONF"

for line in "proxy=127.0.0.1:9050" "onlynet=onion" "listen=1" \
            "torcontrol=127.0.0.1:9051"; do
    key="${line%%=*}"
    if grep -qxF "$line" "$CONF"; then
        ok "$line"
    elif grep -q "^$key=" "$CONF"; then
        # A different value for the same key is a real conflict: say so
        # rather than quietly appending a duplicate bitcoind will ignore.
        existing=$(grep "^$key=" "$CONF" | head -1)
        bad "conflict: $CONF has '$existing', wanted '$line' — edit it by hand"
    else
        printf '%s\n' "$line" >> "$CONF"
        say "  added: $line"
    fi
done

# ------------------------------------------------------------- systemd

head_ "SYSTEMD"
if [ -f "$UNIT" ]; then
    ok "unit already exists at $UNIT (left alone)"
else
    sudo tee "$UNIT" >/dev/null <<UNITEOF
[Unit]
Description=Bitcoin daemon (Tor only)
After=network-online.target tor.service
Wants=network-online.target
Requires=tor.service

[Service]
ExecStart=$(command -v bitcoind) -daemonwait -conf=$CONF -datadir=$DATADIR
Type=simple
User=$USERNAME
Restart=on-failure
TimeoutStartSec=infinity
TimeoutStopSec=600

[Install]
WantedBy=multi-user.target
UNITEOF
    sudo systemctl daemon-reload
    ok "wrote $UNIT"
    say ""
    say "  Requires=tor.service means the node will not start without Tor."
    say "  That is deliberate: failing to start is the correct outcome when"
    say "  the alternative is starting on clearnet."
    say ""
    say "  Enable it with:   sudo systemctl enable --now bitcoind"
    say "  Stop any bitcoind you started by hand first."
fi

head_ "NEXT"
say "1. If this added you to debian-tor, log out and back in."
say "2. Restart the node so the new config takes effect:"
say "     bitcoin-cli stop && sleep 20 && bitcoind -daemon"
say "   or, once enabled:  sudo systemctl restart bitcoind"
say "3. Wait a few minutes for onion peers, then:"
say "     ./tor_setup.sh --verify"
say ""
say "Your IP was visible to peers on every clearnet connection made before"
say "now. Tor prevents future exposure; it cannot retract what was already"
say "learned. Addresses age out of other nodes' address managers over weeks."
