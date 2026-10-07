#!/bin/sh
#
# status_onion.sh — publish the status page as its own onion service.
#
#   sudo ./status_onion.sh          install the service and the unit
#   ./status_onion.sh --address     print the onion address
#   ./status_onion.sh --status      is it running
#   sudo ./status_onion.sh --remove take it down and forget the address
#
# WHY A SEPARATE HIDDEN SERVICE. The node already has one, for P2P. Adding
# this page to that same HiddenServiceDir would give both the same onion
# address, which would publish the node's P2P endpoint to everyone who reads
# the status page. A second directory means a second, unrelated address:
# someone who has the status onion learns nothing about where the node is,
# and cannot connect to its P2P or Electrum ports at all.
#
# WHAT PUBLISHING THIS COSTS. An onion address is a permanent public
# identifier. It reveals no IP by itself, but it only has to leak once — and
# on 24 September 2026 this node ran six hours on clearnet with a correct
# config. If the address had been public then, crawlers could have paired it
# with a home IP, permanently, in archived data. Publish it when the lockdown
# has been boring for a while, not the day it was installed.
#
# If you change your mind, --remove deletes the key. The address is then gone
# for good, which is the point: it cannot be reissued or reclaimed.
#
# BSD-2-Clause.

set -eu

HSDIR=/var/lib/tor/monetary-status
TORRC=/etc/tor/torrc
UNIT=/etc/systemd/system/monetary-status.service
PORT=8081
ACTION=install

case "${1:-}" in
    --address)  ACTION=address ;;
    --status)   ACTION=status ;;
    --remove)   ACTION=remove ;;
    "")         ;;
    -h|--help)  sed -n '2,28p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
esac

say() { printf '%s\n' "$*"; }

# ----------------------------------------------------------------- address

if [ "$ACTION" = address ]; then
    if sudo test -f "$HSDIR/hostname"; then
        say "status page onion:"
        sudo cat "$HSDIR/hostname" | sed 's/^/  /'
        say ""
        say "That is the ONLY address to publish. Not the node's onion, not"
        say "the Electrum port, not your IP."
    else
        say "no hidden service at $HSDIR — run this with sudo first"
        exit 1
    fi
    exit 0
fi

if [ "$ACTION" = status ]; then
    printf '  %-26s %s\n' "monetary-status.service" \
        "$(systemctl is-active monetary-status 2>/dev/null || echo inactive)"
    printf '  %-26s %s\n' "tor.service" \
        "$(systemctl is-active tor 2>/dev/null || echo inactive)"
    if ss -ltn 2>/dev/null | grep -q "127.0.0.1:$PORT "; then
        printf '  %-26s %s\n' "page on 127.0.0.1:$PORT" "listening"
    else
        printf '  %-26s %s\n' "page on 127.0.0.1:$PORT" "NOT listening"
    fi
    exit 0
fi

# ------------------------------------------------------------------ remove

if [ "$ACTION" = remove ]; then
    [ "$(id -u)" = 0 ] || { say "run this with sudo"; exit 1; }
    say "This deletes the hidden service key. The onion address is gone"
    say "permanently — it cannot be regenerated. Anyone who bookmarked it"
    say "gets nothing forever after."
    printf 'Type the word REMOVE to confirm: '
    read -r c
    [ "$c" = "REMOVE" ] || { say "not confirmed, nothing changed"; exit 1; }
    systemctl disable --now monetary-status 2>/dev/null || true
    rm -f "$UNIT"
    sed -i '/# monetary status page/,+2d' "$TORRC"
    rm -rf "$HSDIR"
    systemctl daemon-reload
    systemctl reload tor 2>/dev/null || systemctl restart tor
    say "Removed."
    exit 0
fi

# ----------------------------------------------------------------- install

[ "$(id -u)" = 0 ] || { say "run this with sudo"; exit 1; }
REAL_HOME=$(eval echo "~${SUDO_USER:-root}")
USER_NAME="${SUDO_USER:-root}"
TOOLS="$REAL_HOME/monetary-node/tools"

[ -f "$TOOLS/status_page.py" ] || { say "no status_page.py in $TOOLS"; exit 1; }
[ -f "$TORRC" ] || { say "no $TORRC — is Tor installed?"; exit 1; }

# Refuse to publish a page that has not passed its own leak tests. Those
# tests are the thing standing between this and an accidental disclosure.
say "self-test"
if ! su - "$USER_NAME" -c "python3 '$TOOLS/status_page.py' --selftest" \
        | tail -2 | sed 's/^/  /'; then
    say ""
    say "Self-test failed. Not publishing anything."
    exit 1
fi

# --- the service -----------------------------------------------------------

say ""
say "unit  $UNIT"
cat > "$UNIT" <<EOF
[Unit]
Description=Monetary node public status page
After=network-online.target

[Service]
Type=simple
User=$USER_NAME
ExecStart=$(command -v python3) $TOOLS/status_page.py \\
    --store $REAL_HOME/mstore \\
    --datadir $REAL_HOME/.bitcoin \\
    --cookie $REAL_HOME/.bitcoin/.cookie \\
    --tools $TOOLS --host 127.0.0.1 --port $PORT
Restart=always
RestartSec=15

# The query index caches record offsets. The store stays read-only below, so
# the cache goes here instead — otherwise it rebuilds on every refresh, which
# is a full walk of the store every 60 seconds.
StateDirectory=monetary-status
Environment=MONETARY_CACHE=/var/lib/monetary-status

# Loopback only. Tor is what faces the world; this process must not be
# reachable from the LAN even by accident.
IPAddressDeny=any
IPAddressAllow=127.0.0.1/8
IPAddressAllow=::1/128

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadOnlyPaths=$REAL_HOME/mstore $REAL_HOME/.bitcoin

[Install]
WantedBy=multi-user.target
EOF

# --- the hidden service ----------------------------------------------------

if grep -q "monetary status page" "$TORRC"; then
    say "torrc already has the status hidden service — leaving it"
else
    say "torrc  adding a SEPARATE hidden service (its own address)"
    cat >> "$TORRC" <<EOF

# monetary status page
HiddenServiceDir $HSDIR
HiddenServicePort 80 127.0.0.1:$PORT
EOF
fi

systemctl daemon-reload
systemctl enable monetary-status >/dev/null 2>&1 || true
systemctl restart monetary-status
systemctl reload tor 2>/dev/null || systemctl restart tor

say ""
say "waiting for Tor to publish the service..."
n=0
while [ ! -f "$HSDIR/hostname" ]; do
    n=$((n + 1)); [ "$n" -gt 30 ] && break
    sleep 2
done

say ""
say "=================================================================="
if [ -f "$HSDIR/hostname" ]; then
    say "STATUS PAGE ONION"
    say "=================================================================="
    cat "$HSDIR/hostname" | sed 's/^/  /'
    say ""
    say "Check it yourself over Tor Browser before telling anyone. Read the"
    say "whole page and satisfy yourself that nothing on it is something you"
    say "would mind a stranger knowing — the tests check what I thought of,"
    say "not what you know."
else
    say "Tor has not produced a hostname yet. Check: journalctl -u tor -n 20"
fi
say ""
say "  ./status_onion.sh --address    print it again"
say "  ./status_onion.sh --status     is it up"
say "  sudo ./status_onion.sh --remove  destroy the address permanently"
say ""
say "Publish ONLY this address. Not the node onion, not 50011, not your IP."
