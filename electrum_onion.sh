#!/bin/sh
#
# electrum_onion.sh — reach your own electrs from anywhere, over Tor.
#
#   sudo ./electrum_onion.sh            create the hidden service
#   ./electrum_onion.sh --address       print it, with wallet settings
#   ./electrum_onion.sh --status        is it up
#   sudo ./electrum_onion.sh --remove   destroy the address permanently
#
# TRY THE SSH TUNNEL FIRST. On the Mac:
#
#     ./deploy.sh --wallet
#
# That reaches the same electrs over the SSH connection you already have,
# creates no new listener and no new permanent identifier. If your wallet
# only ever runs at home, stop there — this script exists for the case where
# it does not.
#
# WHAT THIS ONION IS, AND WHY IT IS NOT LIKE THE OTHERS
#
# The status page onion is meant to be handed to strangers. This one is the
# opposite: it is a private key to your own financial history, and it must
# never be published or shared.
#
# An Electrum server learns the complete address set of every wallet that
# connects to it. That is not a flaw in electrs, it is how the protocol
# works: the client asks "what has happened to these scripts?" and the server
# answers. Running your own is how you avoid telling a stranger. Handing the
# address to someone else inverts that — now they tell YOU, and they are
# trusting a laptop with their whole wallet history.
#
# It is also a link between your wallet and this node. Anyone who has this
# address and watches it knows when you are home and when your node is up,
# and if it ever leaks alongside anything that identifies you, it connects
# your name to your transaction history permanently. On 24 September 2026
# this node spent six hours on clearnet with a correct config. Assume that
# can happen again.
#
# So: one person uses this address. You. Not your friend who wants a node to
# point Sparrow at — tell them to run their own, which is the point.
#
# WHAT IT DOES NOT CHANGE
#
# electrs keeps listening on loopback only, and its unit keeps
# IPAddressDeny=any. Tor runs on this machine and connects to 127.0.0.1, so
# nothing about electrs is exposed to the LAN or to clearnet. The hidden
# service is the only route in, and it is authenticated by the fact that the
# address is unguessable — which is why it leaking matters so much.
#
# BSD-2-Clause.

set -eu

HSDIR=/var/lib/tor/monetary-electrum
TORRC=/etc/tor/torrc
ACTION=install
EPORT=""

while [ $# -gt 1 ]; do
    case "$1" in
        --port) EPORT="$2"; shift 2 ;;
        *) break ;;
    esac
done
case "${1:-}" in
    --address) ACTION=address ;;
    --status)  ACTION=status ;;
    --remove)  ACTION=remove ;;
    "")        ;;
    -h|--help) sed -n '2,50p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
esac

say() { printf '%s\n' "$*"; }

REAL_HOME=$(eval echo "~${SUDO_USER:-$(id -un)}")

# The port of record is the one in electrs's own config, not a flag default.
# Guessing 50001 here when electrs was moved to 50011 would publish a hidden
# service pointing at a closed port, and the failure would look like Tor.
if [ -z "$EPORT" ] && [ -f "$REAL_HOME/.electrs/config.toml" ]; then
    EPORT=$(grep -E '^[[:space:]]*electrum_rpc_addr' \
            "$REAL_HOME/.electrs/config.toml" 2>/dev/null \
            | sed 's/.*://; s/"//g; s/[[:space:]]//g')
fi
[ -n "$EPORT" ] || EPORT=50001

wallet_notes() {
    say ""
    say "SPARROW"
    say "  Preferences -> Server -> Private Electrum"
    say "    URL        $1"
    say "    Port       $EPORT"
    say "    Use SSL    OFF"
    say "    Use Proxy  ON   127.0.0.1:9050"
    say ""
    say "  Proxy ON is the difference from the SSH route: Sparrow has to"
    say "  reach a .onion, which needs Tor. Sparrow can also start its own"
    say "  Tor — either works, but if you already run Tor, point at 9050."
    say ""
    say "ELECTRUM"
    say "  electrum --oneserver --server $1:$EPORT:t \\"
    say "           --proxy socks5:127.0.0.1:9050"
    say ""
    say "  --oneserver matters more here than anywhere. Without it Electrum"
    say "  falls back to public servers when yours is unreachable, and the"
    say "  first thing it does is send them every address you own."
    say ""
    say "Keep this address to yourself. It is a key to your own financial"
    say "history, and it is permanent."
}

# ----------------------------------------------------------------- address

if [ "$ACTION" = address ]; then
    if sudo test -f "$HSDIR/hostname" 2>/dev/null; then
        ADDR=$(sudo cat "$HSDIR/hostname")
        say "your private electrs onion:"
        say "  $ADDR"
        wallet_notes "$ADDR"
    else
        say "no hidden service at $HSDIR — run this with sudo first"
        exit 1
    fi
    exit 0
fi

if [ "$ACTION" = status ]; then
    printf '  %-28s %s\n' "electrs.service" \
        "$(systemctl is-active electrs 2>/dev/null || echo inactive)"
    printf '  %-28s %s\n' "tor.service" \
        "$(systemctl is-active tor 2>/dev/null || echo inactive)"
    if ss -ltn 2>/dev/null | grep -q "127.0.0.1:$EPORT "; then
        printf '  %-28s %s\n' "electrs on 127.0.0.1:$EPORT" "listening"
    else
        printf '  %-28s %s\n' "electrs on 127.0.0.1:$EPORT" "NOT listening"
    fi
    if sudo test -f "$HSDIR/hostname" 2>/dev/null; then
        printf '  %-28s %s\n' "hidden service" "published"
    else
        printf '  %-28s %s\n' "hidden service" "not created"
    fi
    exit 0
fi

# ------------------------------------------------------------------ remove

if [ "$ACTION" = remove ]; then
    [ "$(id -u)" = 0 ] || { say "run this with sudo"; exit 1; }
    say "This deletes the hidden service key. The address is gone for good"
    say "and cannot be regenerated. Any wallet configured with it stops"
    say "syncing until you point it somewhere else."
    printf 'Type REMOVE to confirm: '
    read -r c
    [ "$c" = "REMOVE" ] || { say "not confirmed, nothing changed"; exit 1; }
    if grep -q "monetary electrum" "$TORRC" 2>/dev/null; then
        sed -i '/# monetary electrum/,+2d' "$TORRC"
    fi
    rm -rf "$HSDIR"
    systemctl reload tor 2>/dev/null || systemctl restart tor
    say "Removed. electrs is still running, loopback only."
    exit 0
fi

# ----------------------------------------------------------------- install

[ "$(id -u)" = 0 ] || { say "run this with sudo"; exit 1; }
[ -f "$TORRC" ] || { say "no $TORRC — is Tor installed?"; exit 1; }

# Refuse to publish a route to an index that is not ready. A wallet pointed
# at a half-built electrs reports a wrong balance, and a wrong balance is the
# single worst thing this node could tell you.
if ! systemctl is-active --quiet electrs; then
    say "electrs is not running. Start it first:"
    say "    ./electrs_setup.sh --start"
    exit 1
fi
if ! ss -ltn 2>/dev/null | grep -q "127.0.0.1:$EPORT "; then
    say "electrs is not listening on 127.0.0.1:$EPORT."
    say "Check which port it actually took:"
    say "    grep electrum_rpc_addr $REAL_HOME/.electrs/config.toml"
    exit 1
fi

TIP=$(printf '{"jsonrpc":"2.0","method":"blockchain.headers.subscribe","id":0}\n' \
      | timeout 15 nc -q2 127.0.0.1 "$EPORT" 2>/dev/null \
      | grep -o '"height":[0-9]*' | head -1 | cut -d: -f2)
NODE=$(bitcoin-cli -datadir="$REAL_HOME/.bitcoin" getblockcount 2>/dev/null \
       || echo 0)
if [ -z "$TIP" ]; then
    say "electrs is listening but did not answer a headers request."
    say "It is probably still indexing. Check:  ./electrs_setup.sh --progress"
    exit 1
fi
say "electrs tip  $TIP"
say "node tip     $NODE"
if [ "$NODE" -gt 0 ] && [ "$((NODE - TIP))" -gt 10 ]; then
    say ""
    say "electrs is $((NODE - TIP)) blocks behind the node. A wallet pointed at"
    say "it now would report an incomplete balance. Let it catch up first."
    exit 1
fi
say ""

if grep -q "monetary electrum" "$TORRC"; then
    say "torrc already has the electrum hidden service — leaving it"
else
    say "torrc  adding a hidden service on its own directory, so this"
    say "       address is unrelated to the node's P2P onion and to the"
    say "       public status page"
    cat >> "$TORRC" <<EOF

# monetary electrum
HiddenServiceDir $HSDIR
HiddenServicePort $EPORT 127.0.0.1:$EPORT
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
    ADDR=$(cat "$HSDIR/hostname")
    say "PRIVATE ELECTRUM ONION"
    say "=================================================================="
    say "  $ADDR"
    wallet_notes "$ADDR"
    say ""
    say "  ./electrum_onion.sh --address        print it again"
    say "  sudo ./electrum_onion.sh --remove    destroy it permanently"
else
    say "Tor produced no hostname. Check: journalctl -u tor -n 20"
    exit 1
fi
