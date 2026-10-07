#!/bin/sh
#
# tor_lockdown.sh — make clearnet impossible for bitcoind, not merely
# discouraged.
#
# On 24 September 2026 this node ran on clearnet for about six hours with a
# correct bitcoin.conf. The config was right; the running process predated it
# and nothing enforced the intent. Configuration is a request. This adds
# enforcement.
#
#   sudo ./tor_lockdown.sh              install the lockdown
#   ./tor_lockdown.sh --verify          check a running node, STOP it if dirty
#   sudo ./tor_lockdown.sh --clearnet   turn the lockdown OFF (asks first)
#   sudo ./tor_lockdown.sh --tor        put it back
#   ./tor_lockdown.sh --show            print what is installed, change nothing
#
# THE GUARANTEE. systemd's IPAddressDeny applies an eBPF socket filter to the
# unit's cgroup. With everything denied except loopback, bitcoind cannot open
# a socket to any outside address no matter what its config says, what flags
# it is given, or what a future edit gets wrong. Tor runs as its own service
# and reaches the network on bitcoind's behalf; bitcoind only ever talks to
# 127.0.0.1:9050.
#
# THE HOLE IN IT. This binds the systemd unit, so a hand-started
#
#     bitcoind -daemon
#
# is NOT covered and will happily use clearnet. That is exactly how the
# six-hour exposure happened. After running this, start the node only with
# systemctl. --verify exists to catch the case where someone forgets.
#
# BSD-2-Clause.

set -eu

CONF="${BITCOIN_CONF:-$HOME/.bitcoin/bitcoin.conf}"
DATADIR="${BITCOIN_DATADIR:-$HOME/.bitcoin}"
DROPIN=/etc/systemd/system/bitcoind.service.d/20-tor-lockdown.conf
ACTION=install

case "${1:-}" in
    --verify) ACTION=verify ;;
    --selftest) ACTION=selftest ;;
    --show)   ACTION=show ;;
    --clearnet) ACTION=clearnet ;;
    --tor)    ACTION=install ;;
    -h|--help) sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    "") ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
esac

say() { printf '%s\n' "$*"; }

# Same trap as electrs_setup.sh: under sudo, bitcoin-cli looks in /root for
# the cookie and reports a running node as down. Here that was worse than a
# false negative — the "refuse to touch a live node" guard would never fire.
bcli() { bitcoin-cli -datadir="$DATADIR" "$@"; }

# --------------------------------------------------------------- clearnet
#
# Tor is the default and stays the default. This is the way back out, because
# a node nobody can change is not a node anyone should publish — other
# operators have other threat models, and an irreversible setting is a bug
# even when the setting is the right one.
#
# It is deliberately not a toggle in the dashboard. Three reasons:
#
#   - The lockdown is a systemd IPAddressDeny filter enforced by the kernel.
#     Changing it needs root. The dashboard runs as an ordinary user and will
#     not be given root to make a checkbox work.
#   - The dashboard has no authentication. It is loopback-only, but "one
#     click away from publishing your home IP" is not a state to leave a page
#     in.
#   - This deserves a pause. A typed word is a cheap, effective pause.

if [ "$ACTION" = clearnet ]; then
    [ "$(id -u)" = 0 ] || { say "run this with sudo"; exit 1; }
    say "=================================================================="
    say "TURNING OFF THE TOR LOCKDOWN"
    say "=================================================================="
    say ""
    say "After this, your node connects over the open internet. That means:"
    say ""
    say "  - Your home IP address is visible to every peer you connect to,"
    say "    and to anyone running a crawler that watches them. Crawler data"
    say "    is archived and sold, so this is not undone by changing back"
    say "    later."
    say "  - If you have published any onion address for this node, an"
    say "    observer who sees both can pair them. That link is permanent."
    say "  - Your node becomes findable as a node, at your address, running"
    say "    unreviewed alpha software."
    say ""
    say "The config file keeps onlynet=onion unless you change it too, so"
    say "removing this drop-in alone may leave the node Tor-only in practice"
    say "and clearnet-capable in principle. The dashboard banner reports what"
    say "is actually happening — trust that, not this script's say-so."
    say ""
    if [ -f "$DROPIN" ]; then
        say "about to remove: $DROPIN"
    else
        say "The lockdown is not installed. Nothing to remove."
        exit 0
    fi
    say ""
    printf 'Type CLEARNET to confirm, anything else to abort: '
    read -r reply
    [ "$reply" = "CLEARNET" ] || { say "not confirmed, nothing changed"; exit 1; }

    BAK="$DROPIN.removed.$(date +%Y%m%d%H%M%S)"
    cp "$DROPIN" "$BAK"
    rm -f "$DROPIN"
    systemctl daemon-reload
    say ""
    say "removed. a copy is at $BAK"
    say ""
    say "The running node still has the old filter applied: systemd set it"
    say "when the process started and cannot lift it from under a live"
    say "process. Nothing changes until you restart:"
    say ""
    say "    sudo systemctl restart bitcoind"
    say ""
    say "To also let it dial clearnet peers you must change the config as"
    say "well — remove or comment onlynet=onion in:"
    say "    $CONF"
    say ""
    say "To put the lockdown back:"
    say "    sudo ./tor_lockdown.sh --tor"
    say ""
    say "Check the banner at the top of the dashboard afterwards. It reports"
    say "measured peers, not configured intent."
    exit 0
fi

# ------------------------------------------------------------------- show

if [ "$ACTION" = show ]; then
    say "drop-in $DROPIN"
    [ -f "$DROPIN" ] && sed 's/^/  /' "$DROPIN" || say "  NOT INSTALLED"
    say ""
    say "effective unit"
    systemctl cat bitcoind.service 2>/dev/null \
        | grep -E '^Type|^PIDFile|^IPAddress|^ExecStart|^Requires' \
        | sed 's/^/  /'
    say ""
    say "config"
    grep -E '^(proxy|onlynet|listen|listenonion|discover|upnp|natpmp|dnsseed|torcontrol|externalip|bind)' \
        "$CONF" 2>/dev/null | sed 's/^/  /' || say "  none of the relevant keys set"
    exit 0
fi

# ----------------------------------------------------------------- verify
#
# The test is the peer list, not the config and not this script's own
# opinion. Anything that is not an onion peer is a failure, and a failure
# stops the node rather than printing a warning nobody reads.

# A .onion local address is the hidden service, published so onion peers can
# find you. It is desirable and reveals nothing. A clearnet local address is
# the leak. An earlier version of this check counted both and stopped a
# perfectly clean node twice.
clearnet_locals() {
    grep -o '"address": *"[^"]*"' \
        | sed 's/.*"address": *"//; s/"$//' \
        | grep -v '\.onion$' || true
}

if [ "$ACTION" = selftest ]; then
    ok=0; n=0
    ck() {
        n=$((n+1))
        if [ "$2" = "$3" ]; then printf '  [ok  ] %s\n' "$1"; ok=$((ok+1))
        else printf '  [FAIL] %s  got "%s" want "%s"\n' "$1" "$2" "$3"; fi
    }
    ONION_ONLY='{"localaddresses":[{"address":"abc123.onion","port":8334}]}'
    WITH_IP='{"localaddresses":[{"address":"abc123.onion"},{"address":"73.106.129.159"}]}'
    NONE='{"localaddresses":[]}'
    ck "onion-only local address is clean" \
       "$(printf '%s' "$ONION_ONLY" | clearnet_locals | wc -l | tr -d ' ')" "0"
    ck "a clearnet local address is caught" \
       "$(printf '%s' "$WITH_IP" | clearnet_locals | wc -l | tr -d ' ')" "1"
    ck "the caught address is the IP, not the onion" \
       "$(printf '%s' "$WITH_IP" | clearnet_locals)" "73.106.129.159"
    ck "no local addresses at all is clean" \
       "$(printf '%s' "$NONE" | clearnet_locals | wc -l | tr -d ' ')" "0"
    printf '\n%d/%d passed\n' "$ok" "$n"
    [ "$ok" = "$n" ] || exit 1
    exit 0
fi

if [ "$ACTION" = verify ]; then
    if ! bcli -getinfo >/dev/null 2>&1; then
        say "bitcoind is not answering RPC — nothing running, nothing leaking"
        exit 0
    fi

    PEERS=$(bcli getpeerinfo 2>/dev/null) || {
        say "could not read peers — treating as unsafe"; exit 1; }
    NET=$(bcli getnetworkinfo 2>/dev/null) || {
        say "could not read network info — treating as unsafe"; exit 1; }

    DIRTY=$(printf '%s' "$PEERS" | grep -c '"network": *"\(ipv4\|ipv6\)"' || true)
    ONION=$(printf '%s' "$PEERS" | grep -c '"network": *"onion"' || true)
    BAD_LOCAL=$(printf '%s' "$NET" | clearnet_locals)
    ONION_LOCAL=$(printf '%s' "$NET" | grep -c '"address": *"[^"]*\.onion"' || true)

    say "  onion peers        $ONION"
    say "  clearnet peers     $DIRTY"
    say "  onion addresses    $ONION_LOCAL  (expected: your hidden service)"
    if [ -n "$BAD_LOCAL" ]; then
        say "  clearnet addresses $(printf '%s' "$BAD_LOCAL" | wc -l | tr -d ' ')"
        printf '%s\n' "$BAD_LOCAL" | sed 's/^/      /'
    else
        say "  clearnet addresses 0"
    fi

    if [ "$DIRTY" -gt 0 ] || [ -n "$BAD_LOCAL" ]; then
        say ""
        say "CLEARNET DETECTED. Stopping the node now."
        bcli stop >/dev/null 2>&1 || true
        say "Stop issued. Wait for 'Shutdown done' in $DATADIR/debug.log,"
        say "then find out why: ./tor_lockdown.sh --show"
        exit 1
    fi

    say ""
    say "Clean: every peer is onion, and no clearnet address is advertised."
    [ "$ONION_LOCAL" -gt 0 ] && say "The .onion address above is your hidden service. That is correct."
    exit 0
fi

# ---------------------------------------------------------------- install

[ "$(id -u)" = 0 ] || { say "run this with sudo"; exit 1; }

REAL_HOME=$(eval echo "~${SUDO_USER:-root}")
CONF="${BITCOIN_CONF:-$REAL_HOME/.bitcoin/bitcoin.conf}"
DATADIR="${BITCOIN_DATADIR:-$REAL_HOME/.bitcoin}"
[ -f "$CONF" ] || { say "no bitcoin.conf at $CONF"; exit 1; }

if bcli -getinfo >/dev/null 2>&1; then
    say "bitcoind is running. Stop it first — this must not be applied to a"
    say "live process, because the process would keep its existing sockets."
    exit 1
fi

# --- config: belt ---------------------------------------------------------
#
# These do not enforce anything on their own, which is the whole lesson of
# today. They are here so the node's own behaviour matches the firewall
# instead of fighting it and filling the log with failed connections.
#
#   discover=0   stop learning and advertising the public IP. This is what
#                put 73.x.x.x into the "Local addresses" list.
#   upnp/natpmp  stop asking the router to open a port. The shutdown log
#                showed a mapport thread, so one of these was active.
#   dnsseed=0    DNS seed lookups go through the system resolver, which is
#                loopback and therefore permitted by the filter. Peer
#                discovery uses peers.dat and the hardcoded onion seeds.

say "config  $CONF"
cp -a "$CONF" "$CONF.bak.$(date +%Y%m%d%H%M%S)"
# Core v31 removed UPnP support, so writing upnp=0 only earns an "Ignoring
# unknown configuration value" warning. natpmp is the surviving port-mapping
# option and is the one that matters. Check before writing, the same way
# node_config.sh does, rather than trusting a settings list.
HELP=$(bitcoind -help 2>&1 || true)
supported() {
    printf '%s' "$HELP" | grep -qE -- "^[[:space:]]*-$1(=|[[:space:]]|$)"
}

for kv in "proxy=127.0.0.1:9050" "onlynet=onion" "listen=1" \
          "listenonion=1" "torcontrol=127.0.0.1:9051" \
          "discover=0" "upnp=0" "natpmp=0" "dnsseed=0"; do
    k=${kv%%=*}
    if ! supported "$k"; then
        say "  skipped $k — not in this build"
        continue
    fi
    if grep -qE "^[[:space:]]*$k=" "$CONF"; then
        sed -i "s|^[[:space:]]*$k=.*|$kv|" "$CONF"
        say "  set     $kv"
    else
        printf '%s\n' "$kv" >> "$CONF"
        say "  added   $kv"
    fi
done
if grep -qE '^[[:space:]]*externalip=' "$CONF"; then
    sed -i 's|^[[:space:]]*externalip=|#externalip=|' "$CONF"
    say "  removed externalip (it publishes an address by definition)"
fi

# --- unit: braces ---------------------------------------------------------

say ""
say "drop-in $DROPIN"
mkdir -p "$(dirname "$DROPIN")"
cat > "$DROPIN" <<EOF
# Written by tor_lockdown.sh. The kernel enforces this; bitcoin.conf only
# asks. Do not remove without understanding that removing it makes clearnet
# possible again.
[Service]
# -daemonwait forks when initialisation completes, so the unit must be
# forking or systemd declares the service dead at the moment it is ready.
Type=forking
PIDFile=$DATADIR/bitcoind.pid

# The guarantee. Deny every address, then permit loopback only. Tor is a
# separate service and reaches the network itself; bitcoind speaks to
# 127.0.0.1:9050 and nothing else. A socket to any other address is refused
# by the kernel before a packet leaves the machine.
IPAddressDeny=any
IPAddressAllow=127.0.0.1/8
IPAddressAllow=::1/128

# Stop the restart storm that follows a held datadir lock: five failures in
# two seconds hits the start limit and leaves the unit dead.
RestartSec=30
StartLimitIntervalSec=0
EOF
sed 's/^/  /' "$DROPIN"

systemctl daemon-reload
say ""
say "=================================================================="
say "Installed. bitcoind can no longer reach a non-loopback address when"
say "started by systemd."
say ""
say "  sudo systemctl start bitcoind"
say "  ./tor_lockdown.sh --verify"
say ""
say "NEVER run 'bitcoind -daemon' again. A hand-started node is outside"
say "this unit's cgroup and outside the filter, which is precisely how"
say "the clearnet exposure happened. Use systemctl every time."
say ""
say "Still worth doing by hand: remove the port forward on your router."
say "Inbound connections reached this machine, so one exists, and it stays"
say "open whether or not bitcoind is running."
