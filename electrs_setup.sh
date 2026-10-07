#!/bin/sh
#
# electrs_setup.sh — preflight, configure and supervise an electrs index.
#
#   ./electrs_setup.sh --check      preflight only, change nothing
#   sudo ./electrs_setup.sh         write config and unit, do not start
#   ./electrs_setup.sh --start      start it and watch the first minute
#   ./electrs_setup.sh --progress   how far along the index is
#   --port N                        Electrum port, default 50001. Use this
#                                   when something else already owns 50001.
#
# THE CONSTRAINT THAT DECIDES THE ORDER OF EVERYTHING ELSE.
#
# electrs refuses to run against a pruned node — it checks and hard-errors,
# it does not degrade. It reads the raw block files to build its index, so
# the blocks must all still be there.
#
# prune_behind.py deletes those block files. That is where the monetary
# node's disk saving actually arrives.
#
# So: the index must be built BEFORE the node is pruned, and once pruned it
# cannot be rebuilt from this node — only from a different, unpruned one.
# This script refuses to proceed against a pruned node rather than letting
# you discover that after six hours of indexing.
#
# It does not download or install electrs. Fetching and running a binary on
# the machine holding your node is your decision to make deliberately; see
# the install notes printed by --check.
#
# BSD-2-Clause.

set -eu

ACTION=setup
EPORT=""
while [ $# -gt 1 ]; do
    case "$1" in
        --port) EPORT="$2"; shift 2 ;;
        *) break ;;
    esac
done
case "${1:-}" in
    --check)    ACTION=check ;;
    --start)    ACTION=start ;;
    --progress) ACTION=progress ;;
    "")         ACTION=setup ;;
    -h|--help)  sed -n '2,28p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
esac

REAL_HOME=$(eval echo "~${SUDO_USER:-$(id -un)}")
USER_NAME="${SUDO_USER:-$(id -un)}"
DATADIR="${BITCOIN_DATADIR:-$REAL_HOME/.bitcoin}"
DBDIR="${ELECTRS_DB:-$REAL_HOME/electrs-db}"
ETC="$REAL_HOME/.electrs"
UNIT=/etc/systemd/system/electrs.service

say() { printf '%s\n' "$*"; }

# The port of record is the one in config.toml, not a flag default. --start
# and --progress must read it, or they check a port electrs was never told
# to use and report a conflict that does not exist.
if [ -z "$EPORT" ] && [ -f "$ETC/config.toml" ]; then
    EPORT=$(grep -E '^[[:space:]]*electrum_rpc_addr' "$ETC/config.toml" \
            | sed 's/.*://; s/"//g; s/[[:space:]]//g')
fi
[ -n "$EPORT" ] || EPORT=50001

# bitcoin-cli defaults to $HOME/.bitcoin for the cookie. Under sudo, $HOME is
# /root, there is no cookie there, and every RPC call fails — so the preflight
# reported a perfectly healthy node as "not running" and refused to install.
# Always name the datadir explicitly.
bcli() { bitcoin-cli -datadir="$DATADIR" "$@"; }

# ---------------------------------------------------------------- progress

if [ "$ACTION" = progress ]; then
    if [ -d "$DBDIR" ]; then
        say "index size    $(du -sh "$DBDIR" 2>/dev/null | cut -f1)"
    else
        say "index size    not started"
    fi
    say "service       $(systemctl is-active electrs 2>/dev/null || echo inactive)"
    say ""
    say "recent log:"
    journalctl -u electrs -n 12 --no-pager 2>/dev/null | sed 's/^/  /' \
        || say "  (no journal access — try with sudo)"
    say ""
    say "When it is caught up, the tip height here should match the node:"
    say "  node  $(bcli getblockcount 2>/dev/null || echo 'not running')"
    exit 0
fi

# --------------------------------------------------------------- preflight
#
# Every check here is a way this has actually gone wrong, on this project or
# in electrs' own issue tracker.

say "=================================================================="
say "PREFLIGHT"
say "=================================================================="
FAIL=0
warn() { say "  [FAIL] $*"; FAIL=$((FAIL + 1)); }
ok()   { say "  [ok  ] $*"; }

if bcli -getinfo >/dev/null 2>&1; then
    ok "bitcoind is running"

    PRUNED=$(bcli getblockchaininfo 2>/dev/null \
             | grep -o '"pruned": *[a-z]*' | awk '{print $2}')
    if [ "$PRUNED" = "false" ]; then
        ok "node is not pruned — electrs can read the block files"
    else
        warn "NODE IS PRUNED. electrs hard-refuses a pruned node and cannot"
        say "         build an index from it. This is not recoverable here:"
        say "         you would need an unpruned node to index from."
    fi

    IBD=$(bcli getblockchaininfo 2>/dev/null \
          | grep -o '"initialblockdownload": *[a-z]*' | awk '{print $2}')
    [ "$IBD" = "false" ] && ok "node is synced" \
        || warn "node is still in initial block download — wait"

    CLEAR=$(bcli getpeerinfo 2>/dev/null \
            | grep -c '"network": *"\(ipv4\|ipv6\)"' || true)
    if [ "${CLEAR:-0}" -gt 0 ]; then
        warn "$CLEAR clearnet peer(s). Fix Tor before starting a six-hour job."
    else
        ok "no clearnet peers"
    fi
else
    warn "bitcoind is not running — electrs needs its RPC and its block files"
fi

if command -v electrs >/dev/null 2>&1; then
    ok "electrs found: $(command -v electrs)"
else
    warn "electrs is not installed"
    say ""
    say "         This script will not fetch it for you. Two honest routes:"
    say ""
    say "         Build from source (slow on a T480, nothing to verify by"
    say "         hand beyond the git remote):"
    say "           sudo apt install -y cargo clang cmake build-essential"
    say "           git clone https://github.com/romanz/electrs"
    say "           cd electrs && git checkout <a release tag>"
    say "           cargo build --locked --release"
    say "           sudo install -m0755 target/release/electrs /usr/local/bin/"
    say ""
    say "         Or take a release binary and verify its signature the same"
    say "         way you verified Core — checksums file, detached signature,"
    say "         maintainer key. Do not skip that step on the machine that"
    say "         holds your node."
fi

# A port conflict is the failure this script most obviously should have
# caught and did not: electrs binds its metrics port first, logs a cheerful
# line about it, and only then dies on the Electrum port. The log reads like
# a successful start followed by an unrelated error.
for pcheck in "$EPORT:Electrum" "4224:metrics"; do
    pnum=${pcheck%%:*}; pwhat=${pcheck##*:}
    if ss -ltn 2>/dev/null | grep -q ":$pnum "; then
        holder=$(ss -ltnp 2>/dev/null | grep ":$pnum " \
                 | sed 's/.*users:((//; s/)).*//' | head -1)
        warn "port $pnum ($pwhat) is already in use${holder:+ by $holder}"
        say "         electrs will crash-loop on this. Either stop whatever"
        say "         holds it, or choose another port:"
        say "             sudo $0 --port 50011"
        say "         Run ss -ltnp as root to see the process name."
    else
        ok "port $pnum ($pwhat) is free"
    fi
done

AVAIL=$(df -BG --output=avail "$REAL_HOME" 2>/dev/null | tail -1 | tr -dc '0-9')
if [ -n "$AVAIL" ]; then
    if [ "$AVAIL" -gt 80 ]; then
        ok "free space ${AVAIL} GB (index needs roughly 40-50 GB)"
    else
        warn "only ${AVAIL} GB free; the index needs roughly 40-50 GB"
    fi
fi

[ -d "$DATADIR/blocks" ] && ok "block files at $DATADIR/blocks" \
    || warn "no block directory at $DATADIR/blocks"
[ -f "$DATADIR/.cookie" ] && ok "RPC cookie present" \
    || warn "no .cookie in $DATADIR — electrs authenticates with it"

say ""
if [ "$FAIL" -gt 0 ]; then
    say "$FAIL check(s) failed."
    [ "$ACTION" = check ] || exit 1
else
    say "All checks passed."
fi

if [ "$ACTION" = check ]; then
    say ""
    say "Preflight only. Nothing written."
    exit 0
fi

# ------------------------------------------------------------------- start

if [ "$ACTION" = start ]; then
    [ -f "$UNIT" ] || { say "no electrs unit — run this with sudo first"; exit 1; }
    sudo systemctl start electrs
    say "started; first 40 lines of log:"
    sleep 5
    journalctl -u electrs -n 40 --no-pager | sed 's/^/  /'
    say ""
    say "Initial indexing takes hours. Watch it with:"
    say "  ./electrs_setup.sh --progress"
    exit 0
fi

# ------------------------------------------------------------------- setup

[ "$(id -u)" = 0 ] || { say "run this with sudo to write the unit"; exit 1; }

mkdir -p "$ETC" "$DBDIR"
chown -R "$USER_NAME" "$ETC" "$DBDIR"

# electrs 0.10+ fetches blocks over P2P, not only RPC, so it needs the
# node's P2P port — and this node is NOT on 8333. With onlynet=onion and
# listenonion=1, Core binds its onion-facing listener on 127.0.0.1:8334 by
# default, which is why getnetworkinfo reported port 8334 earlier. Detect it
# rather than assume: an electrs pointed at a dead port fails with a
# connection error that looks nothing like "wrong port".
P2P=$(bcli getnetworkinfo 2>/dev/null \
      | grep -o '"port": *[0-9]*' | head -1 | tr -dc '0-9')
[ -n "$P2P" ] || P2P=8334
say ""
say "detected node P2P port: $P2P"

CFG="$ETC/config.toml"
say ""
say "config  $CFG"
cat > "$CFG" <<EOF
# Written by electrs_setup.sh.
#
# electrs reads the RPC cookie out of daemon_dir, so there are no
# credentials in this file and none to rotate.
daemon_dir = "$DATADIR"
daemon_rpc_addr = "127.0.0.1:8332"
daemon_p2p_addr = "127.0.0.1:$P2P"
db_dir = "$DBDIR"
network = "bitcoin"

# Localhost only. This is an unauthenticated protocol; anything that can
# reach this port can query every address you ask about. Reach it from
# another machine with an SSH tunnel, not by binding it wider.
electrum_rpc_addr = "127.0.0.1:$EPORT"

# The dashboard polls this; keep it quiet otherwise.
log_filters = "INFO"
EOF
chown "$USER_NAME" "$CFG"
sed 's/^/  /' "$CFG"

say ""
say "unit    $UNIT"
cat > "$UNIT" <<EOF
[Unit]
Description=electrs address index
Documentation=https://github.com/romanz/electrs
Requires=bitcoind.service
After=bitcoind.service

[Service]
Type=simple
User=$USER_NAME
ExecStart=$(command -v electrs || echo /usr/local/bin/electrs) --conf $CFG
Restart=always
RestartSec=30

# Indexing is a long read over the whole chain; do not let systemd shoot it
# in the head partway through a database write.
TimeoutStopSec=600

# Same reasoning as the bitcoind lockdown: this process has no business
# talking to anything but the node on loopback. It serves wallets over an
# SSH tunnel, not over the network.
IPAddressDeny=any
IPAddressAllow=127.0.0.1/8
IPAddressAllow=::1/128

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ReadWritePaths=$DBDIR

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable electrs >/dev/null 2>&1 || true

say ""
say "=================================================================="
say "Written and enabled at boot. NOT started."
say ""
say "  ./electrs_setup.sh --start       start it and show the first log"
say "  ./electrs_setup.sh --progress    check on it"
say ""
say "Initial index: several hours, 40-50 GB. It reads the whole chain."
say ""
say "Once it is caught up, point the dashboard at it:"
say "  ./services_setup.sh --store ~/mstore --electrum 127.0.0.1:$EPORT"
say ""
say "AND THE THING TO REMEMBER: do not run prune_behind.py while you want"
say "this index. Pruning deletes the block files electrs reads, and the"
say "index cannot be rebuilt from a pruned node afterwards."
