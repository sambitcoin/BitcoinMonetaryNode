#!/bin/sh
#
# docker-entrypoint.sh — bring a monetary node up inside a container.
#
#   docker-entrypoint.sh web       the dashboard
#   docker-entrypoint.sh daemon    follow the tip, stripping as it goes
#   docker-entrypoint.sh derive    one-time batch derive, then exit
#
# This replaces services_setup.sh, tor_setup.sh and tor_lockdown.sh. The
# platform owns networking and Tor; three scripts that configured systemd and
# a kernel packet filter have no equivalent here, and pretending otherwise
# would be worse than dropping them. What this does instead is refuse to
# start when the things it depends on are not true.
#
# WHAT IT CHECKS BEFORE DOING ANYTHING
#
#   - bitcoind is reachable and out of initial block download
#   - the block files are present and readable, for a derive
#   - there is enough free space for the store this will build
#
# The disk check is the one that matters most. A genesis-to-tip monetary
# store is about 675 GB ON TOP OF the 720 GB of blocks it is derived from.
# Filling the drive underneath a running bitcoind is a far worse outcome than
# an app that declines to start, so this declines to start.
#
# BSD-2-Clause.

set -eu

say() { printf '%s\n' "$*"; }
die() { printf '%s\n' "$*" >&2; exit 1; }

ROLE="${1:-web}"

DATA="${MONETARY_DATA_DIR:-/data}"
STORE="$DATA/mstore"
MCONF="$DATA/monetary.conf"
CACHE="$DATA/index-cache"
BITCOIN_DIR="${MONETARY_BITCOIN_DIR:-/bitcoin}"

RPC_HOST="${APP_BITCOIN_NODE_IP:-127.0.0.1}"
RPC_PORT="${APP_BITCOIN_RPC_PORT:-8332}"
RPC_USER="${APP_BITCOIN_RPC_USER:-}"
RPC_PASS="${APP_BITCOIN_RPC_PASS:-}"

# Cookie authentication, for a node that does not use rpcuser/rpcpassword.
#
# Umbrel supplies credentials in the environment, so that is the default. An
# ordinary Bitcoin Core install authenticates with a .cookie file instead,
# which is what you have when testing this container against a real node
# rather than against the platform. Without this the app can only ever be
# tested inside the thing it is being built for, which is the wrong order.
RPC_COOKIE="${MONETARY_RPC_COOKIE:-}"
if [ -n "$RPC_COOKIE" ]; then
    [ -r "$RPC_COOKIE" ] || die "cannot read the RPC cookie at $RPC_COOKIE.
Mount it into the container and make sure the container user can read it."
    RPC_USER=$(cut -d: -f1 "$RPC_COOKIE")
    RPC_PASS=$(cut -d: -f2- "$RPC_COOKIE")
    say "  auth   cookie"
else
    say "  auth   rpcuser"
fi

START_HEIGHT="${MONETARY_START_HEIGHT:-0}"
DEPTH="${MONETARY_DEPTH:-6}"
WEB_PORT="${MONETARY_WEB_PORT:-8080}"
# 0.0.0.0 is correct inside Umbrel: the container has its own network and the
# app proxy is the only thing that can reach it. It is wrong for a test run
# with --network host, where it puts the dashboard on the LAN. Configurable
# so the test can be loopback-only without the package losing its default.
WEB_HOST="${MONETARY_WEB_HOST:-0.0.0.0}"
# Refuse to begin a derive without this much headroom, in GB. A genesis store
# needs ~675; the default is deliberately generous because the cost of being
# wrong is the user's node, not this app.
MIN_FREE_GB="${MONETARY_MIN_FREE_GB:-80}"


mkdir -p "$STORE" "$CACHE"

# ------------------------------------------------------------------ rpc

rpc() {
    # The request body is built inside Python rather than piped in.
    #
    # It WAS piped in, to a `python3 -` reading its program from a heredoc —
    # and `python3 -` takes its program from stdin, so the heredoc won that
    # argument and the piped JSON was thrown away. Every call sent an empty
    # body, the node rejected it, and every check in this file reported
    # "bitcoind unreachable" no matter what the node was doing. Found by
    # pointing it at a fake bitcoind instead of trusting it.
    #
    # Credentials go in argv, not the URL, so they stay out of any log that
    # records the request line.
    python3 -c '
import base64, json, sys, urllib.request
host, port, user, pw, method = sys.argv[1:6]
body = json.dumps({"jsonrpc": "1.0", "id": "e",
                   "method": method, "params": []}).encode()
req = urllib.request.Request(
    "http://%s:%s/" % (host, port), data=body,
    headers={"Content-Type": "application/json",
             "Authorization": "Basic " + base64.b64encode(
                 ("%s:%s" % (user, pw)).encode()).decode()})
try:
    with urllib.request.urlopen(req, timeout=20) as r:
        out = json.loads(r.read())
except Exception:
    sys.exit(1)
if out.get("error"):
    sys.exit(1)
print(json.dumps(out["result"]))
' "$RPC_HOST" "$RPC_PORT" "$RPC_USER" "$RPC_PASS" "$1"
}

wait_for_bitcoind() {
    say "waiting for bitcoind at $RPC_HOST:$RPC_PORT"
    n=0
    while [ "$n" -lt 120 ]; do
        if rpc getblockcount >/dev/null 2>&1; then
            say "  reachable"
            return 0
        fi
        n=$((n + 1))
        sleep 5
    done
    die "bitcoind did not answer in 10 minutes.
The Bitcoin app must be installed, running and past initial block download.
This app reads it over RPC and cannot do anything without it."
}

check_synced() {
    info=$(rpc getblockchaininfo) || die "cannot read getblockchaininfo"
    ibd=$(printf '%s' "$info" | python3 -c \
        'import json,sys;print(json.load(sys.stdin)["initialblockdownload"])')
    chain=$(printf '%s' "$info" | python3 -c \
        'import json,sys;print(json.load(sys.stdin)["chain"])')
    pruned=$(printf '%s' "$info" | python3 -c \
        'import json,sys;print(json.load(sys.stdin)["pruned"])')
    say "  chain $chain · pruned $pruned · ibd $ibd"
    [ "$chain" = "main" ] || die "this app is for mainnet; the node says $chain"
    if [ "$ibd" = "True" ]; then
        die "The Bitcoin node is still in initial block download.
Let it finish first. Deriving from a chain that is still arriving produces a
store whose commitment nobody else can reproduce."
    fi
    if [ "$pruned" = "True" ]; then
        die "The Bitcoin node is pruned, so the historical blocks this derives
from are gone. A monetary store cannot be built from a pruned node."
    fi
}

free_gb() {
    df -BG "$DATA" 2>/dev/null | awk 'NR==2 {gsub(/G/,"",$4); print $4}'
}

# --------------------------------------------------------------- bootstrap

derive() {
    [ -d "$BITCOIN_DIR/blocks" ] \
        || die "no block files at $BITCOIN_DIR/blocks.
The one-time derive reads them directly; following the tip afterwards needs
only RPC. Mount the Bitcoin data directory read-only."

    avail=$(free_gb)
    say "free space  ${avail:-unknown} GB"
    if [ -n "${avail:-}" ] && [ "$avail" -lt "$MIN_FREE_GB" ]; then
        die "Only ${avail} GB free, and this needs at least ${MIN_FREE_GB} GB
to begin.

A genesis-to-tip monetary store is about 675 GB, ON TOP OF the ~720 GB of
blocks it is derived from. Filling the drive under a running bitcoind would
damage the node this app depends on, so it will not start.

Two ways forward:
  - give the drive more room, or
  - set MONETARY_START_HEIGHT to a recent height. A store that begins later
    is much smaller, still verifies every block it holds, and still follows
    the tip. It simply cannot speak to the history below where it starts."
    fi

    tip=$(rpc getblockcount) || die "cannot read getblockcount"
    end=$((tip - DEPTH))
    [ "$end" -gt "$START_HEIGHT" ] \
        || die "nothing to derive: tip $tip, start $START_HEIGHT"

    say ""
    say "=================================================================="
    say "ONE-TIME DERIVE  heights $START_HEIGHT .. $end"
    say "=================================================================="
    say "This reads every block in range and writes the filtered store."
    say "Genesis to tip took 8h43m on an NVMe laptop. It is disk-bound, it"
    say "resumes nothing, and it must not be interrupted."
    say ""

    python3 /app/tools/monetary_store.py \
        --blocks "$BITCOIN_DIR/blocks" \
        --start "$START_HEIGHT" --end "$end" \
        --out "$STORE" \
        --index-cache "$CACHE/mstore_index"

    [ -f "$STORE/derived.json" ] \
        || die "the derive did not write derived.json, so it did not verify.
Refusing to adopt a store that failed its own check."

    say ""
    say "adopting the store"
    python3 /app/tools/monetary_daemon.py --store "$STORE" \
        --adopt --start-height "$START_HEIGHT"
}

# -------------------------------------------------------------------- main

say "monetary node · role $ROLE · sources ${MONETARY_BUILD_STAMP:-unknown}"
say "  data   $DATA"
say "  store  $STORE"

case "$ROLE" in
web)
    # The dashboard does not need bitcoind to be up — a dashboard that
    # refuses to load because the node is down cannot tell you the node is
    # down. It reports what it finds.
    # Authentication has to reach the dashboard, not just this script.
    #
    # The entrypoint resolved the cookie for its own preflight checks and
    # then launched the UI without telling it anything, so the UI fell back
    # to a default cookie path that does not exist in the container and
    # reported "no RPC credentials". Found by looking at the running page.
    if [ -n "$RPC_COOKIE" ]; then
        set -- --cookie "$RPC_COOKIE"
    else
        set -- --rpc-user "$RPC_USER" --rpc-password "$RPC_PASS"
    fi
    # The Electrum port. This binds 0.0.0.0 inside the container because a
    # wallet runs on a phone or a laptop, not in here; whether it is reachable
    # from the LAN is decided by the compose file publishing the port, which
    # is the layer that should decide it.
    #
    # MONETARY_WALLET_ADVERTISE is what the dashboard prints for people to
    # type into Sparrow. The container cannot discover the host's LAN name,
    # so the packaging passes it; without it the page says "this node's IP
    # address" rather than inventing one.
    set -- "$@" --wallet-port "${MONETARY_WALLET_PORT:-50001}" \
                --wallet-host "${MONETARY_WALLET_HOST:-0.0.0.0}"
    if [ -n "${MONETARY_WALLET_START_HEIGHT:-}" ]; then
        set -- "$@" --wallet-start-height "$MONETARY_WALLET_START_HEIGHT"
    fi
    if [ "${MONETARY_WALLET:-1}" = "0" ]; then
        set -- "$@" --no-wallet
    fi
    # Standalone: no bitcoind attached and none expected. Without this the
    # dashboard reports the absent node as a PROBLEM in red, which on a
    # wallet-serving instance describes a working node as broken.
    if [ "${MONETARY_NO_NODE:-0}" = "1" ]; then
        set -- "$@" --no-node
    fi

    exec python3 /app/tools/monetary_ui.py \
        --store "$STORE" \
        --monetary-conf "$MCONF" \
        --conf "$BITCOIN_DIR/bitcoin.conf" \
        --rpc-url "http://$RPC_HOST:$RPC_PORT" \
        "$@" \
        --managed-bitcoin-config \
        --host "$WEB_HOST" --port "$WEB_PORT" \
        --i-understand-this-exposes-node-state
    ;;

all)
    # The whole node, as one process tree: tor, bitcoind, the stripper, the
    # pruner and the dashboard. This is the role the app runs. Everything
    # else below is for taking a piece apart by hand.
    say "starting a full monetary node"
    set --
    [ "${MONETARY_TOR:-1}" = "0" ] && set -- "$@" --no-tor
    [ "${MONETARY_PRUNE:-1}" = "0" ] && set -- "$@" --no-prune
    [ -n "${MONETARY_WALLET_ADVERTISE:-}" ] \
        && set -- "$@" --wallet-advertise "$MONETARY_WALLET_ADVERTISE"
    [ "${MONETARY_INDEX:-1}" = "0" ] && set -- "$@" --no-index
    # MAINNET ONLY.
    #
    # The app ships for Bitcoin and nothing else. A test chain reachable
    # by setting one variable is a way for somebody to end up running a
    # node that looks real, shows balances, and is worth nothing — and
    # then to tell other people their balance.
    #
    # Test networks are still how this gets developed, so they are
    # available, but only to somebody who has deliberately unlocked them.
    if [ -n "${MONETARY_NETWORK:-}" ] && [ "$MONETARY_NETWORK" != "main" ]; then
        if [ "${MONETARY_ALLOW_TEST_NETWORKS:-0}" != "1" ]; then
            die "MONETARY_NETWORK=$MONETARY_NETWORK, but this app is
mainnet only. A test chain shows balances that are not real bitcoin.

If you are developing and mean it, also set
    MONETARY_ALLOW_TEST_NETWORKS=1"
        fi
        say "TEST NETWORK: $MONETARY_NETWORK — balances here are not real"
        set -- "$@" --network "$MONETARY_NETWORK"
    fi
    # An existing datadir, if one was mounted. Without this a first run
    # downloads the whole chain again over Tor — weeks, on hardware that
    # already has the blocks sitting on the same disk.
    if [ -n "${MONETARY_BITCOIN_ADOPT:-}" ]; then
        set -- "$@" --bitcoin-dir "$MONETARY_BITCOIN_ADOPT"
    fi
    # Where the store begins on a FIRST run. The daemon refuses to guess,
    # and it is right to: guessing wrong produces a store whose records
    # are all at the wrong heights, which verifies against nothing.
    set -- "$@" --start-height "${MONETARY_START_HEIGHT:-0}"
    exec python3 /app/tools/monetary_supervisor.py --run \
        --data "$DATA" \
        --rpc-port "${MONETARY_RPC_PORT:-8332}" \
        --web-host "${MONETARY_WEB_HOST:-0.0.0.0}" \
        --web-port "${WEB_PORT:-8080}" \
        --wallet-port "${MONETARY_WALLET_PORT:-50001}" \
        --depth "${MONETARY_DEPTH:-6}" \
        "$@"
    ;;

derive)
    wait_for_bitcoind
    check_synced
    derive
    say "derive complete"
    ;;

daemon)
    wait_for_bitcoind
    check_synced

    if [ ! -f "$STORE/state.json" ]; then
        say ""
        say "no store yet — deriving before following the tip"
        derive
    fi

    say ""
    say "following the tip, $DEPTH blocks behind"
    # Pass the cookie path through rather than the credentials read from it:
    # the daemon runs for weeks and a cookie is regenerated when bitcoind
    # restarts, so a value captured at startup goes stale while a path does
    # not.
    if [ -n "$RPC_COOKIE" ]; then
        exec python3 /app/tools/monetary_daemon.py \
            --store "$STORE" \
            --rpc-host "$RPC_HOST" --rpc-port "$RPC_PORT" \
            --rpc-cookie "$RPC_COOKIE" \
            --depth "$DEPTH"
    fi
    exec python3 /app/tools/monetary_daemon.py \
        --store "$STORE" \
        --rpc-host "$RPC_HOST" --rpc-port "$RPC_PORT" \
        --rpc-user "$RPC_USER" --rpc-password "$RPC_PASS" \
        --depth "$DEPTH"
    ;;

*)
    die "unknown role '$ROLE'. Expected web, daemon or derive."
    ;;
esac
