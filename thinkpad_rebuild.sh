#!/bin/sh
#
# thinkpad_rebuild.sh — rebuild and restart the node on THIS machine.
#
#   RUN THIS ON THE THINKPAD:
#       cd ~/monetary-node && ./thinkpad_rebuild.sh
#
# WHY THIS EXISTS
#
# umbrel_bringup.sh builds here and ships to the Umbrel. When the Umbrel
# is off, or on another network, or being reinstalled, every step of that
# script fails on ssh — including the build, which never needed the Umbrel
# at all. This is the same thing with the Umbrel removed: build the image
# from the working tree, restart the container, say whether it answered.
#
# It reuses what is already on this disk and never deletes any of it:
#
#   ~/.bitcoin      the chain. Unpruned, which the address index requires.
#   ~/mstore        the monetary store, 682 GiB, heights 0..970,000
#   ~/electrs-db    the address index, so it is not rebuilt from scratch
#
# The container is replaced; the data outlives it. Re-runnable.
#
# BSD-2-Clause.

set -eu

say()  { printf '%s\n' "$*"; }
die()  { printf '\n%s\n' "$*" >&2; exit 1; }
rule() { say "=================================================================="; }

HERE="$(cd "$(dirname "$0")" && pwd)"
IMAGE="${IMAGE:-monetary-node}"
TAG="${TAG:-0.1.0-alpha}"
CONTAINER="${CONTAINER:-monetary-node}"
WEB_PORT="${WEB_PORT:-3570}"
WALLET_PORT="${WALLET_PORT:-50001}"

# What is already on this machine. Each is reused only if it exists.
APPDATA="${APPDATA:-$HOME/monetary-data}"
HOST_STORE="${HOST_STORE:-$HOME/mstore}"
INDEX_DIR="${INDEX_DIR:-$HOME/electrs-db}"
BITCOIN_DIR="${BITCOIN_DIR:-$HOME/.bitcoin}"

MN_TOR="${MN_TOR:-1}"
MN_INDEX="${MONETARY_INDEX:-1}"
# The pruner has never run in a release configuration, and with the index
# on it cannot run anyway: electrs refuses a pruned node. Off, explicitly.
MN_PRUNE="${MONETARY_PRUNE:-0}"
NETWORK="${NETWORK:-main}"
ROLE="${ROLE:-all}"
START_HEIGHT="${START_HEIGHT:-770000}"
SKIP_BUILD="${SKIP_BUILD:-0}"

command -v docker >/dev/null 2>&1 \
    || die "no docker here. This runs on the THINKPAD, not the Mac."

# What the dashboard tells people to type into Sparrow.
#
# `hostname` returns the bare name, and the bare name resolves only on
# this machine — so the page was telling every reader to connect to an
# address that could not work from the laptop they were reading it on.
# mDNS is what makes it reachable on the LAN.
ADVERTISE="${ADVERTISE:-$(hostname)}"
case "$ADVERTISE" in
    *.*|localhost) ;;                 # already qualified, or an IP
    *) ADVERTISE="$ADVERTISE.local" ;;
esac

rule
say "MONETARY NODE — LOCAL REBUILD"
rule
say "machine  $(uname -sm)  $(hostname)"
say "tree     $HERE"

# ---------------------------------------------------------------- sources
#
# Which source files are about to go into the image. Printed because the
# most expensive failure on this project was repeatedly debugging an image
# built from an older copy of the tools than the one being edited.

if command -v sha256sum >/dev/null 2>&1; then H=sha256sum; else H="shasum -a 256"; fi
FP=$( (cd "$HERE" && cat tools/*.py umbrel/Dockerfile umbrel/docker-entrypoint.sh) \
      | $H | cut -c1-12 )
say "sources  $FP"
say ""

# ------------------------------------------------------------------ build

if [ "$SKIP_BUILD" = "1" ]; then
    say "SKIP_BUILD=1 — using the image already loaded here"
    docker image inspect "$IMAGE:$TAG" >/dev/null 2>&1 \
        || die "but there is no $IMAGE:$TAG loaded. Build it."
else
    # --local records this machine's architecture, so no part of the build
    # needs the Umbrel to be up.
    sh "$HERE/umbrel/sideload.sh" --local --build || die "build failed."
fi

# ---------------------------------------------------------------- restart

rule
say "RESTART"
rule

mkdir -p "$APPDATA"

mounts="-v $APPDATA:/data"
for pair in "$HOST_STORE:/data/mstore" "$INDEX_DIR:/data/electrs"; do
    d=${pair%%:*}
    if [ -d "$d" ]; then
        say "  reusing  $d"
        mounts="$mounts -v $pair"
    else
        say "  absent   $d  (will be created inside the app data dir)"
    fi
done

if [ -d "$BITCOIN_DIR" ]; then
    # READ-WRITE, deliberately: bitcoind writes chainstate, logs and its
    # cookie into the datadir it runs on. Read-only, it cannot start.
    say "  adopting $BITCOIN_DIR"
    ADOPT="-e MONETARY_BITCOIN_ADOPT=/bitcoin"
    mounts="$mounts -v $BITCOIN_DIR:/bitcoin"
else
    say "  no $BITCOIN_DIR — the node will sync from scratch"
    ADOPT=""
fi

# systemd's bitcoind and electrs hold the same datadir lock as the
# container and will keep it from starting. They were disabled earlier;
# say so plainly if one is back.
for unit in bitcoind electrs monetary-daemon monetary-ui; do
    if systemctl is-active --quiet "$unit" 2>/dev/null; then
        die "systemd's $unit is running and holds the datadir lock.
The container cannot start while it does:
    sudo systemctl disable --now $unit"
    fi
done

docker rm -f "$CONTAINER" >/dev/null 2>&1 || true

# shellcheck disable=SC2086
docker run -d --name "$CONTAINER" --restart unless-stopped \
    -p "$WEB_PORT":8080 -p "$WALLET_PORT":50001 \
    -e MONETARY_DATA_DIR=/data \
    -e MONETARY_WEB_HOST=0.0.0.0 \
    -e MONETARY_WEB_PORT=8080 \
    -e MONETARY_MANAGED_BITCOIN_CONFIG=1 \
    -e MONETARY_TOR="$MN_TOR" \
    -e MONETARY_PRUNE="$MN_PRUNE" \
    -e MONETARY_INDEX="$MN_INDEX" \
    -e MONETARY_NETWORK="$NETWORK" \
    -e MONETARY_WALLET_ADVERTISE="$ADVERTISE:$WALLET_PORT" \
    -e MONETARY_WALLET_START_HEIGHT="$START_HEIGHT" \
    $ADOPT $mounts "$IMAGE:$TAG" "$ROLE" >/dev/null || die "docker run failed."

say ""
say "  waiting for the dashboard..."
i=0; code=000
while [ $i -lt 60 ]; do
    sleep 2
    [ $((i % 10)) -eq 9 ] && say "  still waiting ($((i * 2))s)..."
    code=$(curl -s -o /dev/null -w '%{http_code}' \
           "http://127.0.0.1:$WEB_PORT/" 2>/dev/null || echo 000)
    [ "$code" = "200" ] && break
    i=$((i + 1))
done

# ----------------------------------------------------------------- verdict

rule
say "RESULT"
rule
say "STATUS   $(docker ps -a --filter name="$CONTAINER" --format '{{.Status}}')"
say "HTTP     $code"
say ""

# The reason for this rebuild. One i2pd, started once, still alive.
say "I2P"
starts=$(docker logs "$CONTAINER" 2>&1 | grep -c 'starting i2pd' || true)
locks=$(docker logs "$CONTAINER" 2>&1 | grep -c 'Could not lock pid file' || true)
say "  i2pd start attempts      $starts   (must be 1)"
say "  pid-lock rejections      $locks   (must be 0)"
docker logs "$CONTAINER" 2>&1 | grep -i 'i2p' | tail -6 | sed 's/^/  /' || true
say ""

if [ "$code" = "200" ] && [ "${starts:-0}" -le 1 ] && [ "${locks:-0}" -eq 0 ]; then
    say "Dashboard answering, one router, no lock fight."
    say "    http://$(hostname):$WEB_PORT/     (or http://127.0.0.1:$WEB_PORT/)"
    say ""
    say "Watch it:  docker logs -f $CONTAINER"
    exit 0
fi

say "Not right yet. The last 40 lines:"
docker logs "$CONTAINER" 2>&1 | tail -40 | sed 's/^/  /'
exit 1
