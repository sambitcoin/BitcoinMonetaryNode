#!/bin/sh
#
# umbrel_bringup.sh — bring the Monetary Node up on the Umbrel. One command.
#
#   RUN THIS ON THE THINKPAD:
#       cd ~/monetary-node && ./umbrel_bringup.sh
#
# WHY THIS EXISTS
#
# Getting the app running was taking six or seven round trips: a check, a
# build, a ship, a store write, a run, a log read — each one a separate ssh
# that stopped to ask for a password, and each one capable of failing in a
# way that only showed up two commands later.
#
# That is a tooling problem, not a hard problem. This does the whole thing
# in one go and asks for a password at most twice: once to install an ssh key
# (never again after that), and once for sudo on the Umbrel, inside a single
# privileged session rather than one per command.
#
# It is safe to re-run. Every step checks whether it is already done.
#
# WHAT IT DOES
#
#   1. installs an ssh key on the Umbrel if there is not one
#   2. confirms the image is loaded there, and ships it if not
#   3. confirms the store and derived.json exist
#   4. starts the container
#   5. proves the dashboard answers, from the Umbrel AND from here
#   6. prints one verdict
#
# BSD-2-Clause.

set -eu

say() { printf '%s\n' "$*"; }
die() { printf '\n%s\n' "$*" >&2; exit 1; }
rule() { say "=================================================================="; }

HERE="$(cd "$(dirname "$0")" && pwd)"
UMBREL_HOST="${UMBREL_HOST:-umbrel@umbrel.local}"
IMAGE="${IMAGE:-monetary-node}"
TAG="${TAG:-0.1.0-alpha}"
CONTAINER="${CONTAINER:-monetary-node}"
WEB_PORT="${WEB_PORT:-3570}"
WALLET_PORT="${WALLET_PORT:-50001}"
APPDATA="${APPDATA:-/home/umbrel/monetary-data}"
HOST_STORE="${HOST_STORE:-/home/umbrel/mstore}"
KNOTS_DIR="${KNOTS_DIR:-/home/umbrel/umbrel/app-data/bitcoin-knots/data/bitcoin}"
START_HEIGHT="${START_HEIGHT:-770000}"
# "all" is the whole node: tor, bitcoind, stripper, pruner, dashboard.
# "web" is the dashboard alone, against a store something else built.
ROLE="${ROLE:-all}"
MN_TOR="${MN_TOR:-1}"
# NETWORK=signet runs the entire lifecycle from genesis in hours, on a
# laptop, for real. It is the only way to test prune_behind before an
# alpha tester does.
NETWORK="${NETWORK:-main}"
# The address index. ON by default; MONETARY_INDEX=0 runs the node
# without it, which lets the blockchain be reclaimed behind the stripper
# and costs about one chain instead of two. No wallet can connect.
MN_INDEX="${MONETARY_INDEX:-1}"
# An address index that already exists somewhere else. Mounting it saves
# rebuilding tens of gigabytes that are already on the disk.
INDEX_DIR="${INDEX_DIR:-}"

UHOST="${UMBREL_HOST#*@}"

command -v docker >/dev/null 2>&1 \
    || die "no docker here. This runs on the THINKPAD, not the Mac and not
the Umbrel."

rule
say "MONETARY NODE -> $UMBREL_HOST"
rule

# ------------------------------------------------------- 1. ssh key
#
# Without this, every ssh below stops and waits for a password, and a script
# that pauses six times looks like a script that hung.

printf '  ssh key          '
if ssh -o BatchMode=yes -o ConnectTimeout=5 "$UMBREL_HOST" true 2>/dev/null; then
    say "already installed"
else
    say "missing"
    say ""
    say "  Installing one now. Type the UMBREL's password at the prompt."
    say "  This is the last time it will ask."
    say ""
    ssh-copy-id "$UMBREL_HOST" \
        || die "could not install the key. Is $UHOST reachable?"
    ssh -o BatchMode=yes -o ConnectTimeout=5 "$UMBREL_HOST" true 2>/dev/null \
        || die "key installed but still cannot log in without a password."
    printf '  ssh key          '
    say "installed"
fi

# ------------------------------------------------------- 2. the image
#
# Checked before anything else touches the Umbrel, because shipping 150 MB
# over wifi is the slowest step and discovering at the end that it never
# arrived is the most annoying way to find out.

# The tag never changes, so "is it there?" is the wrong question — after a
# rebuild the Umbrel still has an image by that name and it is the OLD one.
# Asking the Umbrel is also awkward: the image check needs sudo, sudo needs
# a tty, and a tty here means another password prompt.
#
# So compare image IDs, and remember locally which ID was last shipped. A
# rebuild changes the ID, which is exactly the thing that should trigger a
# ship. Delete the marker to force one.

# An image built for one CPU will not run on another. Docker prints a
# WARNING, starts the container anyway, and it dies later somewhere that
# does not mention architecture at all. Check before shipping 150 MB.
printf '  sources          '
stamp=$(cat "$HERE"/tools/*.py "$HERE"/umbrel/docker-entrypoint.sh \
        2>/dev/null | sha256sum | cut -c1-12)
img_stamp=$(docker image inspect "$IMAGE:$TAG" \
    --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null \
    | sed -n 's/^MONETARY_BUILD_STAMP=//p' | tr -d '\r\n')
if [ -n "$img_stamp" ] && [ "$img_stamp" != "$stamp" ]; then
    say "$stamp here, image has $img_stamp"
    die "The image was built from DIFFERENT sources than the ones here.

Almost always this means a fix is on the Mac and was never deployed, so the
build picked up the old files and the same bug comes back with an identical
traceback.

    On the Mac:   cd ~/monetary-node && ./deploy.sh
    Then here:    ./umbrel/sideload.sh --build
    Then:         $0"
fi
say "$stamp"

printf '  architecture     '
host_arch=$(ssh "$UMBREL_HOST" uname -m 2>/dev/null | tr -d '\r\n')
case "$host_arch" in
    aarch64|arm64) want_arch=arm64 ;;
    x86_64|amd64)  want_arch=amd64 ;;
    *)             want_arch="" ;;
esac
img_arch=$(docker image inspect "$IMAGE:$TAG" --format '{{.Architecture}}' \
           2>/dev/null || true)
if [ -n "$want_arch" ] && [ -n "$img_arch" ] \
   && [ "$want_arch" != "$img_arch" ]; then
    say "$host_arch needs $want_arch, image is $img_arch"
    die "The image was built for the wrong architecture.

Rebuild it for THIS host before shipping:
    UMBREL_HOST=$UMBREL_HOST ./umbrel/sideload.sh --check --build

--check reads the target's architecture and --build builds for it, so the
two must be run against the same host as this script."
fi
say "${host_arch:-unknown} / ${img_arch:-no local image}"

MARKER="/tmp/.mn-shipped-$UHOST-$IMAGE-$TAG"

docker image inspect "$IMAGE:$TAG" >/dev/null 2>&1 \
    || die "no local image $IMAGE:$TAG.
Build it first:   ./umbrel/sideload.sh --check --build"
local_id=$(docker image inspect "$IMAGE:$TAG" --format '{{.Id}}')
shipped_id=$(cat "$MARKER" 2>/dev/null || true)

printf '  image            '
if [ "$local_id" = "$shipped_id" ] && [ "${FORCE_SHIP:-0}" != "1" ]; then
    say "already on the Umbrel (unchanged since last run)"
else
    if [ -n "$shipped_id" ]; then
        say "REBUILT since last run — shipping the new one (slow over wifi)"
    else
        say "shipping it (slow over wifi, ~150 MB)"
    fi
    tar="/tmp/$IMAGE-$TAG.tar"
    docker save "$IMAGE:$TAG" -o "$tar"
    scp "$tar" "$UMBREL_HOST:/tmp/" >/dev/null || die "copy failed"
    rm -f "$tar"
    SHIP_TAR="/tmp/$(basename "$tar")"
    NEW_SHIP_ID="$local_id"
fi

# ------------------------------------------------------- 3. the store

printf '  store            '
if ssh "$UMBREL_HOST" "test -f '$HOST_STORE/derived.json'" 2>/dev/null; then
    range=$(ssh "$UMBREL_HOST" "cat '$HOST_STORE/derived.json'" \
        | tr -d ' \n' | sed -n 's/.*"start_height":\([0-9]*\).*"end_height":\([0-9]*\).*/\1 to \2/p')
    size=$(ssh "$UMBREL_HOST" "du -sh '$HOST_STORE' 2>/dev/null | cut -f1")
    say "$size, heights $range"
else
    say "NO derived.json at $HOST_STORE"
    say ""
    say "  The app will still start and the dashboard will load, but the"
    say "  wallet card will have nothing to index. Continuing."
fi

# ------------------------------------------------------- 4. run it
#
# Everything privileged happens inside ONE remote script, run under one
# sudo. Previously each docker command was its own ssh and its own password
# prompt, which is where most of the friction came from.

remote_script=$(mktemp)
trap 'rm -f "$remote_script"' EXIT
cat > "$remote_script" <<REMOTE
#!/bin/sh
set -u
IMAGE="$IMAGE"; TAG="$TAG"; CONTAINER="$CONTAINER"
WEB_PORT="$WEB_PORT"; WALLET_PORT="$WALLET_PORT"
APPDATA="$APPDATA"; HOST_STORE="$HOST_STORE"; KNOTS_DIR="$KNOTS_DIR"
START_HEIGHT="$START_HEIGHT"
SHIP_TAR="${SHIP_TAR:-}"
ROLE="${ROLE:-all}"
MN_TOR="${MN_TOR:-1}"
NETWORK="${NETWORK:-main}"
MN_INDEX="${MONETARY_INDEX:-1}"
INDEX_DIR="${INDEX_DIR:-}"

if [ -n "\$SHIP_TAR" ] && [ -f "\$SHIP_TAR" ]; then
    echo "  loading the image..."
    docker load -i "\$SHIP_TAR" >/dev/null || exit 11
    rm -f "\$SHIP_TAR"
fi

# The container runs as uid 1000, which is the umbrel user.
mkdir -p "\$APPDATA"
chown 1000:1000 "\$APPDATA" 2>/dev/null || true

docker rm -f "\$CONTAINER" >/dev/null 2>&1

mounts="-v \$APPDATA:/data"
if [ "\$NETWORK" = "main" ] && [ -d "\$HOST_STORE" ]; then
    mounts="\$mounts -v \$HOST_STORE:/data/mstore"
fi
if [ -n "\$INDEX_DIR" ] && [ -d "\$INDEX_DIR" ]; then
    echo "  reusing the existing address index at \$INDEX_DIR"
    mounts="\$mounts -v \$INDEX_DIR:/data/electrs"
fi
if [ "\$NETWORK" != "main" ]; then
    # Adopting a mainnet datadir while running signet would create a
    # signet chain directory inside the Bitcoin app's folder. Harmless but
    # confusing, and the blocks there are no use to another chain anyway.
    echo "  network \$NETWORK: not adopting the mainnet datadir"
    mounts="\$mounts"
    ADOPT=""
elif [ -d "\$KNOTS_DIR" ]; then
    # READ-WRITE, deliberately. bitcoind owns a datadir it runs on: it
    # writes chainstate, logs and its cookie there. Mounted read-only it
    # cannot start at all.
    #
    # The blocks themselves are only ever appended to or pruned, and
    # pruning waits for both the stripper and the index. The Knots app is
    # stopped, so nothing else is writing here.
    mounts="\$mounts -v \$KNOTS_DIR:/bitcoin"
    ADOPT="-e MONETARY_BITCOIN_ADOPT=/bitcoin"
else
    ADOPT=""
fi

echo "  starting the container..."
# shellcheck disable=SC2086
docker run -d --name "\$CONTAINER" --restart unless-stopped \
    -p "\$WEB_PORT":8080 -p "\$WALLET_PORT":50001 \
    -e MONETARY_DATA_DIR=/data \
    -e MONETARY_WEB_HOST=0.0.0.0 \
    -e MONETARY_WEB_PORT=8080 \
    -e MONETARY_MANAGED_BITCOIN_CONFIG=1 \
    -e MONETARY_TOR="\$MN_TOR" \
    -e MONETARY_PRUNE=1 \
    -e MONETARY_INDEX="\$MN_INDEX" \
    -e MONETARY_NETWORK="\$NETWORK" \
    -e MONETARY_ALLOW_TEST_NETWORKS=1 \
    -e MONETARY_WALLET_ADVERTISE="$UHOST:\$WALLET_PORT" \
    -e MONETARY_WALLET_START_HEIGHT="\$START_HEIGHT" \
    \$ADOPT \$mounts "\$IMAGE:\$TAG" "\$ROLE" || exit 12

# Give it a moment, then find out whether it is actually serving rather
# than merely existing. "Up" is not the same as "answering".
# 40 seconds was not enough. Tor bootstrap, bitcoind opening its
# databases and the dashboard's first poll all happen before anything
# answers, and on a cold start that can exceed it — so a healthy node was
# being reported as a failure. Wait longer, and show progress while
# waiting rather than sitting silent.
i=0
code=000
while [ \$i -lt 60 ]; do
    sleep 2
    [ \$((i % 10)) -eq 9 ] && echo "  still waiting (\$((i * 2))s)..."
    code=\$(curl -s -o /dev/null -w '%{http_code}' \
           "http://127.0.0.1:\$WEB_PORT/" 2>/dev/null || echo 000)
    [ "\$code" = "200" ] && break
    i=\$((i + 1))
done

echo ""
echo "STATUS   \$(docker ps -a --filter name=\$CONTAINER \
    --format '{{.Status}} | {{.Ports}}')"
echo "HTTP     \$code  (from the Umbrel itself)"

if [ "\$code" != "200" ]; then
    echo ""
    echo "---- container log (last 80) ----"
    docker logs --tail 80 "\$CONTAINER" 2>&1
    echo "---- is anything listening inside? ----"
    docker exec "\$CONTAINER" sh -c \
        'ss -ltnp 2>/dev/null || netstat -ltnp 2>/dev/null || true' 2>&1 \
        | head -20
    exit 13
fi
exit 0
REMOTE

say ""
say "  Running the privileged part. Type the UMBREL's password once."
say ""
scp -q "$remote_script" "$UMBREL_HOST:/tmp/mn-bringup.sh"
set +e
# `sudo sh script; rm -f script` returns rm's status, not the
# script's. Every failure on the far end arrived here as success,
# and this printed RUNNING over a container that never started.
ssh -t "$UMBREL_HOST" "sudo sh /tmp/mn-bringup.sh"
rc=$?
ssh "$UMBREL_HOST" "rm -f /tmp/mn-bringup.sh" 2>/dev/null || true
set -e

# Only record the shipped ID once the container actually came up on it.
if [ "${rc:-1}" -eq 0 ] && [ -n "${NEW_SHIP_ID:-}" ]; then
    printf '%s' "$NEW_SHIP_ID" > "$MARKER"
fi

say ""
rule
if [ "$rc" -ne 0 ]; then
    say "FAILED (exit $rc)"
    rule
    case "$rc" in
        11) say "The image would not load on the Umbrel." ;;
        12) say "docker run failed. The error is above."
            say ""
            say "If it says 'address already in use', something else owns"
            say "that port — an electrs you already run, most likely."
            say "Pick free ones:"
            say "    WEB_PORT=3571 WALLET_PORT=50021 $0" ;;
        13) say "The container started but never answered on port $WEB_PORT.
The last 40 log lines are above and will say why." ;;
        *)  say "See the output above." ;;
    esac
    exit "$rc"
fi

# ------------------------------------------------------- 5. from here too
#
# The Umbrel answering itself does not mean you can reach it. Those are
# different failures with different fixes, and they look identical in a
# browser.

printf '  from this machine  '
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 \
       "http://$UHOST:$WEB_PORT/" 2>/dev/null || echo 000)
if [ "$code" = "200" ]; then
    say "HTTP 200"
else
    say "HTTP $code"
fi

say ""
say "RUNNING"
rule
say ""
say "  Dashboard   http://$UHOST:$WEB_PORT"
say "  Wallets     $UHOST:$WALLET_PORT    (Sparrow: Private Electrum, SSL off)"
say ""
if [ "$code" != "200" ]; then
    say "  The host answers itself but this machine cannot reach it, so"
    say "  the app is fine and the path between them is not. Try the Pi's IP"
    say "  instead of $UHOST — mDNS names fail on some networks:"
    say "      ssh $UMBREL_HOST hostname -I"
    say ""
fi
say "  Node will show as unreachable: this container has no bitcoind, by"
say "  design. The wallet card is the part to try."
say ""
say "  Logs:     ssh $UMBREL_HOST 'sudo docker logs -f $CONTAINER'"
say "  Stop:     ssh $UMBREL_HOST 'sudo docker rm -f $CONTAINER'"
say "  Re-run:   ./umbrel_bringup.sh"
say "  Reship:   FORCE_SHIP=1 ./umbrel_bringup.sh"
