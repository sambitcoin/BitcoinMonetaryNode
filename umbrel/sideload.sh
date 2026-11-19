#!/bin/sh
#
# sideload.sh — put the app on your own Umbrel, without a registry.
#
#   ./umbrel/sideload.sh --check       what the Umbrel is and whether it is ready
#   ./umbrel/sideload.sh --local       target THIS machine (no ssh, no Umbrel)
#   ./umbrel/sideload.sh --build       build for the Umbrel architecture
#   ./umbrel/sideload.sh --ship        copy the image over and load it
#   ./umbrel/sideload.sh --store       write the community app store on the Umbrel
#   ./umbrel/sideload.sh --run         just run the container, no app store
#   ./umbrel/sideload.sh --logs        tail the container log
#   ./umbrel/sideload.sh --stop        stop and remove it
#   ./umbrel/sideload.sh --all         all four, stopping at the first failure
#
# RUN THIS ON THE THINKPAD. It has Docker; the Mac does not, and the Umbrel
# should not. It talks to the Umbrel over ssh.
#
#   UMBREL_HOST=umbrel@umbrel.local ./umbrel/sideload.sh --all
#
# WHY SIDELOADING RATHER THAN A REGISTRY
#
# Umbrel installs apps by cloning an app store repository and running the
# compose file in it, which normally pulls an image from a registry. That is
# the right mechanism for shipping to other people and it needs a published
# package and a token.
#
# For finding out whether the app runs on umbrelOS at all, none of that is
# necessary: build the image, carry it over as a tar, load it, and point a
# local app store at the tag. Nothing is published, nobody else can install
# it, and you learn the thing you actually do not know yet.
#
# THE ARCHITECTURE TRAP
#
# Umbrel most often runs on a Raspberry Pi, which is arm64. A ThinkPad is
# amd64. An image built here will not run there, and the failure arrives as
# "exec format error" buried in a container log, long after you have stopped
# suspecting the obvious. So --check reads the Umbrel's architecture and
# --build builds for THAT, under emulation if it differs.
#
# BSD-2-Clause.

set -eu

say() { printf '%s\n' "$*"; }
die() { printf '%s\n' "$*" >&2; exit 1; }

HERE="$(cd "$(dirname "$0")/.." && pwd)"
UMBREL_HOST="${UMBREL_HOST:-umbrel@umbrel.local}"
IMAGE="${IMAGE:-monetary-node}"
TAG="${TAG:-0.1.0-alpha}"
STORE_ID="${STORE_ID:-sambitcoin}"
TARBALL="/tmp/$IMAGE-$TAG.tar"

# Every argument is an action, in the order given. The old version read
# only $1, so `--build --ship --store` silently did nothing but build and
# exited 0 looking like a success. A script that ignores two thirds of its
# arguments without complaint is worse than one that rejects them.
ACTIONS=""
if [ $# -eq 0 ]; then
    sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
fi
for arg in "$@"; do
    case "$arg" in
        --check) ACTIONS="$ACTIONS check" ;;
        # Build for THIS machine, without asking the Umbrel what it is.
        # --build needs a target architecture and --check is the only
        # thing that records one, so an Umbrel that is off or off the
        # network blocked a build that had nothing to do with it.
        --local) ACTIONS="$ACTIONS local" ;;
        --build) ACTIONS="$ACTIONS build" ;;
        --ship)  ACTIONS="$ACTIONS ship" ;;
        --store) ACTIONS="$ACTIONS store" ;;
        --run)   ACTIONS="$ACTIONS run" ;;
        --stop)  ACTIONS="$ACTIONS stop" ;;
        --logs)  ACTIONS="$ACTIONS logs" ;;
        --all)   ACTIONS="$ACTIONS check build ship store" ;;
        -h|--help)
            sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown option: $arg" ;;
    esac
done

# Refuse to run anywhere but the build machine. Running this on the Mac
# fails at `docker`; running it on the Umbrel would be sideloading onto
# itself. Both have happened on this project with other scripts.
command -v docker >/dev/null 2>&1 \
    || die "no docker here. Run this on the ThinkPad, not the Mac."

remote() { ssh "$UMBREL_HOST" "$@"; }

# Docker on the remote, with or without sudo.
#
# umbrelOS runs Docker as root and does not put the `umbrel` user in the
# docker group. Adding it would work, and would also hand that user
# root-equivalent access to the whole machine, which is a large thing to do
# to somebody's node so a build script can avoid typing a password. So: try
# plain docker, fall back to sudo, and use `ssh -t` for the sudo path so the
# password prompt has a terminal to appear on.
RDOCKER=""

detect_docker() {
    if remote "docker info >/dev/null 2>&1"; then
        RDOCKER="docker"
        return 0
    fi
    if remote "sudo -n docker info >/dev/null 2>&1"; then
        RDOCKER="sudo docker"
        return 0
    fi
    if ssh -t "$UMBREL_HOST" "sudo docker info >/dev/null" 2>/dev/null; then
        RDOCKER="sudo docker"
        return 0
    fi
    return 1
}

# Runs a docker command on the remote. Uses a tty when sudo is involved,
# because otherwise the password prompt goes nowhere and the command simply
# hangs or fails with no explanation.
rdocker() {
    case "$RDOCKER" in
        "sudo docker") ssh -t "$UMBREL_HOST" "sudo docker $*" ;;
        *)             remote "docker $*" ;;
    esac
}

# ------------------------------------------------------------------ check

ARCH_FILE=/tmp/.umbrel-arch

do_check() {
    say "=================================================================="
    say "CHECK  $UMBREL_HOST"
    say "=================================================================="

    remote true 2>/dev/null \
        || die "cannot ssh to $UMBREL_HOST.
Set UMBREL_HOST, and make sure your key is authorised there:
    ssh-copy-id $UMBREL_HOST"

    arch=$(remote uname -m | tr -d '\r\n')
    case "$arch" in
        aarch64|arm64) platform=linux/arm64 ;;
        x86_64|amd64)  platform=linux/amd64 ;;
        *) die "unrecognised architecture '$arch' on the Umbrel" ;;
    esac
    printf '%s' "$platform" > "$ARCH_FILE"
    say "  architecture   $arch  ->  $platform"

    here_arch=$(uname -m)
    if [ "$arch" != "$here_arch" ]; then
        say "  this machine   $here_arch  (different: the build will emulate)"
        if [ ! -f /proc/sys/fs/binfmt_misc/qemu-aarch64 ] \
           && [ "$platform" = linux/arm64 ]; then
            say ""
            say "  Emulation is not registered. Install it first:"
            say "      sudo apt install -y qemu-user-static binfmt-support"
            say "  Without it the build fails with 'exec format error' while"
            say "  running the self-tests, which reads like a broken image."
        fi
    else
        say "  this machine   $here_arch  (same: native build)"
    fi

    if detect_docker; then
        printf '%s' "$RDOCKER" > /tmp/.umbrel-docker
        if [ "$RDOCKER" = "docker" ]; then
            say "  docker         reachable on the Umbrel"
        else
            say "  docker         reachable via sudo (you will be asked for"
            say "                 the Umbrel password during --ship)"
        fi
    else
        die "docker is not usable over ssh on the Umbrel, with or without sudo.
Check that you can run this by hand:
    ssh $UMBREL_HOST 'sudo docker info'"
    fi

    free=$(remote "df -BG --output=avail ~ 2>/dev/null | tail -1 | tr -dc '0-9'")
    say "  free space     ${free:-unknown} GB"
    if [ -n "${free:-}" ] && [ "$free" -lt 50 ]; then
        say ""
        say "  WARNING: a genesis-to-tip store needs about 675 GiB ON TOP OF"
        say "  the blockchain. The app refuses to start a derive without"
        say "  headroom, so it will install and then decline to do anything"
        say "  until you either free space or set a later start height."
    fi

    if remote "test -d /home/umbrel/umbrel/app-stores" 2>/dev/null; then
        say "  app stores     /home/umbrel/umbrel/app-stores"
    else
        say "  app stores     not at the expected path — --store will say so"
    fi
}

# ------------------------------------------------------------------ local

# Target this machine. The architecture comes from uname, so there is no
# ssh, no Umbrel, and no emulation: a native build of exactly what is in
# the working tree.
do_local() {
    arch=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')
    printf 'linux/%s\n' "$arch" > "$ARCH_FILE"
    say "=================================================================="
    say "LOCAL  target linux/$arch (this machine), Umbrel not consulted"
    say "=================================================================="
}

# ------------------------------------------------------------------ build

do_build() {
    [ -f "$ARCH_FILE" ] || die "I do not know what to build for.
    --check  asks the Umbrel its architecture (needs it reachable)
    --local  builds for this machine"
    platform=$(cat "$ARCH_FILE")

    say ""
    say "=================================================================="
    say "BUILD  $IMAGE:$TAG  for $platform"
    say "=================================================================="
    if [ "$platform" != "linux/$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')" ]; then
        say "Emulated build. The self-tests inside the image run under QEMU,"
        say "so expect several minutes rather than seconds."
        say ""
    fi

    cd "$HERE"

    # The image embeds bitcoind, and the build will not proceed without a
    # pre-recorded SHA256 for the exact tarball. That refusal is the point:
    # a node binary that arrived from an unverified download is not a node
    # you can reason about.
    ENVFILE="$HERE/umbrel/bitcoin-release.env"
    [ -f "$ENVFILE" ] || die "no umbrel/bitcoin-release.env.

The image embeds Bitcoin Core and needs a verified hash for it. Record one:
    ./umbrel/pin_core.sh

Then read it, check it against bitcoincore.org yourself, and build again."
    # shellcheck disable=SC1090
    . "$ENVFILE"
    [ -n "${CORE_VERSION:-}" ] || die "bitcoin-release.env has no CORE_VERSION"

    # Sourcing a file means executing it, so a bad line in there is a bad
    # line in this script. One got written once — an error message where a
    # digest belonged — and the failure arrived as a shell error pointing
    # at the env file's line number, which is a confusing way to learn that
    # an image tag does not exist.
    case "${ELECTRS_IMAGE:-}" in
        "") ;;
        *@sha256:*) ;;
        *) say "  ignoring a malformed ELECTRS_IMAGE in bitcoin-release.env"
           say "  (${ELECTRS_IMAGE}) — re-run ./umbrel/pin_core.sh"
           ELECTRS_IMAGE="" ;;
    esac
    say "  bitcoind       Core $CORE_VERSION (sha256 pinned)"
    if [ -n "${ELECTRS_IMAGE:-}" ]; then
        say "  indexer        ${ELECTRS_IMAGE%%@*} (digest pinned)"
    else
        say "  indexer        NONE PINNED — wallets will not connect"
    fi

    # --load rather than --push: the whole point is that nothing is
    # published. buildx needs a builder that can load, so use the default
    # docker driver for a single platform.
    # Hash the sources going in, so the running container can prove which
    # ones they were.
    stamp=$(cat "$HERE"/tools/*.py "$HERE"/umbrel/docker-entrypoint.sh \
            2>/dev/null | sha256sum | cut -c1-12)
    say "  sources        $stamp"

    docker buildx build \
        --platform "$platform" \
        --build-arg BUILD_STAMP="$stamp" \
        -f umbrel/Dockerfile \
        --build-arg CORE_VERSION="$CORE_VERSION" \
        --build-arg CORE_SHA256_ARM64="${CORE_SHA256_ARM64:-}" \
        --build-arg CORE_SHA256_AMD64="${CORE_SHA256_AMD64:-}" \
        ${ELECTRS_IMAGE:+--build-arg ELECTRS_IMAGE="$ELECTRS_IMAGE"} \
        -t "$IMAGE:$TAG" \
        --load .

    say ""
    docker image inspect "$IMAGE:$TAG" \
        --format '  built {{.Id}}
  arch  {{.Os}}/{{.Architecture}}
  size  {{.Size}} bytes' || true
}

# ------------------------------------------------------------------- ship

do_ship() {
    docker image inspect "$IMAGE:$TAG" >/dev/null 2>&1 \
        || die "no local image $IMAGE:$TAG — run --build first"

    say ""
    say "=================================================================="
    say "SHIP"
    say "=================================================================="
    say "saving $IMAGE:$TAG"
    docker save "$IMAGE:$TAG" -o "$TARBALL"
    ls -lh "$TARBALL" | awk '{print "  " $5 "  " $9}'

    say "copying to $UMBREL_HOST (this is the slow part over wifi)"
    scp "$TARBALL" "$UMBREL_HOST:/tmp/" >/dev/null

    say "loading on the Umbrel"
    if [ -z "$RDOCKER" ]; then
        RDOCKER=$(cat /tmp/.umbrel-docker 2>/dev/null || true)
    fi
    if [ -z "$RDOCKER" ]; then
        say "  working out how to reach docker over there..."
        detect_docker || die "docker is not usable over ssh on the Umbrel.
Check this by hand:  ssh $UMBREL_HOST 'sudo docker info'"
        printf '%s' "$RDOCKER" > /tmp/.umbrel-docker
    fi
    rdocker "load -i /tmp/$(basename "$TARBALL")"
    remote "rm -f /tmp/$(basename "$TARBALL")"

    say ""
    rdocker "image inspect $IMAGE:$TAG --format '  on the Umbrel: {{.Os}}/{{.Architecture}}'"
    rm -f "$TARBALL"
}

# ------------------------------------------------------------------ store

do_store() {
    say ""
    say "=================================================================="
    say "APP STORE"
    say "=================================================================="

    # A community app store is just a directory with a manifest and one
    # directory per app. Umbrel normally clones it from git; a local one
    # works the same way once it is on disk.
    dir="/home/umbrel/umbrel/app-stores/$STORE_ID-local"
    say "writing $dir"

    # Prefer the standalone sideload manifests when they exist.
    #
    # The shipping package depends on the `bitcoin` app for its credentials,
    # its data directory and its blocks. A machine running `bitcoin-knots`
    # has no app by that id, so the dependency goes unmet and every
    # APP_BITCOIN_* interpolation comes out empty — an app that installs and
    # then cannot find a node it was never going to be given.
    #
    # docker-compose.sideload.yml runs the dashboard standalone against a
    # store already on the host. That is what this node is for.
    if [ -f "$HERE/umbrel/docker-compose.sideload.yml" ]; then
        compose_src="$HERE/umbrel/docker-compose.sideload.yml"
        say "  using the STANDALONE sideload compose (no bitcoin dependency)"
    else
        compose_src="$HERE/umbrel/docker-compose.yml"
    fi
    if [ -f "$HERE/umbrel/umbrel-app.sideload.yml" ]; then
        app_src="$HERE/umbrel/umbrel-app.sideload.yml"
    else
        app_src="$HERE/umbrel/umbrel-app.yml"
    fi

    compose=$(sed -e "s|image: ghcr.io/sambitcoin/monetary-node:.*|image: $IMAGE:$TAG|" \
                  -e "s|image: monetary-node:.*|image: $IMAGE:$TAG|" \
                  "$compose_src")

    # app-stores/ is root-owned on umbrelOS. Stage everything in /tmp over a
    # plain ssh connection, then move it into place with ONE privileged
    # command.
    #
    # The staging is not fussiness: `ssh -t` allocates a tty, and a tty
    # translates newlines and can swallow control characters, so piping a
    # YAML file through a sudo prompt corrupts it in ways that surface later
    # as a parse error in umbreld rather than an error here.
    stage="/tmp/mn-store-$$"
    remote "rm -rf '$stage' && mkdir -p '$stage/monetary-node'"
    printf 'id: %s\nname: Monetary Node (local)\n' "$STORE_ID" \
        | remote "cat > '$stage/umbrel-app-store.yml'"
    printf '%s\n' "$compose" \
        | remote "cat > '$stage/monetary-node/docker-compose.yml'"
    remote "cat > '$stage/monetary-node/umbrel-app.yml'" < "$app_src"
    if [ -f "$HERE/umbrel/icon.svg" ]; then
        remote "cat > '$stage/monetary-node/icon.svg'" < "$HERE/umbrel/icon.svg"
    fi

    if remote "test -w '$(dirname "$dir")'"; then
        remote "rm -rf '$dir' && mv '$stage' '$dir'"
    else
        say "  app-stores is root-owned; moving it into place with sudo"
        ssh -t "$UMBREL_HOST" \
            "sudo rm -rf '$dir' && sudo mv '$stage' '$dir' \
             && sudo chown -R root:root '$dir'" \
            || die "could not write $dir even with sudo"
    fi
    remote "rm -rf '$stage'" 2>/dev/null || true

    say "  wrote:"
    remote "ls -la '$dir' '$dir/monetary-node' 2>/dev/null | sed 's/^/    /'" \
        || true

    say ""
    say "  wrote the store. Umbrel will install the app as"
    say "      $STORE_ID-monetary-node"
    say ""
    say "  The compose points at the LOCAL image $IMAGE:$TAG rather than a"
    say "  registry, so Umbrel will use what you just loaded instead of"
    say "  trying to pull. That is the whole trick, and it is also why this"
    say "  store cannot be shared: on anyone else's machine the image does"
    say "  not exist."
    say ""
    say "  Next, in the umbrelOS web interface:"
    say "      App Store -> the three dots -> Community App Stores"
    say "      add:  $dir"
    say ""
    say "  If it refuses a local path and insists on a URL, the fallback is"
    say "  to push to a registry instead. Tell me and I will set that up."
}


# -------------------------------------------------------------------- run
#
# Run the container directly, with no Umbrel app framework involved.
#
# The app-store route needs umbreld to accept a community store, an
# app_proxy container, and a manifest it is happy with — three things that
# can each fail for their own reasons, none of which tell you anything about
# whether the node works. Running the image directly skips all of it. The
# tile is presentation; this is the program.
#
# What you give up: the Umbrel dashboard tile and Umbrel's own start/stop
# controls. What you keep: everything the app actually does.

CONTAINER="${CONTAINER:-monetary-node}"
WEB_PORT="${WEB_PORT:-3570}"
APPDATA="${APPDATA:-/home/umbrel/monetary-data}"
HOST_STORE="${HOST_STORE:-/home/umbrel/mstore}"
KNOTS_DIR="${KNOTS_DIR:-/home/umbrel/umbrel/app-data/bitcoin-knots/data/bitcoin}"

ensure_docker() {
    if [ -z "$RDOCKER" ]; then
        RDOCKER=$(cat /tmp/.umbrel-docker 2>/dev/null || true)
    fi
    if [ -z "$RDOCKER" ]; then
        detect_docker || die "docker is not usable over ssh on the Umbrel.
Check by hand:  ssh $UMBREL_HOST 'sudo docker info'"
        printf '%s' "$RDOCKER" > /tmp/.umbrel-docker
    fi
}

do_run() {
    ensure_docker
    say ""
    say "=================================================================="
    say "RUN  $CONTAINER"
    say "=================================================================="

    remote "test -d '$HOST_STORE'" \
        || say "  NOTE: $HOST_STORE does not exist yet. The dashboard will
  start and say so; the wallet card has nothing to index until the
  derive has written a store there."

    # The container runs as uid 1000, which is the umbrel user, so a store
    # owned by umbrel is writable without any chown.
    remote "mkdir -p '$APPDATA'"

    rdocker "rm -f $CONTAINER" >/dev/null 2>&1 || true

    # Errors from `docker run` used to go to /dev/null, so a container that
    # failed to start looked exactly like one that started: the script
    # printed nothing and carried on. Never silence the command that does
    # the work.
    say "  starting..."
    rdocker "run -d --name $CONTAINER --restart unless-stopped \
        -p $WEB_PORT:8080 -p 50001:50001 \
        -e MONETARY_DATA_DIR=/data \
        -e MONETARY_WEB_HOST=0.0.0.0 \
        -e MONETARY_WEB_PORT=8080 \
        -e MONETARY_MANAGED_BITCOIN_CONFIG=1 \
        -e MONETARY_WALLET_ADVERTISE=umbrel.local:50001 \
        -e MONETARY_WALLET_START_HEIGHT=770000 \
        -v '$APPDATA':/data \
        -v '$HOST_STORE':/data/mstore \
        -v '$KNOTS_DIR':/bitcoin:ro \
        $IMAGE:$TAG web" \
        || die "docker run failed — the error is above this line"

    sleep 4
    say ""
    out=$(rdocker "ps -a --filter name=$CONTAINER \
        --format '{{.Names}} | {{.Status}} | {{.Ports}}'" | tr -d '\r')
    if [ -z "$out" ]; then
        die "the container does not exist after docker run reported success.
Look at:  ./umbrel/sideload.sh --logs"
    fi
    say "  $out"
    case "$out" in
        *Exited*|*Created*)
            say ""
            say "  IT IS NOT RUNNING. The log says why:"
            say ""
            rdocker "logs --tail 40 $CONTAINER" || true
            die "container exited" ;;
    esac
    say ""
    say "  Dashboard:  http://umbrel.local:$WEB_PORT"
    say "  Wallets:    umbrel.local:50001   (Sparrow: Private Electrum)"
    say ""
    say "  If the page does not load, the container log says why:"
    say "      ./umbrel/sideload.sh --logs"
}

do_stop() {
    ensure_docker
    rdocker "rm -f $CONTAINER" >/dev/null 2>&1 || true
    say "stopped and removed $CONTAINER"
}

do_logs() {
    ensure_docker
    rdocker "logs --tail 60 $CONTAINER"
}

for a in $ACTIONS; do
    case "$a" in
        check) do_check ;;
        local) do_local ;;
        build) do_build ;;
        ship)  do_ship ;;
        store) do_store ;;
        run)   do_run ;;
        stop)  do_stop ;;
        logs)  do_logs ;;
    esac
done
