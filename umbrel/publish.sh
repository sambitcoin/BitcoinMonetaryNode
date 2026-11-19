#!/bin/sh
#
# publish.sh — push the image to ghcr.io and pin its DIGEST.
#
#   RUN THIS ON THE THINKPAD:
#       cd ~/monetary-node && ./umbrel/publish.sh
#
# WHY A DIGEST
#
# Umbrel requires the compose file to name an image by digest, not by
# tag. A tag is a label someone can move: a user installing next month
# would get whatever `0.1.0-alpha` points at then, which may not be what
# anyone reviewed. A digest is the hash of the image itself — it either
# matches or it is a different image, and there is no third answer.
#
# So this script does not stop at pushing. It reads back the digest the
# registry assigned, checks it looks like a digest, and rewrites
# docker-compose.yml to pin it. A push without that rewrite is half a
# publish and the half that is missing is the one that matters.
#
# WHAT IT NEEDS
#
#   A GitHub personal access token with write:packages, in GHCR_TOKEN or
#   typed at the prompt. The token is passed to docker on stdin and is
#   never written to a file or echoed.
#
# BSD-2-Clause.

set -eu

say()  { printf '%s\n' "$*"; }
die()  { printf '\n%s\n' "$*" >&2; exit 1; }
rule() { say "=================================================================="; }

HERE="$(cd "$(dirname "$0")/.." && pwd)"
OWNER="${OWNER:-sambitcoin}"
IMAGE="${IMAGE:-monetary-node}"
TAG="${TAG:-0.1.0-alpha}"
REGISTRY="${REGISTRY:-ghcr.io}"
REMOTE="$REGISTRY/$OWNER/$IMAGE"
PLATFORMS="${PLATFORMS:-linux/amd64,linux/arm64}"
COMPOSE="$HERE/umbrel/docker-compose.yml"
DRY="${DRY_RUN:-0}"

# --pin-only: the image is already in the registry, only the pin is
# missing. This exists because a push succeeded and the pinning step
# failed afterwards, and re-pushing an identical image to recover from a
# text-parsing bug is thirty seconds of network for no reason.
PIN_ONLY=0
for arg in "$@"; do
    case "$arg" in
        --pin-only) PIN_ONLY=1 ;;
        -h|--help) sed -n '2,28p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown option: $arg" ;;
    esac
done

command -v docker >/dev/null 2>&1 || die "no docker here."
[ -f "$COMPOSE" ] || die "no $COMPOSE"

rule
say "PUBLISH  $REMOTE:$TAG"
rule
say "platforms  $PLATFORMS"
say "compose    $COMPOSE"

# ------------------------------------------------------------- refuse junk
#
# Publishing is the one step that is hard to take back: once a digest is
# pulled by somebody it exists on their disk whatever happens here. So
# the release gate runs first, and a failure stops the push.

if [ "$PIN_ONLY" = "1" ]; then
    say ""
    say "--pin-only: not building, not pushing. Reading the digest that"
    say "is already in the registry and writing the pin."
fi

say ""
say "running release_check.sh first..."
if ! out=$(cd "$HERE" && sh ./release_check.sh 2>&1); then
    printf '%s\n' "$out" | grep -E 'FAIL|MISSING|SYNTAX|failed' | sed 's/^/  /'
    die "release check failed. Not publishing."
fi
say "  release check passed"

# Uncommitted edits mean the image will not match any commit, so nobody
# — including you in a month — can say what is in it.
if command -v git >/dev/null 2>&1 && [ -d "$HERE/.git" ]; then
    if [ -n "$(cd "$HERE" && git status --porcelain 2>/dev/null)" ]; then
        say ""
        say "WARNING: the working tree has uncommitted changes."
        say "The published image will not correspond to any commit."
        printf "  continue anyway? [y/N] "
        read -r ans
        case "$ans" in y|Y|yes) ;; *) die "stopped." ;; esac
    fi
    COMMIT=$(cd "$HERE" && git rev-parse --short HEAD 2>/dev/null || echo none)
else
    COMMIT=none
fi
say "  commit     $COMMIT"

# ------------------------------------------------------------------- login

if [ "$DRY" = "1" ]; then
    say ""
    say "DRY_RUN=1 — not logging in, not pushing."
else
    if [ -z "${GHCR_TOKEN:-}" ]; then
        say ""
        say "A GitHub token with write:packages is needed."
        say "Create one at https://github.com/settings/tokens"
        printf "  token (not echoed): "
        stty -echo 2>/dev/null || true
        read -r GHCR_TOKEN
        stty echo 2>/dev/null || true
        printf '\n'
    fi
    [ -n "$GHCR_TOKEN" ] || die "no token; nothing to log in with."
    printf '%s' "$GHCR_TOKEN" \
        | docker login "$REGISTRY" -u "$OWNER" --password-stdin >/dev/null \
        || die "login to $REGISTRY failed."
    GHCR_TOKEN=""
    say "  logged in to $REGISTRY as $OWNER"
fi

# -------------------------------------------------------------- build/push
#
# Multi-arch, because Umbrel runs on both a Raspberry Pi (arm64) and
# x86 mini PCs, and one digest has to serve both. buildx emits a manifest
# list covering every platform; that list's digest is what gets pinned.

ENVFILE="$HERE/umbrel/bitcoin-release.env"
[ -f "$ENVFILE" ] || [ "$PIN_ONLY" = "1" ] \
    || die "no umbrel/bitcoin-release.env — run ./umbrel/pin_core.sh"
# shellcheck disable=SC1090
[ -f "$ENVFILE" ] && . "$ENVFILE"

say ""
rule
[ "$PIN_ONLY" = "1" ] && say "PIN ONLY" || say "BUILD AND PUSH"
rule

if [ "$PIN_ONLY" != "1" ] && ! docker buildx inspect mnbuilder >/dev/null 2>&1; then
    say "  creating a container-backed builder (needed for multi-arch)"
    docker buildx create --name mnbuilder --driver docker-container >/dev/null
fi

set -- \
    --builder mnbuilder \
    --platform "$PLATFORMS" \
    -f umbrel/Dockerfile \
    --build-arg BUILD_STAMP="$(date -u '+%Y-%m-%dT%H:%M:%SZ') $COMMIT" \
    --build-arg CORE_VERSION="$CORE_VERSION" \
    --build-arg CORE_SHA256_ARM64="${CORE_SHA256_ARM64:-}" \
    --build-arg CORE_SHA256_AMD64="${CORE_SHA256_AMD64:-}" \
    -t "$REMOTE:$TAG"
[ -n "${ELECTRS_IMAGE:-}" ] && set -- "$@" --build-arg ELECTRS_IMAGE="$ELECTRS_IMAGE"

cd "$HERE"
if [ "$DRY" = "1" ]; then
    say "  DRY_RUN: would build $PLATFORMS and push $REMOTE:$TAG"
    DIGEST="sha256:0000000000000000000000000000000000000000000000000000000000000000"
else
    [ "$PIN_ONLY" = "1" ] || docker buildx build "$@" --push . \
        || die "build/push failed."

    # Read the digest BACK FROM THE REGISTRY rather than from the build
    # output. The build prints one too, but what matters is what the
    # registry will serve to a user pulling it — those are the same thing
    # right up until they are not, and this is not an assumption worth
    # making in the one step that is hard to undo.
    #
    # Parse the human output FIRST. --format is the tidier way to ask and
    # it is not supported by every buildx: the version on this machine
    # ignores the template and prints the whole inspect block, which was
    # then taken for a digest. It failed safe only because the shape
    # check caught it. Asking in the way that works everywhere, and
    # treating the template as the fallback, is the right way round.
    inspect=$(docker buildx imagetools inspect "$REMOTE:$TAG" 2>/dev/null) \
        || die "could not inspect $REMOTE:$TAG — was it pushed?"
    # The FIRST Digest: line is the manifest list's own digest, which is
    # what covers every platform. The per-platform digests below it are
    # one architecture each: pinning one of those would ship an app that
    # installs on amd64 and not on arm64, or the reverse.
    DIGEST=$(printf '%s\n' "$inspect" | awk '/^Digest:/{print $2; exit}')
    if [ -z "$DIGEST" ]; then
        DIGEST=$(docker buildx imagetools inspect "$REMOTE:$TAG" \
                 --format '{{.Manifest.Digest}}' 2>/dev/null | tr -d '[:space:]')
    fi
fi

# pin_core.sh once wrote docker's error message into a file as if it were
# a digest. Check the shape before it goes anywhere near the compose file.
case "$DIGEST" in
    sha256:*) ;;
    *) die "did not get a digest back; got: ${DIGEST:-nothing}" ;;
esac
[ "${#DIGEST}" -eq 71 ] || die "digest is the wrong length: $DIGEST"

say ""
say "  digest  $DIGEST"

# ------------------------------------------------------------------- pin

say ""
rule
say "PIN"
rule

PINNED="$REMOTE@$DIGEST"
if [ "$DRY" = "1" ]; then
    say "  DRY_RUN: would pin $PINNED"
else
    cp "$COMPOSE" "$COMPOSE.bak"
    # Replace the whole image line, whether it currently names a tag or an
    # older digest.
    awk -v pin="$PINNED" '
        /^[[:space:]]*image:[[:space:]]/ && !done {
            match($0, /^[[:space:]]*/)
            printf "%simage: %s\n", substr($0, 1, RLENGTH), pin
            done = 1
            next
        }
        { print }
    ' "$COMPOSE.bak" > "$COMPOSE"
    grep -q "$DIGEST" "$COMPOSE" || {
        mv "$COMPOSE.bak" "$COMPOSE"
        die "could not write the pin; compose file restored unchanged."
    }
    rm -f "$COMPOSE.bak"
    say "  docker-compose.yml now pins the digest"
fi

say ""
rule
say "DONE"
rule
say "image   $PINNED"
say "commit  $COMMIT"
say ""
say "Next:"
say "  1. make the package public — GitHub › Packages › $IMAGE › settings"
say "     (a private package installs as 'image not found' with no hint why)"
say "  2. copy the pinned docker-compose.yml into the app store repo"
say "  3. commit the pin here too, so the tree matches what was published"
