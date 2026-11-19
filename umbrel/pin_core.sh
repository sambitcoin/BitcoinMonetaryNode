#!/bin/sh
#
# pin_core.sh — record which Bitcoin Core release the image will embed.
#
#   RUN THIS ON THE THINKPAD:
#       ./umbrel/pin_core.sh                  # pin the default version
#       ./umbrel/pin_core.sh 32.0             # pin a specific one
#       ./umbrel/pin_core.sh --verify         # re-check the pinned hashes
#
# WHY THIS IS A SEPARATE STEP AND NOT A LINE IN THE DOCKERFILE
#
# The image runs a Bitcoin node. The one thing that must never happen is the
# build silently installing whatever binary a network path hands it, so the
# Dockerfile refuses to build without an explicit, pre-recorded SHA256 for
# the exact tarball it is about to unpack.
#
# Those hashes have to come from somewhere trustworthy, which means they are
# fetched and recorded here, deliberately, on a machine you control — not
# written into the repository by somebody who never saw them.
#
# WHAT THIS DOES NOT DO, AND WHY YOU SHOULD DO IT
#
# It downloads SHA256SUMS and takes the hashes out of it. It does NOT verify
# the detached signature, because doing that properly needs the Bitcoin Core
# release keys in your keyring and a decision about which of them you trust —
# a judgement this script should not make for you.
#
# Fetching over HTTPS protects you from a passive observer and from nothing
# else. To check the signature yourself:
#
#     gpg --keyserver hkps://keys.openpgp.org --recv-keys <release key ids>
#     gpg --verify SHA256SUMS.asc SHA256SUMS
#
# The guix.sigs repository lists the keys:
#     https://github.com/bitcoin-core/guix.sigs
#
# BSD-2-Clause.

set -eu

say() { printf '%s\n' "$*"; }
die() { printf '\n%s\n' "$*" >&2; exit 1; }

HERE="$(cd "$(dirname "$0")/.." && pwd)"
ENVFILE="$HERE/umbrel/bitcoin-release.env"
BASE="https://bitcoincore.org/bin"

VERSION=""
VERIFY=0
case "${1:-}" in
    --verify) VERIFY=1 ;;
    -h|--help) sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    "") VERSION="31.1" ;;
    -*) die "unknown option: $1" ;;
    *) VERSION="$1" ;;
esac

if [ "$VERIFY" = "1" ]; then
    [ -f "$ENVFILE" ] || die "nothing pinned yet. Run: ./umbrel/pin_core.sh"
    . "$ENVFILE"
    say "pinned Bitcoin Core $CORE_VERSION"
    say "  arm64  $CORE_SHA256_ARM64"
    say "  amd64  $CORE_SHA256_AMD64"
    say ""
    say "Check these against bitcoincore.org yourself, and against a second"
    say "source. Two people reading the same compromised page agree."
    exit 0
fi

command -v curl >/dev/null 2>&1 || die "curl is required"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

url="$BASE/bitcoin-core-$VERSION/SHA256SUMS"
say "fetching $url"
curl -fsSL --max-time 60 "$url" -o "$tmp/SHA256SUMS" \
    || die "could not fetch SHA256SUMS for $VERSION.
Check the version exists:  $BASE/"

curl -fsSL --max-time 60 "$url.asc" -o "$tmp/SHA256SUMS.asc" 2>/dev/null \
    && have_asc=1 || have_asc=0

arm=$(grep "bitcoin-$VERSION-aarch64-linux-gnu.tar.gz" "$tmp/SHA256SUMS" \
      | awk '{print $1}' | head -1)
amd=$(grep "bitcoin-$VERSION-x86_64-linux-gnu.tar.gz" "$tmp/SHA256SUMS" \
      | awk '{print $1}' | head -1)

[ -n "$arm" ] || die "no aarch64 tarball listed for $VERSION"
[ -n "$amd" ] || die "no x86_64 tarball listed for $VERSION"

cat > "$ENVFILE" <<EOF
# Bitcoin Core release embedded in the Monetary Node image.
#
# Written by umbrel/pin_core.sh on $(date -u '+%Y-%m-%d %H:%M UTC').
# Taken from $url
#
# VERIFY THESE YOURSELF before trusting a build that uses them. The script
# fetched them over HTTPS and did not check the release signature.
CORE_VERSION=$VERSION
CORE_SHA256_ARM64=$arm
CORE_SHA256_AMD64=$amd
EOF

say ""
say "pinned Bitcoin Core $VERSION in umbrel/bitcoin-release.env"
say "  arm64  $arm"
say "  amd64  $amd"
say ""
if [ "$have_asc" = "1" ]; then
    say "SHA256SUMS.asc was also available. Verify it before you ship:"
    say "    curl -fsSL $url -o SHA256SUMS"
    say "    curl -fsSL $url.asc -o SHA256SUMS.asc"
    say "    gpg --verify SHA256SUMS.asc SHA256SUMS"
else
    say "No detached signature was served. That is unusual — look into it"
    say "before building an image that runs this binary."
fi
# ------------------------------------------------------------- electrs
#
# electrs is distributed as source, not as Linux binaries, so there is no
# tarball to hash the way Core has. Building Rust inside the image would
# work and would also add half an hour to every build, most of it emulated.
#
# The practical route is the binary from a published container image — the
# same ones the Umbrel and Citadel electrs apps use. Pinned BY DIGEST, so
# the tag cannot be moved under you afterwards.
#
# Which images and tags exist changes, so this probes rather than assumes,
# and records the first one that actually resolves for this architecture.

say ""
say "---- electrs ----"

# Ask the registry over HTTP rather than the docker CLI.
#
# `docker manifest inspect` needs experimental mode and
# `docker buildx imagetools` is not in Debian's docker.io package, so both
# probes reported "not resolvable" for images that plainly exist. The Hub
# API needs neither, and it returns the manifest-list digest, which is the
# right thing to pin for a multi-architecture image.

CANDS="${ELECTRS_IMAGES:-getumbrel/electrs:v0.12.0 getumbrel/electrs:v0.11.1 getumbrel/electrs:v0.10.10}"

found=""
for cand in $CANDS; do
    repo=${cand%%:*}
    tag=${cand##*:}
    case "$repo" in */*) ;; *) repo="library/$repo" ;; esac
    url="https://hub.docker.com/v2/repositories/$repo/tags/$tag"
    d=$(curl -fsSL --max-time 30 "$url" 2>/dev/null | python3 -c '
import json,sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(0)
# The manifest-list digest when there is one, so a single pin covers both
# architectures. Falling back to a per-arch digest would pin the image to
# whichever machine happened to run this script.
dig = d.get("digest") or ""
if not dig:
    for i in d.get("images") or []:
        if i.get("architecture") == "amd64":
            dig = i.get("digest") or ""
            break
arches = sorted({i.get("architecture") for i in (d.get("images") or [])
                 if i.get("architecture") not in (None, "unknown")})
print(dig)
print(",".join(arches))
' 2>/dev/null) || d=""
    digest=$(printf '%s' "$d" | sed -n 1p)
    arches=$(printf '%s' "$d" | sed -n 2p)
    case "$digest" in
        sha256:*) ;;
        *) digest="" ;;
    esac
    if [ -n "$digest" ]; then
        say "  $cand"
        say "    $digest"
        say "    architectures: ${arches:-unknown}"
        found="$cand@$digest"
        break
    fi
    say "  $cand  not found in the registry"
done

if [ -n "$found" ]; then
    echo "ELECTRS_IMAGE=$found" >> "$ENVFILE"
    say ""
    say "  pinned by digest, so the tag cannot be moved underneath you."
    say "  This is somebody else's build of electrs. If that is not"
    say "  acceptable for what you ship, build your own and set"
    say "  ELECTRS_IMAGES to it."
else
    say ""
    say "  NO electrs image resolved. The build will produce a node"
    say "  WITHOUT an indexer: it validates, strips and stores, and no"
    say "  wallet can connect to it."
    say ""
    say "  Name one yourself:"
    say "      ELECTRS_IMAGES=\"someorg/electrs:tag\" ./umbrel/pin_core.sh"
fi

say ""
say "Then build:   ./umbrel/sideload.sh --build"
