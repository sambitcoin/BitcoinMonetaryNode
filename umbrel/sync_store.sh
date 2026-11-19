#!/bin/sh
#
# sync_store.sh — regenerate app-store/ from umbrel/.
#
#   ./umbrel/sync_store.sh          rewrite the store tree
#   ./umbrel/sync_store.sh --check  fail if it is out of date
#
# WHY THIS EXISTS
#
# The community store needs its own copy of the manifest and the compose
# file, because umbrelOS requires the app id to carry the store id as a
# prefix — `sambitcoin-monetary-node` rather than `monetary-node` — and
# that prefix also determines the environment variables it exports
# (APP_SAMBITCOIN_MONETARY_NODE_IP). So the two trees cannot be the same
# file, and two copies of anything drift.
#
# They drift in the worst possible way, too: the source tree is the one
# that gets edited and tested, and the store tree is the one strangers
# install. A fix made here and not copied there is a fix nobody receives.
#
# So the store tree is GENERATED, never edited, and --check in the
# release gate fails if it has fallen behind.
#
# BSD-2-Clause.

set -eu

say() { printf '%s\n' "$*"; }
die() { printf '%s\n' "$*" >&2; exit 1; }

HERE="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$HERE/umbrel"
STORE="$HERE/app-store"
APPDIR="$STORE/sambitcoin-monetary-node"
CHECK=0
[ "${1:-}" = "--check" ] && CHECK=1

[ -f "$SRC/umbrel-app.yml" ] || die "no $SRC/umbrel-app.yml"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# The two transformations, and they are the only two. Keeping them here
# rather than in a person's memory is the point of the script.
sed -e 's/^id: monetary-node$/id: sambitcoin-monetary-node/' \
    "$SRC/umbrel-app.yml" > "$tmp/umbrel-app.yml"
sed -e 's/\$APP_MONETARY_NODE_IP/$APP_SAMBITCOIN_MONETARY_NODE_IP/g' \
    "$SRC/docker-compose.yml" > "$tmp/docker-compose.yml"
cp "$SRC/icon.svg" "$tmp/icon.svg" 2>/dev/null || true

# The transformation must actually have happened. A sed that matches
# nothing exits 0 and produces a file that looks fine and installs as the
# wrong app id.
grep -q '^id: sambitcoin-monetary-node$' "$tmp/umbrel-app.yml" \
    || die "the app id was not rewritten — did umbrel-app.yml's id change?"
grep -q 'APP_SAMBITCOIN_MONETARY_NODE_IP' "$tmp/docker-compose.yml" \
    || die "the compose variables were not rewritten."
grep -q 'APP_MONETARY_NODE_IP' "$tmp/docker-compose.yml" \
    && die "an un-prefixed variable survived the rewrite."

if [ "$CHECK" = "1" ]; then
    rc=0
    for f in umbrel-app.yml docker-compose.yml; do
        if ! cmp -s "$tmp/$f" "$APPDIR/$f"; then
            say "  OUT OF DATE: app-store/sambitcoin-monetary-node/$f"
            rc=1
        fi
    done
    [ "$rc" = "0" ] && say "  store tree matches umbrel/"
    exit "$rc"
fi

mkdir -p "$APPDIR/gallery"
cp "$tmp/umbrel-app.yml" "$tmp/docker-compose.yml" "$APPDIR/"
[ -f "$tmp/icon.svg" ] && cp "$tmp/icon.svg" "$APPDIR/"
say "regenerated $APPDIR from umbrel/"
