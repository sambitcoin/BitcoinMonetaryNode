#!/bin/sh
#
# release_check.sh — prove the tree is publishable before you push it.
#
# Runs every tool's self-test, records a hash of every file, and refuses if
# anything fails or is missing. Run from the repository root.
#
# This exists because "make sure I have the right versions" is not something
# anyone can answer by looking. Files get copied between machines, edited in
# two places, and restored from an older download. The only reliable answer
# is: every self-test passes here, now, and here is the hash of what ran.
#
#   ./release_check.sh
#   ./release_check.sh > MANIFEST.txt
#
# BSD-2-Clause.

set -u

ROOT="$(cd "$(dirname "$0")" && pwd)"
TOOLS="$ROOT/tools"
FAILED=0
MISSING=0

say()  { printf '%s\n' "$*"; }
head_() { say ""; say "======================================================================"; say "$*"; say "======================================================================"; }

head_ "MONETARY NODE — RELEASE CHECK"
say "$(date -u '+%Y-%m-%d %H:%M:%SZ')"
say "root   $ROOT"
say "python $(python3 -c 'import sys;print("%d.%d.%d"%sys.version_info[:3])' 2>/dev/null || echo MISSING)"
say "uname  $(uname -sm)"

# ------------------------------------------------------------- required set
#
# Everything a stranger needs to reproduce the published results. A tool
# missing here is a broken release, not a warning.

REQUIRED="gallery_pages.py mindex.py monetary_store.py test_monetary_store.py monetary_commit.py
spend_check.py wallet_check.py chainstate_filter.py commit_scan.py
monetary_ibd.py monetary_daemon.py monetary_convert.py prune_behind.py
chain_check.py flag_count.py monetary_ui.py quips.py
carrier_policy.py sbtc_scan.py node_settings.py tip_race.py tx_query.py
status_page.py fit_store.py monetary_electrum.py
monetary_supervisor.py"

head_ "FILES"
for f in $REQUIRED; do
    if [ ! -f "$TOOLS/$f" ]; then
        say "  [MISSING] tools/$f"
        MISSING=$((MISSING + 1))
        continue
    fi
    # A truncated file or a stub that got copied over the real thing is the
    # failure mode this catches. monetary_daemon.py has been a 186-byte stub
    # in at least one workspace during this project.
    size=$(wc -c < "$TOOLS/$f")
    if [ "$size" -lt 1000 ]; then
        say "  [STUB?  ] tools/$f — only $size bytes"
        FAILED=$((FAILED + 1))
    elif ! head -c 2 "$TOOLS/$f" | grep -q '#!'; then
        say "  [NOSHBNG] tools/$f — no shebang; truncated or bytecode?"
        FAILED=$((FAILED + 1))
    else
        printf '  [ok     ] tools/%-26s %8s bytes\n' "$f" "$size"
    fi
done

# ------------------------------------------------------------- self-tests

head_ "SELF-TESTS"
run() {
    name="$1"; shift
    if [ ! -f "$TOOLS/$name" ]; then
        printf '  %-28s SKIPPED (missing)\n' "$name"
        return
    fi
    printf '  %-28s ' "$name"
    if out=$(cd "$TOOLS" && "$@" 2>&1); then
        line=$(printf '%s' "$out" | grep -E '[0-9]+/[0-9]+ passed' | tail -1)
        printf '%s\n' "${line:-passed}"
    else
        printf 'FAILED\n'
        printf '%s\n' "$out" | tail -6 | sed 's/^/        /'
        FAILED=$((FAILED + 1))
    fi
}

run test_monetary_store.py python3 test_monetary_store.py
run spend_check.py         python3 spend_check.py --selftest
run wallet_check.py        python3 wallet_check.py --selftest
run monetary_commit.py     python3 monetary_commit.py --selftest
run monetary_ibd.py        python3 monetary_ibd.py --selftest
run monetary_ibd.py        python3 monetary_ibd.py --attack-suite
run monetary_daemon.py     python3 monetary_daemon.py --selftest
run chainstate_filter.py   python3 chainstate_filter.py --selftest
run commit_scan.py         python3 commit_scan.py --selftest
run chain_check.py         python3 chain_check.py --selftest
run fit_store.py           python3 fit_store.py --selftest
run gallery_pages.py       python3 gallery_pages.py --selftest
run monetary_electrum.py   python3 monetary_electrum.py --selftest
run monetary_supervisor.py python3 monetary_supervisor.py --selftest
run flag_count.py          python3 flag_count.py --selftest
run monetary_ui.py         python3 monetary_ui.py --selftest
run carrier_policy.py      python3 carrier_policy.py --selftest
run sbtc_scan.py           python3 sbtc_scan.py --selftest
run node_settings.py       python3 node_settings.py --selftest
run tip_race.py            python3 tip_race.py --selftest
run tx_query.py            python3 tx_query.py --selftest
run status_page.py         python3 status_page.py --selftest
run quips.py               python3 quips.py --selftest

# ------------------------------------------------------- shell and packaging
#
# Every shell script must at least parse. A syntax error in one of these is
# only discovered when someone runs it, which on this project has meant
# discovering it on the node, under sudo, at the worst moment.

head_ "SHELL SYNTAX"
for s in "$ROOT"/*.sh "$ROOT"/umbrel/*.sh; do
    [ -f "$s" ] || continue
    printf '  %-28s ' "$(basename "$s")"
    if sh -n "$s" 2>/dev/null; then
        say "ok"
    else
        say "SYNTAX ERROR"
        FAILED=$((FAILED + 1))
    fi
done

# Every shell script must be executable. A script synced to the node with
# mode 600 fails with "Permission denied", which reads like an ssh or sudo
# problem and sends you looking in the wrong place entirely. umbrel/
# sideload.sh shipped that way and cost a round trip.
head_ "SCRIPT MODES"
for f in "$ROOT"/*.sh "$ROOT"/umbrel/*.sh; do
    [ -f "$f" ] || continue
    printf '  %-28s ' "$(basename "$f")"
    if [ -x "$f" ]; then
        say "executable"
    else
        say "NOT EXECUTABLE — chmod +x $f"
        FAILED=$((FAILED + 1))
    fi
done

# The Umbrel package manifests have to parse as YAML, and the app id has to
# match the directory Umbrel will install into.
if [ -d "$ROOT/umbrel" ]; then
    head_ "UMBREL PACKAGE"
    for f in umbrel-app.yml docker-compose.yml Dockerfile docker-entrypoint.sh; do
        printf '  %-28s ' "$f"
        [ -f "$ROOT/umbrel/$f" ] && say "present" || {
            say "MISSING"; MISSING=$((MISSING + 1)); }
    done
    if command -v python3 >/dev/null 2>&1; then
        printf '  %-28s ' "yaml parses"
        if python3 - "$ROOT" <<'PY'
import sys
try:
    import yaml
except ImportError:
    print("skipped (no pyyaml)"); raise SystemExit(0)
root = sys.argv[1]
app = yaml.safe_load(open(root + "/umbrel/umbrel-app.yml"))
comp = yaml.safe_load(open(root + "/umbrel/docker-compose.yml"))
assert app["id"] == "monetary-node", app["id"]

# Standalone. The app embeds Core, tor and the index, so it must declare
# no dependency on a Bitcoin app — a dependency on one would go unmet on a
# machine running Knots, and the APP_BITCOIN_* variables would all be
# empty while the app looked installed.
assert app.get("dependencies") == [], app.get("dependencies")

svcs = set(comp["services"])
assert svcs >= {"app_proxy", "web"}, svcs
web = comp["services"]["web"]
assert web["command"] == ["all"], web["command"]

# Wallets reach the index over raw TCP, which app_proxy cannot carry.
ports = [str(p) for p in web.get("ports", [])]
assert any(p.startswith("50001:") for p in ports), ports
env = web["environment"]
assert env.get("MONETARY_WALLET_ADVERTISE"), "nothing to tell Sparrow"
assert env.get("MONETARY_TOR") == "1", "tor must default on"
assert env.get("MONETARY_INDEX") == "1", "the index must default on"

# The pruner is the only component that deletes data and it has never run
# in a release configuration. The listing states it ships disabled, so the
# package must actually ship it disabled.
assert env.get("MONETARY_PRUNE") == "0", \
    "the pruner must ship OFF: untested and destructive"

# Claims a stranger reads before installing. Each of these was wrong in a
# previous revision, and each would have cost somebody real disk.
# Read the PARSED text, not the file: YAML folds long lines, so a phrase
# that reads as one sentence to a human is split by a newline on disk and
# a raw substring search misses it.
_doc = yaml.safe_load(open(root + "/umbrel/umbrel-app.yml"))
_app = (_doc.get("description") or "") + "\n" + (_doc.get("releaseNotes") or "")
for _needle in ("2 TB RECOMMENDED", "REFUSES to run",
                "never asked for an extended public key",
                "has never run in a release configuration",
                # Added when the Pi died and the only remaining machine
                # could not do a mainnet fresh install. If this sentence
                # disappears, the listing is claiming a test nobody ran.
                "has NEVER been tested end to end",
                "No promises and no roadmap"):
    assert _needle in _app, "listing no longer says: " + _needle
assert "never writes bitcoin.conf" not in _app, \
    "stale claim: the app writes bitcoin.conf now"

# The stripper must not be SIGKILLed mid-record.
grace = str(web.get("stop_grace_period", ""))
assert grace and grace != "10s", grace

# No interpolation of another app's variables can remain.
blob = open(root + "/umbrel/docker-compose.yml").read()
assert "APP_BITCOIN_" not in blob, "still reading the Bitcoin app's config"
print("ok")
PY
        then :; else say "FAILED"; FAILED=$((FAILED + 1)); fi
    fi
fi

# ----------------------------------------------------- digest extraction
#
# publish.sh reads the digest out of `docker buildx imagetools inspect`.
# The first attempt used --format, which the buildx on the build machine
# silently ignores — it printed the whole inspect block, which was then
# taken for a digest. The push had already happened by then, so the only
# thing standing between that and a corrupt compose file was the shape
# check. Keep the output that broke it and prove the parser survives it.

head_ "DIGEST EXTRACTION"
fixture=$(cat <<'FIX'
Name:      ghcr.io/sambitcoin/monetary-node:0.1.0-alpha
MediaType: application/vnd.oci.image.index.v1+json
Digest:    sha256:d274ef44a4f8068eca50a175fe77503eeed9754c03805fe105939d89e49c0319

Manifests:
  Name:        ghcr.io/sambitcoin/monetary-node:0.1.0-alpha@sha256:5a4d0f3c678912a087e3ca9265c96bc7ee6f005b94556432cb3311a33ca6287a
  MediaType:   application/vnd.oci.image.manifest.v1+json
  Platform:    linux/amd64

  Name:        ghcr.io/sambitcoin/monetary-node:0.1.0-alpha@sha256:419de168cfe551eb4d474df2811d3f6515604c7d9429388562499e9573876fbb
  MediaType:   application/vnd.oci.image.manifest.v1+json
  Platform:    linux/arm64
FIX
)
got=$(printf '%s\n' "$fixture" | awk '/^Digest:/{print $2; exit}')
printf '  %-28s ' "parses real inspect output"
if [ "$got" = "sha256:d274ef44a4f8068eca50a175fe77503eeed9754c03805fe105939d89e49c0319" ]; then
    say "ok"
else
    say "FAILED — got: ${got:-nothing}"
    FAILED=$((FAILED + 1))
fi
# The manifest LIST digest, not a per-platform one. Pinning a platform
# digest ships an app that installs on one architecture and not the other.
printf '  %-28s ' "takes the index, not amd64"
if [ "$got" != "sha256:5a4d0f3c678912a087e3ca9265c96bc7ee6f005b94556432cb3311a33ca6287a" ]; then
    say "ok"
else
    say "FAILED — pinned a single platform"
    FAILED=$((FAILED + 1))
fi

# --------------------------------------------------------- app store tree
#
# The community store carries its own copy of the manifest and compose
# file, because umbrelOS requires the store id as a prefix on the app id.
# Two copies drift, and the copy that drifts is the one strangers
# install — so it is generated, and this fails if it has fallen behind.

if [ -d "$ROOT/app-store" ]; then
    head_ "APP STORE TREE"
    printf '  %-28s ' "in sync with umbrel/"
    if out=$(sh "$ROOT/umbrel/sync_store.sh" --check 2>&1); then
        say "yes"
    else
        say "NO"
        printf '%s\n' "$out" | sed 's/^/      /'
        say "      run ./umbrel/sync_store.sh"
        FAILED=$((FAILED + 1))
    fi

    if command -v python3 >/dev/null 2>&1; then
        printf '  %-28s ' "store manifest"
        if python3 - "$ROOT" <<'PY'
import sys
try:
    import yaml
except ImportError:
    print("skipped (no pyyaml)"); raise SystemExit(0)
root = sys.argv[1]
store = yaml.safe_load(open(root + "/app-store/umbrel-app-store.yml"))
app = yaml.safe_load(
    open(root + "/app-store/sambitcoin-monetary-node/umbrel-app.yml"))

# umbrelOS rejects an app whose id does not begin with the store id, and
# the directory name has to match the id as well. Getting this wrong
# produces a store that loads with no apps in it and no error saying why.
sid = store["id"]
assert app["id"].startswith(sid + "-"), (app["id"], sid)
assert app["id"] == "sambitcoin-monetary-node", app["id"]

# The compose file must reference the PREFIXED variables. The
# un-prefixed ones are never exported for a community app, so they
# interpolate to empty and the app gets no IP address at all.
blob = open(root
            + "/app-store/sambitcoin-monetary-node/docker-compose.yml").read()
assert "APP_SAMBITCOIN_MONETARY_NODE_IP" in blob
assert "$APP_MONETARY_NODE_IP" not in blob
print("ok")
PY
        then :; else say "FAILED"; FAILED=$((FAILED + 1)); fi

        # A tag can be moved under you; Umbrel wants a digest. This is a
        # warning rather than a failure because the digest only exists
        # after the first push.
        printf '  %-28s ' "image pinned by digest"
        if grep -q 'image:.*@sha256:' \
            "$ROOT/app-store/sambitcoin-monetary-node/docker-compose.yml"; then
            say "yes"
        else
            say "NO — still a tag. Run ./umbrel/publish.sh before submitting."
        fi

        printf '  %-28s ' "gallery images"
        n=$(find "$ROOT/app-store/sambitcoin-monetary-node/gallery" \
            -type f \( -name '*.png' -o -name '*.jpg' \) 2>/dev/null | wc -l)
        if [ "$n" -ge 3 ]; then
            say "$n"
        else
            say "$n — the listing wants 3 to 5."
        fi
    fi
fi

# ------------------------------------------------------------- manifest

head_ "MANIFEST"
say "Hash of every tracked file. Paste this beside a release so anyone can"
say "check they are running what you tested."
say ""
if command -v sha256sum >/dev/null 2>&1; then
    HASH=sha256sum
else
    HASH="shasum -a 256"
fi
( cd "$ROOT" && find . -type f \
    \( -name '*.py' -o -name '*.sh' -o -name '*.md' -o -name 'LICENSE' \) \
    ! -path './.git/*' ! -path './results/*' ! -path './store/*' \
    | sort | xargs $HASH ) 2>/dev/null | sed 's/^/  /'

# ------------------------------------------------------------- result

head_ "RESULT"
if [ "$MISSING" -gt 0 ]; then
    say "$MISSING required file(s) missing. This tree cannot be released:"
    say "someone cloning it would not be able to reproduce the results."
fi
if [ "$FAILED" -gt 0 ]; then
    say "$FAILED check(s) failed. Fix before publishing."
fi
if [ "$MISSING" -eq 0 ] && [ "$FAILED" -eq 0 ]; then
    say "All files present, all self-tests pass on this machine."
    say ""
    say "Still not verified by this script, and worth doing by hand:"
    say "  - the numbers in README.md match your latest build log"
    say "  - the commitment C is quoted WITH its block height"
    say "  - results/ and store/ are excluded by .gitignore"
    exit 0
fi
exit 1
