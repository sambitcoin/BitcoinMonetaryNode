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

REQUIRED="mindex.py monetary_store.py test_monetary_store.py monetary_commit.py
spend_check.py wallet_check.py chainstate_filter.py commit_scan.py
monetary_ibd.py monetary_daemon.py monetary_convert.py prune_behind.py
chain_check.py flag_count.py monetary_ui.py quips.py
carrier_policy.py sbtc_scan.py node_settings.py tip_race.py tx_query.py
status_page.py"

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
run flag_count.py          python3 flag_count.py --selftest
run monetary_ui.py         python3 monetary_ui.py --selftest
run carrier_policy.py      python3 carrier_policy.py --selftest
run sbtc_scan.py           python3 sbtc_scan.py --selftest
run node_settings.py       python3 node_settings.py --selftest
run tip_race.py            python3 tip_race.py --selftest
run tx_query.py            python3 tx_query.py --selftest
run status_page.py         python3 status_page.py --selftest
run quips.py               python3 quips.py --selftest

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
