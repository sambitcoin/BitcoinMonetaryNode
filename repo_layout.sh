#!/bin/sh
#
# repo_layout.sh — put a git checkout into the canonical layout.
#
# Run inside a clone of the repository, with ~/monetary-node/tools holding
# the authoritative current tools. It copies the real versions in, moves
# misfiled things where they belong, retires superseded experiments to
# archive/, and reports anything still missing.
#
# It does NOT delete history and does NOT commit or push. Review `git status`
# afterwards and commit yourself.
#
#   cd ~/src/BitcoinMonetaryNode
#   sh ~/monetary-node/repo_layout.sh
#   git status
#
# BSD-2-Clause.

set -eu

SRC="${SRC:-$HOME/monetary-node}"
[ -d .git ] || { echo "not a git checkout — cd into your clone first"; exit 1; }
[ -d "$SRC/tools" ] || { echo "no $SRC/tools — set SRC to your working tree"; exit 1; }

mkdir -p tools docs patches results archive .github/workflows

say() { printf '%s\n' "$*"; }
MISSING=0

# ------------------------------------------------------------ authoritative
#
# The working tree on the node is the source of truth. Files in the repo were
# uploaded at different times over several weeks and at least some are stale.

TOOLS="mindex.py monetary_store.py test_monetary_store.py monetary_commit.py
monetary_ibd.py monetary_daemon.py monetary_convert.py prune_behind.py
spend_check.py wallet_check.py chainstate_filter.py commit_scan.py
chain_check.py flag_count.py monetary_ui.py quips.py
carrier_policy.py sbtc_scan.py node_settings.py tip_race.py tx_query.py
status_page.py"

# Never copied over, never deleted, never moved. These are the repository's
# own: a landing page, a plan, and a README whose structure and corrections
# log are part of what makes the measurements believable.
#
# The working tree has its own README.md, and copying it over the repo's was
# this script's behaviour until now. That is wrong for a refresh: the repo's
# README carries the published figures and the corrections table, and
# clobbering it from a machine where it was edited for local use loses both.
PROTECTED="README.md index.html technical.html GAMEPLAN.md CNAME"

say "tools/ — copying current versions from $SRC/tools"
for f in $TOOLS; do
    if [ -f "$SRC/tools/$f" ]; then
        cp "$SRC/tools/$f" "tools/$f"
        printf '  [copied ] tools/%-26s %8s bytes\n' "$f" "$(wc -c < "tools/$f")"
    else
        printf '  [MISSING] tools/%s\n' "$f"
        MISSING=$((MISSING + 1))
    fi
done

# ------------------------------------------------------------ retire
#
# Early experiments, superseded by the tools above. Kept rather than deleted:
# they are what the measurements were originally taken with, and deleting
# them would quietly erase how the project got here.

RETIRE="Node Script.py
Simulation Script.py
init.py
inscription_scan.py
spam_strip.py
utxo_scan.py
witness_split.py
build_index.py
inscription_scan_local.py"

say ""
say "archive/ — retiring superseded experiments"
OLDIFS=$IFS; IFS='
'
for f in $RETIRE; do
    for p in "tools/$f" "$f"; do
        if [ -f "$p" ]; then
            git mv -f "$p" "archive/$(basename "$p")" 2>/dev/null \
                || mv -f "$p" "archive/"
            say "  [ ->    ] $p -> archive/"
        fi
    done
done
IFS=$OLDIFS

# ------------------------------------------------------------ misfiled

say ""
say "moving misfiled files out of tools/"
move_out() {
    [ -f "tools/$1" ] || return 0
    git mv -f "tools/$1" "$2/$1" 2>/dev/null || mv -f "tools/$1" "$2/"
    say "  [ ->    ] tools/$1 -> $2/"
}
# INSTALL.md and README.md belong at the root, not in docs/ — a reader
# should find them without opening a folder.
for f in FORMAT.md CARRIERS.md CORE_PATCH.md FORMAT_V2.md \
         SPAM_TIEBREAK.md ELECTRS_PLAN.md; do
    move_out "$f" docs
done
for f in INSTALL.md README.md; do
    if [ -f "tools/$f" ] && [ ! -f "./$f" ]; then
        git mv -f "tools/$f" "./$f" 2>/dev/null || mv -f "tools/$f" .
        say "  [ ->    ] tools/$f -> ./"
    elif [ -f "tools/$f" ]; then
        rm -f "tools/$f"
        say "  [dropped] tools/$f — root copy is authoritative"
    fi
done
for f in core-spam-tiebreak.patch electrum-dust-filter.patch \
         test_tiebreak_comparator.cpp feature_spam_tiebreak.py; do
    move_out "$f" patches
done
for f in install.sh tor_setup.sh release_check.sh assemble_repo.sh; do
    if [ -f "tools/$f" ]; then
        git mv -f "tools/$f" "$f" 2>/dev/null || mv -f "tools/$f" .
        say "  [ ->    ] tools/$f -> ./"
    fi
done

# alpha_warning_snippet.py is a paste-in, not a tool you run
if [ -f tools/alpha_warning_snippet.py ]; then
    git mv -f tools/alpha_warning_snippet.py docs/ 2>/dev/null \
        || mv -f tools/alpha_warning_snippet.py docs/
    say "  [ ->    ] tools/alpha_warning_snippet.py -> docs/"
fi

# ------------------------------------------------------------ leftovers
#
# Files that accumulated in the wrong place over several weeks of uploads.
# Each one is either a duplicate of a file that now lives somewhere better,
# or a document the README links to under a different path.

say ""
say "tidying leftovers"

# A duplicate is only safe to delete if it is byte-identical to the copy we
# are keeping. Otherwise it is a divergent edit and the operator should see
# both, so it gets moved rather than removed.
dedupe() {
    [ -f "$1" ] || return 0
    if [ -f "$2" ] && cmp -s "$1" "$2"; then
        git rm -q -f "$1" 2>/dev/null || rm -f "$1"
        say "  [removed] $1 — byte-identical to $2"
    elif [ -f "$2" ]; then
        say "  [KEPT   ] $1 — DIFFERS from $2, not touching it"
        say "             diff $1 $2"
    fi
}
dedupe tools/CARRIER_POLICY.md docs/CARRIER_POLICY.md
dedupe tools/core-useragent.patch patches/core-useragent.patch

# The README links docs/Monetary_Nodes.md; the file sits at the root.
if [ -f Monetary_Nodes.md ] && [ ! -f docs/Monetary_Nodes.md ]; then
    git mv -f Monetary_Nodes.md docs/Monetary_Nodes.md 2>/dev/null \
        || mv -f Monetary_Nodes.md docs/
    say "  [ ->    ] Monetary_Nodes.md -> docs/  (README links it there)"
fi

# "Electrum Patch/" — a directory with a space in its name holding one plan
# and one patch, both of which belong with their own kind.
if [ -d "Electrum Patch" ]; then
    [ -f "Electrum Patch/ELECTRS_PLAN.md" ] && {
        git mv -f "Electrum Patch/ELECTRS_PLAN.md" docs/ELECTRS_PLAN.md \
            2>/dev/null || mv -f "Electrum Patch/ELECTRS_PLAN.md" docs/
        say "  [ ->    ] Electrum Patch/ELECTRS_PLAN.md -> docs/"; }
    dedupe "Electrum Patch/electrum-dust-filter.patch" \
           patches/electrum-dust-filter.patch
    say "  [note   ] 'Electrum Patch/' still holds: $(ls "Electrum Patch" 2>/dev/null | tr '\n' ' ')"
    say "             a directory name with a space breaks shell one-liners;"
    say "             move anything left and remove it."
fi

# Documents filed under results/, which is for logs. The README treats
# results/ as evidence, so nothing is deleted from it — only documents that
# have a canonical home elsewhere are deduped.
for f in FORMAT.md STRIP_RESULTS.md; do
    dedupe "results/$f" "docs/$f"
done

# ------------------------------------------------------------ root files

say ""
say "protected — left exactly as the repository has them"
for f in $PROTECTED; do
    if [ -f "./$f" ]; then
        printf '  [kept   ] %-20s %8s bytes\n' "$f" "$(wc -c < "./$f")"
        # Say so when the working tree disagrees, rather than resolving it
        # silently in either direction. A stale README beside fresh code is
        # a real problem, and so is overwriting one that holds the published
        # numbers. The operator decides, knowing the files differ.
        if [ -f "$SRC/$f" ] && ! cmp -s "./$f" "$SRC/$f"; then
            say "             NOTE: $SRC/$f differs and was NOT copied."
            say "             Diff them yourself:  diff ./$f $SRC/$f"
        fi
    else
        printf '  [absent ] %s — nothing to protect\n' "$f"
    fi
done

say ""
say "docs/ from $SRC/docs"
for f in CARRIERS.md CARRIER_POLICY.md CORE_PATCH.md FORMAT_V2.md \
         USER_AGENT.md; do
    if [ -f "$SRC/docs/$f" ]; then
        cp "$SRC/docs/$f" "docs/$f"
        say "  [copied ] docs/$f"
    fi
done

say ""
say "patches/ from $SRC/patches"
for f in core-spam-policy.patch core-spam-tiebreak.patch \
         core-useragent.patch electrum-dust-filter.patch \
         feature_spam_policy.py; do
    if [ -f "$SRC/patches/$f" ]; then
        cp "$SRC/patches/$f" "patches/$f"
        say "  [copied ] patches/$f"
    fi
done

say ""
say "scripts and root files from $SRC"
SCRIPTS="tor_setup.sh tor_lockdown.sh services_setup.sh electrs_setup.sh
electrum_onion.sh status_onion.sh peering_setup.sh node_config.sh
patch_build.sh deploy.sh release_check.sh repo_layout.sh"
for f in $SCRIPTS INSTALL.md LICENSE .gitignore MANIFEST.txt; do
    if [ -f "$SRC/$f" ]; then
        cp "$SRC/$f" "./$f"
        say "  [copied ] $f"
    elif [ -f "./$f" ]; then
        say "  [kept   ] $f (already here, not in $SRC)"
    else
        say "  [MISSING] $f"
        MISSING=$((MISSING + 1))
    fi
done
[ -f "$SRC/.github/workflows/tests.yml" ] \
    && cp "$SRC/.github/workflows/tests.yml" .github/workflows/tests.yml \
    && say "  [copied ] .github/workflows/tests.yml"

# shellcheck disable=SC2086
chmod +x $SCRIPTS 2>/dev/null || true

# ------------------------------------------------------------ report

say ""
say "=================================================================="
say "LAYOUT"
say "=================================================================="
find . -path ./.git -prune -o -type f -print | sed 's|^\./||' | sort | sed 's/^/  /'

say ""
if [ "$MISSING" -gt 0 ]; then
    say "$MISSING file(s) missing — copy them into $SRC and rerun."
fi
say "Nothing has been committed. Next:"
say "  ./release_check.sh          every self-test, plus a hash of each file"
say "  git status                  review what changed"
say "  git add -A"
say "  git commit -m 'reorganise into canonical layout; genesis-to-tip results'"
say ""
say "Do not force-push or rewrite history. The corrections in the log are"
say "part of what makes the measurements believable."
