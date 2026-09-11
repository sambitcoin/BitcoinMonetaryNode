#!/bin/sh
#
# install.sh — check this machine can run a monetary node, and say what next.
#
# Installs nothing. Changes nothing. Needs no root. It verifies the tools are
# intact, runs their self-tests, and hands you to the converter.
#
# There is deliberately no curl-pipe-shell one-liner. Read this file first;
# that is the point of it being short.
#
# Usage:   ./install.sh
#
# BSD-2-Clause.

set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
TOOLS="$HERE/tools"
FAIL=0

say()  { printf '%s\n' "$*"; }
head_() { say ""; say "=================================================================="; say "$*"; say "=================================================================="; }
ok()   { say "  [ok  ] $*"; }
bad()  { say "  [FAIL] $*"; FAIL=1; }

head_ "MONETARY NODE — ALPHA SOFTWARE"
say ""
say "  This is an alpha release. It has not been reviewed or audited by"
say "  anyone but its author. An earlier version contained a bug that"
say "  permanently deleted block data from a node."
say ""
say "  Point these tools only at a node you can afford to lose and"
say "  re-sync from scratch. Do not run them against a node you depend on."
say ""
say "  WALLETS"
say ""
say "    Keep your seed words offline, on a hardware wallet."
say ""
say "    If you connect a hot wallet to this node, fund it with an amount"
say "    you would not mind losing entirely."
say ""
say "  Nothing here can spend your coins — these tools hold no keys and"
say "  never touch a wallet. The risk is to your node's block data, and"
say "  to any wallet that relies on this node for its view of the chain."

head_ "ENVIRONMENT CHECK"
say ""
say "This installs nothing and changes nothing. It checks that the tools"
say "work on this machine, then tells you what to run."

# ----------------------------------------------------------------- python

say ""
say "python"
if ! command -v python3 >/dev/null 2>&1; then
    bad "python3 not found"
else
    PYV=$(python3 -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])')
    if python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,8) else 1)'; then
        ok "python3 $PYV"
    else
        bad "python3 $PYV — 3.8 or later required"
    fi
    # Everything is standard library. Confirm rather than assume.
    if python3 -c 'import hashlib,struct,socket,json,glob,argparse,fcntl' 2>/dev/null; then
        ok "standard library modules present"
    else
        bad "a standard library module is missing — unusual, worth investigating"
    fi
fi

# ----------------------------------------------------------------- tools

say ""
say "tools"
for t in mindex.py monetary_store.py test_monetary_store.py monetary_commit.py \
         spend_check.py wallet_check.py chainstate_filter.py commit_scan.py \
         monetary_ibd.py monetary_daemon.py monetary_convert.py prune_behind.py
do
    if [ -f "$TOOLS/$t" ]; then
        # A truncated or bytecode file fails later in confusing ways.
        if head -c 2 "$TOOLS/$t" | grep -q '#!'; then
            ok "$t"
        else
            bad "$t does not start with a shebang — truncated or not source?"
        fi
    else
        bad "$t missing from tools/"
    fi
done

# ----------------------------------------------------------------- self-tests

if [ "$FAIL" -eq 0 ]; then
    say ""
    say "self-tests  (these prove the tools work here, before touching real data)"
    say ""
    run_test() {
        name=$1; shift
        printf '  %-28s' "$name"
        if out=$(cd "$TOOLS" && "$@" 2>&1); then
            printf '%s\n' "$(printf '%s' "$out" | grep -E '[0-9]+/[0-9]+ passed' | tail -1)"
        else
            printf 'FAILED\n'
            printf '%s\n' "$out" | tail -5 | sed 's/^/      /'
            FAIL=1
        fi
    }
    run_test "storage format"      python3 test_monetary_store.py
    run_test "spend validation"    python3 spend_check.py --selftest
    run_test "sync protocol"       python3 monetary_ibd.py --selftest
    run_test "adversarial suite"   python3 monetary_ibd.py --attack-suite
    run_test "daemon"              python3 monetary_daemon.py --selftest
    run_test "commitment"          python3 monetary_commit.py --selftest
    run_test "chainstate filter"   python3 chainstate_filter.py --selftest
    run_test "commit scan"         python3 commit_scan.py --selftest
    run_test "wallet check"        python3 wallet_check.py --selftest
fi

# ----------------------------------------------------------------- disk

say ""
say "disk"
AVAIL=$(df -k "$HERE" | awk 'NR==2 {print $4}')
AVAIL_GB=$((AVAIL / 1024 / 1024))
say "  $AVAIL_GB GB free where this repo lives"
if [ "$AVAIL_GB" -lt 250 ]; then
    say "  NOTE: a full store needs roughly 700 GB, an inscription-era store"
    say "  about 250 GB. You can still run the tests and the checks."
fi

# ----------------------------------------------------------------- result

head_ "RESULT"
if [ "$FAIL" -ne 0 ]; then
    say "Something failed above. Please open an issue with the output —"
    say "a failing self-test on your machine is worth more to me than a"
    say "passing one on mine."
    exit 1
fi

say "Everything passed. The tools work on this machine."
say ""
say "IMPORTANT: today this COSTS disk space rather than saving it. Your node"
say "keeps its own block files; the store is additional. The saving only"
say "arrives when the node stops keeping complete blocks, which means"
say "pruning it and letting the store be the archive."
say ""
say "Next, and it changes nothing:"
say ""
say "    python3 tools/monetary_convert.py --check"
say ""
say "That inspects your node, finds your block files, checks you have the"
say "space, and refuses if anything is wrong. Then:"
say ""
say "    python3 tools/monetary_convert.py --run"
say ""
say "Stages 1-6 are reversible — delete the store and your node is untouched."
say "Stage 7 prunes the node and is not reversible. It is a separate command"
say "and it refuses to run until the store has been verified."
say ""
say "Once more, because it is the thing that matters: this is alpha software."
say "Use an expendable node. Keep seed words offline on a hardware wallet, and"
say "keep only small amounts in any hot wallet pointed at this node."
say ""
say "Read docs/CARRIERS.md before believing any claim about coverage."
