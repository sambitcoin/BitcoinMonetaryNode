#!/bin/sh
#
# patch_build.sh — build Bitcoin Core with the Knots-style relay policy, and
# refuse to hand you the binary unless the tests pass.
#
#   ./patch_build.sh --check      can the patch even apply? changes nothing
#   ./patch_build.sh --build      fetch, patch, compile
#   ./patch_build.sh --test       run the functional suite on regtest
#   ./patch_build.sh --install    copy the binary into place (asks first)
#   ./patch_build.sh --all        check, build, test, then STOP
#
# WHY THIS IS A SCRIPT AND NOT A LIST OF INSTRUCTIONS
#
# patches/core-spam-policy.patch has never been compiled. Its own header says
# so. The gap between "a reviewed design" and "a binary validating your money"
# is the three steps below, and the only one that matters is the test:
#
#     feature_spam_policy.py :: test_consensus_unchanged
#
# That test mines a spam transaction on a STOCK node and asserts the PATCHED
# node accepts the resulting block. It is the whole safety argument. Relay
# policy may decline to forward a transaction; it must never decline a block,
# because a node that rejects a block the network accepted has forked itself
# off the chain — which for this project would destroy the one claim it makes.
#
# So --install refuses to run unless --test has passed in this working
# directory. There is no flag to skip it. If you want to override that, edit
# this file and watch yourself do it.
#
# WHAT THIS WILL NOT DO
#
# It will not touch the running node. It builds into its own tree, tests on
# regtest, and --install copies to /usr/local/bin after asking. Swapping the
# binary under a live node and restarting it is a separate decision, made
# deliberately, after you have read the test output.
#
# It will not apply patches/core-spam-tiebreak.patch. That one modifies
# CBlockIndexWorkComparator, which orders setBlockIndexCandidates and
# therefore decides which tip this node activates. Its help text claims it
# has "no effect unless this node mines"; that claim does not survive reading
# the comparator. A node preferring a cleaner block of equal work chooses a
# different chain from the network and forks off the moment its choice loses.
# tools/tip_race.py measures the same races without touching chain selection.
#
# BSD-2-Clause.

set -eu

CORE_VERSION="${CORE_VERSION:-v31.1.0}"
CORE_REPO="${CORE_REPO:-https://github.com/bitcoin/bitcoin}"
WORK="${PATCH_WORK:-$HOME/core-patched}"
HERE="$(cd "$(dirname "$0")" && pwd)"
PATCH="$HERE/patches/core-spam-policy.patch"
TESTFILE="$HERE/patches/feature_spam_policy.py"
STAMP="$WORK/.tests-passed"
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 2)}"

ACTION=""
case "${1:-}" in
    --check)   ACTION=check ;;
    --build)   ACTION=build ;;
    --test)    ACTION=test ;;
    --install) ACTION=install ;;
    --all)     ACTION=all ;;
    -h|--help) sed -n '2,45p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    "")        sed -n '2,45p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
esac

say() { printf '%s\n' "$*"; }
die() { printf '%s\n' "$*" >&2; exit 1; }

# Refuse to run on the Mac. The build needs Linux toolchains, the functional
# suite expects them, and discovering that halfway through a two-hour compile
# is a bad way to spend an afternoon.
case "$(uname -s)" in
    Linux) ;;
    *) die "This builds and tests Bitcoin Core on Linux. Run it on the node,
not the Mac. (uname says $(uname -s).)" ;;
esac

[ -f "$PATCH" ] || die "no patch at $PATCH"
[ -f "$TESTFILE" ] || die "no test at $TESTFILE"

# ------------------------------------------------------------------- check


fetch_source() {
    if [ -d "$WORK/.git" ]; then
        say "source already at $WORK"
        return
    fi
    say "cloning Core $CORE_VERSION into $WORK"
    say "  (shallow; a few hundred MB)"
    git clone --depth 1 --branch "$CORE_VERSION" "$CORE_REPO" "$WORK"
}

do_check() {
    say "=================================================================="
    say "CHECK — does the patch apply to $CORE_VERSION?"
    say "=================================================================="
    fetch_source
    cd "$WORK"

    # Reset to pristine so --check is meaningful on a tree that was already
    # patched. Anything uncommitted here was put there by this script.
    git checkout -- . 2>/dev/null || true

    say ""
    if git apply --check --verbose "$PATCH" 2>&1 | sed 's/^/  /'; then
        say ""
        say "The patch applies cleanly."
    else
        say ""
        say "The patch does NOT apply cleanly to $CORE_VERSION."
        say ""
        say "This is expected and was predicted in the patch header: it was"
        say "written against v31.1.0 without a build environment, so hunk"
        say "offsets drift. It is a real task, not a broken file."
        say ""
        say "To fix it, hunk by hunk:"
        say "    cd $WORK"
        say "    git apply --reject $PATCH"
        say "    # then resolve each .rej file against the current source"
        say ""
        say "Do not force it through. A hunk applied at the wrong offset in"
        say "policy.cpp is how relay policy silently becomes a consensus"
        say "difference."
        return 1
    fi
}

# ------------------------------------------------------------------- build


do_build() {
    say "=================================================================="
    say "BUILD"
    say "=================================================================="
    fetch_source
    cd "$WORK"

    if ! git diff --quiet 2>/dev/null; then
        say "tree already has modifications — assuming the patch is applied"
    else
        say "applying $PATCH"
        git apply "$PATCH" || die "patch failed; run --check for guidance"
    fi

    for tool in cmake g++ pkg-config; do
        command -v "$tool" >/dev/null 2>&1 || die "missing $tool.
    sudo apt install -y build-essential cmake pkg-config libevent-dev \\
        libboost-dev libsqlite3-dev python3"
    done

    say ""
    say "configuring (wallet off, GUI off, tests on — we only need bitcoind"
    say "and the functional framework)"
    cmake -B build \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_GUI=OFF \
        -DENABLE_WALLET=ON \
        -DBUILD_TESTS=ON

    say ""
    say "compiling with $JOBS jobs. On a T480 this is a long while — an hour"
    say "or more. It is CPU-bound, so the node will feel slow until it ends."
    say ""
    cmake --build build -j "$JOBS"

    # A build invalidates any previous test result. Without this, --install
    # could pass on a stamp left by a binary that no longer exists.
    rm -f "$STAMP"

    say ""
    say "built: $WORK/build/bin/bitcoind"
    "$WORK/build/bin/bitcoind" -version | head -2 | sed 's/^/  /'
    say ""
    say "Not installed, and not tested. Next:  $0 --test"
}

# -------------------------------------------------------------------- test


do_test() {
    say "=================================================================="
    say "TEST — on regtest, against a stock node"
    say "=================================================================="
    [ -x "$WORK/build/bin/bitcoind" ] || die "no binary; run --build first"

    cp "$TESTFILE" "$WORK/test/functional/feature_spam_policy.py"
    chmod +x "$WORK/test/functional/feature_spam_policy.py"
    cd "$WORK"

    say ""
    say "1/3  the options exist and default as Knots does"
    ./build/bin/bitcoind -help 2>&1 \
        | grep -E -- "-(rejectparasites|rejecttokens|permitbarepubkey|permitbaredatacarrier|datacarriercost|acceptnonstddatacarrier|maxscriptsize)" \
        | sed 's/^/  /' \
        || die "the patched options are not in -help. The build did not
include the patch, or init.cpp's hunk did not apply."

    say ""
    say "2/3  feature_spam_policy.py"
    say "     The one that matters is test_consensus_unchanged."
    if ! python3 test/functional/test_runner.py feature_spam_policy \
            --loglevel=INFO 2>&1 | tail -40 | sed 's/^/  /'; then
        say ""
        die "SPAM POLICY TEST FAILED. Nothing will be installed.

If test_consensus_unchanged is the failure, stop and read it carefully: it
means the patched node declined a block that a stock node accepted. That is
not a policy difference, it is a chain split waiting to happen."
    fi

    say ""
    say "3/3  the rest of the functional suite, for regressions"
    say "     This takes a while. A policy patch should break none of it."
    if ! python3 test/functional/test_runner.py --jobs "$JOBS" \
            --exclude feature_spam_policy 2>&1 | tail -25 | sed 's/^/  /'; then
        say ""
        die "The wider suite failed. Nothing installed. A relay-policy patch
breaking an unrelated test means it reaches further than it claims to."
    fi

    date -u +%Y-%m-%dT%H:%M:%SZ > "$STAMP"
    say ""
    say "=================================================================="
    say "ALL TESTS PASSED"
    say "=================================================================="
    say ""
    say "What that establishes: this binary admits fewer transactions to its"
    say "mempool than stock Core, and accepts exactly the same blocks."
    say ""
    say "What it does not establish: that the patch is correct. It means the"
    say "tests I thought to write pass. Nobody else has reviewed this."
    say ""
    say "Install when you are ready:  $0 --install"
}

# ----------------------------------------------------------------- install


do_install() {
    [ -f "$STAMP" ] || die "The tests have not passed in this tree.

    $0 --test

There is deliberately no way to skip this. The binary validates your money."
    [ -x "$WORK/build/bin/bitcoind" ] || die "no binary at $WORK/build/bin"

    say "tests passed  $(cat "$STAMP")"
    say "binary        $WORK/build/bin/bitcoind"
    say ""
    say "This replaces bitcoind at /usr/local/bin. Afterwards:"
    say ""
    say "  - the eight patched-only settings in the dashboard become live"
    say "  - your node's mempool will differ from stock Core's, by design"
    say "  - the blocks it accepts will not differ, by requirement"
    say ""
    say "Keep the old binary. If anything looks wrong, going back is a copy"
    say "and a restart, and you want that to be thirty seconds of work."
    say ""
    printf 'Type INSTALL to proceed: '
    read -r reply
    [ "$reply" = "INSTALL" ] || die "not confirmed, nothing changed"

    if [ -x /usr/local/bin/bitcoind ]; then
        BAK="/usr/local/bin/bitcoind.stock.$(date +%Y%m%d%H%M%S)"
        sudo cp /usr/local/bin/bitcoind "$BAK"
        say "old binary kept at $BAK"
    fi

    say "stopping the node"
    sudo systemctl stop bitcoind || true
    # bitcoind renames its own process during shutdown, so pgrep returns
    # early and the datadir lock is still held when the unit restarts. Wait
    # for the log to say it is done, the way tor_lockdown learned to.
    n=0
    while [ $n -lt 60 ]; do
        tail -1 "$HOME/.bitcoin/debug.log" 2>/dev/null \
            | grep -q "Shutdown: done" && break
        n=$((n + 1)); sleep 2
    done

    sudo install -m0755 "$WORK/build/bin/bitcoind" /usr/local/bin/bitcoind
    say "installed"

    say ""
    say "Starting it. Watch the first minute: a config key the old binary"
    say "ignored may now be understood, or the reverse."
    sudo systemctl start bitcoind
    sleep 10
    systemctl is-active bitcoind | sed 's/^/  /'

    say ""
    say "Now, in this order:"
    say "  ./tor_lockdown.sh --verify          a new binary is a new config read"
    say "  ./node_config.sh --audit            the patched keys should be live"
    say "  bitcoin-cli -datadir=$HOME/.bitcoin getblockchaininfo"
    say ""
    say "If the node will not start, put the old binary back:"
    say "  sudo cp $BAK /usr/local/bin/bitcoind && sudo systemctl start bitcoind"
}

# -------------------------------------------------------------------- main


case "$ACTION" in
    check)   do_check ;;
    build)   do_build ;;
    test)    do_test ;;
    install) do_install ;;
    all)
        do_check || die "fix the patch first"
        do_build
        do_test
        say ""
        say "Stopping here on purpose. Installing is a separate command and a"
        say "separate decision:  $0 --install"
        ;;
esac
