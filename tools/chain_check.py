#!/usr/bin/env python3
"""
chain_check.py — confirm a node is on Bitcoin before anything irreversible.

Run this before stripping, converting or pruning. A monetary store is only
meaningful if every node computed it over the same chain: the commitment C is
a hash over what was stored, so two nodes on different chains produce
different C values and neither is wrong. Worse, stripping the wrong chain is
days of work that has to be thrown away.

This is not hypothetical. On 2026-08-08 a chain split occurred at height
961,632 over BIP-110, and on 2026-08-30 the minority chain changed its
proof-of-work from SHA256d to BLAKE2b. A node synced with the wrong release
reaches a plausible-looking tip, reports "Chain: main", shows no warnings, and
is on a different chain. The only cheap way to notice is to compare block
hashes against a reference.

Standard library only. Reads; never writes. Exit status 0 means the node
matched every checkpoint it could be tested against, 1 means it did not.

Usage:
    python3 chain_check.py
    python3 chain_check.py --datadir ~/.bitcoin
    python3 chain_check.py --rpc-url http://127.0.0.1:8332 --cookie /path/.cookie
    python3 chain_check.py --selftest

BSD-2-Clause.
"""

import argparse
import base64
import json
import os
import sys
import urllib.error
import urllib.request

# ---------------------------------------------------------------- checkpoints
#
# Block hashes on Bitcoin (SHA256d). These are a trust assumption and should
# be treated as one: verify them yourself against sources you choose before
# relying on this tool. Every entry below was taken from a block explorer and
# is independently checkable in seconds.
#
# 840,000 is the 2024 halving block, which is widely published and easy to
# confirm from memory or a search. 961,632 is the BIP-110 activation height
# where the 2026 split occurred, and is the checkpoint that actually catches
# the failure this tool exists for.

CHECKPOINTS = {
    0:       "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
    840_000: "0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5",
    961_600: "0000000000000000000070f326449fa434aacb647269dd38cabe4444b0bf98d8",
    961_632: "00000000000000000000d1e01392faa65ceeaed307f0a3159144b84146ff24ba",
    966_000: "0000000000000000000013b8a367391f68a9891808c636ced0a399cdc1e0d5ab",
}

SPLIT_HEIGHT = 961_632


class RPCError(Exception):
    pass


class RPC:
    """Minimal Bitcoin RPC client. Cookie auth by default."""

    def __init__(self, url, user=None, password=None, cookie=None, timeout=30):
        self.url = url
        self.timeout = timeout
        if user is None and cookie:
            with open(cookie, "r") as fh:
                user, password = fh.read().strip().split(":", 1)
        if user is None:
            raise RPCError("no credentials: pass --cookie or --rpc-user/--rpc-password")
        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        self.auth = f"Basic {token}"

    def call(self, method, *params):
        body = json.dumps({"jsonrpc": "1.0", "id": "chain_check",
                           "method": method, "params": list(params)}).encode()
        req = urllib.request.Request(
            self.url, data=body,
            headers={"Content-Type": "application/json",
                     "Authorization": self.auth})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                payload = json.loads(r.read().decode())
        except urllib.error.URLError as e:
            raise RPCError(f"cannot reach {self.url}: {e}") from None
        if payload.get("error"):
            raise RPCError(f"{method}: {payload['error']}")
        return payload["result"]


def default_cookie(datadir):
    return os.path.join(os.path.expanduser(datadir), ".cookie")


# ---------------------------------------------------------------- the check


def check_blocks(blocks_dir, cache=None, checkpoints=None):
    """Same check, straight from blk*.dat, with no node running.

    WHY THIS EXISTS. A monetary node is meant to work without bitcoind, and
    the most important thing to know before deriving a store is which chain
    the block files belong to. Until now that could only be answered by
    asking a running node — so the one check you must not skip was
    impossible in exactly the situation this project is for: an orphaned
    datadir, a decommissioned node, a drive carried over from elsewhere.

    Reads nothing but headers. The index walks prev-hash links from genesis,
    so it also establishes that the files form one chain rather than a heap
    of blocks that merely contains the right ones.
    """
    checkpoints = CHECKPOINTS if checkpoints is None else checkpoints
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    try:
        import monetary_store as ms
    except ImportError as e:
        return False, [f"need monetary_store.py beside this file: {e}"], {}

    lines = []
    key = ms.load_xor_key(blocks_dir)
    lines.append("blocks dir      %s" % blocks_dir)
    lines.append("XOR key         %s"
                 % ("present (Core 28+)" if key else "none"))

    blob, files = ms.build_index(blocks_dir, key,
                                 cache or os.path.expanduser("~/.mstore_index"))
    # height_map exits the process when it cannot find genesis — fine for a
    # command line tool, wrong for this, which is a check whose whole job is
    # to report a verdict. An orphaned datadir missing its early files is
    # exactly the input this mode exists for, and it must come back with an
    # answer rather than killing the caller.
    try:
        by_hash, heights = ms.height_map(blob, files, max(checkpoints) + 1)
    except SystemExit as e:
        lines.append("")
        lines.append("Cannot walk these files from genesis: %s" % e)
        lines.append("Either the early block files are missing, or they are")
        lines.append("not a Bitcoin chain. Nothing can be derived from them.")
        return False, lines, {"tip": 0, "tested": 0, "skipped": 0}
    tip = max(heights) if heights else 0

    lines.append("block files     %d" % len(files))
    lines.append("highest linked  %s" % f"{tip:,}")
    lines.append("")

    ok, tested, skipped = True, 0, 0
    for height in sorted(checkpoints):
        want = checkpoints[height]
        if height not in heights:
            lines.append(f"  [skip] {height:>9,}  not reachable from genesis"
                         " in these files")
            skipped += 1
            continue
        got = heights[height][::-1].hex()
        if got == want:
            lines.append(f"  [ok  ] {height:>9,}  {got}")
            tested += 1
        else:
            ok = False
            lines.append(f"  [FAIL] {height:>9,}")
            lines.append(f"           expected {want}")
            lines.append(f"           files have {got}")
            if height >= SPLIT_HEIGHT:
                lines.append("           at or above the 2026 split height —"
                             " these files are the wrong chain")

    lines.append("")
    if tested == 0:
        ok = False
        lines.append("NO CHECKPOINTS TESTED. These files do not reach any"
                     " known height, so this proves nothing.")
    elif not ok:
        lines.append("MISMATCH. Do not derive a store from these files.")
    else:
        lines.append(f"All {tested} checkpoints matched"
                     + (f", {skipped} not reached." if skipped else "."))
        lines.append("These files are the SHA256 chain and form one chain"
                     " from genesis.")
    return ok, lines, {"tip": tip, "tested": tested, "skipped": skipped}


def check(rpc, checkpoints=None):
    """Compare a node against the checkpoints. Returns (ok, lines, facts)."""
    checkpoints = CHECKPOINTS if checkpoints is None else checkpoints
    info = rpc.call("getblockchaininfo")
    tip = info["blocks"]
    lines = []
    ok = True

    lines.append(f"chain           {info.get('chain')}")
    lines.append(f"tip height      {tip:,}")
    lines.append(f"tip hash        {info.get('bestblockhash')}")
    lines.append(f"chain work      {info.get('chainwork')}")
    lines.append(f"IBD             {info.get('initialblockdownload')}")
    lines.append("")

    if info.get("chain") != "main":
        lines.append(f"NOT MAINNET: chain is {info.get('chain')!r}")
        return False, lines, {"tip": tip}

    tested = skipped = 0
    for height in sorted(checkpoints):
        want = checkpoints[height]
        if height > tip:
            lines.append(f"  [skip] {height:>9,}  above this node's tip")
            skipped += 1
            continue
        got = rpc.call("getblockhash", height)
        if got == want:
            lines.append(f"  [ok  ] {height:>9,}  {got}")
            tested += 1
        else:
            ok = False
            lines.append(f"  [FAIL] {height:>9,}")
            lines.append(f"           expected {want}")
            lines.append(f"           node has {got}")
            if height >= SPLIT_HEIGHT:
                lines.append("           this is at or above the 2026 split"
                             " height — likely the wrong chain")

    lines.append("")
    if tested == 0:
        ok = False
        lines.append("NO CHECKPOINTS TESTED. The node is below every known"
                     " height, so this proves nothing.")
    elif not ok:
        lines.append("MISMATCH. Do not strip, convert or prune this node.")
    elif skipped:
        lines.append(f"{tested} checkpoints matched, {skipped} above the tip.")
        lines.append("Node is still syncing: re-run once it reaches the tip,"
                     " because the checkpoints it has not reached are the")
        lines.append("ones that would catch a post-split divergence.")
    else:
        lines.append(f"All {tested} checkpoints matched.")

    return ok, lines, {"tip": tip, "tested": tested, "skipped": skipped}


def compare(rpc_a, rpc_b, heights):
    """Cross-check two nodes at the same heights. Checkpoint-free."""
    lines = []
    ok = True
    tip = min(rpc_a.call("getblockchaininfo")["blocks"],
              rpc_b.call("getblockchaininfo")["blocks"])
    for h in heights:
        if h > tip:
            continue
        a = rpc_a.call("getblockhash", h)
        b = rpc_b.call("getblockhash", h)
        same = a == b
        ok = ok and same
        lines.append(f"  [{'ok  ' if same else 'FAIL'}] {h:>9,}  "
                     + (a if same else f"\n           A {a}\n           B {b}"))
    return ok, lines


# ---------------------------------------------------------------- self-test


def selftest():
    passed = []

    def ck(name, cond, detail=""):
        passed.append(cond)
        print(f"  [{'ok  ' if cond else 'FAIL'}] {name}"
              + (f"  — {detail}" if detail else ""))

    class Fake:
        """A node that answers from a dict, so the check logic is testable."""
        def __init__(self, tip, hashes, chain="main"):
            self.tip, self.hashes, self.chain = tip, hashes, chain
            self.asked = []

        def call(self, method, *params):
            if method == "getblockchaininfo":
                return {"chain": self.chain, "blocks": self.tip,
                        "bestblockhash": "ff" * 32, "chainwork": "00" * 32,
                        "initialblockdownload": False}
            if method == "getblockhash":
                self.asked.append(params[0])
                return self.hashes.get(params[0], "de" * 32)
            raise AssertionError(method)

    good = Fake(970_000, dict(CHECKPOINTS))
    ok, _lines, facts = check(good)
    ck("node matching every checkpoint passes", ok)
    ck("all checkpoints were tested", facts["tested"] == len(CHECKPOINTS),
       f"tested {facts['tested']}")

    # the real failure: correct below the split, divergent at and above it
    forked = dict(CHECKPOINTS)
    forked[961_632] = "aa" * 32
    forked[966_000] = "bb" * 32
    ok, lines, _ = check(Fake(972_800, forked))
    ck("post-split divergence is caught", not ok)
    ck("failure names the split height",
       any("2026 split" in ln for ln in lines))
    ck("pre-split checkpoints still report ok",
       any("961,600" in ln and "[ok" in ln for ln in lines))

    # a node still syncing must not be reported as verified
    syncing = Fake(900_000, dict(CHECKPOINTS))
    ok, lines, facts = check(syncing)
    ck("syncing node passes on what it can test", ok)
    ck("untested checkpoints are counted as skipped", facts["skipped"] == 3,
       f"skipped {facts['skipped']}")
    ck("output warns the decisive checkpoints were not reached",
       any("still syncing" in ln for ln in lines))

    # a node below every checkpoint proves nothing and must not pass
    ok, lines, facts = check(Fake(-1, {}), {840_000: "ab" * 32})
    ck("node below all checkpoints fails rather than passes", not ok)
    ck("says plainly that nothing was proven",
       any("proves nothing" in ln for ln in lines))

    # wrong network short-circuits before any height is queried
    testnet = Fake(970_000, dict(CHECKPOINTS), chain="test")
    ok, lines, _ = check(testnet)
    ck("non-mainnet rejected", not ok)
    ck("no block hashes requested once chain is wrong",
       testnet.asked == [], f"asked {testnet.asked}")

    # two-node comparison
    a = Fake(970_000, {100: "aa" * 32, 200: "bb" * 32})
    b = Fake(970_000, {100: "aa" * 32, 200: "cc" * 32})
    ok, lines = compare(a, b, [100])
    ck("agreeing nodes compare equal", ok)
    ok, lines = compare(a, b, [100, 200])
    ck("disagreeing nodes are caught", not ok)

    # --- from block files, with no node ------------------------------
    #
    # The point of this mode is that it works when nothing is running, so
    # the test builds real blk files and reads them rather than mocking RPC.
    print("\nfrom block files, no node")
    import struct
    import tempfile
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import monetary_store as ms

    base = tempfile.mkdtemp()
    d1 = os.path.join(base, "blocks")
    os.makedirs(d1, exist_ok=True)
    prev, hashes = b"\x00" * 32, {}
    with open(os.path.join(d1, "blk00000.dat"), "wb") as f:
        for i in range(6):
            hdr = (struct.pack("<i", 4) + prev + b"\x22" * 32
                   + struct.pack("<III", 1700000000, 0x1d00ffff, i))
            body = hdr + b"\x00"
            f.write(b"\xf9\xbe\xb4\xd9" + struct.pack("<I", len(body)) + body)
            prev = ms.dsha(hdr)
            hashes[i] = prev

    # height_map walks from the real genesis hash. These synthetic blocks
    # cannot have it, so point the constant at this chain's first block.
    real_genesis = ms.GENESIS
    ms.GENESIS = hashes[0]
    cps = {3: hashes[3][::-1].hex(), 5: hashes[5][::-1].hex()}
    good, lines, facts = check_blocks(d1, os.path.join(base, "c1"), cps)
    ck("matching files pass with no node running", good, lines[-1])
    ck("it reports how many checkpoints it tested", facts["tested"] == 2)
    ck("and says the files form one chain from genesis",
       any("one chain from genesis" in x for x in lines))

    bad, lines, _ = check_blocks(d1, os.path.join(base, "c2"), {3: "aa" * 32})
    ck("a wrong hash at a known height fails", not bad)
    ck("and the failure names both hashes",
       any("expected" in x for x in lines)
       and any("files have" in x for x in lines))

    _b2, lines, _ = check_blocks(d1, os.path.join(base, "c3"),
                                 {SPLIT_HEIGHT: "bb" * 32})
    ck("a checkpoint the files never reach is skipped, not failed",
       any("not reachable from genesis" in x for x in lines))

    # A datadir with no genesis must return a verdict, not exit. This is the
    # orphaned-drive case the mode is for.
    ms.GENESIS = real_genesis
    nog, lines, _ = check_blocks(d1, os.path.join(base, "c4"), cps)
    ck("a datadir without genesis reports instead of exiting", not nog)
    ck("and says what is wrong",
       any("Cannot walk these files from genesis" in x for x in lines))

    print(f"\n{sum(passed)}/{len(passed)} passed")
    return 0 if all(passed) else 1


# ---------------------------------------------------------------- main


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rpc-url", default="http://127.0.0.1:8332")
    ap.add_argument("--datadir", default="~/.bitcoin")
    ap.add_argument("--cookie", help="path to .cookie (default: datadir/.cookie)")
    ap.add_argument("--rpc-user")
    ap.add_argument("--rpc-password")
    ap.add_argument("--compare-url", help="second node's RPC URL to cross-check")
    ap.add_argument("--compare-cookie")
    ap.add_argument("--blocks", metavar="DIR",
                    help="check blk*.dat directly, with no node running. "
                         "For an orphaned datadir, a decommissioned node, or "
                         "a drive carried over from another machine.")
    ap.add_argument("--index-cache",
                    default=os.path.expanduser("~/.mstore_index"))
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()

    if a.selftest:
        return selftest()

    if a.blocks:
        ok, lines, _facts = check_blocks(a.blocks, a.index_cache)
        for line in lines:
            print(line)
        return 0 if ok else 1

    try:
        rpc = RPC(a.rpc_url, a.rpc_user, a.rpc_password,
                  a.cookie or default_cookie(a.datadir))
        ok, lines, facts = check(rpc)
    except (RPCError, OSError) as e:
        print(f"chain_check: {e}", file=sys.stderr)
        return 2

    print("=" * 70)
    print("CHAIN CHECK")
    print("=" * 70)
    for ln in lines:
        print(ln)

    if a.compare_url:
        try:
            other = RPC(a.compare_url, a.rpc_user, a.rpc_password,
                        a.compare_cookie)
            print()
            print("second node")
            same, clines = compare(rpc, other, sorted(CHECKPOINTS))
            for ln in clines:
                print(ln)
            if not same:
                ok = False
                print("\nThe two nodes disagree. At most one of them is on"
                      " Bitcoin.")
        except (RPCError, OSError) as e:
            print(f"\nsecond node unreachable: {e}")

    print("=" * 70)
    print("SAFE TO PROCEED" if ok else "DO NOT PROCEED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
