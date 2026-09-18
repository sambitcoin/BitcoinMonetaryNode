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
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()

    if a.selftest:
        return selftest()

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
