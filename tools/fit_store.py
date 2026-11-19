#!/usr/bin/env python3
"""
fit_store.py — will a monetary store fit on this disk, and from what height?

A monetary store is the blockchain minus the data carriers. Across the whole
chain that turned out to be a 6.33% saving, which means the store is roughly
the SAME SIZE as the blocks it was derived from. People assume stripping makes
the node small. It does not. It makes the node honest.

So on any machine that is already holding the blockchain, the question is not
"does a monetary node fit" but "from what height does one fit". This tool
answers that by measuring, not estimating: it walks the block files, totals
the real bytes at every height, and reports the lowest start height whose
store fits in the space you actually have.

It needs no node running. It reads blk*.dat directly, the same way
monetary_store.py --blocks does, so it works on an orphaned data directory
after the node that wrote it has been removed.

Usage:
    python3 fit_store.py --blocks ~/.bitcoin/blocks
    python3 fit_store.py --blocks /path/to/blocks --index-cache /tmp/idx
    python3 fit_store.py --blocks /path/to/blocks --free 382 --reserve 40
    python3 fit_store.py --selftest

  --free     GB available, if the store will live on a different filesystem
             than the blocks. Default: measured from --store-dir, or from the
             blocks directory's filesystem.
  --reserve  GB to keep free for everything else. Default 40: the daemon
             needs room for the chain to keep growing underneath it, and a
             disk at 100% takes the whole machine down, not just this app.

TWO NUMBERS, NOT ONE

The report gives a range for every candidate height:

  upper bound   the block bytes themselves. What the store costs if nothing
                in that range strips at all. This is the number to budget
                against, because it cannot be exceeded.
  measured      the same bytes at the 6.33% saving measured genesis-to-tip.
                Recent history strips harder than early history, so for a
                recent start height the real figure usually lands below this.

Budget against the upper bound. A derive that runs out of disk at hour seven
is worse than one that was never started.

BSD-2-Clause.
"""

import argparse
import os
import shutil
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import monetary_store as ms  # noqa: E402

GB = 1024 ** 3

# Measured genesis->tip, 2026-10: 720.3 GiB of blocks became a 674.7 GiB
# store. Carriers were 36.6 GiB; the rest of the difference is per-record
# overhead running the other way. Recorded as a ratio so the arithmetic here
# stays honest about where the figure came from.
MEASURED_RATIO = 674.7 / 720.3

# Per record: 32-byte claimed hash, 80-byte header, and the length and digest
# fields. Costs about 4 MiB per 30,000 blocks, which rounds to nothing at
# this scale but is cheap to carry.
RECORD_OVERHEAD = 128


def human(n):
    """GiB-based, matching every other tool in this repo."""
    return ms.human(n)


def cumulative_sizes(blocks_dir, cache_path=None):
    """
    Returns (heights, sizes) where sizes[h] is the on-disk bytes of the block
    at height h, for every height reachable from genesis.

    Raises SystemExit's message as a RuntimeError rather than exiting, so a
    caller can report an unusable directory instead of dying on a library
    call. monetary_store treats some of these as fatal; here they are not.
    """
    key = ms.load_xor_key(blocks_dir)
    try:
        blob, files = ms.build_index(blocks_dir, key, cache_path)
        by_hash, heights = ms.height_map(blob, files, 10 ** 9)
    except SystemExit as e:
        raise RuntimeError(str(e))

    sizes = {}
    for h, bh in heights.items():
        loc = by_hash.get(bh)
        if loc is None:
            continue
        sizes[h] = loc[2]
    return heights, sizes


def plan(sizes, budget, ratio=MEASURED_RATIO, overhead=RECORD_OVERHEAD):
    """
    Lowest start height whose store fits in `budget` bytes.

    Walks backwards from the tip accumulating bytes, because a store always
    ends at the tip -- you choose where it begins, never where it stops.

    Returns a dict with the chosen height, both bounds for it, and the tip.
    `fits_from` is None when even the single newest block does not fit.
    """
    if not sizes:
        return {"tip": 0, "fits_from": None, "upper": 0, "measured": 0,
                "blocks": 0, "budget": budget}

    tip = max(sizes)
    total = 0
    fits_from = None
    upper_at = 0
    for h in range(tip, -1, -1):
        sz = sizes.get(h)
        if sz is None:
            break
        nxt = total + sz + overhead
        if nxt > budget:
            break
        total = nxt
        fits_from = h
        upper_at = total

    if fits_from is None:
        return {"tip": tip, "fits_from": None, "upper": 0, "measured": 0,
                "blocks": 0, "budget": budget}

    return {
        "tip": tip,
        "fits_from": fits_from,
        "upper": upper_at,
        "measured": int(upper_at * ratio),
        "blocks": tip - fits_from + 1,
        "budget": budget,
    }


def bytes_from(sizes, start, overhead=RECORD_OVERHEAD):
    """Upper-bound store bytes for a store beginning at `start`."""
    if not sizes:
        return 0
    tip = max(sizes)
    total = 0
    for h in range(start, tip + 1):
        sz = sizes.get(h)
        if sz is None:
            continue
        total += sz + overhead
    return total


def report(sizes, budget, candidates=()):
    """Human-readable plan. Returns (ok, lines)."""
    lines = []
    p = plan(sizes, budget)

    if not sizes:
        return False, ["No blocks could be walked from genesis.",
                       "Nothing can be planned from this directory."]

    whole = bytes_from(sizes, 0)
    lines.append("=" * 66)
    lines.append("STORE FIT")
    lines.append("=" * 66)
    lines.append("")
    lines.append("  tip height          %d" % p["tip"])
    lines.append("  blocks on disk      %s" % human(whole))
    lines.append("  usable budget       %s" % human(budget))
    lines.append("")

    lines.append("  A genesis-to-tip store needs %s (upper bound)."
                 % human(whole))
    if whole <= budget:
        lines.append("  That fits. Start at 0 and keep the whole history.")
    else:
        lines.append("  That does NOT fit. Short by %s."
                     % human(whole - budget))
    lines.append("")

    if p["fits_from"] is None:
        lines.append("  Nothing fits, not even the newest block. Free space")
        lines.append("  or attach a larger disk before going further.")
        return False, lines

    lines.append("  Lowest start height that fits:  %d" % p["fits_from"])
    lines.append("    blocks covered    %d" % p["blocks"])
    lines.append("    upper bound       %s" % human(p["upper"]))
    lines.append("    at measured rate  %s" % human(p["measured"]))
    lines.append("")

    if candidates:
        lines.append("  Other start heights, for comparison:")
        lines.append("")
        lines.append("    %-10s %-12s %-12s %-12s"
                     % ("height", "blocks", "upper", "measured"))
        for c in sorted(candidates):
            if c > p["tip"]:
                continue
            b = bytes_from(sizes, c)
            mark = "" if b <= budget else "   DOES NOT FIT"
            lines.append("    %-10d %-12d %-12s %-12s%s"
                         % (c, p["tip"] - c + 1, human(b),
                            human(int(b * MEASURED_RATIO)), mark))
        lines.append("")

    lines.append("  Budget against the upper bound, not the measured rate.")
    lines.append("  The measured rate is a genesis-to-tip average and recent")
    lines.append("  history strips harder, so the real figure usually lands")
    lines.append("  below it -- but 'usually' is not a basis for an 8-hour")
    lines.append("  job on a disk that has no slack.")
    return True, lines


# ------------------------------------------------------------------ selftest


def _selftest():
    ok = [0]

    def check(name, cond):
        print(("PASS  " if cond else "FAIL  ") + name)
        if not cond:
            ok[0] = 1

    # Fixed sizes make the arithmetic checkable by hand.
    sizes = {h: 1000 for h in range(0, 101)}
    ov = 0

    p = plan(sizes, 1000 * 101, overhead=ov)
    check("whole chain fits exactly", p["fits_from"] == 0)
    check("whole chain upper bound", p["upper"] == 101_000)
    check("block count", p["blocks"] == 101)

    p = plan(sizes, 10_000, overhead=ov)
    check("10 blocks fit in 10 blocks of budget", p["fits_from"] == 91)
    check("ten blocks counted", p["blocks"] == 10)
    check("upper bound is the budget", p["upper"] == 10_000)

    p = plan(sizes, 10_500, overhead=ov)
    check("partial block does not round up", p["fits_from"] == 91)

    p = plan(sizes, 999, overhead=ov)
    check("nothing fits below one block", p["fits_from"] is None)
    check("tip still reported when nothing fits", p["tip"] == 100)

    p = plan({}, 10 ** 12)
    check("empty sizes is not a crash", p["fits_from"] is None)

    # Stores end at the tip. A budget covering 10 blocks must take the NEWEST
    # ten, never the oldest -- the whole point is to follow the chain.
    p = plan(sizes, 10_000, overhead=ov)
    check("store ends at the tip", p["fits_from"] + p["blocks"] - 1 == 100)

    # Overhead is charged per block, so it must move the answer.
    p = plan(sizes, 10_000, overhead=1000)
    check("overhead reduces what fits", p["blocks"] == 5)

    # A gap below the start height must not be silently walked through.
    gapped = {h: 1000 for h in range(0, 101)}
    del gapped[50]
    p = plan(gapped, 1000 * 101, overhead=ov)
    check("walk stops at a gap", p["fits_from"] == 51)

    check("bytes_from matches plan at the same height",
          bytes_from(sizes, 91, overhead=ov) == 10_000)
    check("bytes_from from genesis is everything",
          bytes_from(sizes, 0, overhead=ov) == 101_000)

    # The measured ratio must be a saving, not a growth. If someone edits the
    # constants and inverts this, every plan silently under-budgets.
    check("measured ratio is below 1", 0.5 < MEASURED_RATIO < 1.0)
    p = plan(sizes, 10_000, overhead=ov)
    check("measured is below upper", p["measured"] < p["upper"])

    r_ok, lines = report(sizes, 10_000, candidates=(0, 50, 91))
    body = "\n".join(lines)
    check("report says the whole chain does not fit",
          "does NOT fit" in body)
    check("report names the start height", "91" in body)
    check("report flags candidates that do not fit",
          "DOES NOT FIT" in body)
    check("report succeeds when something fits", r_ok)

    # report() charges the real per-record overhead, so the budget here has
    # to cover it too. Passing 1000*101 would fail, and the failure would be
    # the test's arithmetic rather than the code's.
    r_ok, lines = report(sizes, (1000 + RECORD_OVERHEAD) * 101, candidates=())
    check("report says the whole chain fits",
          "That fits" in "\n".join(lines))

    r_ok, lines = report({}, 10 ** 12)
    check("report on no blocks fails", not r_ok)

    r_ok, lines = report(sizes, 999)
    check("report fails when nothing fits", not r_ok)
    check("report says why nothing fits",
          "Nothing fits" in "\n".join(lines))

    check("human is GiB-based", human(1536) == "1.5 KiB")

    print("")
    print("ok" if ok[0] == 0 else "FAILURES")
    return ok[0]


def main():
    ap = argparse.ArgumentParser(
        description="Plan a monetary store against the disk you have.")
    ap.add_argument("--blocks", help="path to a blocks/ directory")
    ap.add_argument("--index-cache", help="reuse/!write a block index here")
    ap.add_argument("--store-dir",
                    help="where the store will live (for free-space "
                         "measurement); defaults to the blocks filesystem")
    ap.add_argument("--free", type=float,
                    help="GB available, overriding measurement")
    ap.add_argument("--reserve", type=float, default=40.0,
                    help="GB to leave free (default 40)")
    ap.add_argument("--candidates", default="0,700000,770000,800000,"
                                            "820000,850000,900000",
                    help="comma-separated heights to tabulate")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()

    if a.selftest:
        return _selftest()

    if not a.blocks:
        return ap.error("--blocks is required (or --selftest)")
    if not os.path.isdir(a.blocks):
        print("not a directory: %s" % a.blocks, file=sys.stderr)
        return 1

    if a.free is not None:
        free = int(a.free * GB)
        src = "given on the command line"
    else:
        probe = a.store_dir or a.blocks
        free = shutil.disk_usage(probe).free
        src = "measured on %s" % probe
    budget = free - int(a.reserve * GB)
    if budget <= 0:
        print("Free space (%s, %s) is below the %.0f GB reserve. Nothing to "
              "plan." % (human(free), src, a.reserve), file=sys.stderr)
        return 1

    try:
        heights, sizes = cumulative_sizes(a.blocks, a.index_cache)
    except RuntimeError as e:
        print("")
        print("Cannot walk these files from genesis: %s" % e)
        print("Either the early block files are missing, or this is not a")
        print("Bitcoin chain. Run chain_check.py --blocks before planning.")
        return 1

    print("")
    print("  free space          %s (%s)" % (human(free), src))
    print("  reserved            %s" % human(int(a.reserve * GB)))
    ok, lines = report(sizes, budget,
                       candidates=[int(x) for x in a.candidates.split(",")
                                   if x.strip()])
    print("")
    for ln in lines:
        print(ln)
    print("")
    print("This tool does not verify WHICH chain these blocks are on.")
    print("Run chain_check.py --blocks first. A perfectly-sized store of the")
    print("wrong chain is still the wrong chain.")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
