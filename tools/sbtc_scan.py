#!/usr/bin/env python3
"""
sbtc_scan.py — prove the carrier policy changes nothing already on chain.

Enabling the Shielded Bitcoin entry in carrier_policy.py only alters the
store, and therefore C, if some transaction at or below the measured tip
already carries an OP_RETURN that the entry retains. Shielded Bitcoin was
published on 24 September 2026 and nothing implements it, so the expected
count is zero — but expected is not measured, and C is a published number.

This measures it. For every block in range it asks the policy about every
OP_RETURN output and reports the ones where the new ruleset and the old
size rule disagree. That disagreement set, and nothing else, is what would
move C.

    python3 sbtc_scan.py --blocks ~/.bitcoin/blocks
    python3 sbtc_scan.py --blocks ~/.bitcoin/blocks --end 967984
    python3 sbtc_scan.py --blocks ~/.bitcoin/blocks --full    # slow, see below

WHY THIS IS FAST. A retained payload must begin with the four bytes "sbtc",
so a block whose raw bytes do not contain that substring cannot contain one.
Blocks are skipped on a memchr over the raw block rather than parsed. The
scan becomes disk-bound rather than CPU-bound: expect roughly an hour on
NVMe against many hours for a full parse.

That skip is exact for the question asked, not an approximation. Around 170
blocks will contain "sbtc" by chance in 720 GB, plus any that contain it as
text, and every one of those is parsed in full.

--full parses every transaction in every block instead, and additionally
reports the total OP_RETURN population. Use it if you want the census; the
default answers the question about C.

Imports monetary_store.py for block-file handling, so the two agree about
what a block is by construction. Run it from the directory holding both.

Exit status is 0 when nothing would change and 1 when something would, so
this can gate a republication of C.

BSD-2-Clause.
"""

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    import monetary_store as ms
except ImportError:
    sys.exit("monetary_store.py must sit alongside this script")

from carrier_policy import (OP_RETURN, OP_RETURN_LIMIT, Policy,
                            ShieldedBitcoinV1, op_return_pushes)

MAGIC = ShieldedBitcoinV1.magic


# ------------------------------------------------------------- tx traversal


def tx_output_scripts(c):
    """Advance the cursor past one transaction, yielding its scriptPubKeys.

    Returns [(vout_index, script)]. Witness data is skipped by length rather
    than interpreted: the carrier profile says indexers ignore witness bytes,
    and so does the store's OP_RETURN accounting.
    """
    c.u32()                                   # version
    n_in = c.varint()
    segwit = False
    if n_in == 0:                             # marker 0x00, then flag
        c.u8()
        segwit = True
        n_in = c.varint()
    for _ in range(n_in):
        c.take(36)                            # prevout
        c.take(c.varint())                    # scriptSig
        c.u32()                               # sequence
    outs = []
    for i in range(c.varint()):
        c.u64()                               # value
        outs.append((i, c.take(c.varint())))
    if segwit:
        for _ in range(n_in):
            for _ in range(c.varint()):
                c.take(c.varint())
    c.u32()                                   # locktime
    return outs


def block_op_returns(raw):
    """[(tx_index, vout_index, script)] for every OP_RETURN in a block."""
    c = ms.Cursor(raw)
    c.take(80)
    out = []
    for t in range(c.varint()):
        for i, spk in tx_output_scripts(c):
            if spk[:1] == bytes([OP_RETURN]):
                out.append((t, i, spk))
    return out


# -------------------------------------------------------------------- scan


def scan(blocks_dir, start, end, full, cache, progress_every):
    key = ms.load_xor_key(blocks_dir)
    # build_index returns (blob, files) in that order — blob is the packed
    # record bytes, files is [(path, size)]. Getting this backwards fails
    # deep inside height_map with a type error, not here.
    blob, files = ms.build_index(blocks_dir, key, cache)
    if not isinstance(blob, (bytes, bytearray)):
        sys.exit("build_index returned %s for blob — check the return order"
                 % type(blob).__name__)
    by_hash, heights = ms.height_map(blob, files, end)

    tip = max(heights)
    if end > tip:
        print("index reaches %d; scanning to there instead of %d"
              % (tip, end))
        end = tip
    if start > end:
        sys.exit("nothing to scan: start %d is above end %d" % (start, end))

    new = Policy()                            # sbtc entry active
    old = Policy(entries=[])                  # the published ruleset

    if not new.entries:
        sys.exit("the policy has no entries active — nothing to compare")

    handles = {}

    def read_block(h):
        path, off, size = by_hash[heights[h]]
        bf = handles.get(path)
        if bf is None:
            bf = handles[path] = ms.BlockFile(path, key)
        return bf.read_at(off, size)

    scanned = candidates = op_returns = oversized = 0
    parsed = 0
    hits = []
    unparsable = []
    t0 = time.time()

    try:
        for h in range(start, end + 1):
            if h not in heights:
                break
            raw = read_block(h)
            scanned += 1

            # The exact shortcut: an envelope starts with these four bytes.
            has_magic = MAGIC in raw
            if has_magic:
                candidates += 1
            if not (full or has_magic):
                if progress_every and scanned % progress_every == 0:
                    _tick(h, start, end, scanned, candidates, len(hits), t0)
                continue

            try:
                found = block_op_returns(raw)
            except Exception as e:
                # A block we cannot parse is not a block we can clear.
                unparsable.append((h, str(e)[:80]))
                continue
            parsed += 1

            for t, i, spk in found:
                op_returns += 1
                pushes = op_return_pushes(spk)
                payload = b"" if pushes is None \
                    else b"".join(d for d, _ in pushes)
                if len(payload) > OP_RETURN_LIMIT:
                    oversized += 1
                vn, vo = new.should_retain(spk), old.should_retain(spk)
                if vn.retain != vo.retain:
                    hits.append((h, t, i, vn, vo, payload[:32].hex()))
                    print("\n  DIVERGENCE  height %d tx %d vout %d" % (h, t, i))
                    print("    new: %r" % (vn,))
                    print("    old: %r" % (vo,))

            if progress_every and scanned % progress_every == 0:
                _tick(h, start, end, scanned, candidates, len(hits), t0)
    finally:
        for bf in handles.values():
            bf.close()

    el = time.time() - t0
    print("\n" + "=" * 66)
    print("SCAN COMPLETE")
    print("=" * 66)
    print("  heights              %d - %d" % (start, end))
    print("  blocks read          %d" % scanned)
    print("  contained \"sbtc\"     %d" % candidates)
    print("  blocks parsed        %d%s"
          % (parsed, "  (every block)" if full else "  (candidates only)"))
    if full:
        print("  OP_RETURN outputs    %d" % op_returns)
        print("  ... over %d bytes    %d" % (OP_RETURN_LIMIT, oversized))
    else:
        print("  OP_RETURN outputs    %d  (in parsed blocks only)" % op_returns)
    print("  elapsed              %s" % _hms(el))
    print("  policy_id            %s" % new.policy_id())

    if unparsable:
        print("\n  %d BLOCK(S) COULD NOT BE PARSED — not cleared:" % len(unparsable))
        for h, e in unparsable[:10]:
            print("    height %d: %s" % (h, e))
        print("\n  Resolve these before trusting the result. An unparsed block")
        print("  is an unanswered question, not a clean one.")
        return 1

    if hits:
        print("\n  %d OUTPUT(S) WOULD BE RETAINED THAT ARE STRIPPED TODAY."
              % len(hits))
        print("  C CHANGES. Do not republish the old value against the new")
        print("  policy — rebuild, or run with Policy(entries=[]).")
        return 1

    print("\n  No divergence. Every output in range is decided exactly as it")
    print("  was under the published ruleset, so C is unchanged:")
    print("    C = 026ae8b580757d50b4c7ead71de090e11c80f37a612caddc19cd7592f0ee97d4")
    print("  Publish policy_id beside it from now on.")
    return 0


def _hms(s):
    return "%dh%02dm%02ds" % (s // 3600, (s % 3600) // 60, s % 60)


def _tick(h, start, end, scanned, cand, hits, t0):
    el = time.time() - t0
    done = h - start + 1
    total = end - start + 1
    rate = done / el if el > 0 else 0
    eta = (total - done) / rate if rate > 0 else 0
    sys.stdout.write("\r  %d/%d  %.1f%%  %.0f blk/s  eta %s  "
                     "magic %d  divergences %d   "
                     % (done, total, 100.0 * done / total, rate,
                        _hms(eta), cand, hits))
    sys.stdout.flush()


# ---------------------------------------------------------------- selftest


def selftest():
    from carrier_policy import encode_op_return, _envelope
    ok = []

    def ck(label, cond, extra=""):
        ok.append(bool(cond))
        print("  [%s] %s%s" % ("ok  " if cond else "FAIL", label,
                               "" if cond else "  <- " + str(extra)))

    def tx(scripts, segwit=False):
        import struct
        b = struct.pack("<I", 1)
        b += b"\x00\x01" if segwit else b""
        b += b"\x01" + b"\x00" * 32 + b"\xff\xff\xff\xff" + b"\x00" \
            + b"\xff\xff\xff\xff"
        b += bytes([len(scripts)])
        for s in scripts:
            b += struct.pack("<Q", 0)
            b += ms.write_varint(len(s)) + s
        if segwit:
            b += b"\x01\x02ab"                 # one input, one 2-byte item
        return b + b"\x00" * 4

    def block(txs):
        return b"\x00" * 80 + bytes([len(txs)]) + b"".join(txs)

    env = _envelope(2, 2)
    spk = encode_op_return(env)

    ck("legacy tx outputs parsed",
       [s for _, s in tx_output_scripts(ms.Cursor(tx([spk])))] == [spk])
    ck("segwit tx outputs parsed",
       [s for _, s in tx_output_scripts(ms.Cursor(tx([spk], segwit=True)))]
       == [spk])
    ck("cursor lands exactly at the end of a segwit tx",
       _consumes_all(tx([spk], segwit=True)))
    ck("multiple outputs, indices correct",
       [i for i, _ in tx_output_scripts(ms.Cursor(tx([b"\x51", spk, b"\x51"])))]
       == [0, 1, 2])
    ck("block walk finds the OP_RETURN",
       block_op_returns(block([tx([b"\x51"]), tx([spk])]))
       == [(1, 0, spk)])
    ck("block with no OP_RETURN yields nothing",
       block_op_returns(block([tx([b"\x51"])])) == [])

    ck("the magic shortcut would not skip a real envelope",
       MAGIC in block([tx([spk])]),
       "if this fails the fast path is unsound")
    ck("a block of ordinary outputs lacks the magic",
       MAGIC not in block([tx([b"\x51" + b"\x20" + b"\x00" * 32])]))

    import inspect
    src = inspect.getsource(ms.build_index)
    ret = [l.strip() for l in src.splitlines() if l.strip().startswith("return")]
    ck("build_index returns (blob, files), not (files, blob)",
       ret == ["return bytes(kept), current"], ret)
    ck("height_map wants bytes first",
       list(inspect.signature(ms.height_map).parameters) == ["blob", "files", "max_height"])

    new, old = Policy(), Policy(entries=[])
    ck("policies disagree about a real envelope",
       new.should_retain(spk).retain and not old.should_retain(spk).retain,
       "otherwise the scan can never detect anything")
    ck("policies agree about an oversized blob",
       new.should_retain(encode_op_return(b"A" * 5000)).retain
       == old.should_retain(encode_op_return(b"A" * 5000)).retain)

    # End to end over the exact sequence the scan loop runs: prefilter,
    # parse, compare both policies. A scanner that cannot find a planted
    # envelope proves nothing when it finds none.
    def sweep(blk):
        if MAGIC not in blk:
            return "skipped"
        out = []
        for t, i, sp in block_op_returns(blk):
            if new.should_retain(sp).retain != old.should_retain(sp).retain:
                out.append((t, i))
        return out

    planted = block([tx([b"\x51"]), tx([b"\x51", spk])])
    ck("planted envelope is found at the right position",
       sweep(planted) == [(1, 1)], sweep(planted))
    ck("a 5000-byte blob is not a divergence",
       sweep(block([tx([encode_op_return(MAGIC + b"A" * 5000)])])) == [])
    ck("an ordinary block is skipped by the prefilter",
       sweep(block([tx([b"\x51"]), tx([encode_op_return(b"x" * 40)])]))
       == "skipped")
    ck("a padded envelope is not a divergence",
       sweep(block([tx([encode_op_return(_envelope(2, 2, pad=1))])])) == [])
    ck("every supported arity is caught",
       all(sweep(block([tx([encode_op_return(_envelope(a, b))])])) == [(0, 0)]
           for a in (1, 2, 8, 16) for b in (1, 2, 8, 16)))

    print("\n%d/%d passed" % (sum(ok), len(ok)))
    return 0 if all(ok) else 1


def _consumes_all(raw):
    c = ms.Cursor(raw)
    tx_output_scripts(c)
    return c.p == len(raw)


# -------------------------------------------------------------------- main


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--blocks", default=os.path.expanduser("~/.bitcoin/blocks"))
    ap.add_argument("--start", type=int, default=0)
    ap.add_argument("--end", type=int, default=10 ** 9,
                    help="default: the tip the index reaches")
    ap.add_argument("--full", action="store_true",
                    help="parse every block, not only those containing the "
                         "magic; also reports the OP_RETURN census")
    ap.add_argument("--cache", default=os.path.expanduser("~/.mstore_index"),
                    help="block index cache, shared with monetary_store.py")
    ap.add_argument("--progress", type=int, default=2000,
                    help="progress line every N blocks, 0 to silence")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()

    if a.selftest:
        return selftest()
    if not os.path.isdir(a.blocks):
        sys.exit("no such blocks directory: %s" % a.blocks)

    print("scanning %s" % a.blocks)
    print("mode     %s" % ("full parse" if a.full
                           else "magic prefilter (exact for this question)"))
    return scan(a.blocks, a.start, a.end, a.full, a.cache, a.progress)


if __name__ == "__main__":
    sys.exit(main())
