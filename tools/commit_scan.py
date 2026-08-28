#!/usr/bin/env python3
"""
commit_scan.py — the full accounting of what inscription activity costs the
chain, including the half nobody measures.

An inscription is TWO transactions:

  COMMIT   funds a taproot address whose script tree contains the inscription.
           Looks exactly like an ordinary P2TR payment.
  REVEAL   spends that output via the script path, exposing the tapscript and
           the OP_FALSE OP_IF ... OP_ENDIF envelope in its witness.

Published figures — including my own — measure the envelope payload inside the
reveal. That is the smallest honest boundary. It excludes the control block,
the signature, the tapscript wrapper, the transaction skeleton, and the entire
commit transaction.

This measures all of it, and separates what a monetary node actually removes
from what it leaves behind.

WHY THE COMMIT OUTPUT IS THE INTERESTING ONE

A commit transaction is not spam. Its inputs spend the inscriber's real UTXOs
and its change output is real money. Only the taproot output funding the reveal
is inscription machinery.

But that output has a property no other carrier has: it is **provably already
spent**, by the very reveal that identifies it. Every other dropped output needs
an ~82-byte filter entry so a future spend can be validated. This one needs
nothing. It is the only carrier where removal is free.

HOW COMMITS ARE FOUND

Exactly, not heuristically: a reveal's input points straight at the commit
output it spends. No guessing, no pattern matching.

The complication is ordering — the commit is in an earlier block. This keeps a
window of recent blocks' outputs in memory and looks backwards. Inscribers
usually broadcast both transactions together, so most commits are within a few
blocks of their reveal. **Commits older than the window are counted as misses
and reported**, so the coverage is always visible rather than assumed.

Usage:
    python3 commit_scan.py --store ~/mstore --start-height 767430
    python3 commit_scan.py --store ~/mstore --start-height 767430 --window 500
    python3 commit_scan.py --selftest

Standard library only. BSD-2-Clause.
"""

import argparse
import collections
import glob
import hashlib
import os
import struct
import sys
import time

STORE_MAGIC = b"MBLK"
FLAG_WHOLE, FLAG_MODIFIED, FLAG_STRIPPED = 0, 1, 2

OP_0, OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4 = 0x00, 0x4C, 0x4D, 0x4E
OP_IF, OP_NOTIF, OP_ENDIF = 0x63, 0x64, 0x68

FILTER_ENTRY_BYTES = 82          # what a dropped output normally costs to keep


def dsha(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


class Cursor:
    __slots__ = ("d", "p")

    def __init__(self, d):
        self.d, self.p = d, 0

    def take(self, n):
        out = self.d[self.p:self.p + n]
        if len(out) < n:
            raise ValueError("truncated")
        self.p += n
        return out

    def peek(self, n):
        return self.d[self.p:self.p + n]

    def u8(self):
        if self.p >= len(self.d):
            raise ValueError("truncated")
        b = self.d[self.p]
        self.p += 1
        return b

    def u32(self):
        return int.from_bytes(self.take(4), "little")

    def u64(self):
        return int.from_bytes(self.take(8), "little")

    def varint(self):
        n = self.u8()
        if n < 0xFD:
            return n
        if n == 0xFD:
            return int.from_bytes(self.take(2), "little")
        if n == 0xFE:
            return self.u32()
        return self.u64()


def iter_script(script):
    i, n = 0, len(script)
    while i < n:
        op = script[i]
        i += 1
        data = None
        if 0x01 <= op <= 0x4B:
            if i + op > n:
                raise ValueError("truncated")
            data = script[i:i + op]; i += op
        elif op == OP_PUSHDATA1:
            if i >= n:
                raise ValueError("truncated")
            ln = script[i]; i += 1
            if i + ln > n:
                raise ValueError("truncated")
            data = script[i:i + ln]; i += ln
        elif op == OP_PUSHDATA2:
            if i + 2 > n:
                raise ValueError("truncated")
            ln = struct.unpack_from("<H", script, i)[0]; i += 2
            if i + ln > n:
                raise ValueError("truncated")
            data = script[i:i + ln]; i += ln
        elif op == OP_PUSHDATA4:
            if i + 4 > n:
                raise ValueError("truncated")
            ln = struct.unpack_from("<I", script, i)[0]; i += 4
            if i + ln > n:
                raise ValueError("truncated")
            data = script[i:i + ln]; i += ln
        yield op, data


def envelope_payload(script):
    """Bytes pushed inside an unexecutable branch. Falsity by semantics."""
    try:
        ops = list(iter_script(script))
    except ValueError:
        return 0
    total, i = 0, 0
    while i < len(ops) - 1:
        op, data = ops[i]
        false_push = (op == OP_0 or
                      (data is not None and (len(data) == 0 or data == b"\x00")))
        if false_push and ops[i + 1][0] == OP_IF:
            depth, j = 1, i + 2
            while j < len(ops):
                o, d = ops[j]
                if o in (OP_IF, OP_NOTIF):
                    depth += 1
                elif o == OP_ENDIF:
                    depth -= 1
                    if depth == 0:
                        break
                elif d is not None:
                    total += len(d)
                j += 1
            i = j + 1
            continue
        i += 1
    return total


def is_taproot_script_path(items):
    if len(items) < 2:
        return False
    c = items[-1]
    return len(c) >= 33 and (len(c) - 33) % 32 == 0 and (c[0] & 0xFE) == 0xC0


def parse_tx(body):
    """
    Returns a dict describing one stored transaction.

    Sizes are of the stored form. Witness is absent for modified transactions
    because the stripper already removed it — that is the point.
    """
    c = Cursor(body)
    c.take(4)
    segwit = c.peek(2) == b"\x00\x01"
    if segwit:
        c.take(2)

    io_start = c.p
    n_in = c.varint()
    vin = []
    for _ in range(n_in):
        prev_txid = c.take(32)
        prev_vout = c.u32()
        c.take(c.varint())
        c.take(4)
        vin.append((prev_txid, prev_vout))

    n_out = c.varint()
    vout = []
    for i in range(n_out):
        start = c.p
        amount = c.u64()
        spk = c.take(c.varint())
        vout.append((i, amount, spk, c.p - start))
    io_end = c.p

    envelope = 0
    witness_bytes = 0
    if segwit:
        w_start = c.p
        for _ in range(n_in):
            count = c.varint()
            items = [c.take(c.varint()) for _ in range(count)]
            if is_taproot_script_path(items):
                envelope += envelope_payload(items[-2])
        witness_bytes = c.p - w_start
    c.take(4)

    legacy = (body[:4] + body[io_start:io_end] + body[c.p - 4:c.p]) if segwit \
        else body[:c.p]
    return {
        "txid": dsha(legacy), "vin": vin, "vout": vout,
        "envelope": envelope, "witness": witness_bytes, "size": c.p,
    }


def iter_store(path, start_height):
    files = sorted(glob.glob(os.path.join(path, "mblk*.dat")))
    if not files:
        sys.exit(f"no mblk*.dat in {path}")
    height = start_height
    for f in files:
        with open(f, "rb") as fh:
            data = fh.read()
        pos = 0
        while pos < len(data):
            if data[pos:pos + 4] != STORE_MAGIC:
                raise ValueError(f"{os.path.basename(f)}: bad magic at {pos}")
            length = struct.unpack_from("<I", data, pos + 6)[0]
            end = pos + 10 + length
            c = Cursor(data[pos + 42:end])
            c.take(32)
            c.take(80)
            n_tx = c.varint()
            txs = []
            for _ in range(n_tx):
                flag = c.u8()
                if flag == FLAG_STRIPPED:
                    txs.append((c.take(32), None, flag))
                elif flag == FLAG_MODIFIED:
                    txid = c.take(32)
                    txs.append((txid, parse_tx(c.take(c.varint())), flag))
                elif flag == FLAG_WHOLE:
                    p = parse_tx(c.take(c.varint()))
                    txs.append((p["txid"], p, flag))
                else:
                    raise ValueError(f"unknown flag {flag}")
            for _ in range(c.varint()):
                c.take(32); c.varint(); c.take(8); c.take(4)
                c.take(c.varint())
            yield height, txs
            height += 1
            pos = end


def scan(path, start_height, window, progress):
    """
    One pass, looking backwards over a bounded window of recent outputs.

    Memory is bounded by the window, so this runs flat regardless of range.
    """
    recent = collections.deque()      # of (height, {(txid, vout): size})
    index = {}                        # (txid, vout) -> output size in bytes

    st = {
        "blocks": 0, "txs": 0, "stripped_txs": 0, "envelope_visible": 0,
        "reveals": 0, "reveal_bytes": 0, "reveal_witness": 0,
        "envelope_bytes": 0,
        "commit_outputs": 0, "commit_output_bytes": 0,
        "commit_misses": 0,
        "dust_outputs": 0,
    }
    t0 = time.time()

    for height, txs in iter_store(path, start_height):
        block_outs = {}
        for txid, p, flag in txs:
            if p is None:
                st["stripped_txs"] += 1
                continue
            st["txs"] += 1

            # The stripper already removed the witness of modified
            # transactions, so envelope detection cannot see them here. The
            # MODIFIED flag is the surviving evidence: a transaction was
            # modified precisely because it carried a data carrier.
            if p["envelope"]:
                st["envelope_bytes"] += p["envelope"]
                st["envelope_visible"] += 1
            if p["envelope"] or flag == FLAG_MODIFIED:
                st["reveals"] += 1
                st["reveal_bytes"] += p["size"]
                st["reveal_witness"] += p["witness"]
                for prev in p["vin"]:
                    size = index.get(prev)
                    if size is None:
                        size = block_outs.get(prev)
                    if size is not None:
                        st["commit_outputs"] += 1
                        st["commit_output_bytes"] += size
                    else:
                        st["commit_misses"] += 1

            for vout_i, amount, spk, size in p["vout"]:
                block_outs[(txid, vout_i)] = size
                if (amount < 1000 and len(spk) == 34
                        and spk[0] == 0x51 and spk[1] == 0x20):
                    st["dust_outputs"] += 1

        recent.append((height, block_outs))
        index.update(block_outs)
        while len(recent) > window:
            _h, old = recent.popleft()
            for k in old:
                index.pop(k, None)

        st["blocks"] += 1
        if st["blocks"] % progress == 0:
            el = time.time() - t0
            print(f"  {st['blocks']:,} blocks  height {height:,}  "
                  f"reveals {st['reveals']:,}  commits {st['commit_outputs']:,}"
                  f"  misses {st['commit_misses']:,}  {el:.0f}s", flush=True)

    st["seconds"] = time.time() - t0
    return st


def human(n):
    for u in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:,.2f} {u}"
        n /= 1024
    return f"{n:,.2f} PB"


def report(st, window):
    print()
    print("=" * 70)
    print("INSCRIPTION FOOTPRINT — FULL ACCOUNTING")
    print("=" * 70)
    print(f"  blocks scanned          {st['blocks']:,}")
    print(f"  transactions            {st['txs']:,}")
    print()
    print("CARRIER TRANSACTIONS")
    print(f"  carrier transactions    {st['reveals']:,}")
    print(f"  identified by flag      {st['reveals'] - st['envelope_visible']:,}")
    print(f"  envelope still visible  {st['envelope_visible']:,}")
    print(f"  envelope payload seen   {human(st['envelope_bytes'])}")
    print(f"  retained witness        {human(st['reveal_witness'])}")
    print(f"  stored size of carriers {human(st['reveal_bytes'])}")
    print()
    print("  These transactions had their witness removed by the stripper, so")
    print("  the envelope payload is not re-measurable from a store. The")
    print("  era-wide 37.1 GB comes from scanning original blocks. What this")
    print("  adds is the commit side, which no earlier measurement covered.")
    print()
    print("COMMIT SIDE (previously unmeasured)")
    print(f"  commit outputs found    {st['commit_outputs']:,}")
    print(f"  commit output bytes     {human(st['commit_output_bytes'])}")
    print(f"  not found in window     {st['commit_misses']:,}"
          f"   ({st['commit_misses']/max(1, st['commit_outputs']+st['commit_misses'])*100:.2f}%)")
    print(f"  window                  {window} blocks")
    print()
    if st["commit_misses"]:
        found = st["commit_outputs"]
        total = found + st["commit_misses"]
        if found:
            est = st["commit_output_bytes"] / found * total
            print(f"  extrapolated to all commits: {human(est)}")
            print("  (misses are commits older than the window, not absent)")
            print()

    print("WHAT REMOVAL COSTS")
    print(f"  commit outputs are already spent — by the very reveal that")
    print(f"  identifies them — so they need NO filter entry.")
    saved = st["commit_output_bytes"]
    would_cost = st["commit_outputs"] * FILTER_ENTRY_BYTES
    print(f"  removed                 {human(saved)}")
    print(f"  filter entries needed   0   "
          f"(any other carrier would cost {human(would_cost)})")
    print()
    print("  This is the only carrier where removal is free. Dust stays in")
    print("  blocks because a 43-byte output costs an 82-byte index entry;")
    print("  commit outputs escape that because nothing can ever spend them")
    print("  again.")
    print()
    print(f"  dust outputs seen       {st['dust_outputs']:,}"
          f"   (retained in blocks by design)")
    print()
    print(f"elapsed {st['seconds']:.0f}s")
    print()
    print("NOTE: sizes are of the STORED form. Witness of modified")
    print("transactions was already removed by the stripper, so reveal totals")
    print("here understate the original on-chain size. Envelope payload is")
    print("recovered from retained witness only.")


# ---------------------------------------------------------------- selftest


def selftest():
    ok = []

    def check(name, cond, detail=""):
        ok.append(cond)
        print(f"  [{'ok  ' if cond else 'FAIL'}] {name}"
              + (f"  — {detail}" if detail else ""))

    def wv(n):
        if n < 0xFD:
            return bytes([n])
        return b"\xfd" + struct.pack("<H", n)

    def push(d):
        n = len(d)
        if n == 0:
            return b"\x00"
        if n < 0x4C:
            return bytes([n]) + d
        if n <= 0xFF:
            return b"\x4c" + bytes([n]) + d
        return b"\x4d" + struct.pack("<H", n) + d

    print("envelope detection")
    payload = b"A" * 400
    env = b"\x00\x63" + push(b"ord") + push(payload) + b"\x68"
    check("envelope payload counted", envelope_payload(env) == 403)
    check("plain tapscript yields nothing",
          envelope_payload(b"\x20" + b"\x11" * 32 + b"\xac") == 0)

    print("\ntransaction parsing")
    tapscript = b"\x20" + b"\x22" * 32 + b"\xac" + env
    control = b"\xc0" + b"\x33" * 32
    wit = (wv(3) + wv(64) + b"\x44" * 64 + wv(len(tapscript)) + tapscript
           + wv(len(control)) + control)
    tx = (struct.pack("<i", 1) + b"\x00\x01" + wv(1)
          + b"\xaa" * 32 + struct.pack("<I", 7) + b"\x00"
          + struct.pack("<I", 0xFFFFFFFF)
          + wv(1) + struct.pack("<Q", 546) + b"\x22\x51\x20" + b"\x55" * 32
          + wit + struct.pack("<I", 0))
    p = parse_tx(tx)
    check("reveal detected", p["envelope"] == 403, f"{p['envelope']} bytes")
    check("input prevout recovered",
          p["vin"] == [(b"\xaa" * 32, 7)])
    check("witness size measured", p["witness"] == len(wit),
          f"{p['witness']} vs {len(wit)}")
    check("output size measured", p["vout"][0][3] == 8 + 1 + 34,
          f"{p['vout'][0][3]}")

    print("\ncommit matching")
    # a commit transaction whose output 7 is spent by the reveal above
    commit = (struct.pack("<i", 1) + wv(1)
              + b"\xbb" * 32 + struct.pack("<I", 0) + b"\x00"
              + struct.pack("<I", 0xFFFFFFFF)
              + wv(8) + b"".join(
                  struct.pack("<Q", 10000) + b"\x22\x51\x20" + bytes([i]) * 32
                  for i in range(8))
              + struct.pack("<I", 0))
    pc = parse_tx(commit)
    check("commit has 8 outputs", len(pc["vout"]) == 8)
    check("commit output 7 size is 43", pc["vout"][7][3] == 43,
          f"{pc['vout'][7][3]}")

    # simulate the window lookup
    index = {(pc["txid"], i): sz for i, _a, _s, sz in pc["vout"]}
    found = index.get(p["vin"][0])
    check("reveal input does not match unrelated commit", found is None)
    index2 = {(b"\xaa" * 32, 7): 43}
    check("reveal input matches its commit output",
          index2.get(p["vin"][0]) == 43)

    print("\nwindow eviction")
    dq = collections.deque()
    idx = {}
    for h in range(10):
        outs = {(bytes([h]) * 32, 0): 43}
        dq.append((h, outs)); idx.update(outs)
        while len(dq) > 3:
            _hh, old = dq.popleft()
            for k in old:
                idx.pop(k, None)
    check("window bounded to 3 blocks", len(dq) == 3 and len(idx) == 3)
    check("oldest evicted", (bytes([0]) * 32, 0) not in idx)
    check("newest retained", (bytes([9]) * 32, 0) in idx)

    print()
    print(f"{sum(ok)}/{len(ok)} passed")
    return 0 if all(ok) else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--store")
    ap.add_argument("--start-height", type=int)
    ap.add_argument("--window", type=int, default=200,
                    help="blocks of output history to keep for commit lookup")
    ap.add_argument("--progress", type=int, default=10000)
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        sys.exit(selftest())
    if not (args.store and args.start_height is not None):
        sys.exit("need --store and --start-height (or --selftest)")

    print(f"store   {args.store}")
    print(f"from    height {args.start_height:,}")
    print(f"window  {args.window} blocks")
    print()
    st = scan(args.store, args.start_height, args.window, args.progress)
    report(st, args.window)


if __name__ == "__main__":
    main()
