#!/usr/bin/env python3
"""
inscription_scan_local.py — measure inscription envelope payload bytes by
reading Bitcoin block files directly. No RPC, no network, no rate limits.

Handles the XOR-obfuscated blocksdir introduced in Bitcoin Core 28 (and
inherited by Knots): if blocks/xor.dat is present, its 8-byte key is applied
cyclically by absolute file offset to decode block data on read.

Reads blk*.dat, builds the block index itself, then parses only the blocks in
the requested height range.

Usage:
    python3 inscription_scan_local.py \
        --blocks /data/umbrel-os/home/umbrel/umbrel/app-data/bitcoin-knots/data/bitcoin/blocks \
        --start 767430 --end 962292 \
        --csv ~/inscription_results.csv

    # resume after an interruption
    ... same command ... --resume

Standard library only. Python 3.8+.
"""

import argparse
import glob
import hashlib
import os
import struct
import sys
import time

MAINNET_MAGIC = b"\xf9\xbe\xb4\xd9"
GENESIS = bytes.fromhex(
    "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000")

CSV_HEADER = (
    "height,block_bytes,tx_count,witness_bytes,envelope_count,"
    "envelope_payload_bytes,ord_envelope_count,ord_payload_bytes,"
    "malformed_scripts\n"
)

FIELDS = ("block_bytes", "tx_count", "witness_bytes", "envelope_count",
          "envelope_payload_bytes", "ord_envelope_count", "ord_payload_bytes",
          "malformed_scripts")


def dsha(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


# ---------------------------------------------------------------- xor blocksdir


def load_xor_key(blocks_dir):
    """Return the 8-byte obfuscation key, or None if the dir isn't obfuscated."""
    path = os.path.join(blocks_dir, "xor.dat")
    if not os.path.exists(path):
        return None
    with open(path, "rb") as f:
        key = f.read()
    if len(key) != 8:
        sys.exit(f"unexpected xor.dat length {len(key)} (expected 8)")
    if key == b"\x00" * 8:
        return None
    return key


def dexor(data, key, offset):
    """
    Undo the blocksdir obfuscation.

    The key repeats every 8 bytes, indexed by absolute position in the file, so
    the tile must be phase-aligned to `offset`. Done as one big-integer XOR
    rather than a Python loop — a 4MB block decodes in milliseconds.
    """
    if not key or not data:
        return data
    n = len(data)
    phase = offset % 8
    tile = key[phase:] + key * (n // 8 + 2)
    tile = tile[:n]
    return (int.from_bytes(data, "big") ^ int.from_bytes(tile, "big")).to_bytes(
        n, "big")


class BlockFile:
    """A blk*.dat opened for sequential or random access, XOR-aware."""

    def __init__(self, path, key):
        self.path = path
        self.key = key
        self.fh = open(path, "rb")

    def read_at(self, offset, n):
        self.fh.seek(offset)
        return dexor(self.fh.read(n), self.key, offset)

    def read_seq(self, n):
        offset = self.fh.tell()
        return dexor(self.fh.read(n), self.key, offset)

    def tell(self):
        return self.fh.tell()

    def seek(self, pos):
        self.fh.seek(pos)

    def close(self):
        self.fh.close()


# ---------------------------------------------------------------- index pass


def index_block_files(blocks_dir, key):
    """
    First pass: walk every blk*.dat reading only headers.

    Returns:
        by_hash:  block_hash -> (file_path, data_offset, size)
        children: prev_hash  -> [block_hash, ...]
    """
    by_hash = {}
    children = {}
    files = sorted(glob.glob(os.path.join(blocks_dir, "blk*.dat")))
    if not files:
        sys.exit(f"no blk*.dat found in {blocks_dir}")

    print(f"indexing {len(files)} block files"
          f"{' (XOR-obfuscated)' if key else ''}...", flush=True)
    t0 = time.time()

    for n, path in enumerate(files, 1):
        bf = BlockFile(path, key)
        try:
            while True:
                head = bf.read_seq(8)
                if len(head) < 8:
                    break
                if head[:4] != MAINNET_MAGIC:
                    break  # padding / end of useful data
                size = struct.unpack("<I", head[4:])[0]
                if size < 80 or size > 8_000_000:
                    break
                offset = bf.tell()
                header = bf.read_seq(80)
                if len(header) < 80:
                    break
                bh = dsha(header)
                prev = header[4:36]
                by_hash[bh] = (path, offset, size)
                children.setdefault(prev, []).append(bh)
                bf.seek(offset + size)
        finally:
            bf.close()

        if n % 250 == 0 or n == len(files):
            print(f"  {n}/{len(files)} files, {len(by_hash):,} blocks, "
                  f"{time.time()-t0:.0f}s", flush=True)

    print(f"indexed {len(by_hash):,} blocks in {time.time()-t0:.0f}s", flush=True)
    return by_hash, children


def build_height_map(by_hash, children, max_height):
    """
    Walk forward from genesis assigning heights, preferring the branch that
    extends furthest at any fork. Drops orphans.
    """
    if GENESIS not in by_hash:
        sys.exit("genesis block not found — is this a mainnet blocks directory?")

    def depth_from(h, limit=200):
        d, cur = 0, h
        while d < limit:
            kids = children.get(cur)
            if not kids:
                break
            cur = kids[0]
            d += 1
        return d

    heights = {}
    cur, h = GENESIS, 0
    while h <= max_height:
        heights[h] = cur
        kids = children.get(cur)
        if not kids:
            break
        cur = kids[0] if len(kids) == 1 else max(kids, key=depth_from)
        h += 1

    print(f"height map built to {max(heights):,}", flush=True)
    return heights


# ---------------------------------------------------------------- parsing


class Reader:
    __slots__ = ("data", "pos")

    def __init__(self, data):
        self.data = data
        self.pos = 0

    def read(self, n):
        if self.pos + n > len(self.data):
            raise ValueError("read past end")
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def peek(self, n=1):
        return self.data[self.pos:self.pos + n]

    def u8(self):
        b = self.data[self.pos]
        self.pos += 1
        return b

    def u32(self):
        v = struct.unpack_from("<I", self.data, self.pos)[0]
        self.pos += 4
        return v

    def u64(self):
        v = struct.unpack_from("<Q", self.data, self.pos)[0]
        self.pos += 8
        return v

    def varint(self):
        n = self.u8()
        if n < 0xFD:
            return n
        if n == 0xFD:
            v = struct.unpack_from("<H", self.data, self.pos)[0]
            self.pos += 2
            return v
        if n == 0xFE:
            return self.u32()
        return self.u64()


OP_0, OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4 = 0x00, 0x4C, 0x4D, 0x4E
OP_IF, OP_NOTIF, OP_ENDIF = 0x63, 0x64, 0x68
ORD_MARKER = b"ord"


def iter_script(script):
    i, n = 0, len(script)
    while i < n:
        start = i
        op = script[i]
        i += 1
        data = None
        if 0x01 <= op <= 0x4B:
            if i + op > n:
                raise ValueError("truncated push")
            data = script[i:i + op]; i += op
        elif op == OP_PUSHDATA1:
            if i + 1 > n:
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
        yield op, data, i - start


def find_envelopes(script):
    """Unexecutable OP_IF branches; falsity by script semantics, not literals."""
    out = []
    try:
        ops = list(iter_script(script))
    except ValueError:
        return out

    i = 0
    while i < len(ops) - 1:
        op, data, _ = ops[i]
        pushes_false = (op == OP_0 or
                        (data is not None and (len(data) == 0 or data == b"\x00")))
        if pushes_false and ops[i + 1][0] == OP_IF:
            depth, payload, has_ord = 1, 0, False
            j = i + 2
            while j < len(ops):
                op_j, data_j, _ = ops[j]
                if op_j in (OP_IF, OP_NOTIF):
                    depth += 1
                elif op_j == OP_ENDIF:
                    depth -= 1
                    if depth == 0:
                        break
                elif data_j is not None:
                    payload += len(data_j)
                    if data_j == ORD_MARKER:
                        has_ord = True
                j += 1
            if depth == 0:
                out.append((payload, has_ord))
            i = j + 1
            continue
        i += 1
    return out


def is_taproot_script_path(items):
    if len(items) < 2:
        return False
    c = items[-1]
    if len(c) < 33 or (len(c) - 33) % 32 != 0:
        return False
    return (c[0] & 0xFE) == 0xC0


def scan_block(data):
    r = Reader(data)
    r.read(80)
    n_tx = r.varint()

    s = dict.fromkeys(FIELDS, 0)
    s["block_bytes"] = len(data)
    s["tx_count"] = n_tx

    for _ in range(n_tx):
        r.u32()
        segwit = r.peek(2) == b"\x00\x01"
        if segwit:
            r.read(2)

        n_in = r.varint()
        for _ in range(n_in):
            r.read(32); r.u32(); r.read(r.varint()); r.u32()

        for _ in range(r.varint()):
            r.u64(); r.read(r.varint())

        if segwit:
            w0 = r.pos
            for _ in range(n_in):
                items = [r.read(r.varint()) for _ in range(r.varint())]
                if is_taproot_script_path(items):
                    ts = items[-2]
                    found = find_envelopes(ts)
                    if not found and b"\x00\x63" in ts:
                        s["malformed_scripts"] += 1
                    for payload, has_ord in found:
                        s["envelope_count"] += 1
                        s["envelope_payload_bytes"] += payload
                        if has_ord:
                            s["ord_envelope_count"] += 1
                            s["ord_payload_bytes"] += payload
            s["witness_bytes"] += (r.pos - w0) + 2

        r.u32()

    return s


# ---------------------------------------------------------------- helpers


def human(n):
    for u in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:,.1f} {u}"
        n /= 1024
    return f"{n:,.1f} PB"


def hms(sec):
    sec = int(sec)
    h, rem = divmod(sec, 3600)
    m, s = divmod(rem, 60)
    return f"{h}h{m:02d}m" if h else f"{m}m{s:02d}s"


def read_existing(path):
    totals = dict.fromkeys(FIELDS, 0)
    last = None
    if not path or not os.path.exists(path):
        return last, totals
    with open(path) as f:
        next(f, None)
        for line in f:
            p = line.strip().split(",")
            if len(p) != 9:
                continue
            try:
                v = [int(x) for x in p]
            except ValueError:
                continue
            last = v[0]
            for k, val in zip(FIELDS, v[1:]):
                totals[k] += val
    return last, totals


def summarise(totals, first, last, elapsed):
    bb, wb = totals["block_bytes"], totals["witness_bytes"]
    ep, op = totals["envelope_payload_bytes"], totals["ord_payload_bytes"]
    print()
    print(f"blocks {first:,} .. {last:,}")
    print(f"elapsed              {hms(elapsed)}")
    print(f"transactions         {totals['tx_count']:,}")
    print(f"block bytes          {human(bb)}")
    print(f"witness bytes        {human(wb)}   ({wb/bb*100 if bb else 0:.2f}% of blocks)")
    print(f"envelopes            {totals['envelope_count']:,}")
    print(f"envelope payload     {human(ep)}   "
          f"({ep/wb*100 if wb else 0:.2f}% of witness, "
          f"{ep/bb*100 if bb else 0:.2f}% of blocks)")
    print(f"  with 'ord' marker  {totals['ord_envelope_count']:,}, {human(op)}")
    print(f"  without marker     {totals['envelope_count']-totals['ord_envelope_count']:,}, "
          f"{human(ep-op)}")
    print(f"malformed scripts    {totals['malformed_scripts']:,}")


# ---------------------------------------------------------------- main


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--blocks", required=True, help="path to the blocks/ directory")
    ap.add_argument("--start", type=int, required=True)
    ap.add_argument("--end", type=int, required=True)
    ap.add_argument("--csv")
    ap.add_argument("--resume", action="store_true")
    ap.add_argument("--progress", type=int, default=2000)
    args = ap.parse_args()

    key = load_xor_key(args.blocks)
    by_hash, children = index_block_files(args.blocks, key)
    heights = build_height_map(by_hash, children, args.end)

    if args.end not in heights:
        sys.exit(f"--end {args.end} not reachable; highest is {max(heights):,}")

    start = args.start
    totals = dict.fromkeys(FIELDS, 0)

    if args.resume and args.csv:
        last, totals = read_existing(args.csv)
        if last is not None:
            start = last + 1
            print(f"resuming from {start:,} (CSV has through {last:,})")
            if start > args.end:
                summarise(totals, args.start, args.end, 0)
                return

    csv_file = None
    if args.csv:
        fresh = not (args.resume and os.path.exists(args.csv))
        csv_file = open(args.csv, "w" if fresh else "a")
        if fresh:
            csv_file.write(CSV_HEADER)
            csv_file.flush()

    n_total = args.end - start + 1
    t0 = time.time()
    done = 0
    last_h = start - 1
    open_path, bf = None, None

    try:
        for height in range(start, args.end + 1):
            bh = heights.get(height)
            if bh is None:
                print(f"  missing height {height}, stopping", file=sys.stderr)
                break
            path, offset, size = by_hash[bh]

            if path != open_path:
                if bf:
                    bf.close()
                bf = BlockFile(path, key)
                open_path = path

            s = scan_block(bf.read_at(offset, size))

            for k in FIELDS:
                totals[k] += s[k]
            done += 1
            last_h = height

            if csv_file:
                csv_file.write(",".join(str(x) for x in
                               [height] + [s[k] for k in FIELDS]) + "\n")
                if done % 500 == 0:
                    csv_file.flush()

            if done % args.progress == 0:
                el = time.time() - t0
                rate = done / el
                ep, bb = totals["envelope_payload_bytes"], totals["block_bytes"]
                print(f"  {height:,}  {done/n_total*100:5.1f}%  {rate:.0f} blk/s  "
                      f"eta {hms((n_total-done)/rate if rate else 0)}  "
                      f"payload {human(ep)} ({ep/bb*100 if bb else 0:.1f}% of blocks)",
                      flush=True)

    except KeyboardInterrupt:
        print("\ninterrupted — CSV intact, rerun with --resume", file=sys.stderr)
    finally:
        if bf:
            bf.close()
        if csv_file:
            csv_file.flush()
            csv_file.close()

    summarise(totals, args.start, last_h, time.time() - t0)


if __name__ == "__main__":
    main()
