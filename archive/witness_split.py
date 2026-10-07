#!/usr/bin/env python3
"""
witness_split.py — demonstrate segregated witness storage on real block files.

Splits each block into two parts:

    body     the block with every transaction in legacy (non-witness)
             serialisation — exactly the bytes that txids are computed over
    witness  the witness stacks, stored separately

then recombines them and asserts the result is **byte-identical** to the
original block.

This is a feasibility demonstration for storing witness data in separate files
(`wit*.dat` alongside `blk*.dat`) so that discarding it becomes whole-file
deletion, as safe as existing pruning, rather than rewriting block files in
place.

What it proves:
  1. Witness data separates cleanly from transaction bodies at the storage layer
  2. Recombination is byte-perfect across every block tested
  3. Exactly how much disk a witness/body split would free

Usage:
    python3 witness_split.py --blocks /path/to/bitcoin/blocks \
        --start 767430 --end 962292

    # also write real split files for a sample range
    python3 witness_split.py --blocks /path/to/blocks \
        --start 800000 --end 800100 --write /tmp/split

Standard library only. Handles the XOR-obfuscated blocksdir from Core 28+.
BSD-2-Clause.
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


def dsha(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


# ---------------------------------------------------------------- block files


def load_xor_key(blocks_dir):
    path = os.path.join(blocks_dir, "xor.dat")
    if not os.path.exists(path):
        return None
    with open(path, "rb") as f:
        key = f.read()
    return None if key == b"\x00" * 8 else key


def dexor(data, key, offset):
    if not key or not data:
        return data
    n = len(data)
    tile = (key[offset % 8:] + key * (n // 8 + 2))[:n]
    return (int.from_bytes(data, "big") ^ int.from_bytes(tile, "big")).to_bytes(
        n, "big")


class BlockFile:
    def __init__(self, path, key):
        self.path, self.key = path, key
        self.fh = open(path, "rb")

    def read_at(self, offset, n):
        self.fh.seek(offset)
        return dexor(self.fh.read(n), self.key, offset)

    def read_seq(self, n):
        off = self.fh.tell()
        return dexor(self.fh.read(n), self.key, off)

    def tell(self):
        return self.fh.tell()

    def seek(self, p):
        self.fh.seek(p)

    def close(self):
        self.fh.close()


def index_block_files(blocks_dir, key):
    by_hash, children = {}, {}
    files = sorted(glob.glob(os.path.join(blocks_dir, "blk*.dat")))
    if not files:
        sys.exit(f"no blk*.dat in {blocks_dir}")
    print(f"indexing {len(files)} files{' (XOR)' if key else ''}...", flush=True)
    t0 = time.time()
    for n, path in enumerate(files, 1):
        bf = BlockFile(path, key)
        try:
            while True:
                head = bf.read_seq(8)
                if len(head) < 8 or head[:4] != MAINNET_MAGIC:
                    break
                size = struct.unpack("<I", head[4:])[0]
                if size < 80 or size > 8_000_000:
                    break
                off = bf.tell()
                hdr = bf.read_seq(80)
                if len(hdr) < 80:
                    break
                bh = dsha(hdr)
                by_hash[bh] = (path, off, size)
                children.setdefault(hdr[4:36], []).append(bh)
                bf.seek(off + size)
        finally:
            bf.close()
        if n % 500 == 0 or n == len(files):
            print(f"  {n}/{len(files)}  {len(by_hash):,} blocks  "
                  f"{time.time()-t0:.0f}s", flush=True)
    print(f"indexed {len(by_hash):,} blocks in {time.time()-t0:.0f}s", flush=True)
    return by_hash, children


def build_height_map(by_hash, children, max_height):
    if GENESIS not in by_hash:
        sys.exit("genesis not found — mainnet blocks directory?")

    def depth(h, limit=200):
        d, cur = 0, h
        while d < limit:
            k = children.get(cur)
            if not k:
                break
            cur, d = k[0], d + 1
        return d

    heights, cur, h = {}, GENESIS, 0
    while h <= max_height:
        heights[h] = cur
        kids = children.get(cur)
        if not kids:
            break
        cur = kids[0] if len(kids) == 1 else max(kids, key=depth)
        h += 1
    return heights


# ---------------------------------------------------------------- splitting


class Cursor:
    __slots__ = ("d", "p")

    def __init__(self, d):
        self.d, self.p = d, 0

    def take(self, n):
        out = self.d[self.p:self.p + n]
        if len(out) < n:
            raise ValueError("truncated block")
        self.p += n
        return out

    def peek(self, n):
        return self.d[self.p:self.p + n]

    def u8(self):
        b = self.d[self.p]
        self.p += 1
        return b

    def varint(self):
        n = self.u8()
        if n < 0xFD:
            return n
        if n == 0xFD:
            v = struct.unpack_from("<H", self.d, self.p)[0]; self.p += 2
            return v
        if n == 0xFE:
            v = struct.unpack_from("<I", self.d, self.p)[0]; self.p += 4
            return v
        v = struct.unpack_from("<Q", self.d, self.p)[0]; self.p += 8
        return v


def write_varint(n):
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def split_block(raw):
    """
    Split a raw block into (body_bytes, witness_bytes).

    body    : header, tx count, and every transaction in legacy serialisation
              (no marker, no flag, no witness) — the exact preimage of its txid
    witness : per transaction, a varint length followed by that transaction's
              witness section; length 0 means the transaction had none

    Both are self-describing enough to reconstruct the original block exactly.
    """
    c = Cursor(raw)
    header = c.take(80)
    n_tx = c.varint()

    bodies = [header, write_varint(n_tx)]
    witnesses = [write_varint(n_tx)]

    for _ in range(n_tx):
        tx_start = c.p
        version = c.take(4)

        segwit = c.peek(2) == b"\x00\x01"
        if segwit:
            c.take(2)  # marker + flag, dropped from the body

        io_start = c.p
        n_in = c.varint()
        for _ in range(n_in):
            c.take(32); c.take(4)          # prevout
            c.take(c.varint())             # scriptSig
            c.take(4)                      # sequence
        for _ in range(c.varint()):
            c.take(8)                      # value
            c.take(c.varint())             # scriptPubKey
        io_end = c.p

        wit = b""
        if segwit:
            w_start = c.p
            for _ in range(n_in):
                for _ in range(c.varint()):
                    c.take(c.varint())
            wit = raw[w_start:c.p]

        locktime = c.take(4)

        bodies.append(version)
        bodies.append(raw[io_start:io_end])
        bodies.append(locktime)

        witnesses.append(write_varint(len(wit)))
        if wit:
            witnesses.append(wit)

        del tx_start  # documented above; not needed further

    return b"".join(bodies), b"".join(witnesses)


def recombine(body, witness):
    """Rebuild the original block from its two parts."""
    b = Cursor(body)
    w = Cursor(witness)

    header = b.take(80)
    n_tx = b.varint()
    if w.varint() != n_tx:
        raise ValueError("tx count mismatch between body and witness")

    out = [header, write_varint(n_tx)]

    for _ in range(n_tx):
        version = b.take(4)
        io_start = b.p
        n_in = b.varint()
        for _ in range(n_in):
            b.take(32); b.take(4)
            b.take(b.varint())
            b.take(4)
        for _ in range(b.varint()):
            b.take(8)
            b.take(b.varint())
        io = body[io_start:b.p]
        locktime = b.take(4)

        wlen = w.varint()
        if wlen:
            out.append(version)
            out.append(b"\x00\x01")
            out.append(io)
            out.append(w.take(wlen))
            out.append(locktime)
        else:
            out.append(version)
            out.append(io)
            out.append(locktime)

    return b"".join(out)


# ---------------------------------------------------------------- main


def human(n):
    for u in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:,.1f} {u}"
        n /= 1024
    return f"{n:,.1f} PB"


def hms(s):
    s = int(s)
    h, r = divmod(s, 3600)
    m, sec = divmod(r, 60)
    return f"{h}h{m:02d}m" if h else f"{m}m{sec:02d}s"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--blocks", required=True)
    ap.add_argument("--start", type=int, required=True)
    ap.add_argument("--end", type=int, required=True)
    ap.add_argument("--write", help="directory to write sample split files into")
    ap.add_argument("--progress", type=int, default=5000)
    args = ap.parse_args()

    key = load_xor_key(args.blocks)
    by_hash, children = index_block_files(args.blocks, key)
    heights = build_height_map(by_hash, children, args.end)
    if args.end not in heights:
        sys.exit(f"--end {args.end} not reachable; highest {max(heights):,}")

    body_out = wit_out = None
    if args.write:
        os.makedirs(args.write, exist_ok=True)
        body_out = open(os.path.join(args.write, "blk_bodies.dat"), "wb")
        wit_out = open(os.path.join(args.write, "wit.dat"), "wb")

    total_orig = total_body = total_wit = 0
    mismatches = 0
    n = args.end - args.start + 1
    t0 = time.time()
    done = 0
    open_path, bf = None, None

    try:
        for height in range(args.start, args.end + 1):
            path, off, size = by_hash[heights[height]]
            if path != open_path:
                if bf:
                    bf.close()
                bf = BlockFile(path, key)
                open_path = path

            raw = bf.read_at(off, size)
            body, wit = split_block(raw)

            # the whole point: prove it round-trips
            if recombine(body, wit) != raw:
                mismatches += 1
                print(f"  MISMATCH at height {height}", file=sys.stderr)

            total_orig += len(raw)
            total_body += len(body)
            total_wit += len(wit)

            if body_out:
                body_out.write(write_varint(len(body)) + body)
                wit_out.write(write_varint(len(wit)) + wit)

            done += 1
            if done % args.progress == 0:
                el = time.time() - t0
                rate = done / el
                print(f"  {height:,}  {done/n*100:5.1f}%  {rate:.0f} blk/s  "
                      f"eta {hms((n-done)/rate)}  "
                      f"witness {total_wit/total_orig*100:.1f}%  "
                      f"mismatches {mismatches}", flush=True)

    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
    finally:
        if bf:
            bf.close()
        if body_out:
            body_out.close()
            wit_out.close()

    print()
    print("=" * 62)
    print(f"blocks {args.start:,} .. {args.start + done - 1:,}  ({done:,} blocks)")
    print("=" * 62)
    print(f"original            {human(total_orig)}")
    print(f"bodies              {human(total_body)}   "
          f"({total_body/total_orig*100:.2f}%)")
    print(f"witness             {human(total_wit)}   "
          f"({total_wit/total_orig*100:.2f}%)")
    print(f"split overhead      {human(total_body + total_wit - total_orig)}")
    print(f"round-trip failures {mismatches}")
    print()
    if mismatches == 0:
        print(f"Every one of {done:,} blocks recombined byte-identically.")
        print(f"Storing witness data separately would allow {human(total_wit)}")
        print("to be discarded by whole-file deletion, leaving bodies — and")
        print("therefore every txid and the merkle root — fully intact.")
    else:
        print(f"{mismatches} blocks failed to round-trip. Do not trust the")
        print("size figures until that is resolved.")


if __name__ == "__main__":
    main()
