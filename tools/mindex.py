#!/usr/bin/env python3
"""
mindex.py — build the block index, reading only what the index needs.

Writes the cache file `monetary_store.py` reads, so once this finishes every
later run starts immediately.

THE PROBLEM THIS SOLVES. Only 88 bytes per block matter to an index: the
8-byte record prefix and the 80-byte header. Everything else is transaction
data this pass never looks at. Across the whole chain that is roughly 90 MB of
headers sitting inside 763 GB of block files.

Two earlier approaches both read far more than that:

  - Reading whole files: 763 GB of IO for 90 MB of headers. Measured at
    11 MB/s on Umbrel-class hardware, which is ~19 hours.
  - A fixed 1 MB buffer with seeks: fine for the early chain where blocks are
    tiny, but on recent files with 1-2 MB blocks it fetches a megabyte to use
    88 bytes of it. Roughly 9 hours.

This switches strategy on the size of the block just read, which predicts the
gap to the next header exactly:

  Early chain — thousands of tiny blocks per file, headers a few hundred bytes
  apart. One 256 KB read serves hundreds of them; seeking per block would be
  pure syscall overhead.

  Recent chain — about a hundred large blocks per file, headers megabytes
  apart. Take the 88 bytes and seek; reading ahead would discard almost
  everything fetched.

Measured on simulated files: a recent-chain file reads 8.8 KB of 130 MB.

It also checkpoints every few hundred files. A partial cache is valid — files
not yet reached are simply absent and get picked up next run — so an
interrupted build resumes rather than restarting.

Usage:
    python3 -u mindex.py --blocks /path/to/bitcoin/blocks --benchmark 20
    python3 -u mindex.py --blocks /path/to/bitcoin/blocks

Then run monetary_store.py normally; it will find the cache and skip indexing.

Standard library only. BSD-2-Clause.
"""

import argparse
import glob
import hashlib
import os
import struct
import sys
import time

MAINNET_MAGIC = b"\xf9\xbe\xb4\xd9"
INDEX_MAGIC = b"MIDX"
INDEX_VERSION = 1

# Must match monetary_store.py exactly:
#   hash(32) prev(32) file_idx(H) offset(Q) size(I)
IDX_REC = struct.Struct("<32s32sHQI")

RECORD_HEAD = 88               # 8-byte prefix + 80-byte header
SMALL_BLOCK = 32 * 1024        # below this, batching pays
BATCH_READ = 256 * 1024        # how much to grab when batching


def dsha(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def load_xor_key(blocks_dir):
    p = os.path.join(blocks_dir, "xor.dat")
    if not os.path.exists(p):
        return None
    with open(p, "rb") as f:
        key = f.read()
    return None if key == b"\x00" * 8 else key


def dexor(data, key, offset):
    if not key or not data:
        return data
    n = len(data)
    tile = (key[offset % 8:] + key * (n // 8 + 2))[:n]
    return (int.from_bytes(data, "big") ^ int.from_bytes(tile, "big")).to_bytes(
        n, "big")


def scan_file(path, key, file_idx):
    """Index one blk file, reading only the 88 bytes per block that matter."""
    file_size = os.path.getsize(path)
    out = []
    buf, buf_start = b"", 0
    # Start minimal: the first block's size is unknown, and guessing wrong
    # costs a wasted 256 KB on every recent file. One small read tells us
    # which regime we are in, and the next iteration adapts.
    readahead = RECORD_HEAD
    bytes_read = 0

    with open(path, "rb", buffering=0) as f:
        pos = 0
        while pos + RECORD_HEAD <= file_size:
            if not (buf_start <= pos
                    and pos + RECORD_HEAD <= buf_start + len(buf)):
                f.seek(pos)
                buf = f.read(max(RECORD_HEAD, readahead))
                buf_start = pos
                bytes_read += len(buf)
                if len(buf) < RECORD_HEAD:
                    break
            off = pos - buf_start
            chunk = buf[off:off + RECORD_HEAD]

            if dexor(chunk[:4], key, pos) != MAINNET_MAGIC:
                break
            size = struct.unpack("<I", dexor(chunk[4:8], key, pos + 4))[0]
            if size < 80 or size > 8_000_000:
                break

            hoff = pos + 8
            hdr = dexor(chunk[8:88], key, hoff)
            out.append((dsha(hdr), hdr[4:36], file_idx, hoff, size))

            readahead = BATCH_READ if size < SMALL_BLOCK else RECORD_HEAD
            pos = hoff + size

    return out, bytes_read


def load_cache(path):
    """Returns (files, blob) or (None, None). files is [(path, size)]."""
    if not path or not os.path.exists(path):
        return None, None
    try:
        with open(path, "rb") as f:
            if f.read(4) != INDEX_MAGIC:
                return None, None
            if struct.unpack("<H", f.read(2))[0] != INDEX_VERSION:
                return None, None
            n_files = struct.unpack("<I", f.read(4))[0]
            files = []
            for _ in range(n_files):
                ln = struct.unpack("<H", f.read(2))[0]
                p = f.read(ln).decode()
                sz = struct.unpack("<Q", f.read(8))[0]
                files.append((p, sz))
            n = struct.unpack("<Q", f.read(8))[0]
            blob = f.read(n * IDX_REC.size)
            if len(blob) != n * IDX_REC.size:
                return None, None
            return files, blob
    except Exception:
        return None, None


def save_cache(path, files, blob):
    """Atomic write, so a checkpoint never leaves a half-written cache."""
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(INDEX_MAGIC)
        f.write(struct.pack("<H", INDEX_VERSION))
        f.write(struct.pack("<I", len(files)))
        for p, sz in files:
            b = p.encode()
            f.write(struct.pack("<H", len(b)) + b + struct.pack("<Q", sz))
        f.write(struct.pack("<Q", len(blob) // IDX_REC.size))
        f.write(blob)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def human_time(s):
    s = int(s)
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s//60}m{s%60:02d}s"
    return f"{s//3600}h{(s%3600)//60:02d}m"


def benchmark(paths, key, n):
    """
    Time a sample of files from both ends of the chain.

    Early and recent files behave completely differently, so a sample taken
    only from the start predicts nothing about total runtime.
    """
    half = max(1, n // 2)
    sample = paths[:half] + paths[-(n - half):]
    print(f"benchmarking {len(sample)} files "
          f"({half} earliest, {n-half} most recent)...\n", flush=True)
    total_blocks = total_read = total_span = 0
    t0 = time.time()
    for p in sample:
        recs, read = scan_file(p, key, 0)
        total_blocks += len(recs)
        total_read += read
        total_span += os.path.getsize(p)
    el = max(time.time() - t0, 1e-6)

    print(f"  files            {len(sample)}")
    print(f"  blocks indexed   {total_blocks:,}")
    print(f"  file span        {total_span/1e6:.0f} MB")
    print(f"  bytes read       {total_read/1e6:.1f} MB "
          f"({total_read/max(total_span,1)*100:.3f}% of span)")
    print(f"  elapsed          {el:.1f}s")
    print(f"  read throughput  {total_read/el/1e6:.1f} MB/s")
    print()
    print(f"  projected full run: "
          f"{human_time(el/len(sample)*len(paths))}")
    print()
    print("  If bytes read is a small fraction of span, the adaptive reader is")
    print("  working. If throughput is far below what the drive can do, the")
    print("  bottleneck is contention rather than this program.")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--blocks", required=True)
    ap.add_argument("--cache",
                    default=os.path.expanduser("~/.monetary_index.bin"))
    ap.add_argument("--checkpoint", type=int, default=250,
                    help="write the cache every N files")
    ap.add_argument("--progress", type=int, default=50)
    ap.add_argument("--benchmark", type=int, metavar="N",
                    help="time N sample files and project, without building")
    args = ap.parse_args()

    key = load_xor_key(args.blocks)
    paths = sorted(glob.glob(os.path.join(args.blocks, "blk*.dat")))
    if not paths:
        sys.exit(f"no blk*.dat in {args.blocks}")

    if args.benchmark:
        benchmark(paths, key, args.benchmark)
        return

    current = [(p, os.path.getsize(p)) for p in paths]
    total_bytes = sum(sz for _p, sz in current)

    cached_files, cached_blob = load_cache(args.cache)
    sizes = {p: sz for p, sz in current}
    reusable = {}
    if cached_files is not None:
        for i, (p, sz) in enumerate(cached_files):
            if sizes.get(p) == sz:
                reusable[i] = p

    idx_of = {p: i for i, (p, _s) in enumerate(current)}
    blob = bytearray()
    if reusable and cached_blob:
        for r in range(len(cached_blob) // IDX_REC.size):
            h, prev, fi, o, sz = IDX_REC.unpack_from(cached_blob,
                                                     r * IDX_REC.size)
            p = reusable.get(fi)
            if p is not None:
                blob += IDX_REC.pack(h, prev, idx_of[p], o, sz)

    done_paths = set(reusable.values())
    todo = [(i, p, sz) for i, (p, sz) in enumerate(current)
            if p not in done_paths]

    print(f"block files      {len(current)}  ({total_bytes/1e9:.1f} GB)",
          flush=True)
    print(f"already cached   {len(done_paths)}", flush=True)
    print(f"to scan          {len(todo)}", flush=True)
    if key:
        print("blocksdir is XOR-obfuscated; handled", flush=True)
    print(flush=True)

    if not todo:
        print(f"index already complete: {len(blob)//IDX_REC.size:,} blocks")
        return

    t0 = time.time()
    span_done = read_done = 0
    for n, (fi, p, sz) in enumerate(todo, 1):
        recs, read = scan_file(p, key, fi)
        blob += b"".join(IDX_REC.pack(*rec) for rec in recs)
        span_done += sz
        read_done += read
        done_paths.add(p)

        if n % args.checkpoint == 0:
            save_cache(args.cache,
                       [(p2, s2) for p2, s2 in current if p2 in done_paths],
                       bytes(blob))
            print(f"  checkpoint saved ({len(blob)//IDX_REC.size:,} blocks)",
                  flush=True)

        if n % args.progress == 0 or n == len(todo):
            el = max(time.time() - t0, 1e-6)
            left = human_time(el / n * (len(todo) - n))
            print(f"  {n}/{len(todo)}  {len(blob)//IDX_REC.size:,} blocks  "
                  f"read {read_done/1e9:.2f} GB of {span_done/1e9:.1f} GB span "
                  f"({read_done/max(span_done,1)*100:.2f}%)  "
                  f"{read_done/el/1e6:.1f} MB/s  "
                  f"{human_time(el)} elapsed, ~{left} left", flush=True)

    save_cache(args.cache, current, bytes(blob))
    n_blocks = len(blob) // IDX_REC.size
    print()
    print(f"index complete: {n_blocks:,} blocks in {human_time(time.time()-t0)}")
    print(f"read {read_done/1e9:.2f} GB of {span_done/1e9:.1f} GB on disk")
    print(f"cached to {args.cache}")
    print()
    print("monetary_store.py will now start without re-indexing.")


if __name__ == "__main__":
    main()
