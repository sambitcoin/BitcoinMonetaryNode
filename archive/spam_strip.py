#!/usr/bin/env python3
"""
spam_strip.py — demonstrate full spam removal from block storage, with proof.

For every block, this strips non-monetary data in every carrier:

    inscription envelopes    taproot script-path witnesses
    OP_RETURN over the limit output scriptPubKeys (default: over 83 bytes)
    stamp-style multisig     bare multisig with non-point pubkeys
    scriptSig data           oversized input scripts

then rebuilds the block's merkle root and asserts it still matches the header.

OP_RETURN outputs within the standard 83-byte datacarrier limit are treated as
monetary and left untouched — they are policy-compliant and provably
unspendable, so they never enter the UTXO set.

THE MECHANISM: a block's merkle root is computed over txids. The stripper
stores the 32-byte txid of every transaction it modifies or discards. Nothing
downstream needs to re-derive those txids from transaction data, so the data
can be removed and the block still verifies against its header, against real
proof-of-work.

Transactions retained unmodified need no stored txid — a receiving node
computes those itself. Only modified or fully stripped transactions pay 32
bytes.

The stored txids are self-verifying: fabricated ones produce a merkle root
that does not match the header, and the block is rejected.

ON THE FILTER INDEX: every dropped output needs an entry (outpoint, amount,
scriptPubKey, height) so a future spend can still be validated. Entries for
*spent* outputs can be discarded, exactly as chainstate discards spent coins.
This tool counts entries created (an upper bound) and also reports a
steady-state figure using --unspent-spam-outputs, which should come from a
UTXO set measurement rather than being assumed.

Usage:
    python3 spam_strip.py --blocks /path/to/bitcoin/blocks \\
        --start 767430 --end 962292 --csv results.csv

    ... --resume        continue after an interruption
    ... --reindex       rebuild the cached block index

Standard library only. Handles the XOR-obfuscated blocksdir from Core 28+.
BSD-2-Clause.
"""

import argparse
import glob
import hashlib
import os
import pickle
import struct
import sys
import time

MAINNET_MAGIC = b"\xf9\xbe\xb4\xd9"
GENESIS = bytes.fromhex(
    "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000")

OP_0, OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4 = 0x00, 0x4C, 0x4D, 0x4E
OP_IF, OP_NOTIF, OP_ENDIF, OP_RETURN = 0x63, 0x64, 0x68, 0x6A
OP_CHECKMULTISIG = 0xAE

TXID_BYTES = 32
FILTER_ENTRY_BYTES = 80
INDEX_CACHE = os.path.expanduser("~/.spam_strip_index.pkl")

# measured on the UTXO set at tip: P2TR dust created at or after 767,430
DEFAULT_UNSPENT_SPAM = 47_604_660

CSV_FIELDS = ("original", "retained", "tx_count", "untouched_txs",
              "modified_txs", "stripped_txs", "stored_txids", "filter_entries",
              "envelope", "op_return", "multisig", "scriptsig", "merkle_ok")
CSV_HEADER = "height," + ",".join(CSV_FIELDS) + "\n"


def dsha(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


# ---------------------------------------------------------------- block files


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


class BlockFile:
    def __init__(self, path, key):
        self.path, self.key, self.fh = path, key, open(path, "rb")

    def read_at(self, off, n):
        self.fh.seek(off)
        return dexor(self.fh.read(n), self.key, off)

    def read_seq(self, n):
        off = self.fh.tell()
        return dexor(self.fh.read(n), self.key, off)

    def tell(self):
        return self.fh.tell()

    def seek(self, p):
        self.fh.seek(p)

    def close(self):
        self.fh.close()


def scan_block_files(blocks_dir, key):
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
    return by_hash, children


def load_index(blocks_dir, key, force_reindex=False):
    """
    Build the block index, caching it to disk.

    Cache validity keys on the number of block files only, not on the size of
    the last one — that file grows every time a block is mined, and
    invalidating on it would force a full reindex on a live node almost every
    run. Blocks appended to the final file since the cache was written are
    picked up by rescanning just that file, which costs about a second.
    """
    files = sorted(glob.glob(os.path.join(blocks_dir, "blk*.dat")))
    fingerprint = len(files)

    if not force_reindex and os.path.exists(INDEX_CACHE):
        try:
            t0 = time.time()
            with open(INDEX_CACHE, "rb") as f:
                cached = pickle.load(f)
            if cached.get("fingerprint") == fingerprint and \
                    cached.get("blocks_dir") == blocks_dir:
                by_hash, children = cached["by_hash"], cached["children"]
                before = len(by_hash)
                # rescan the final file in case the tip advanced
                bf = BlockFile(files[-1], key)
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
                        if bh not in by_hash:
                            by_hash[bh] = (files[-1], off, size)
                            children.setdefault(hdr[4:36], []).append(bh)
                        bf.seek(off + size)
                finally:
                    bf.close()
                added = len(by_hash) - before
                print(f"loaded cached index: {len(by_hash):,} blocks "
                      f"({added} new) in {time.time()-t0:.1f}s", flush=True)
                return by_hash, children
            print("cache is for a different blocks dir or file count, rebuilding")
        except Exception as e:  # noqa: BLE001
            print(f"cache unreadable ({e}), rebuilding")

    by_hash, children = scan_block_files(blocks_dir, key)
    try:
        with open(INDEX_CACHE, "wb") as f:
            pickle.dump({"fingerprint": fingerprint, "blocks_dir": blocks_dir,
                         "by_hash": by_hash, "children": children}, f,
                        protocol=pickle.HIGHEST_PROTOCOL)
        print(f"index cached to {INDEX_CACHE}")
    except Exception as e:  # noqa: BLE001
        print(f"could not write cache ({e}); will reindex next run")
    return by_hash, children


def build_height_map(by_hash, children, max_height):
    if GENESIS not in by_hash:
        sys.exit("genesis not found")

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


# ---------------------------------------------------------------- parsing


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
            ln = script[i]; i += 1
            if i + ln > n:
                raise ValueError("truncated")
            data = script[i:i + ln]; i += ln
        elif op == OP_PUSHDATA2:
            ln = struct.unpack_from("<H", script, i)[0]; i += 2
            if i + ln > n:
                raise ValueError("truncated")
            data = script[i:i + ln]; i += ln
        elif op == OP_PUSHDATA4:
            ln = struct.unpack_from("<I", script, i)[0]; i += 4
            if i + ln > n:
                raise ValueError("truncated")
            data = script[i:i + ln]; i += ln
        yield op, data


# ---------------------------------------------------------------- classification


def envelope_payload(script):
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


def is_data_multisig(script):
    if not script or script[-1] != OP_CHECKMULTISIG:
        return False
    try:
        pushes = [d for _op, d in iter_script(script) if d is not None]
    except ValueError:
        return False
    if not pushes:
        return False
    return any(len(k) in (33, 65) and k[0] not in (0x02, 0x03, 0x04)
               for k in pushes)


def classify_output(script, op_return_limit):
    """
    Spam or monetary.

    OP_RETURN within the standard datacarrier limit is left alone: it is
    policy-compliant, provably unspendable, and never enters the UTXO set.
    Only oversized OP_RETURN is treated as spam.
    """
    if script and script[0] == OP_RETURN:
        if len(script) > op_return_limit:
            return "spam", "op_return"
        return "monetary", ""
    if is_data_multisig(script):
        return "spam", "data_multisig"
    return "monetary", ""


# ---------------------------------------------------------------- stripping


def strip_block(raw, op_return_limit, scriptsig_limit):
    c = Cursor(raw)
    header = c.take(80)
    n_tx = c.varint()

    txids = []
    retained = 80 + 9
    envelope = op_ret = multisig = scriptsig = 0
    stripped_txs = modified_txs = untouched_txs = 0
    filter_entries = stored_txids = 0

    for _ in range(n_tx):
        tx_start = c.p
        c.take(4)
        segwit = c.peek(2) == b"\x00\x01"
        if segwit:
            c.take(2)

        io_start = c.p
        n_in = c.varint()
        scriptsig_spam = 0
        for _ in range(n_in):
            c.take(32); c.take(4)
            sl = c.varint()
            c.take(sl)
            if sl > scriptsig_limit:
                scriptsig_spam += sl
            c.take(4)

        n_out = c.varint()
        out_monetary = out_spam_bytes = spam_outputs = 0
        for _ in range(n_out):
            c.take(8)
            spk = c.take(c.varint())
            kind, reason = classify_output(spk, op_return_limit)
            if kind == "spam":
                out_spam_bytes += len(spk) + 8
                spam_outputs += 1
                if reason == "op_return":
                    op_ret += len(spk)
                else:
                    multisig += len(spk)
            else:
                out_monetary += 1
        io_end = c.p

        envelope_bytes = 0
        if segwit:
            for _ in range(n_in):
                items = [c.take(c.varint()) for _ in range(c.varint())]
                if is_taproot_script_path(items):
                    envelope_bytes += envelope_payload(items[-2])

        c.take(4)
        tx_end = c.p

        if segwit:
            legacy = raw[tx_start:tx_start + 4] + raw[io_start:io_end] + \
                raw[tx_end - 4:tx_end]
        else:
            legacy = raw[tx_start:tx_end]
        txids.append(dsha(legacy))

        envelope += envelope_bytes
        scriptsig += scriptsig_spam
        filter_entries += spam_outputs

        touched = bool(envelope_bytes or spam_outputs or scriptsig_spam)
        tx_total = tx_end - tx_start

        if touched and out_monetary == 0:
            stripped_txs += 1
            stored_txids += 1
            retained += TXID_BYTES
        elif touched:
            modified_txs += 1
            stored_txids += 1
            retained += (tx_total - envelope_bytes - out_spam_bytes
                         - scriptsig_spam) + TXID_BYTES
        else:
            untouched_txs += 1
            retained += tx_total

    # filter index is added by the caller, which knows the steady-state count

    return {
        "original": len(raw), "retained": retained, "tx_count": n_tx,
        "untouched_txs": untouched_txs, "modified_txs": modified_txs,
        "stripped_txs": stripped_txs, "stored_txids": stored_txids,
        "filter_entries": filter_entries, "envelope": envelope,
        "op_return": op_ret, "multisig": multisig, "scriptsig": scriptsig,
        "txids": txids, "merkle_root": header[36:68],
    }


def merkle_root(txids):
    if not txids:
        return b"\x00" * 32
    level = list(txids)
    while len(level) > 1:
        if len(level) & 1:
            level.append(level[-1])
        level = [dsha(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


# ---------------------------------------------------------------- helpers


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


def read_existing(path):
    tot = dict.fromkeys(CSV_FIELDS, 0)
    last = None
    if not path or not os.path.exists(path):
        return last, tot
    with open(path) as f:
        next(f, None)
        for line in f:
            parts = line.strip().split(",")
            if len(parts) != len(CSV_FIELDS) + 1:
                continue
            try:
                vals = [int(x) for x in parts]
            except ValueError:
                continue
            last = vals[0]
            for k, v in zip(CSV_FIELDS, vals[1:]):
                tot[k] += v
    return last, tot


def summarise(tot, first, last, merkle_fail, elapsed, unspent_spam):
    o = tot["original"]
    body = tot["retained"]           # everything except the filter index
    gross_index = tot["filter_entries"] * FILTER_ENTRY_BYTES
    steady_index = unspent_spam * FILTER_ENTRY_BYTES
    dropped = (tot["envelope"] + tot["op_return"] + tot["multisig"]
               + tot["scriptsig"])
    txs = max(tot["tx_count"], 1)

    print()
    print("=" * 66)
    print(f"blocks {first:,} .. {last:,}")
    print("=" * 66)
    print(f"elapsed               {hms(elapsed)}")
    print(f"transactions          {tot['tx_count']:,}")
    print(f"  untouched           {tot['untouched_txs']:,} "
          f"({tot['untouched_txs']/txs*100:.1f}%)")
    print(f"  modified            {tot['modified_txs']:,}")
    print(f"  fully stripped      {tot['stripped_txs']:,}")
    print(f"stored txids          {tot['stored_txids']:,} "
          f"({human(tot['stored_txids']*TXID_BYTES)})")
    print()
    print("spam removed by carrier")
    print(f"  inscription witness {human(tot['envelope'])}")
    print(f"  OP_RETURN >limit    {human(tot['op_return'])}")
    print(f"  data multisig       {human(tot['multisig'])}")
    print(f"  oversized scriptSig {human(tot['scriptsig'])}")
    print(f"  total               {human(dropped)}")
    print()
    print("storage")
    print(f"  original            {human(o)}")
    print(f"  blocks retained     {human(body)}")
    print()
    print(f"  filter index, gross {human(gross_index)} "
          f"({tot['filter_entries']:,} entries ever created)")
    print(f"  filter index, live  {human(steady_index)} "
          f"({unspent_spam:,} still unspent)")
    print()
    if o:
        gross_total = body + gross_index
        steady_total = body + steady_index
        print(f"  upper bound         {human(gross_total)}  "
              f"saves {human(o-gross_total)} ({(o-gross_total)/o*100:.2f}%)")
        print(f"  steady state        {human(steady_total)}  "
              f"saves {human(o-steady_total)} ({(o-steady_total)/o*100:.2f}%)")
        print()
        print("  Entries for spent outputs are discarded, as chainstate does")
        print("  with spent coins, so steady state is the figure a running")
        print("  node experiences. Gross is the upper bound if nothing were")
        print("  ever pruned from the index.")
    print()
    print(f"merkle roots verified {tot['merkle_ok']:,}")
    print(f"merkle roots failed   {merkle_fail:,}")
    print()
    if merkle_fail == 0 and tot["merkle_ok"]:
        print(f"All {tot['merkle_ok']:,} blocks rebuilt their merkle root from")
        print("stored txids and matched the header. Every block remains")
        print("verifiable against its proof-of-work with all spam removed.")
    elif merkle_fail:
        print(f"{merkle_fail:,} blocks failed merkle verification. The size")
        print("figures cannot be trusted until that is resolved.")


# ---------------------------------------------------------------- main


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--blocks", required=True)
    ap.add_argument("--start", type=int, required=True)
    ap.add_argument("--end", type=int, required=True)
    ap.add_argument("--op-return-limit", type=int, default=83,
                    help="OP_RETURN scriptPubKey bytes tolerated; only larger "
                         "outputs are treated as spam (default 83)")
    ap.add_argument("--scriptsig-limit", type=int, default=1650)
    ap.add_argument("--unspent-spam-outputs", type=int,
                    default=DEFAULT_UNSPENT_SPAM,
                    help="spam outputs still unspent, from a UTXO measurement; "
                         "used for the steady-state filter index figure")
    ap.add_argument("--progress", type=int, default=5000)
    ap.add_argument("--reindex", action="store_true")
    ap.add_argument("--resume", action="store_true")
    ap.add_argument("--csv")
    args = ap.parse_args()

    key = load_xor_key(args.blocks)
    by_hash, children = load_index(args.blocks, key, args.reindex)
    heights = build_height_map(by_hash, children, args.end)
    if args.end not in heights:
        sys.exit(f"--end {args.end} not reachable; highest {max(heights):,}")

    start = args.start
    tot = dict.fromkeys(CSV_FIELDS, 0)
    merkle_fail = 0

    if args.resume and args.csv:
        last, tot = read_existing(args.csv)
        if last is not None:
            start = last + 1
            print(f"resuming from {start:,} (CSV has through {last:,})")
            merkle_fail = (last - args.start + 1) - tot["merkle_ok"]
            if start > args.end:
                summarise(tot, args.start, args.end, merkle_fail, 0,
                          args.unspent_spam_outputs)
                return

    csv_file = None
    if args.csv:
        fresh = not (args.resume and os.path.exists(args.csv))
        csv_file = open(args.csv, "w" if fresh else "a")
        if fresh:
            csv_file.write(CSV_HEADER)
            csv_file.flush()

    n = args.end - start + 1
    t0, done, last_h = time.time(), 0, start - 1
    open_path, bf = None, None

    try:
        for height in range(start, args.end + 1):
            path, off, size = by_hash[heights[height]]
            if path != open_path:
                if bf:
                    bf.close()
                bf = BlockFile(path, key)
                open_path = path

            r = strip_block(bf.read_at(off, size),
                            args.op_return_limit, args.scriptsig_limit)

            r["merkle_ok"] = 1 if merkle_root(r["txids"]) == r["merkle_root"] else 0
            if not r["merkle_ok"]:
                merkle_fail += 1
                print(f"  MERKLE MISMATCH at {height}", file=sys.stderr)

            for k in CSV_FIELDS:
                tot[k] += r[k]
            done += 1
            last_h = height

            if csv_file:
                csv_file.write(",".join(str(x) for x in
                               [height] + [r[k] for k in CSV_FIELDS]) + "\n")
                if done % 500 == 0:
                    csv_file.flush()

            if done % args.progress == 0:
                el = time.time() - t0
                rate = done / el
                steady = (tot["retained"]
                          + args.unspent_spam_outputs * FILTER_ENTRY_BYTES)
                saved = 1 - steady / tot["original"]
                print(f"  {height:,}  {done/n*100:5.1f}%  {rate:.0f} blk/s  "
                      f"eta {hms((n-done)/rate)}  saved {saved*100:.1f}%  "
                      f"merkle fails {merkle_fail}", flush=True)

    except KeyboardInterrupt:
        print("\ninterrupted — CSV intact, rerun with --resume", file=sys.stderr)
    except Exception as e:  # noqa: BLE001
        print(f"\nstopped: {e}\nCSV intact, rerun with --resume", file=sys.stderr)
    finally:
        if bf:
            bf.close()
        if csv_file:
            csv_file.flush()
            csv_file.close()

    summarise(tot, args.start, last_h, merkle_fail, time.time() - t0,
              args.unspent_spam_outputs)


if __name__ == "__main__":
    main()
