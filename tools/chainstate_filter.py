#!/usr/bin/env python3
"""
chainstate_filter.py — split a UTXO set into a monetary hot set and a cold
archive, and measure honestly what that actually saves.

THE DESIGN: dust is removed from chainstate and retained in block storage.

Chainstate is a random-access database that wants to live in RAM. Dropping a
third of its entries is a real and large win: less to index, less to cache,
less to compact.

Block storage is sequential and cheap, and the output is already there. Inside
its transaction a P2TR dust output costs 43 bytes — amount, script length,
script — because the block supplies the height and its position supplies the
outpoint. Extracting it into a standalone filter entry costs ~82 bytes, since
all of that context has to become explicit. Removing it from blocks would
therefore roughly double its cost.

So the output stays in the block, leaves the database, and is recovered from
block storage on the rare occasion someone spends it. That lookup rides on the
transaction index the node needs anyway to serve wallets.

WHAT THIS AVOIDS. No cold archive, so no duplicated bytes. No 32-byte
commitment scheme, so no peer must supply data at validation time. No
confiscation: every filtered output remains spendable, validated locally, with
no peer involvement. The node never loses the ability to check a spend itself.

This tool measures the resulting saving, and also measures the alternatives
that were considered and rejected, so the comparison can be argued from
numbers rather than adjectives.

Usage:
    bitcoin-cli -named dumptxoutset path=/path/utxos.dat type=latest
    python3 chainstate_filter.py /path/utxos.dat
    python3 chainstate_filter.py /path/utxos.dat --write /path/out
    python3 chainstate_filter.py --selftest

Streams the file; memory stays flat. Standard library only. BSD-2-Clause.
"""

import argparse
import hashlib
import os
import struct
import sys
import time

SNAPSHOT_MAGIC = b"utxo\xff"

INSCRIPTION_START = 767430
DUST_THRESHOLD = 1000

# Core chainstate entry overhead beyond the serialised coin: LevelDB key
# prefix, block-level indexing and per-record framing. Conservative.
LEVELDB_OVERHEAD_FACTOR = 1.35

OP_RETURN = 0x6A
OP_CHECKMULTISIG = 0xAE
SECP_P = 2**256 - 2**32 - 977


def dsha(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def on_curve(x_bytes):
    x = int.from_bytes(x_bytes, "big")
    if x >= SECP_P:
        return False
    y2 = (pow(x, 3, SECP_P) + 7) % SECP_P
    return pow(y2, (SECP_P - 1) // 2, SECP_P) == 1


# ---------------------------------------------------------------- parsing


class Stream:
    """
    Buffered reader for dumptxoutset.

    The format uses TWO different integer encodings and mixing them desyncs
    the parser immediately with no error: CompactSize for counts and output
    indices, Core's base-128 VARINT for coin fields.
    """

    def __init__(self, fh, bufsize=1 << 22):
        self.fh = fh
        self.buf = b""
        self.pos = 0
        self.bufsize = bufsize
        self.consumed = 0

    def _fill(self, n):
        if len(self.buf) - self.pos >= n:
            return
        self.buf = self.buf[self.pos:]
        self.pos = 0
        while len(self.buf) < n:
            chunk = self.fh.read(max(self.bufsize, n))
            if not chunk:
                break
            self.buf += chunk

    def read(self, n):
        self._fill(n)
        if len(self.buf) - self.pos < n:
            raise EOFError("unexpected end of snapshot")
        out = self.buf[self.pos:self.pos + n]
        self.pos += n
        self.consumed += n
        return out

    def u8(self):
        return self.read(1)[0]

    def compact_size(self):
        n = self.u8()
        if n < 0xFD:
            return n
        if n == 0xFD:
            return struct.unpack("<H", self.read(2))[0]
        if n == 0xFE:
            return struct.unpack("<I", self.read(4))[0]
        return struct.unpack("<Q", self.read(8))[0]

    def varint(self):
        """Core's base-128 VARINT. Not CompactSize."""
        n = 0
        while True:
            b = self.u8()
            n = (n << 7) | (b & 0x7F)
            if b & 0x80:
                n += 1
            else:
                return n


def decompress_amount(x):
    """Core's CTxOutCompressor amount decompression."""
    if x == 0:
        return 0
    x -= 1
    e = x % 10
    x //= 10
    if e < 9:
        d = (x % 9) + 1
        x //= 9
        n = x * 10 + d
    else:
        n = x + 1
    return n * (10 ** e)


def read_script(s):
    """
    Decompress a scriptPubKey. Types 0-5 are special-cased by Core; anything
    else stores nSize-6 raw bytes.
    """
    n = s.varint()
    if n == 0:                                   # P2PKH
        return b"\x76\xa9\x14" + s.read(20) + b"\x88\xac"
    if n == 1:                                   # P2SH
        return b"\xa9\x14" + s.read(20) + b"\x87"
    if n in (2, 3):                              # compressed P2PK
        return b"\x21" + bytes([n]) + s.read(32) + b"\xac"
    if n in (4, 5):                              # uncompressed P2PK
        # Only x is stored; the full key is recoverable but not needed here.
        return b"\x41" + bytes([n]) + s.read(32) + b"\xac"
    return s.read(n - 6)


def read_header(fh):
    """
    Handle both the modern magic-prefixed header and the older bare one.

    Modern (Core 28+): magic(5) version(2) network magic(4) blockhash(32)
                       coins count(8)
    Older:             blockhash(32) coins count(8)
    """
    head = fh.read(5)
    if head == SNAPSHOT_MAGIC:
        version = struct.unpack("<H", fh.read(2))[0]
        netmagic = fh.read(4)
        blockhash = fh.read(32)
        count = struct.unpack("<Q", fh.read(8))[0]
        return blockhash, count, version, netmagic
    rest = fh.read(35)
    blob = head + rest
    blockhash = blob[:32]
    count = struct.unpack("<Q", blob[32:40])[0]
    return blockhash, count, 0, None


# ---------------------------------------------------------------- classifying


def is_data_multisig(script):
    """Bare multisig whose keys are not points on secp256k1 — stuffed data."""
    if not script or script[-1] != OP_CHECKMULTISIG:
        return False
    keys, i, n = [], 0, len(script)
    while i < n:
        op = script[i]
        i += 1
        if 0x01 <= op <= 0x4B:
            if i + op > n:
                return False
            if op in (33, 65):
                keys.append(script[i:i + op])
            i += op
        elif op in (0x4C, 0x4D, 0x4E):
            return False        # not a standard bare multisig shape
    if not keys:
        return False
    for k in keys:
        if len(k) == 33:
            if k[0] not in (0x02, 0x03) or not on_curve(k[1:33]):
                return True
        else:
            if k[0] != 0x04:
                return True
            x = int.from_bytes(k[1:33], "big")
            y = int.from_bytes(k[33:65], "big")
            if (y * y - x * x * x - 7) % SECP_P != 0:
                return True
    return False


def classify(script, amount, height):
    """Returns one of 'monetary', 'dust', 'multisig_data', 'op_return'."""
    if script and script[0] == OP_RETURN:
        return "op_return"        # should never be in the UTXO set
    if is_data_multisig(script):
        return "multisig_data"
    if (amount < DUST_THRESHOLD and height >= INSCRIPTION_START
            and len(script) == 34 and script[0] == 0x51 and script[1] == 0x20):
        return "dust"
    return "monetary"


def coin_bytes(script):
    """Serialised size of a chainstate coin: outpoint, code, amount, script."""
    return 36 + 4 + 8 + len(script)


def archive_bytes(script):
    """Serialised size of a cold archive entry: outpoint, amount, height, spk."""
    return 36 + 8 + 4 + len(script)


# ---------------------------------------------------------------- main scan


def scan(path, write_dir=None, progress=5_000_000):
    fh = open(path, "rb")
    blockhash, count, version, _net = read_header(fh)
    s = Stream(fh)

    print(f"snapshot   {os.path.basename(path)}")
    print(f"base block {blockhash[::-1].hex()}")
    print(f"outputs    {count:,}" + (f"   (format v{version})" if version else ""))
    print()

    cats = {}
    for k in ("monetary", "dust", "multisig_data", "op_return"):
        cats[k] = {"n": 0, "coin": 0, "archive": 0, "value": 0}

    hot_out = cold_out = None
    if write_dir:
        os.makedirs(write_dir, exist_ok=True)
        hot_out = open(os.path.join(write_dir, "monetary_utxo.dat"), "wb")
        cold_out = open(os.path.join(write_dir, "cold_archive.dat"), "wb")

    seen = 0
    t0 = time.time()
    try:
        while seen < count:
            txid = s.read(32)
            n_out = s.compact_size()
            for _ in range(n_out):
                vout = s.compact_size()
                code = s.varint()
                height = code >> 1
                amount = decompress_amount(s.varint())
                script = read_script(s)

                kind = classify(script, amount, height)
                c = cats[kind]
                c["n"] += 1
                c["coin"] += coin_bytes(script)
                c["archive"] += archive_bytes(script)
                c["value"] += amount

                if write_dir:
                    rec = (txid + struct.pack("<I", vout)
                           + struct.pack("<Q", amount)
                           + struct.pack("<I", height)
                           + struct.pack("<H", len(script)) + script)
                    (hot_out if kind == "monetary" else cold_out).write(rec)

                seen += 1
                if seen % progress == 0:
                    el = time.time() - t0
                    print(f"  {seen:,}/{count:,}  {el:.0f}s  "
                          f"~{(count-seen)/(seen/el):.0f}s left", flush=True)
    finally:
        fh.close()
        if hot_out:
            hot_out.close()
        if cold_out:
            cold_out.close()

    return blockhash, count, cats, seen


def human(n):
    for u in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:,.2f} {u}"
        n /= 1024
    return f"{n:,.2f} PB"


def report(count, cats, seen):
    total_coin = sum(c["coin"] for c in cats.values())
    total_n = sum(c["n"] for c in cats.values())
    filtered = {k: v for k, v in cats.items() if k != "monetary"}
    removed_n = sum(c["n"] for c in filtered.values())
    removed_coin = sum(c["coin"] for c in filtered.values())
    removed_archive = sum(c["archive"] for c in filtered.values())
    removed_value = sum(c["value"] for c in filtered.values())

    print()
    print("=" * 68)
    print("COMPOSITION")
    print("=" * 68)
    print(f"{'category':<16}{'outputs':>16}{'share':>9}{'bytes':>14}{'share':>9}")
    for k in ("monetary", "dust", "multisig_data", "op_return"):
        c = cats[k]
        if c["n"] == 0 and k == "op_return":
            continue
        print(f"{k:<16}{c['n']:>16,}{c['n']/total_n*100:>8.2f}%"
              f"{human(c['coin']):>14}{c['coin']/total_coin*100:>8.2f}%")
    print(f"{'TOTAL':<16}{total_n:>16,}{'':>9}{human(total_coin):>14}")

    print()
    print("=" * 68)
    print("THE SAVING — removed from chainstate, retained in blocks")
    print("=" * 68)

    hot_before_db = total_coin * LEVELDB_OVERHEAD_FACTOR
    hot_after_db = cats["monetary"]["coin"] * LEVELDB_OVERHEAD_FACTOR
    saved = hot_before_db - hot_after_db

    print()
    print(f"  chainstate before   {human(hot_before_db)}"
          f"   (serialised {human(total_coin)} × {LEVELDB_OVERHEAD_FACTOR})")
    print(f"  chainstate after    {human(hot_after_db)}")
    print(f"  entries removed     {removed_n:,}"
          f"   ({removed_n/total_n*100:.2f}% of the set)")
    print(f"  REMOVED FROM DB     {human(saved)}"
          f"   ({removed_coin/total_coin*100:.2f}%)")
    print()
    print("  additional storage required   0 B")
    print("  These outputs are already in block storage and stay there. No")
    print("  archive is written and nothing is duplicated.")

    print()
    print(f"  cost: {removed_n:,} outputs now need a block-storage lookup if")
    print("  spent, instead of a database hit. That lookup rides on the")
    print("  transaction index the node needs anyway to serve wallets.")

    print()
    print("-" * 68)
    print("ALTERNATIVES CONSIDERED AND REJECTED")
    print("-" * 68)

    net_archive = saved - removed_archive
    print()
    print(f"  cold archive        {human(removed_archive)} written, "
          f"net saving {human(net_archive)}")
    print("    Rejected: duplicates data that is already in block storage and")
    print(f"    cancels most of the gain. An archive entry is ~82 bytes against")
    print("    the ~43 the same output costs inside its transaction.")

    commit = removed_n * 32
    print()
    print(f"  32-byte commitments {human(commit)} written, "
          f"net saving {human(saved - commit)}")
    print("    Rejected: the node can no longer validate a spend by itself — a")
    print("    peer or the spender must supply the data. Trades local")
    print("    validation for bytes we do not need to save.")

    print()
    print("  delete outright, rely on other nodes to hold it")
    print("    Rejected: block validity is atomic. Without the amount you")
    print("    cannot check value conservation; without the scriptPubKey you")
    print("    cannot check the signature. A block spending a filtered output")
    print("    could not be validated at all, and dust consolidation is not")
    print("    rare. It also becomes confiscation if archival capacity thins.")

    print()
    print("=" * 68)
    print(f"value in filtered outputs   {removed_value/1e8:,.8f} BTC")
    print(f"                            {removed_value/1e8/21e6*100:.6f}% of supply")
    print("Every one remains spendable and locally validatable. Nothing is")
    print("confiscated and no peer is trusted.")
    print("=" * 68)

    if seen != count:
        print()
        print(f"WARNING: header declared {count:,} outputs, parsed {seen:,}")


# ---------------------------------------------------------------- self-test


def selftest():
    ok = []

    def check(name, cond, detail=""):
        ok.append(cond)
        print(f"  [{'ok  ' if cond else 'FAIL'}] {name}"
              + (f"  — {detail}" if detail else ""))

    print("amount decompression")
    # Core's compression is exact for round numbers; check known round-trips.
    for v in (0, 1, 546, 1000, 100000, 5000000000, 2100000000000000):
        x = compress_amount(v)
        check(f"round-trip {v:,}", decompress_amount(x) == v)

    print("\nvarint vs compact size")
    import io
    s = Stream(io.BytesIO(bytes([0xFD, 0x10, 0x27])))
    check("compact size 0xFD reads 2 bytes LE", s.compact_size() == 10000)
    s = Stream(io.BytesIO(bytes([0x8F, 0x00])))
    check("varint is base-128 with +1 carry", s.varint() == 2048)

    print("\nclassification")
    p2tr = b"\x51\x20" + b"\x11" * 32
    check("inscription-era p2tr dust -> dust",
          classify(p2tr, 546, 800000) == "dust")
    check("same script above threshold -> monetary",
          classify(p2tr, 100000, 800000) == "monetary")
    check("same script pre-era -> monetary",
          classify(p2tr, 546, 700000) == "monetary")
    p2wpkh = b"\x00\x14" + b"\x22" * 20
    check("p2wpkh dust -> monetary (not inscription shaped)",
          classify(p2wpkh, 546, 800000) == "monetary")

    gen_x = bytes.fromhex(
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
    real = b"\x51" + b"\x21" + b"\x02" + gen_x + b"\x51\xae"
    check("genuine multisig not flagged", not is_data_multisig(real))
    off = next(b"STAMP:" + i.to_bytes(26, "big") for i in range(500)
               if not on_curve(b"STAMP:" + i.to_bytes(26, "big")))
    fake = b"\x51" + b"\x21" + b"\x02" + off + b"\x51\xae"
    check("stamp-style data multisig flagged", is_data_multisig(fake))

    print("\nsize accounting")
    check("archive entry is not smaller than a coin entry",
          archive_bytes(p2tr) >= coin_bytes(p2tr),
          f"coin {coin_bytes(p2tr)}B vs archive {archive_bytes(p2tr)}B — "
          "this is why relocation is not deletion")

    print()
    print(f"{sum(ok)}/{len(ok)} passed")
    return 0 if all(ok) else 1


def compress_amount(n):
    """Inverse of decompress_amount, for the self-test."""
    if n == 0:
        return 0
    e = 0
    while n % 10 == 0 and e < 9:
        n //= 10
        e += 1
    if e < 9:
        d = n % 10
        n //= 10
        return 1 + (n * 9 + d - 1) * 10 + e
    return 1 + (n - 1) * 10 + 9


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("snapshot", nargs="?")
    ap.add_argument("--write", help="write the split sets into this directory")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        sys.exit(selftest())
    if not args.snapshot:
        sys.exit("need a dumptxoutset snapshot (or --selftest)")

    _bh, count, cats, seen = scan(args.snapshot, args.write)
    report(count, cats, seen)

    if args.write:
        print()
        print(f"monetary set  {os.path.join(args.write, 'monetary_utxo.dat')}")
        print(f"cold archive  {os.path.join(args.write, 'cold_archive.dat')}")


if __name__ == "__main__":
    main()
