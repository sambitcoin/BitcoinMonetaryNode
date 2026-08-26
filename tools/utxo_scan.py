#!/usr/bin/env python3
"""
utxo_scan.py — analyse a Bitcoin UTXO set snapshot produced by dumptxoutset.

Reports the composition of the UTXO set by script type, value band, and
creation era, so you can measure how much of chainstate is dust and how much
was created during the inscription era.

Usage:
    python3 utxo_scan.py /path/to/utxos.dat
    python3 utxo_scan.py /path/to/utxos.dat --csv per_type.csv

Standard library only. Streams the file, so memory use stays flat regardless
of snapshot size.

Format notes (Core's WriteUTXOSnapshot):
  header: b"utxo\\xff" | version u16 | network magic 4 | base hash 32 |
          coins count u64
  then, grouped by txid:
      txid 32 bytes
      CompactSize  number of outputs for this txid
      per output:
          CompactSize  vout index
          VARINT       code = height * 2 + coinbase
          VARINT       compressed amount
          script       compressed scriptPubKey

Note the two different integer encodings: counts and indices use CompactSize,
while the coin fields use Core's base-128 VARINT. Mixing them up desyncs the
parser immediately.

"Bytes" here means the serialised size of each entry, not Core's on-disk
chainstate encoding, which differs and carries LevelDB overhead. Treat the
figures as proportional.
"""

import argparse
import sys
import time
from collections import defaultdict

SNAPSHOT_MAGIC = b"utxo\xff"
MAINNET_MAGIC = b"\xf9\xbe\xb4\xd9"

INSCRIPTION_START = 767430
DUST_THRESHOLD = 1000
MAX_SCRIPT = 20_000  # sanity bound; real scripts are far smaller

VALUE_BANDS = [
    (0, 1, "0 sats"),
    (1, 331, "1-330"),
    (331, 546, "331-545"),
    (546, 1000, "546-999"),
    (1000, 10_000, "1k-10k"),
    (10_000, 100_000, "10k-100k"),
    (100_000, 1_000_000, "100k-1M"),
    (1_000_000, 10_000_000, "1M-10M"),
    (10_000_000, 100_000_000, "10M-1BTC"),
    (100_000_000, 1 << 62, "1BTC+"),
]


class Stream:
    def __init__(self, fh, bufsize=1 << 22):
        self.fh = fh
        self.buf = b""
        self.pos = 0
        self.bufsize = bufsize

    def _fill(self, need):
        if len(self.buf) - self.pos >= need:
            return
        self.buf = self.buf[self.pos:]
        self.pos = 0
        while len(self.buf) < need:
            chunk = self.fh.read(self.bufsize)
            if not chunk:
                break
            self.buf += chunk

    def read(self, n):
        if n < 0 or n > MAX_SCRIPT * 4:
            raise ValueError(f"refusing absurd read of {n} bytes — parser desync")
        self._fill(n)
        if len(self.buf) - self.pos < n:
            raise EOFError("unexpected end of snapshot")
        out = self.buf[self.pos:self.pos + n]
        self.pos += n
        return out

    def u8(self):
        self._fill(1)
        b = self.buf[self.pos]
        self.pos += 1
        return b

    def compact_size(self):
        """CompactSize: used for counts and indices."""
        n = self.u8()
        if n < 0xFD:
            return n
        if n == 0xFD:
            return int.from_bytes(self.read(2), "little")
        if n == 0xFE:
            return int.from_bytes(self.read(4), "little")
        return int.from_bytes(self.read(8), "little")

    def varint(self):
        """Core's base-128 VARINT: used for coin fields."""
        n = 0
        while True:
            ch = self.u8()
            n = (n << 7) | (ch & 0x7F)
            if ch & 0x80:
                n += 1
            else:
                return n


def decompress_amount(x):
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


def classify_raw_script(script):
    n = len(script)
    if n == 34 and script[0] == 0x51 and script[1] == 0x20:
        return "p2tr"
    if n == 22 and script[0] == 0x00 and script[1] == 0x14:
        return "p2wpkh"
    if n == 34 and script[0] == 0x00 and script[1] == 0x20:
        return "p2wsh"
    if n >= 1 and script[-1] == 0xAE:
        return "bare_multisig"
    if n >= 1 and script[0] == 0x6A:
        return "op_return"
    if n >= 4 and 0x51 <= script[0] <= 0x60:
        return "witness_other"
    return "other"


def read_script(s):
    """Returns (kind, script_length). Special sizes 0-5 are compressed forms."""
    size = s.varint()
    if size == 0:
        s.read(20); return "p2pkh", 25
    if size == 1:
        s.read(20); return "p2sh", 23
    if size in (2, 3):
        s.read(32); return "p2pk", 35
    if size in (4, 5):
        s.read(32); return "p2pk", 67
    n = size - 6
    if n > MAX_SCRIPT:
        raise ValueError(f"implausible script length {n} — parser desync")
    return classify_raw_script(s.read(n)), n


def scan(path, inscription_start, dust):
    fh = open(path, "rb")
    s = Stream(fh)

    if s.read(5) != SNAPSHOT_MAGIC:
        sys.exit("not a dumptxoutset snapshot")
    version = int.from_bytes(s.read(2), "little")
    if s.read(4) != MAINNET_MAGIC:
        sys.exit("not mainnet")
    base_hash = s.read(32)[::-1].hex()
    coins_count = int.from_bytes(s.read(8), "little")

    print(f"snapshot version {version}, base block {base_hash}")
    print(f"declared coins: {coins_count:,}\n", flush=True)

    by_type = defaultdict(lambda: {"count": 0, "bytes": 0, "sats": 0})
    by_band = defaultdict(lambda: {"count": 0, "bytes": 0})
    by_era = defaultdict(lambda: {"count": 0, "bytes": 0})
    insc = {"count": 0, "bytes": 0, "sats": 0}
    dust_total = {"count": 0, "bytes": 0}
    total = {"count": 0, "bytes": 0, "sats": 0}

    t0 = time.time()
    seen = 0
    next_report = 5_000_000

    while seen < coins_count:
        s.read(32)                        # txid
        n_outputs = s.compact_size()      # CompactSize, not VARINT
        for _ in range(n_outputs):
            s.compact_size()              # vout index, CompactSize
            code = s.varint()
            height = code >> 1
            amount = decompress_amount(s.varint())
            kind, script_len = read_script(s)

            entry_bytes = script_len + 8 + 4 + 36

            total["count"] += 1
            total["bytes"] += entry_bytes
            total["sats"] += amount

            t = by_type[kind]
            t["count"] += 1
            t["bytes"] += entry_bytes
            t["sats"] += amount

            for lo, hi, label in VALUE_BANDS:
                if lo <= amount < hi:
                    b = by_band[label]
                    b["count"] += 1
                    b["bytes"] += entry_bytes
                    break

            era = "post_inscription" if height >= inscription_start else "pre_inscription"
            e = by_era[era]
            e["count"] += 1
            e["bytes"] += entry_bytes

            if amount < dust:
                dust_total["count"] += 1
                dust_total["bytes"] += entry_bytes

            if kind == "p2tr" and amount < dust and height >= inscription_start:
                insc["count"] += 1
                insc["bytes"] += entry_bytes
                insc["sats"] += amount

            seen += 1

        if seen >= next_report:
            el = time.time() - t0
            rate = seen / el
            print(f"  {seen:,} / {coins_count:,}  {seen/coins_count*100:5.1f}%  "
                  f"{el/60:.1f}m elapsed, eta {(coins_count-seen)/rate/60:.0f}m",
                  flush=True)
            next_report += 5_000_000

    fh.close()
    return {
        "base_hash": base_hash, "coins_count": coins_count, "total": total,
        "by_type": dict(by_type), "by_band": dict(by_band),
        "by_era": dict(by_era), "dust": dust_total,
        "inscription_assoc": insc, "elapsed": time.time() - t0,
    }


def human(n):
    for u in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:,.1f} {u}"
        n /= 1024
    return f"{n:,.1f} PB"


def report(r, dust, inscription_start):
    total = r["total"]
    tc, tb = total["count"], total["bytes"]

    print()
    print("=" * 70)
    print(f"UTXO set at block {r['base_hash']}")
    print("=" * 70)
    print(f"total outputs        {tc:,}")
    print(f"serialised bytes     {human(tb)}")
    print(f"total value          {total['sats']/1e8:,.2f} BTC")
    print(f"scan time            {r['elapsed']/60:.1f}m")

    print("\nby script type")
    print(f"  {'type':<16}{'count':>14}{'share':>9}{'bytes':>12}{'share':>9}")
    for kind, v in sorted(r["by_type"].items(), key=lambda x: -x[1]["count"]):
        print(f"  {kind:<16}{v['count']:>14,}{v['count']/tc*100:>8.2f}%"
              f"{human(v['bytes']):>12}{v['bytes']/tb*100:>8.2f}%")

    print("\nby value")
    print(f"  {'band':<16}{'count':>14}{'share':>9}{'bytes':>12}{'share':>9}")
    for _lo, _hi, label in VALUE_BANDS:
        v = r["by_band"].get(label)
        if not v:
            continue
        print(f"  {label:<16}{v['count']:>14,}{v['count']/tc*100:>8.2f}%"
              f"{human(v['bytes']):>12}{v['bytes']/tb*100:>8.2f}%")

    print("\nby creation era")
    for era, v in sorted(r["by_era"].items()):
        print(f"  {era:<20}{v['count']:>14,}{v['count']/tc*100:>8.2f}%"
              f"{human(v['bytes']):>12}{v['bytes']/tb*100:>8.2f}%")

    d, i = r["dust"], r["inscription_assoc"]
    print("\nheadline figures")
    print(f"  outputs below {dust} sats:")
    print(f"    {d['count']:,} ({d['count']/tc*100:.2f}% of outputs), "
          f"{human(d['bytes'])} ({d['bytes']/tb*100:.2f}% of bytes)")
    print(f"  P2TR below {dust} sats created at or after block {inscription_start:,}:")
    print(f"    {i['count']:,} ({i['count']/tc*100:.2f}% of outputs), "
          f"{human(i['bytes'])} ({i['bytes']/tb*100:.2f}% of bytes)")
    print(f"    holding {i['sats']/1e8:,.4f} BTC")
    print()
    print("  The second figure is a proxy. A UTXO does not record whether its")
    print("  creating transaction carried an inscription envelope, so this")
    print("  counts dust taproot outputs from the inscription era. It will")
    print("  include some ordinary small taproot payments and exclude any")
    print("  inscription output above the dust threshold.")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("snapshot")
    ap.add_argument("--dust", type=int, default=DUST_THRESHOLD)
    ap.add_argument("--inscription-start", type=int, default=INSCRIPTION_START)
    ap.add_argument("--csv")
    args = ap.parse_args()

    r = scan(args.snapshot, args.inscription_start, args.dust)
    report(r, args.dust, args.inscription_start)

    if args.csv:
        with open(args.csv, "w") as f:
            f.write("script_type,count,bytes,sats\n")
            for kind, v in sorted(r["by_type"].items()):
                f.write(f"{kind},{v['count']},{v['bytes']},{v['sats']}\n")
        print(f"\nwrote {args.csv}")


if __name__ == "__main__":
    main()
