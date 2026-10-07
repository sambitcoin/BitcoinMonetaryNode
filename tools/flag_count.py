#!/usr/bin/env python3
"""
flag_count.py — count transaction flags across a monetary store.

Answers one question: of the transactions the stripper touched, how many are
MODIFIED (flag 1, body retained, reconstructable) versus STRIPPED (flag 2,
txid only, inputs lost)?

That split is the single unmeasured input to format v2. Only flag 2 records
need prevout retention, so the cost of v2 is bounded by their input count —
and until this runs, any figure quoted for it is a guess.

Standard library only. Reads the store; writes nothing. Safe to run against a
live store, though results are a snapshot if the daemon is writing.

Usage:
    python3 flag_count.py --store ~/mstore
    python3 flag_count.py --selftest

BSD-2-Clause.
"""

import argparse
import glob
import os
import struct
import sys

STORE_MAGIC = b"MBLK"
FLAG_WHOLE, FLAG_MODIFIED, FLAG_STRIPPED = 0, 1, 2


class Cursor:
    """Bounds-safe reader. A malformed store must not raise struct.error."""

    def __init__(self, d, p=0):
        self.d, self.p = d, p

    def take(self, n):
        if n < 0 or self.p + n > len(self.d):
            raise ValueError("record truncated")
        b = self.d[self.p:self.p + n]
        self.p += n
        return b

    def u8(self):
        return self.take(1)[0]

    def varint(self):
        n = self.u8()
        if n < 0xfd:
            return n
        if n == 0xfd:
            return struct.unpack("<H", self.take(2))[0]
        if n == 0xfe:
            return struct.unpack("<I", self.take(4))[0]
        return struct.unpack("<Q", self.take(8))[0]


def count_record(data, pos):
    """Count flags in one record. Returns (counts, next_pos).

    The body digest is deliberately not verified: this is a counting pass over
    a possibly-large store, and verify_store() already exists for integrity.
    """
    if data[pos:pos + 4] != STORE_MAGIC:
        raise ValueError(f"bad magic at offset {pos}")
    version = struct.unpack_from("<H", data, pos + 4)[0]
    length = struct.unpack_from("<I", data, pos + 6)[0]
    end = pos + 10 + length
    if end > len(data):
        raise ValueError(f"record at {pos} runs past end of file")

    c = Cursor(data, pos + 42)
    c.take(32)                      # block hash
    c.take(80)                      # header
    n_tx = c.varint()

    r = {"whole": 0, "modified": 0, "stripped": 0,
         "modified_bytes": 0, "version": version}

    for _ in range(n_tx):
        flag = c.u8()
        if flag == FLAG_WHOLE:
            c.take(c.varint())
            r["whole"] += 1
        elif flag == FLAG_MODIFIED:
            c.take(32)
            body_len = c.varint()
            c.take(body_len)
            r["modified"] += 1
            r["modified_bytes"] += body_len
        elif flag == FLAG_STRIPPED:
            c.take(32)
            r["stripped"] += 1
        else:
            raise ValueError(f"unknown tx flag {flag} at {pos}")

    r["filters"] = c.varint()
    return r, end


def scan(store):
    files = sorted(glob.glob(os.path.join(store, "mblk*.dat")))
    if not files:
        raise SystemExit(f"no mblk*.dat files in {store}")

    t = {"whole": 0, "modified": 0, "stripped": 0,
         "modified_bytes": 0, "filters": 0, "blocks": 0}
    versions = set()

    for path in files:
        with open(path, "rb") as fh:
            data = fh.read()
        pos = 0
        while pos < len(data):
            r, pos = count_record(data, pos)
            versions.add(r.pop("version"))
            t["blocks"] += 1
            for k, v in r.items():
                t[k] += v
        print(f"  {os.path.basename(path)}: {t['blocks']:,} blocks so far",
              file=sys.stderr)

    t["versions"] = sorted(versions)
    return t


def report(t):
    tx = t["whole"] + t["modified"] + t["stripped"]
    touched = t["modified"] + t["stripped"]
    pct = lambda n, d: (100.0 * n / d) if d else 0.0

    print()
    print(f"store version(s)      {t['versions']}")
    print(f"blocks                {t['blocks']:,}")
    print(f"transactions          {tx:,}")
    print()
    print(f"  whole      flag 0   {t['whole']:>14,}   {pct(t['whole'], tx):6.2f}%")
    print(f"  modified   flag 1   {t['modified']:>14,}   {pct(t['modified'], tx):6.2f}%")
    print(f"  stripped   flag 2   {t['stripped']:>14,}   {pct(t['stripped'], tx):6.2f}%")
    print()
    print(f"touched (1 + 2)       {touched:,}  ({pct(touched, tx):.2f}% of transactions)")
    if touched:
        print(f"  of which modified   {pct(t['modified'], touched):6.2f}%")
        print(f"  of which stripped   {pct(t['stripped'], touched):6.2f}%")
    print()
    print(f"filter entries        {t['filters']:,}")
    print(f"modified bodies       {t['modified_bytes'] / 1e9:.2f} GB")
    print()
    print("FORMAT V2 COST")
    print("  Only flag 2 records need prevout retention. Each input costs 33")
    print("  bytes (32-byte prevout txid + 1-byte varint vout for vout < 253).")
    print("  Input counts are NOT in the store, so this is a lower bound that")
    print("  assumes one input per stripped transaction:")
    print()
    lo = t["stripped"] * 33
    print(f"    >= {lo / 1e6:,.1f} MB  ({t['stripped']:,} x 33 bytes, 1 input each)")
    print()
    print("  Measure real input counts against the chain before publishing.")


# ---------------------------------------------------------------- selftest


def selftest():
    checks, passed = [], 0

    def ck(name, got, want):
        nonlocal passed
        ok = got == want
        passed += ok
        checks.append((ok, name, got, want))

    def vi(n):
        if n < 0xfd:
            return bytes([n])
        if n <= 0xffff:
            return b"\xfd" + struct.pack("<H", n)
        return b"\xfe" + struct.pack("<I", n)

    def rec(entries, n_filters=0):
        """Build a record with the given (flag, payload_len) transactions."""
        parts = [b"\x00" * 32, b"\x00" * 80, vi(len(entries))]
        for flag, ln in entries:
            if flag == FLAG_WHOLE:
                parts.append(bytes([flag]) + vi(ln) + b"\x00" * ln)
            elif flag == FLAG_MODIFIED:
                parts.append(bytes([flag]) + b"\x11" * 32 + vi(ln) + b"\x00" * ln)
            else:
                parts.append(bytes([flag]) + b"\x22" * 32)
        parts.append(vi(n_filters))
        for _ in range(n_filters):
            parts.append(b"\x33" * 32 + vi(0) + struct.pack("<Q", 0)
                         + struct.pack("<I", 0) + vi(0))
        body = b"".join(parts)
        return (STORE_MAGIC + struct.pack("<H", 1)
                + struct.pack("<I", len(body) + 32) + b"\x00" * 32 + body)

    r, nxt = count_record(rec([(FLAG_WHOLE, 10)]), 0)
    ck("single whole tx counted", r["whole"], 1)
    ck("next_pos is end of record", nxt, len(rec([(FLAG_WHOLE, 10)])))

    r, _ = count_record(rec([(FLAG_MODIFIED, 40)]), 0)
    ck("modified counted", r["modified"], 1)
    ck("modified body bytes", r["modified_bytes"], 40)

    r, _ = count_record(rec([(FLAG_STRIPPED, 0)]), 0)
    ck("stripped counted", r["stripped"], 1)

    mixed = rec([(FLAG_WHOLE, 5), (FLAG_MODIFIED, 7), (FLAG_STRIPPED, 0),
                 (FLAG_STRIPPED, 0)], n_filters=3)
    r, _ = count_record(mixed, 0)
    ck("mixed: whole", r["whole"], 1)
    ck("mixed: modified", r["modified"], 1)
    ck("mixed: stripped", r["stripped"], 2)
    ck("mixed: filters", r["filters"], 3)

    # two records back to back, as a real file has
    two = mixed + mixed
    r1, p1 = count_record(two, 0)
    r2, p2 = count_record(two, p1)
    ck("second record parses", r2["stripped"], 2)
    ck("walk reaches exactly end of file", p2, len(two))

    # varint boundary: 300 transactions needs a 3-byte count
    many = rec([(FLAG_STRIPPED, 0)] * 300)
    r, _ = count_record(many, 0)
    ck("varint tx count over 252", r["stripped"], 300)

    # tamper resistance
    try:
        count_record(b"XXXX" + rec([(FLAG_WHOLE, 1)])[4:], 0)
        ck("bad magic rejected", False, True)
    except ValueError:
        ck("bad magic rejected", True, True)

    try:
        bad = bytearray(rec([(FLAG_WHOLE, 1)]))
        bad[42 + 32 + 80 + 1] = 9          # unknown flag
        count_record(bytes(bad), 0)
        ck("unknown flag rejected", False, True)
    except ValueError:
        ck("unknown flag rejected", True, True)

    try:
        count_record(rec([(FLAG_WHOLE, 10)])[:60], 0)
        ck("truncated record rejected", False, True)
    except ValueError:
        ck("truncated record rejected", True, True)

    for ok, name, got, want in checks:
        print(f"  [{'ok  ' if ok else 'FAIL'}] {name}"
              + ("" if ok else f": got {got!r}, want {want!r}"))
    print(f"\n{passed}/{len(checks)} passed")
    return 0 if passed == len(checks) else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--store", help="path to the monetary store directory")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()

    if a.selftest:
        return selftest()
    if not a.store:
        ap.error("--store is required (or use --selftest)")
    report(scan(os.path.expanduser(a.store)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
