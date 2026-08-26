#!/usr/bin/env python3
"""
monetary_commit.py — compute the chained commitment C over a monetary store.

The merkle check proves a stripped block still belongs to the chain. It does
not prove two monetary nodes stripped it the same way: both can hold valid
blocks and disagree completely about what was removed, and nothing detects it.

C closes that gap.

    C_h = SHA256d( C_{h-1} || block_hash_h || K_h )

where K_h is the record's body digest — a hash over everything the node stored
for that block: retained transactions, stored txids, and the filter entries
describing every dropped output. Two nodes that made identical stripping
decisions produce identical K at every height and therefore identical C.
One classifier disagreement anywhere in history produces a different C and
stays different forever.

So "do we agree?" reduces to comparing one 32-byte value.

WHY THIS IS DERIVED, NOT STORED. C is a function of the store. Computing it
from the store rather than writing it during stripping means any node can
recompute and check it independently, and a node cannot assert a C its own data
does not support. It is a check, not a claim.

WHAT IT IS NOT. This is a commitment to stripping decisions. It is not the
full L/M UTXO accumulator described in the design, which commits to UTXO set
state and needs a UTXO database to compute. That remains unimplemented. C as
computed here answers "did we strip identically", not "do we hold identical
UTXO sets". Those are different questions and this only answers the first.

C also confers no security of its own. It anchors to proof-of-work by
reference: each step mixes in a block hash that real work committed to. It is
not proof of that work, and node counts still confer nothing.

Usage:
    python3 monetary_commit.py /path/to/mstore
    python3 monetary_commit.py /path/to/mstore --csv commitments.csv
    python3 monetary_commit.py /path/to/mstore --expect <hex>
    python3 monetary_commit.py --selftest

Standard library only. BSD-2-Clause.
"""

import argparse
import glob
import hashlib
import os
import struct
import sys

STORE_MAGIC = b"MBLK"
STORE_VERSION = 1

# Fixed offsets within a record. Computing C needs only these two fields, so
# no transaction parsing is required and this stays fast over a large store.
OFF_LENGTH = 6          # uint32, counts bytes after this field
OFF_DIGEST = 10         # 32 bytes, SHA256d over everything after it
OFF_BLOCKHASH = 42      # 32 bytes, start of the digested body
HEADER_LEN = 42         # bytes before the digested body begins

GENESIS_C = b"\x00" * 32


def dsha(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def iter_records(path, verify=True):
    """
    Yield (block_hash, body_digest) for each record, in stored order.

    With verify=True the body digest is recomputed and checked, so a corrupt
    store is caught here rather than silently producing a plausible C.
    """
    files = sorted(glob.glob(os.path.join(path, "mblk*.dat")))
    if not files:
        sys.exit(f"no mblk*.dat in {path}")
    for f in files:
        with open(f, "rb") as fh:
            data = fh.read()
        pos = 0
        while pos < len(data):
            if data[pos:pos + 4] != STORE_MAGIC:
                raise ValueError(f"{os.path.basename(f)}: bad magic at {pos}")
            version = struct.unpack_from("<H", data, pos + 4)[0]
            if version != STORE_VERSION:
                raise ValueError(f"unsupported store version {version}")
            length = struct.unpack_from("<I", data, pos + OFF_LENGTH)[0]
            digest = data[pos + OFF_DIGEST:pos + OFF_DIGEST + 32]
            end = pos + OFF_DIGEST + length
            if end > len(data):
                raise ValueError(f"{os.path.basename(f)}: truncated record "
                                 f"at {pos}")
            body = data[pos + HEADER_LEN:end]
            if verify and dsha(body) != digest:
                raise ValueError(f"{os.path.basename(f)}: body digest mismatch "
                                 f"at {pos} — store is corrupt")
            block_hash = body[:32]
            yield block_hash, digest
            pos = end


def chain(records, start=GENESIS_C):
    """Fold records into the commitment chain, yielding (block_hash, K, C)."""
    c = start
    for block_hash, k in records:
        c = dsha(c + block_hash + k)
        yield block_hash, k, c


def compute(path, csv_path=None, verify=True, start=GENESIS_C):
    n = 0
    c = start
    out = None
    if csv_path:
        out = open(csv_path, "w")
        out.write("index,block_hash,K,C\n")
    try:
        for block_hash, k, c in chain(iter_records(path, verify), start):
            if out:
                out.write(f"{n},{block_hash[::-1].hex()},{k.hex()},{c.hex()}\n")
            n += 1
    finally:
        if out:
            out.close()
    return n, c


# ---------------------------------------------------------------- self-test


def selftest():
    """
    Verify the properties C is supposed to have, without needing a real store.

    Builds synthetic records directly, since C depends only on block hashes and
    body digests, not on transaction contents.
    """
    ok = []

    def check(name, cond):
        ok.append(cond)
        print(f"  [{'ok  ' if cond else 'FAIL'}] {name}")

    a = [(bytes([i]) * 32, bytes([i + 100]) * 32) for i in range(10)]

    c_a = list(chain(a))[-1][2]
    c_a2 = list(chain(a))[-1][2]
    check("deterministic: same input gives same C", c_a == c_a2)

    # one differing stripping decision anywhere changes C
    b = list(a)
    b[5] = (b[5][0], bytes([255]) * 32)
    c_b = list(chain(b))[-1][2]
    check("one differing decision changes C", c_a != c_b)

    # and the divergence is permanent, not self-healing
    a_ext = a + [(bytes([200]) * 32, bytes([201]) * 32)]
    b_ext = b + [(bytes([200]) * 32, bytes([201]) * 32)]
    check("divergence persists once introduced",
          list(chain(a_ext))[-1][2] != list(chain(b_ext))[-1][2])

    # order matters: the chain is over an ordered history
    r = list(reversed(a))
    check("order sensitive", list(chain(r))[-1][2] != c_a)

    # a truncated history is a different commitment, not a prefix match
    check("truncation is detectable", list(chain(a[:9]))[-1][2] != c_a)

    # chaining is resumable: computing in two halves matches one pass
    mid = list(chain(a[:5]))[-1][2]
    resumed = list(chain(a[5:], start=mid))[-1][2]
    check("resumable from a checkpoint", resumed == c_a)

    # every intermediate C differs from every other
    cs = [c for _h, _k, c in chain(a)]
    check("no repeated intermediate values", len(set(cs)) == len(cs))

    # block hash participates: same decisions on a different block diverge
    d = list(a)
    d[3] = (bytes([99]) * 32, d[3][1])
    check("block hash participates", list(chain(d))[-1][2] != c_a)

    print()
    if all(ok):
        print(f"{len(ok)} passed. C is deterministic, order-sensitive,")
        print("permanently divergent on disagreement, and resumable.")
        return 0
    print(f"{sum(ok)}/{len(ok)} passed")
    return 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("store", nargs="?", help="directory containing mblk*.dat")
    ap.add_argument("--csv", help="write per-block K and C here")
    ap.add_argument("--expect", help="compare the final C against this hex")
    ap.add_argument("--resume-from", help="start the chain from this C (hex)")
    ap.add_argument("--no-verify", action="store_true",
                    help="skip body digest checks (faster, less safe)")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        sys.exit(selftest())
    if not args.store:
        sys.exit("need a store directory (or --selftest)")

    start = bytes.fromhex(args.resume_from) if args.resume_from else GENESIS_C
    if len(start) != 32:
        sys.exit("--resume-from must be 32 bytes of hex")

    n, c = compute(args.store, args.csv, not args.no_verify, start)

    print(f"blocks committed  {n:,}")
    print(f"C                 {c.hex()}")
    if args.csv:
        print(f"per-block chain   {args.csv}")

    if args.expect:
        match = c.hex() == args.expect.lower().strip()
        print()
        print("MATCH — identical stripping decisions" if match
              else "MISMATCH — the two stores disagree about what was removed")
        sys.exit(0 if match else 1)


if __name__ == "__main__":
    main()
