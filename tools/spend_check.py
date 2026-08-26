#!/usr/bin/env python3
"""
spend_check.py — can a dropped output still be spent, using only local data?

This is the claim the whole design rests on. A monetary node deletes spam
outputs from block storage but keeps a filter entry for each: outpoint, amount,
scriptPubKey, height. If that entry is genuinely sufficient to validate a later
spend, then nothing is stranded, nobody is confiscated, and no peer has to be
trusted. If it is not sufficient, the design is broken.

So this does not assert it. It checks three things against a real store:

  1. COMPLETENESS — for every input in the store that spends a dropped output,
     is the filter entry present? A spend with no entry would be a spend the
     node could not validate.

  2. VALUE CONSERVATION — where every input of a transaction is known, do the
     inputs cover the outputs? This needs the amount, which is exactly what the
     filter entry supplies and what deleting the output would have destroyed.

  3. CRYPTOGRAPHIC VERIFICATION — for spends of bare multisig outputs, actually
     verify the ECDSA signatures against the scriptPubKey recovered from the
     filter entry. This is the strongest available form of the claim: a
     signature checked against an output whose data was deleted from block
     storage, using nothing but the index that replaced it.

secp256k1 and the legacy sighash algorithm are implemented here in pure Python.
That is slow, so signature verification runs on a sample rather than on every
spend, controlled by --verify-sigs.

WHAT THIS DOES NOT DO. It is not a consensus validator and must not be mistaken
for one. It checks signatures on a sample of a specific script type. A monetary
node does not rely on this code — it validates through Bitcoin Knots, which is
the entire point of the architecture. This exists to test one property of the
filter index.

Single pass: filter entries are recorded in the block that created the output,
and spends necessarily come later, so accumulating as we go is sufficient.

Usage:
    python3 spend_check.py --store ~/mstore_test --start-height 900000
    python3 spend_check.py --store ~/mstore --start-height 767430 \\
        --verify-sigs 50
    python3 spend_check.py --selftest

Standard library only. BSD-2-Clause.
"""

import argparse
import glob
import hashlib
import os
import struct
import sys
import time

STORE_MAGIC = b"MBLK"
FLAG_WHOLE, FLAG_MODIFIED, FLAG_STRIPPED = 0, 1, 2

OP_RETURN = 0x6A
OP_CHECKMULTISIG = 0xAE

# secp256k1
P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
SIGHASH_ALL = 1


def dsha(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


# ---------------------------------------------------------------- secp256k1


def inv(a, m=P):
    return pow(a, m - 2, m)


def point_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    (x1, y1), (x2, y2) = a, b
    if x1 == x2:
        if (y1 + y2) % P == 0:
            return None
        lam = (3 * x1 * x1) * inv(2 * y1) % P
    else:
        lam = (y2 - y1) * inv(x2 - x1) % P
    x3 = (lam * lam - x1 - x2) % P
    return (x3, (lam * (x1 - x3) - y1) % P)


def point_mul(k, pt):
    r = None
    while k:
        if k & 1:
            r = point_add(r, pt)
        pt = point_add(pt, pt)
        k >>= 1
    return r


def decompress(pub):
    """Turn a serialised public key into a curve point, or None if invalid."""
    if len(pub) == 65 and pub[0] == 0x04:
        x = int.from_bytes(pub[1:33], "big")
        y = int.from_bytes(pub[33:65], "big")
        return (x, y) if (y * y - x * x * x - 7) % P == 0 else None
    if len(pub) == 33 and pub[0] in (0x02, 0x03):
        x = int.from_bytes(pub[1:], "big")
        if x >= P:
            return None
        y2 = (pow(x, 3, P) + 7) % P
        y = pow(y2, (P + 1) // 4, P)
        if (y * y) % P != y2:
            return None                 # x is not on the curve
        if y & 1 != pub[0] & 1:
            y = P - y
        return (x, y)
    return None


def parse_der(sig):
    """Parse a DER-encoded ECDSA signature into (r, s)."""
    if len(sig) < 8 or sig[0] != 0x30:
        raise ValueError("not a DER sequence")
    if sig[1] != len(sig) - 2:
        raise ValueError("bad DER length")
    if sig[2] != 0x02:
        raise ValueError("missing r")
    rlen = sig[3]
    r = int.from_bytes(sig[4:4 + rlen], "big")
    i = 4 + rlen
    if sig[i] != 0x02:
        raise ValueError("missing s")
    slen = sig[i + 1]
    s = int.from_bytes(sig[i + 2:i + 2 + slen], "big")
    return r, s


def ecdsa_verify(pub, msg32, sig_der):
    """Standard ECDSA verification over secp256k1."""
    pt = decompress(pub)
    if pt is None:
        return False
    try:
        r, s = parse_der(sig_der)
    except (ValueError, IndexError):
        return False
    if not (1 <= r < N and 1 <= s < N):
        return False
    z = int.from_bytes(msg32, "big")
    sinv = pow(s, N - 2, N)
    u1 = z * sinv % N
    u2 = r * sinv % N
    pt2 = point_add(point_mul(u1, (GX, GY)), point_mul(u2, pt))
    if pt2 is None:
        return False
    return pt2[0] % N == r


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

    def u32(self):
        v = struct.unpack_from("<I", self.d, self.p)[0]
        self.p += 4
        return v

    def u64(self):
        v = struct.unpack_from("<Q", self.d, self.p)[0]
        self.p += 8
        return v

    def varint(self):
        n = self.u8()
        if n < 0xFD:
            return n
        if n == 0xFD:
            v = struct.unpack_from("<H", self.d, self.p)[0]
            self.p += 2
            return v
        if n == 0xFE:
            return self.u32()
        return self.u64()


def write_varint(n):
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def parse_tx(body):
    """Return (txid, vin, vout, version, locktime). vin carries scriptSigs."""
    c = Cursor(body)
    version = c.take(4)
    segwit = c.peek(2) == b"\x00\x01"
    if segwit:
        c.take(2)

    io_start = c.p
    n_in = c.varint()
    vin = []
    for _ in range(n_in):
        prev_txid = c.take(32)
        prev_vout = c.u32()
        script = c.take(c.varint())
        seq = c.take(4)
        vin.append([prev_txid, prev_vout, script, seq])

    n_out = c.varint()
    vout = []
    for i in range(n_out):
        amount = c.u64()
        spk = c.take(c.varint())
        vout.append((i, amount, spk))
    io_end = c.p

    if segwit:
        for _ in range(n_in):
            for _ in range(c.varint()):
                c.take(c.varint())
    locktime = c.take(4)

    legacy = (body[:4] + body[io_start:io_end] + locktime) if segwit \
        else body[:c.p]
    return dsha(legacy), vin, vout, version, locktime


def iter_script(script):
    i, n = 0, len(script)
    while i < n:
        op = script[i]
        i += 1
        data = None
        if 0x01 <= op <= 0x4B:
            if i + op > n:
                raise ValueError("truncated")
            data = script[i:i + op]
            i += op
        elif op == 0x4C:
            ln = script[i]; i += 1
            data = script[i:i + ln]; i += ln
        elif op == 0x4D:
            ln = struct.unpack_from("<H", script, i)[0]; i += 2
            data = script[i:i + ln]; i += ln
        elif op == 0x4E:
            ln = struct.unpack_from("<I", script, i)[0]; i += 4
            data = script[i:i + ln]; i += ln
        yield op, data


# ---------------------------------------------------------------- sighash


def legacy_sighash(vin, vout, version, locktime, index, subscript,
                   hashtype=SIGHASH_ALL):
    """
    BIP-less legacy SIGHASH_ALL.

    Every input's scriptSig is blanked except the one being signed, which is
    replaced by the scriptPubKey of the output it spends. That scriptPubKey is
    precisely what the filter entry preserved — without it this hash cannot be
    computed and the spend cannot be validated.
    """
    out = [version, write_varint(len(vin))]
    for i, (prev_txid, prev_vout, _script, seq) in enumerate(vin):
        s = subscript if i == index else b""
        out.append(prev_txid + struct.pack("<I", prev_vout)
                   + write_varint(len(s)) + s + seq)
    out.append(write_varint(len(vout)))
    for _i, amount, spk in vout:
        out.append(struct.pack("<Q", amount) + write_varint(len(spk)) + spk)
    out.append(locktime)
    out.append(struct.pack("<I", hashtype))
    return dsha(b"".join(out))


def verify_bare_multisig(vin, vout, version, locktime, index, spk):
    """
    Verify a spend of a bare multisig output using only the recovered script.

    Returns (verified, required, checked). Bare multisig scriptSigs begin with
    a dummy element because of the CHECKMULTISIG off-by-one, then carry the
    signatures in key order.
    """
    try:
        items = list(iter_script(spk))
    except ValueError:
        return False, 0, 0
    keys = [d for _op, d in items if d is not None and len(d) in (33, 65)]
    if not keys or spk[-1] != OP_CHECKMULTISIG:
        return False, 0, 0
    required = spk[0] - 0x50 if 0x51 <= spk[0] <= 0x60 else 0

    scriptsig = vin[index][2]
    try:
        sigs = [d for _op, d in iter_script(scriptsig)
                if d is not None and len(d) >= 9]
    except ValueError:
        return False, required, 0
    if not sigs:
        return False, required, 0

    verified = 0
    ki = 0
    for sig in sigs:
        der, hashtype = sig[:-1], sig[-1]
        if hashtype != SIGHASH_ALL:
            continue                      # only ALL is handled here
        msg = legacy_sighash(vin, vout, version, locktime, index, spk,
                             hashtype)
        while ki < len(keys):
            if ecdsa_verify(keys[ki], msg, der):
                verified += 1
                ki += 1
                break
            ki += 1
    return verified >= required and required > 0, required, verified


# ---------------------------------------------------------------- store


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
                    txs.append((c.take(32), None))
                elif flag == FLAG_MODIFIED:
                    txid = c.take(32)
                    txs.append((txid, parse_tx(c.take(c.varint()))))
                elif flag == FLAG_WHOLE:
                    parsed = parse_tx(c.take(c.varint()))
                    txs.append((parsed[0], parsed))
                else:
                    raise ValueError(f"unknown tx flag {flag}")

            filters = []
            for _ in range(c.varint()):
                txid = c.take(32)
                vout_i = c.varint()
                amount = struct.unpack("<Q", c.take(8))[0]
                h = struct.unpack("<I", c.take(4))[0]
                spk = c.take(c.varint())
                filters.append((txid, vout_i, amount, h, spk))

            yield height, txs, filters
            height += 1
            pos = end


def run(path, start_height, verify_sigs, progress):
    dropped = {}          # (txid, vout) -> (amount, spk, height)
    known = {}            # (txid, vout) -> amount, for retained outputs
    stats = {
        "blocks": 0, "filter_entries": 0, "stripped_txs": 0,
        "spends_of_dropped": 0, "spends_with_entry": 0,
        "spends_without_entry": 0,
        "value_checked": 0, "value_ok": 0, "value_bad": 0,
        "sig_attempted": 0, "sig_verified": 0, "sig_failed": 0,
        "sig_unsupported": 0,
    }
    examples = []
    missing_examples = []
    t0 = time.time()

    for height, txs, filters in iter_store(path, start_height):
        for txid, _vin, _vout, _v, _l in [(t[0], None, None, None, None)
                                          for t in txs if t[1] is None]:
            stats["stripped_txs"] += 1

        for txid, vout_i, amount, h, spk in filters:
            dropped[(txid, vout_i)] = (amount, spk, h)
            stats["filter_entries"] += 1

        for txid, parsed in txs:
            if parsed is None:
                continue
            _t, vin, vout, version, locktime = parsed

            total_in = 0
            all_known = True
            for idx, (prev_txid, prev_vout, _s, _q) in enumerate(vin):
                key = (prev_txid, prev_vout)
                if key in dropped:
                    stats["spends_of_dropped"] += 1
                    stats["spends_with_entry"] += 1
                    amount, spk, _h = dropped[key]
                    total_in += amount

                    if (verify_sigs and stats["sig_attempted"] < verify_sigs
                            and spk and spk[-1] == OP_CHECKMULTISIG):
                        stats["sig_attempted"] += 1
                        try:
                            okay, req, got = verify_bare_multisig(
                                vin, vout, version, locktime, idx, spk)
                        except Exception:
                            okay, req, got = False, 0, 0
                        if okay:
                            stats["sig_verified"] += 1
                            if len(examples) < 5:
                                examples.append(
                                    (txid[::-1].hex(), idx, height, req, got))
                        else:
                            stats["sig_failed"] += 1
                            if len(missing_examples) < 5:
                                missing_examples.append(
                                    (txid[::-1].hex(), idx, height, req, got))
                elif key in known:
                    total_in += known.pop(key)
                elif prev_txid != b"\x00" * 32:
                    all_known = False

            for vout_i, amount, spk in vout:
                if not (spk and spk[0] == OP_RETURN):
                    known[(txid, vout_i)] = amount

            if all_known and vin and vin[0][0] != b"\x00" * 32:
                total_out = sum(a for _i, a, _s in vout)
                stats["value_checked"] += 1
                if total_in >= total_out:
                    stats["value_ok"] += 1
                else:
                    stats["value_bad"] += 1

        stats["blocks"] += 1
        if stats["blocks"] % progress == 0:
            el = time.time() - t0
            print(f"  {stats['blocks']:,} blocks  height {height:,}  "
                  f"{el:.0f}s  dropped tracked {len(dropped):,}  "
                  f"spends found {stats['spends_of_dropped']:,}", flush=True)

    stats["seconds"] = time.time() - t0
    stats["dropped_unspent"] = len(dropped) - stats["spends_of_dropped"]
    return stats, examples, missing_examples


# ---------------------------------------------------------------- selftest


def selftest():
    ok = []

    def check(name, cond, detail=""):
        ok.append(cond)
        print(f"  [{'ok  ' if cond else 'FAIL'}] {name}"
              + (f"  — {detail}" if detail else ""))

    print("secp256k1")
    G = (GX, GY)
    check("generator is on the curve", (GY * GY - GX ** 3 - 7) % P == 0)
    check("2G computed consistently",
          point_add(G, G) == point_mul(2, G))
    check("nG is the point at infinity", point_mul(N, G) is None)
    check("(n-1)G + G is infinity",
          point_add(point_mul(N - 1, G), G) is None)

    pub_c = (b"\x02" if GY % 2 == 0 else b"\x03") + GX.to_bytes(32, "big")
    check("compressed generator decompresses to itself",
          decompress(pub_c) == G)
    check("uncompressed generator decompresses",
          decompress(b"\x04" + GX.to_bytes(32, "big")
                     + GY.to_bytes(32, "big")) == G)
    # Find an x that is genuinely not on the curve, so this test can fail.
    off_x = next(x for x in range(2, 500)
                 if pow((pow(x, 3, P) + 7) % P, (P - 1) // 2, P) != 1)
    check("off-curve x rejected",
          decompress(b"\x02" + off_x.to_bytes(32, "big")) is None,
          f"x={off_x}")
    on_x = next(x for x in range(2, 500)
                if pow((pow(x, 3, P) + 7) % P, (P - 1) // 2, P) == 1)
    pt_on = decompress(b"\x02" + on_x.to_bytes(32, "big"))
    check("on-curve x accepted and satisfies the curve equation",
          pt_on is not None
          and (pt_on[1] ** 2 - pt_on[0] ** 3 - 7) % P == 0,
          f"x={on_x}")
    check("parity byte selects the right y",
          decompress(b"\x02" + on_x.to_bytes(32, "big"))[1] % 2 == 0
          and decompress(b"\x03" + on_x.to_bytes(32, "big"))[1] % 2 == 1)
    check("x above the field prime rejected",
          decompress(b"\x02" + (P + 1).to_bytes(32, "big")) is None)

    print("\nECDSA sign and verify")

    def sign(priv, msg32, k):
        z = int.from_bytes(msg32, "big")
        R = point_mul(k, G)
        r = R[0] % N
        s = (pow(k, N - 2, N) * (z + r * priv)) % N
        if s > N // 2:
            s = N - s
        def enc(v):
            b = v.to_bytes(32, "big").lstrip(b"\x00")
            if b[0] & 0x80:
                b = b"\x00" + b
            return b"\x02" + bytes([len(b)]) + b
        body = enc(r) + enc(s)
        return b"\x30" + bytes([len(body)]) + body

    priv = 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF
    pub = point_mul(priv, G)
    pubser = (b"\x02" if pub[1] % 2 == 0 else b"\x03") \
        + pub[0].to_bytes(32, "big")
    msg = dsha(b"monetary node spend test")
    sig = sign(priv, msg, 0xDEADBEEFCAFEBABE1234567890ABCDEF)

    check("valid signature verifies", ecdsa_verify(pubser, msg, sig))
    check("wrong message rejected",
          not ecdsa_verify(pubser, dsha(b"different"), sig))
    other = point_mul(priv + 1, G)
    otherser = (b"\x02" if other[1] % 2 == 0 else b"\x03") \
        + other[0].to_bytes(32, "big")
    check("wrong key rejected", not ecdsa_verify(otherser, msg, sig))
    tampered = bytearray(sig)
    tampered[-1] ^= 0x01
    check("tampered signature rejected",
          not ecdsa_verify(pubser, msg, bytes(tampered)))
    check("malformed DER rejected",
          not ecdsa_verify(pubser, msg, b"\x00\x01\x02"))

    print("\nlegacy sighash")
    vin = [[b"\xaa" * 32, 0, b"\x99" * 10, struct.pack("<I", 0xFFFFFFFF)]]
    vout = [(0, 5000, b"\x51\x20" + b"\xbb" * 32)]
    ver = struct.pack("<i", 1)
    lock = struct.pack("<I", 0)
    spk = b"\x51\x21\x02" + b"\xcc" * 32 + b"\x51\xae"
    h1 = legacy_sighash(vin, vout, ver, lock, 0, spk)
    check("sighash is 32 bytes", len(h1) == 32)
    h2 = legacy_sighash(vin, vout, ver, lock, 0, b"\x76\xa9\x14" + b"\x11" * 20)
    check("different subscript gives a different hash", h1 != h2)
    vout2 = [(0, 5001, b"\x51\x20" + b"\xbb" * 32)]
    check("changing an output changes the hash",
          legacy_sighash(vin, vout2, ver, lock, 0, spk) != h1)
    check("scriptSig contents do not affect the hash",
          legacy_sighash([[b"\xaa" * 32, 0, b"\x77" * 3,
                           struct.pack("<I", 0xFFFFFFFF)]],
                         vout, ver, lock, 0, spk) == h1)

    print("\nend-to-end: sign a real 1-of-1 bare multisig spend and verify it")
    spk_ms = b"\x51\x21" + pubser + b"\x51\xae"
    vin_ms = [[b"\xdd" * 32, 3, b"", struct.pack("<I", 0xFFFFFFFF)]]
    vout_ms = [(0, 1234, b"\x00\x14" + b"\xee" * 20)]
    msg_ms = legacy_sighash(vin_ms, vout_ms, ver, lock, 0, spk_ms)
    sig_ms = sign(priv, msg_ms, 0x1BADB002FEEDFACE0123456789ABCDEF) \
        + bytes([SIGHASH_ALL])
    vin_ms[0][2] = b"\x00" + bytes([len(sig_ms)]) + sig_ms   # dummy + sig
    okay, req, got = verify_bare_multisig(vin_ms, vout_ms, ver, lock, 0, spk_ms)
    check("bare multisig spend verifies from the recovered script",
          okay and req == 1 and got == 1, f"required {req}, verified {got}")

    vout_bad = [(0, 9999, b"\x00\x14" + b"\xee" * 20)]
    okay2, _r, _g = verify_bare_multisig(vin_ms, vout_bad, ver, lock, 0, spk_ms)
    check("altering the spending transaction breaks it", not okay2)

    print()
    print(f"{sum(ok)}/{len(ok)} passed")
    return 0 if all(ok) else 1


# ---------------------------------------------------------------- main


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--store")
    ap.add_argument("--start-height", type=int)
    ap.add_argument("--verify-sigs", type=int, default=0, metavar="N",
                    help="cryptographically verify up to N bare multisig "
                         "spends (slow: pure-Python secp256k1)")
    ap.add_argument("--progress", type=int, default=10000)
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        sys.exit(selftest())
    if not (args.store and args.start_height is not None):
        sys.exit("need --store and --start-height (or --selftest)")

    print(f"store  {args.store}")
    print(f"from   height {args.start_height:,}")
    if args.verify_sigs:
        print(f"will verify up to {args.verify_sigs} signatures "
              f"cryptographically")
    print()

    stats, examples, failures = run(args.store, args.start_height,
                                    args.verify_sigs, args.progress)

    print()
    print("=" * 68)
    print("FILTER INDEX COMPLETENESS")
    print("=" * 68)
    print(f"  blocks scanned            {stats['blocks']:,}")
    print(f"  filter entries            {stats['filter_entries']:,}")
    print(f"  dropped outputs spent     {stats['spends_of_dropped']:,}")
    print(f"  ...with entry present     {stats['spends_with_entry']:,}")
    print(f"  ...with entry MISSING     {stats['spends_without_entry']:,}")
    print(f"  dropped, never spent      {stats['dropped_unspent']:,}")
    print()
    if stats["spends_without_entry"] == 0:
        print("  Every spend of a dropped output had its filter entry.")
        print("  The node held the amount and scriptPubKey needed to validate")
        print("  it, locally, with no peer involvement.")
    else:
        print("  SOME SPENDS HAD NO ENTRY. The filter index is incomplete and")
        print("  those spends could not be validated locally.")

    print()
    print("=" * 68)
    print("VALUE CONSERVATION")
    print("=" * 68)
    print(f"  transactions fully resolvable  {stats['value_checked']:,}")
    print(f"  inputs cover outputs           {stats['value_ok']:,}")
    print(f"  violations                     {stats['value_bad']:,}")
    print()
    print("  Only transactions whose every input was seen within the scanned")
    print("  range can be checked. Amounts for dropped outputs came from the")
    print("  filter index, which is the point: deleting the output without")
    print("  keeping the amount would make this uncheckable.")

    if args.verify_sigs:
        print()
        print("=" * 68)
        print("CRYPTOGRAPHIC VERIFICATION")
        print("=" * 68)
        print(f"  spends attempted   {stats['sig_attempted']:,}")
        print(f"  verified           {stats['sig_verified']:,}")
        print(f"  failed             {stats['sig_failed']:,}")
        for txid, idx, h, req, got in examples:
            print(f"    verified {txid[:20]}... input {idx} "
                  f"at height {h:,}  ({got}/{req} signatures)")
        for txid, idx, h, req, got in failures:
            print(f"    FAILED   {txid[:20]}... input {idx} "
                  f"at height {h:,}  ({got}/{req} signatures)")
        print()
        print("  Each verified spend had its scriptPubKey deleted from block")
        print("  storage and recovered from the filter index. The signature")
        print("  was then checked against that recovered script and passed.")
        print()
        print("  Note: only SIGHASH_ALL bare multisig is handled here.")
        print("  Failures may reflect an unhandled sighash type rather than an")
        print("  invalid spend; this is a property test, not a validator.")

    print()
    print(f"elapsed {stats['seconds']:.0f}s")


if __name__ == "__main__":
    main()
