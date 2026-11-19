#!/usr/bin/env python3
"""
test_monetary_store.py — verify the monetary store format before it touches
real chain data.

Builds synthetic blocks containing every spam carrier we target, with real
merkle roots computed the way Bitcoin computes them, then checks that:

  1. every carrier is detected and its bytes removed
  2. the stripped block still verifies against its header
  3. the record round-trips through disk and still verifies
  4. filter entries preserve what a future spend needs
  5. real public keys are NOT flagged as data (no false positives)
  6. corruption anywhere in a record is detected

Run: python3 test_monetary_store.py
"""

import os
import struct
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from monetary_store import (  # noqa: E402
    dsha, write_varint, strip_block, read_record, merkle_root, on_curve,
    is_data_multisig, envelope_payload, classify_output,
    STORE_MAGIC, INSCRIPTION_START,
)

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    mark = "ok  " if cond else "FAIL"
    print(f"  [{mark}] {name}" + (f"  — {detail}" if detail else ""))


# ------------------------------------------------------------------ builders


def push(data):
    n = len(data)
    if n == 0:
        return b"\x00"
    if n < 0x4C:
        return bytes([n]) + data
    if n <= 0xFF:
        return b"\x4c" + bytes([n]) + data
    if n <= 0xFFFF:
        return b"\x4d" + struct.pack("<H", n) + data
    return b"\x4e" + struct.pack("<I", n) + data


def make_input(txid=None, vout=0, script=b"", seq=0xFFFFFFFF):
    txid = txid or os.urandom(32)
    return (txid + struct.pack("<I", vout) + write_varint(len(script))
            + script + struct.pack("<I", seq))


def make_output(value, script):
    return struct.pack("<Q", value) + write_varint(len(script)) + script


def make_tx(inputs, outputs, witnesses=None, version=1, locktime=0):
    """Returns (serialised_tx, txid). Witness excluded from txid per SegWit."""
    legacy = (struct.pack("<i", version)
              + write_varint(len(inputs)) + b"".join(inputs)
              + write_varint(len(outputs)) + b"".join(outputs)
              + struct.pack("<I", locktime))
    txid = dsha(legacy)
    if not witnesses:
        return legacy, txid
    wit = b""
    for stack in witnesses:
        wit += write_varint(len(stack))
        for item in stack:
            wit += write_varint(len(item)) + item
    full = (struct.pack("<i", version) + b"\x00\x01"
            + write_varint(len(inputs)) + b"".join(inputs)
            + write_varint(len(outputs)) + b"".join(outputs)
            + wit + struct.pack("<I", locktime))
    return full, txid


def make_block(txs, prev=None):
    """txs is a list of (bytes, txid). Header carries the real merkle root."""
    root = merkle_root([t[1] for t in txs])
    header = (struct.pack("<i", 4) + (prev or os.urandom(32)) + root
              + struct.pack("<I", 1700000000) + struct.pack("<I", 0x1d00ffff)
              + struct.pack("<I", 42))
    return header + write_varint(len(txs)) + b"".join(t[0] for t in txs)


# a real secp256k1 point: the generator
GEN_X = bytes.fromhex(
    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
GEN_Y = bytes.fromhex(
    "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
REAL_KEY = b"\x02" + GEN_X
REAL_KEY_UNCOMPRESSED = b"\x04" + GEN_X + GEN_Y


def p2tr_script():
    return b"\x51\x20" + os.urandom(32)


def p2wpkh_script():
    return b"\x00\x14" + os.urandom(20)


def off_curve_32():
    """Deterministically find 32 bytes that are provably not an x-coordinate."""
    for i in range(1000):
        cand = b"STAMP:" + i.to_bytes(26, "big")
        if not on_curve(cand):
            return cand
    raise AssertionError("no off-curve candidate found")


# ------------------------------------------------------------------ unit


def test_curve():
    print("\ncurve arithmetic")
    check("generator x is on the curve", on_curve(GEN_X))
    hits = sum(on_curve(os.urandom(32)) for _ in range(200))
    check("random data is on-curve about half the time",
          60 < hits < 140, f"{hits}/200")
    check("x >= field prime rejected",
          not on_curve((2**256 - 1).to_bytes(32, "big")))


def test_multisig():
    print("\nbare multisig detection")
    real = b"\x51" + push(REAL_KEY) + push(REAL_KEY) + b"\x52\xae"
    check("genuine 1-of-2 multisig NOT flagged", not is_data_multisig(real))

    real_u = b"\x51" + push(REAL_KEY_UNCOMPRESSED) + b"\x51\xae"
    check("genuine uncompressed key NOT flagged", not is_data_multisig(real_u))

    off = off_curve_32()
    stamp = b"\x51" + push(b"\x02" + off) + push(b"\x03" + off) + b"\x52\xae"
    check("stamp-style data keys ARE flagged", is_data_multisig(stamp),
          "02-prefixed but off-curve")

    check("non-multisig script ignored", not is_data_multisig(p2wpkh_script()))


def test_envelope():
    print("\ninscription envelope detection")
    payload = b"A" * 500
    env = b"\x00\x63" + push(b"ord") + push(payload) + b"\x68"
    check("OP_0 OP_IF envelope found", envelope_payload(env) == 503,
          f"{envelope_payload(env)} bytes")

    # The false value before OP_IF has three encodings. All are real
    # envelopes; all must be found — but only with the protocol tag present.
    env2 = push(b"") + b"\x63" + push(b"ord") + push(payload) + b"\x68"
    check("empty-push variant found", envelope_payload(env2) == 503)

    env3 = push(b"\x00") + b"\x63" + push(b"ord") + push(payload) + b"\x68"
    check("push-of-zero variant found", envelope_payload(env3) == 503)

    env4 = b"\x51\x64" + push(b"ord") + push(payload) + b"\x68"
    check("true-push OP_NOTIF variant found", envelope_payload(env4) == 503)

    # ---------------------------------------------------------------------
    # REGRESSION: an ordinary contract must not be mistaken for an envelope.
    #
    # Until an outside review caught it, this function matched on the SHAPE
    # of the envelope alone, so any OP_IF with pushes inside counted. That
    # marked ordinary contract spends as touched, and a touched transaction
    # loses its entire witness in rebuild_without — destroying signature
    # material for transactions carrying no data whatsoever.
    #
    # Every script below is a legitimate contract. Every one of them must
    # measure zero.

    print("\n  contracts that must NOT be read as envelopes")
    preimage = b"\xaa" * 32
    digest = b"\xbb" * 20
    pk = b"\x02" + b"\xcc" * 32

    # Hash-locked branch: OP_IF <preimage> OP_ENDIF — the exact shape the
    # old heuristic matched.
    htlc = b"\x63" + push(preimage) + b"\x68"
    check("hash-locked OP_IF branch ignored", envelope_payload(htlc) == 0,
          f"got {envelope_payload(htlc)}")

    # Lightning HTLC success path, roughly as BOLT 3 builds it: a size check
    # before OP_NOTIF, then pushes inside.
    bolt3 = (b"\x76\xa9" + push(digest) + b"\x87\x63" + b"\xac\x67"
             + push(pk) + b"\x7c\x82" + push(b"\x20") + b"\x87\x64"
             + push(digest) + b"\x88\x68\x68")
    check("BOLT 3 HTLC script ignored", envelope_payload(bolt3) == 0,
          f"got {envelope_payload(bolt3)}")

    # A true push before OP_NOTIF with contract data inside.
    notif = push(digest) + b"\x64" + push(preimage) + push(pk) + b"\x68"
    check("OP_NOTIF contract branch ignored", envelope_payload(notif) == 0,
          f"got {envelope_payload(notif)}")

    # Nested conditionals, no tag anywhere.
    nested = (b"\x63" + push(preimage) + b"\x63" + push(pk) + b"\x68"
              + push(digest) + b"\x68")
    check("nested conditionals ignored", envelope_payload(nested) == 0,
          f"got {envelope_payload(nested)}")

    # A near miss: the tag is present but not first, so it is contract data
    # that happens to contain the bytes, not a protocol announcement.
    notfirst = b"\x00\x63" + push(preimage) + push(b"ord") + b"\x68"
    check("tag not in first position ignored",
          envelope_payload(notfirst) == 0,
          f"got {envelope_payload(notfirst)}")

    # And the direction of the remaining error, stated as a test so nobody
    # mistakes it for a bug: an envelope protocol we do not know is retained.
    unknown = b"\x00\x63" + push(b"zzz") + push(payload) + b"\x68"
    check("unknown envelope protocol is retained, not stripped",
          envelope_payload(unknown) == 0,
          "a missed carrier wastes disk; a false match destroys signatures")


def test_units_are_consistent():
    """Every tool must report the same size for the same number of bytes.

    The tools are deliberately standalone — no imports between them — so each
    carries its own human(). Two of them divided by 1024 and two by 1000, and
    all four printed "GB". The same store read by monetary_store.py and
    monetary_commit.py came back as 674.7 GB and 724.5 GB, and every storage
    figure this project published carried the error.

    Nothing could have caught that except a test that compares the tools to
    each other, which is the one kind of test a standalone-by-design codebase
    does not naturally have."""
    print("\nunit consistency across tools")
    import importlib
    mods = ["monetary_store", "monetary_commit", "tip_race", "monetary_ui"]
    humans = {}
    for name in mods:
        try:
            humans[name] = importlib.import_module(name).human
        except Exception as e:
            check(f"{name} imports", False, str(e)[:60])
    check("every tool exposes human()", len(humans) == len(mods),
          sorted(set(mods) - set(humans)))

    cases = [724_500_000_000, 1_073_741_824, 1536, 1024, 1023, 0]
    for v in cases:
        outs = {n: f(v) for n, f in humans.items()}
        agreed = len(set(outs.values())) == 1
        check(f"all tools agree on {v:,} bytes", agreed,
              outs if not agreed else "")

    # And the labels must be the binary ones, since the values are binary.
    h = humans["monetary_store"]
    check("1024 bytes reads as 1.0 KiB", h(1024) == "1.0 KiB", h(1024))
    check("a GiB is labelled GiB", "GiB" in h(1024 ** 3), h(1024 ** 3))
    check("no decimal label is used on a binary value",
          "GB" not in h(1024 ** 3) and "KB" not in h(1024))
    # The store this project published: 674.7 GiB, which is 724.5 GB.
    check("the published store size is GiB, not GB",
          h(724_500_000_000).startswith("674.7 GiB"),
          h(724_500_000_000))


def test_build_index_contract():
    """build_index returns (blob, files) — and every caller unpacks it so.

    This has broken twice. It is invisible until a FULL index rebuild: on a
    cache hit the blob comes back from the cache and the shapes happen to
    line up, so a swapped call site runs fine for weeks and then dies with
    "a bytes-like object is required, not 'list'" the first time someone
    reindexes from scratch — which is exactly when they are least able to
    afford a crash.

    So the order is pinned by type here, and every call site is checked by
    reading the source. A unit test on build_index alone would not have
    caught it, because the bug was never in build_index."""
    print("\nbuild_index contract")
    import glob as _glob
    import inspect
    import tempfile
    import monetary_store as ms

    MAGIC = b"\xf9\xbe\xb4\xd9"
    d = tempfile.mkdtemp()
    os.makedirs(os.path.join(d, "blocks"), exist_ok=True)
    prev = b"\x00" * 32
    with open(os.path.join(d, "blocks", "blk00000.dat"), "wb") as f:
        for i in range(3):
            hdr = (struct.pack("<i", 4) + prev + b"\x22" * 32
                   + struct.pack("<III", 1700000000, 0x1d00ffff, i))
            body = hdr + b"\x00"
            f.write(MAGIC + struct.pack("<I", len(body)) + body)
            prev = dsha(hdr)

    blob, files = ms.build_index(os.path.join(d, "blocks"), None, "")
    check("first return value is the blob, and is bytes",
          isinstance(blob, (bytes, bytearray)))
    check("second return value is the file list",
          isinstance(files, list) and isinstance(files[0], tuple))
    check("the blob holds one record per block",
          len(blob) // ms.IDX_REC.size == 3)
    check("height_map's parameters are in that order",
          list(inspect.signature(ms.height_map).parameters)[:2]
          == ["blob", "files"])

    # The check that would actually have caught it: read the call sites.
    #
    # Scoped to monetary_store's build_index specifically. tx_query.py has an
    # unrelated function of the same name that returns a plain list, and an
    # earlier version of this test flagged its *assertions* as swapped
    # callers — a test that reports phantom failures is one you learn to
    # ignore, which is worse than not having it.
    import re as _re
    CALL = _re.compile(
        r"^(?P<lhs>[A-Za-z_][A-Za-z0-9_,\s]*?)\s*=\s*"
        r"(?:ms\.|monetary_store\.)build_index\(")
    here = os.path.dirname(os.path.abspath(__file__))
    bad, seen = [], 0
    for path in sorted(_glob.glob(os.path.join(here, "*.py"))):
        own = os.path.basename(path) == "monetary_store.py"
        pattern = CALL if not own else _re.compile(
            r"^(?P<lhs>[A-Za-z_][A-Za-z0-9_,\s]*?)\s*=\s*build_index\(")
        for n, line in enumerate(open(path, errors="replace"), 1):
            m = pattern.match(line.strip())
            if not m:
                continue
            lhs = m.group("lhs")
            if "," not in lhs:
                continue              # single-value caller
            seen += 1
            if lhs.split(",")[0].strip() != "blob":
                bad.append("%s:%d  %s" % (os.path.basename(path), n,
                                          line.strip()))
    check("the check found the real call sites", seen >= 2,
          "found %d" % seen)
    check("every two-value caller unpacks blob first", not bad, bad)


def test_scriptsig_actually_stripped():
    """The counted saving must be bytes that actually leave the disk.

    Oversized scriptSig was counted into st["scriptsig"] and then copied
    verbatim into the store, so the published figure was a saving that never
    happened. Caught by an outside review, not by any test here."""
    print("\noversized scriptSig is removed, not just counted")

    big = b"\xee" * 4000
    normal = b"\x47" + b"\x30" * 70        # an ordinary 72-byte signature

    spam_in = (b"\x11" * 32 + struct.pack("<I", 0)
               + write_varint(len(big)) + big + b"\xff\xff\xff\xff")
    good_in = (b"\x22" * 32 + struct.pack("<I", 1)
               + write_varint(len(normal)) + normal + b"\xff\xff\xff\xff")
    out = struct.pack("<Q", 50000) + write_varint(len(p2wpkh_script()))
    out += p2wpkh_script()[:0]             # placeholder replaced below
    spk = p2wpkh_script()
    out = struct.pack("<Q", 50000) + write_varint(len(spk)) + spk

    tx, txid = make_tx([spam_in, good_in], [out])
    cb, cbid = make_tx([b"\x00" * 32 + b"\xff\xff\xff\xff"
                        + write_varint(4) + b"\x01\x02\x03\x04"
                        + b"\xff\xff\xff\xff"],
                       [struct.pack("<Q", 0) + write_varint(0)])
    blk = make_block([(cb, cbid), (tx, txid)])

    rec, st = strip_block(blk, 800000, 83, 1650)
    check("the oversized scriptSig is counted", st["scriptsig"] == 4000,
          f"got {st['scriptsig']}")
    check("the transaction is modified, not dropped",
          st["modified"] == 1 and st["stripped"] == 0)

    parsed, _ = read_record(rec, 0)
    check("the block still verifies against its own header",
          merkle_root(parsed["txids"]) == parsed["merkle_root"])
    check("the stored txid is unchanged", txid in parsed["txids"])

    # The load-bearing assertion: those 4000 bytes are not on disk.
    check("the spam scriptSig is gone from the record",
          big not in rec, f"{len(rec)} byte record")
    check("the ordinary signature survives", normal in rec)
    # The saving is the carrier minus the format's own overhead: a 42-byte
    # record prefix, and 32 bytes for the txid a modified transaction has to
    # store because its body no longer hashes to it. Asserting the exact
    # accounting rather than a round number is the point — a "saving" that
    # does not survive subtraction is the bug this test exists for.
    saved = len(blk) - len(rec)
    overhead = saved - st["scriptsig"]
    check("the real saving is the carrier minus format overhead",
          -160 < overhead < 0,
          f"carrier {st['scriptsig']}, saved {saved}, "
          f"overhead {-overhead} bytes (record prefix + stored txid)")

    # What it spent must still be recorded, or the store cannot say what
    # happened to those coins.
    check("the outpoint of the stripped input is preserved",
          b"\x11" * 32 in rec)
    check("the outpoint of the untouched input is preserved",
          b"\x22" * 32 in rec)

    # A transaction whose scriptSig is within the limit must be untouched.
    tx2, txid2 = make_tx([good_in], [out])
    blk2 = make_block([(cb, cbid), (tx2, txid2)])
    rec2, st2 = strip_block(blk2, 800000, 83, 1650)
    check("a normal scriptSig is left alone",
          st2["scriptsig"] == 0 and st2["whole"] == 2)
    check("and its bytes are still there", normal in rec2)

    plain = b"\x20" + os.urandom(32) + b"\xac"
    check("ordinary tapscript yields nothing", envelope_payload(plain) == 0)


def test_classify():
    print("\noutput classification")
    big = b"\x6a\x4c" + bytes([200]) + b"X" * 200
    check("OP_RETURN over 83 bytes is spam",
          classify_output(big, 0, 800000, 83)[0] == "spam")

    small = b"\x6a" + push(b"Y" * 40)
    check("OP_RETURN under 83 bytes is monetary",
          classify_output(small, 0, 800000, 83)[0] == "monetary")

    check("inscription-era p2tr dust is dust",
          classify_output(p2tr_script(), 546, 800000, 83)[0] == "dust")
    check("p2tr above dust threshold is monetary",
          classify_output(p2tr_script(), 100000, 800000, 83)[0] == "monetary")
    check("pre-inscription-era dust is monetary",
          classify_output(p2tr_script(), 546,
                          INSCRIPTION_START - 1, 83)[0] == "monetary")


# ------------------------------------------------------------------ end-to-end


def build_test_block(height=800000):
    """A block containing one of every carrier plus ordinary transactions."""
    txs = []

    cb_in = make_input(b"\x00" * 32, 0xFFFFFFFF, b"\x03\x01\x02\x03")
    txs.append(make_tx([cb_in], [make_output(625000000, p2wpkh_script())]))

    # ordinary payment — must come through untouched
    txs.append(make_tx([make_input()],
                       [make_output(50000, p2wpkh_script()),
                        make_output(120000, p2wpkh_script())]))

    # inscription: taproot script-path with a 20 KB envelope
    payload = os.urandom(20000)
    tapscript = (b"\x20" + os.urandom(32) + b"\xac"
                 + b"\x00\x63" + push(b"ord") + push(payload) + b"\x68")
    control = b"\xc0" + os.urandom(32)
    txs.append(make_tx([make_input()],
                       [make_output(546, p2tr_script())],
                       witnesses=[[os.urandom(64), tapscript, control]]))

    # large OP_RETURN alongside a real payment — mixed transaction
    data = os.urandom(900)
    txs.append(make_tx(
        [make_input()],
        [make_output(0, b"\x6a\x4d" + struct.pack("<H", 900) + data),
         make_output(75000, p2wpkh_script())]))

    # stamp-style bare multisig, no monetary output at all
    off = off_curve_32()
    ms = b"\x51" + push(b"\x02" + off) + push(b"\x03" + off) + b"\x52\xae"
    txs.append(make_tx([make_input()], [make_output(1000, ms)]))

    # oversized scriptSig
    txs.append(make_tx(
        [make_input(script=b"\x4d" + struct.pack("<H", 2000) + os.urandom(2000))],
        [make_output(30000, p2wpkh_script())]))

    # inscription-era dust — retained in blocks, excluded from chainstate
    txs.append(make_tx([make_input()],
                       [make_output(546, p2tr_script()),
                        make_output(546, p2tr_script()),
                        make_output(200000, p2wpkh_script())]))

    return make_block(txs), txs


def test_end_to_end():
    print("\nend-to-end: strip, verify, persist, re-verify")
    height = 800000
    raw, txs = build_test_block(height)

    record, st = strip_block(raw, height, 83, 1650)

    check("merkle root rebuilds after stripping",
          merkle_root(st["txids"]) == st["merkle_root"])
    check("txid list matches the block", st["txids"] == [t[1] for t in txs])

    # 20,000-byte payload plus the 3-byte "ord" marker beside it: everything
    # inside the envelope counts, not just the largest push.
    check("inscription payload removed", st["envelope"] == 20003,
          f"{st['envelope']} bytes")
    check("large OP_RETURN removed", st["op_return"] == 904,
          f"{st['op_return']} bytes")
    check("stamp multisig removed", st["multisig"] > 0,
          f"{st['multisig']} bytes")
    # 2,000 data bytes plus the 3-byte PUSHDATA2 prefix: the whole script goes.
    check("oversized scriptSig removed", st["scriptsig"] == 2003,
          f"{st['scriptsig']} bytes")
    check("dust outputs identified", st["dust_outputs"] == 3,
          f"{st['dust_outputs']} outputs")

    check("multisig tx fully stripped", st["stripped"] == 1, f"{st['stripped']}")
    check("ordinary transactions untouched", st["whole"] >= 3,
          f"{st['whole']} of {len(txs)}")
    check("store is smaller than the block", st["stored"] < st["original"],
          f"{st['original']:,} -> {st['stored']:,} bytes")

    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "mblk00000.dat")
        with open(p, "wb") as f:
            f.write(record)
        data = open(p, "rb").read()

        check("record starts with the store magic", data[:4] == STORE_MAGIC)

        rec, nxt = read_record(data, 0)
        check("record length is exact", nxt == len(data),
              f"consumed {nxt} of {len(data)}")
        check("block hash recomputes from stored header",
              dsha(rec["header"]) == rec["block_hash"])
        check("MERKLE VERIFIES FROM DISK ALONE",
              merkle_root(rec["txids"]) == rec["merkle_root"])
        check("txids recovered identically", rec["txids"] == [t[1] for t in txs])

        check("filter entries written",
              len(rec["filters"]) == st["filter_entries"] > 0,
              f"{len(rec['filters'])} entries")
        wellformed = all(h == height and len(spk) > 0
                         for _t, _v, _a, h, spk in rec["filters"])
        check("filter entries carry amount, script and height", wellformed)


def test_multi_block():
    print("\nmulti-block file")
    blob = b""
    for i in range(5):
        raw, _txs = build_test_block(800000 + i)
        rec, _st = strip_block(raw, 800000 + i, 83, 1650)
        blob += rec

    pos, seen = 0, []
    while pos < len(blob):
        rec, pos = read_record(blob, pos)
        seen.append(merkle_root(rec["txids"]) == rec["merkle_root"])
    check("all 5 records read sequentially", len(seen) == 5, f"{len(seen)}")
    check("all 5 verify from disk", all(seen))
    check("no trailing bytes", pos == len(blob))


def test_tamper():
    """A forged txid must break the merkle root. This is the security claim."""
    print("\ntamper resistance")
    raw, _txs = build_test_block(800000)
    record, _st = strip_block(raw, 800000, 83, 1650)

    rec, _ = read_record(record, 0)
    check("untampered record verifies",
          merkle_root(rec["txids"]) == rec["merkle_root"])

    forged = list(rec["txids"])
    forged[2] = os.urandom(32)
    check("forged txid breaks the merkle root",
          merkle_root(forged) != rec["merkle_root"])

    def corrupt_at(idx):
        ba = bytearray(record)
        ba[idx] ^= 0xFF
        try:
            rec2, _ = read_record(bytes(ba), 0)
        except ValueError:
            return True          # digest caught it
        return merkle_root(rec2["txids"]) != rec2["merkle_root"]

    check("corrupted filter entry is detected", corrupt_at(len(record) - 1))
    check("corrupted transaction body is detected", corrupt_at(len(record) // 2))
    check("corrupted header is detected", corrupt_at(50))

    # Prove the merkle root genuinely does not cover filter entries, so the
    # digest is doing real work rather than duplicating an existing guarantee.
    ba = bytearray(record)
    ba[-1] ^= 0xFF
    rec3, _ = read_record(bytes(ba), 0, verify_digest=False)
    check("merkle alone would NOT have caught it",
          merkle_root(rec3["txids"]) == rec3["merkle_root"],
          "filter entries sit outside the merkle commitment")


def main():
    print("=" * 62)
    print("monetary store — format verification")
    print("=" * 62)
    test_curve()
    test_multisig()
    test_envelope()
    test_units_are_consistent()
    test_build_index_contract()
    test_scriptsig_actually_stripped()
    test_classify()
    test_end_to_end()
    test_multi_block()
    test_tamper()

    print()
    print("=" * 62)
    print(f"{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        for f in FAIL:
            print(f"  FAILED: {f}")
        sys.exit(1)
    print("Format verified. Every carrier detected, every block reconstructed")
    print("from the store alone and verified against its own header.")
    print("=" * 62)


if __name__ == "__main__":
    main()
