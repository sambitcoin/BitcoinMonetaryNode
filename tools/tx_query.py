#!/usr/bin/env python3
"""
tx_query.py — answer "what did your node do with this transaction?"

Somebody hands you a txid. This tells them exactly what the monetary store
holds for it, and hands back a merkle branch so they can check the answer
against their own node instead of believing yours.

    python3 tx_query.py --store ~/mstore --height 780000 --txid <64 hex>
    python3 tx_query.py --store ~/mstore --height 780000 --txid <64 hex> --json
    python3 tx_query.py --selftest

WHY THE HEIGHT IS REQUIRED, AND WHY THAT IS A FEATURE.

There is no txid index here and there is not going to be one. A txid ->
location index over 1.44 billion transactions is tens of gigabytes to build
and maintain, for a lookup the asker can already do in one command against
their own node:

    bitcoin-cli getrawtransaction <txid> 1 | grep blockhash
    bitcoin-cli getblockheader <blockhash> | grep height

So the asker supplies the height. That keeps this node from quietly becoming
somebody's block explorer, and it means the person asking has already touched
their own node before they ask — which is the only way the answer means
anything to them.

WHAT THE ANSWER PROVES, EXACTLY. This is the part that must not be oversold.

  RETAINED WHOLE  The stored bytes are the transaction. Its txid is derived
                  from those bytes, and the merkle branch folds that txid into
                  the root in the block header. Corrupt one byte anywhere and
                  the root stops matching. This is a complete proof: the asker
                  needs nothing from this node but the bytes.

  MODIFIED        The merkle branch proves this TXID belongs in this block.
                  It does NOT prove the retained body matches that txid — it
                  cannot, because the body no longer hashes to it. That is the
                  whole point of the format: the txid is stored rather than
                  derived, so the block still verifies after the data is gone.
                  The retained body is covered only by the record's own body
                  digest, which detects corruption on this disk and nothing
                  else. To check the body, diff it against the copy on your
                  own node. The difference you find is precisely what this node
                  declined to keep.

  STRIPPED        Only the txid survives, and the branch proves it belongs in
                  the block. There is no body to return. Every output of this
                  transaction was a data carrier; it moved no value.

WHAT THIS NODE CANNOT TELL YOU. It cannot show you what it dropped. The bytes
are gone — that is the entire purpose of the project, not an oversight. It can
prove what it kept, and prove the block still hashes the same without the
rest. Anyone who wants the dropped bytes should ask a node that keeps them.

THE DUPLICATE-HASH QUIRK. Bitcoin's merkle tree duplicates the final node of
any odd-length level. That is reproduced here because it is consensus. It also
means a branch is not by itself proof of position in a tree of known width;
it is checked against a root the asker already has, which is what makes that
harmless.

Standard library only. BSD-2-Clause.
"""

import argparse
import glob
import json
import os
import struct
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from monetary_store import (Cursor, dsha, body_legacy, write_varint,
                                STORE_MAGIC, STORE_VERSION,
                                FLAG_WHOLE, FLAG_MODIFIED, FLAG_STRIPPED)
except ImportError as e:            # pragma: no cover
    sys.exit(f"tx_query.py needs monetary_store.py beside it: {e}")

CACHE_MAGIC = b"TXQI"
CACHE_VERSION = 1
CLASS_NAME = {FLAG_WHOLE: "RETAINED WHOLE",
              FLAG_MODIFIED: "MODIFIED",
              FLAG_STRIPPED: "STRIPPED"}


# ------------------------------------------------------------------ merkle


def merkle_branch(txids, idx):
    """Sibling hashes from txids[idx] up to the root."""
    branch, level, i = [], list(txids), idx
    while len(level) > 1:
        if len(level) & 1:
            level.append(level[-1])          # consensus quirk, reproduced
        branch.append(level[i ^ 1])
        level = [dsha(level[j] + level[j + 1])
                 for j in range(0, len(level), 2)]
        i >>= 1
    return branch


def fold_branch(txid, idx, branch):
    """Recompute the root from a leaf and its branch. The asker runs this."""
    h, i = txid, idx
    for sib in branch:
        h = dsha(h + sib) if (i & 1) == 0 else dsha(sib + h)
        i >>= 1
    return h


def merkle_root(txids):
    if not txids:
        return b"\x00" * 32
    level = list(txids)
    while len(level) > 1:
        if len(level) & 1:
            level.append(level[-1])
        level = [dsha(level[i] + level[i + 1])
                 for i in range(0, len(level), 2)]
    return level[0]


# ------------------------------------------------------- record offset index
#
# Records are written in height order and never rewritten, so record ordinal N
# is height (tip - records + 1 + N). Finding one means knowing its byte offset,
# which means walking record prefixes: 10 bytes read, then seek past the body.
# Roughly 968,000 of those, cached afterwards so it happens once.
#
# The cache stores each file's size. The newest file grows as the daemon
# appends, so that one is rescanned from its previous end rather than from
# zero, and a file whose size shrank is treated as unknown and rebuilt.


def store_files(store):
    return sorted(glob.glob(os.path.join(store, "mblk*.dat")))


def scan_offsets(path, start=0):
    """Record offsets in one file, from `start`. Stops at the first bad magic."""
    offs = []
    with open(path, "rb") as f:
        f.seek(start)
        pos = start
        while True:
            head = f.read(10)
            if len(head) < 10:
                break
            if head[:4] != STORE_MAGIC:
                break                        # trailing garbage or torn write
            ver = struct.unpack_from("<H", head, 4)[0]
            if ver != STORE_VERSION:
                break
            length = struct.unpack_from("<I", head, 6)[0]
            nxt = pos + 10 + length
            offs.append(pos)
            f.seek(nxt)
            pos = nxt
    return offs, pos


def cache_path(store):
    # The store is mounted read-only under the status-page unit, deliberately:
    # a public service has no business writing into the thing it publishes. So
    # the offset cache can be sent elsewhere. Without this it silently falls
    # back to rebuilding, which is a full walk of every record prefix on every
    # refresh — minutes of disk, every minute, forever.
    d = os.environ.get("MONETARY_CACHE")
    if d:
        try:
            os.makedirs(d, exist_ok=True)
        except OSError:
            return os.path.join(store, ".txq_offsets")
        key = os.path.abspath(store).strip("/").replace("/", "_")
        return os.path.join(d, "txq_%s.idx" % key)
    return os.path.join(store, ".txq_offsets")


def load_cache(store):
    p = cache_path(store)
    if not os.path.exists(p):
        return {}
    try:
        with open(p, "rb") as f:
            if f.read(4) != CACHE_MAGIC:
                return {}
            if struct.unpack("<H", f.read(2))[0] != CACHE_VERSION:
                return {}
            out = {}
            for _ in range(struct.unpack("<I", f.read(4))[0]):
                nlen = struct.unpack("<H", f.read(2))[0]
                name = f.read(nlen).decode()
                size, end, n = struct.unpack("<QQI", f.read(20))
                offs = list(struct.unpack("<%dQ" % n, f.read(8 * n)))
                out[name] = {"size": size, "end": end, "offs": offs}
            return out
    except Exception:
        return {}                            # a bad cache is rebuilt, not fatal


def save_cache(store, cache):
    p = cache_path(store)
    try:
        tmp = p + ".tmp"
        with open(tmp, "wb") as f:
            f.write(CACHE_MAGIC)
            f.write(struct.pack("<H", CACHE_VERSION))
            f.write(struct.pack("<I", len(cache)))
            for name in sorted(cache):
                e = cache[name]
                b = name.encode()
                f.write(struct.pack("<H", len(b)) + b)
                f.write(struct.pack("<QQI", e["size"], e["end"],
                                    len(e["offs"])))
                f.write(struct.pack("<%dQ" % len(e["offs"]), *e["offs"]))
        os.replace(tmp, p)
    except OSError:
        pass                                 # read-only store is fine


def build_index(store, quiet=False):
    """[(path, offset)] for every record, in height order."""
    files = store_files(store)
    if not files:
        sys.exit(f"no mblk*.dat in {store}")
    cache = load_cache(store)
    dirty = False
    index = []
    for path in files:
        name = os.path.basename(path)
        size = os.path.getsize(path)
        e = cache.get(name)
        if e and e["size"] == size:
            pass                                     # unchanged
        elif e and size > e["size"]:
            if not quiet:
                print(f"  extending {name}", file=sys.stderr)
            more, end = scan_offsets(path, e["end"])
            e = {"size": size, "end": end, "offs": e["offs"] + more}
            cache[name] = e
            dirty = True
        else:
            if not quiet:
                print(f"  indexing {name}", file=sys.stderr)
            offs, end = scan_offsets(path)
            e = {"size": size, "end": end, "offs": offs}
            cache[name] = e
            dirty = True
        index.extend((path, o) for o in e["offs"])
    if dirty:
        save_cache(store, cache)
    return index


def read_state(store):
    p = os.path.join(store, "state.json")
    if not os.path.exists(p):
        return None
    try:
        with open(p) as f:
            return json.load(f)
    except ValueError:
        return None


def base_height(store, index, override=None):
    """Height of record 0."""
    if override is not None:
        return override
    st = read_state(store)
    if st and st.get("height") is not None:
        return st["height"] - len(index) + 1
    sys.exit("no usable state.json — pass --base-height for the first record")


# ------------------------------------------------------------------ parsing
#
# monetary_store.read_record throws away the per-transaction flag and body,
# which is exactly what this tool needs. So parse it here rather than widening
# that function's return value for one caller.


def parse_record(data):
    if data[:4] != STORE_MAGIC:
        raise ValueError("bad magic")
    ver = struct.unpack_from("<H", data, 4)[0]
    if ver != STORE_VERSION:
        raise ValueError(f"unsupported store version {ver}")
    length = struct.unpack_from("<I", data, 6)[0]
    digest = data[10:42]
    body = data[42:10 + length]
    if dsha(body) != digest:
        raise ValueError("body digest mismatch — record corrupt")

    c = Cursor(body)
    stored_hash = c.take(32)
    header = c.take(80)
    n_tx = c.varint()

    txs = []
    for _ in range(n_tx):
        flag = c.u8()
        if flag == FLAG_STRIPPED:
            txs.append({"flag": flag, "txid": c.take(32), "body": None})
        elif flag == FLAG_MODIFIED:
            txid = c.take(32)
            txs.append({"flag": flag, "txid": txid,
                        "body": c.take(c.varint())})
        elif flag == FLAG_WHOLE:
            b = c.take(c.varint())
            txs.append({"flag": flag, "txid": dsha(body_legacy(b)), "body": b})
        else:
            raise ValueError(f"unknown tx flag {flag}")

    return {"block_hash": stored_hash, "header": header, "txs": txs,
            "merkle_root": header[36:68],
            "txids": [t["txid"] for t in txs]}


def read_record_at(path, offset):
    with open(path, "rb") as f:
        f.seek(offset)
        head = f.read(10)
        if len(head) < 10 or head[:4] != STORE_MAGIC:
            raise ValueError(f"no record at {path}:{offset}")
        length = struct.unpack_from("<I", head, 6)[0]
        return parse_record(head + f.read(length))


# ------------------------------------------------------------------- lookup


def lookup(store, height, txid, base=None, quiet=False):
    index = build_index(store, quiet=quiet)
    b = base_height(store, index, base)
    top = b + len(index) - 1
    if not b <= height <= top:
        sys.exit(f"height {height:,} is outside this store "
                 f"({b:,}-{top:,})")

    path, off = index[height - b]
    rec = read_record_at(path, off)

    if dsha(rec["header"]) != rec["block_hash"]:
        sys.exit("stored block hash does not match its header — corrupt store")
    if merkle_root(rec["txids"]) != rec["merkle_root"]:
        sys.exit("stored txids do not reproduce the header merkle root")

    try:
        pos = rec["txids"].index(txid)
    except ValueError:
        return {"found": False, "height": height,
                "block_hash": rec["block_hash"][::-1].hex(),
                "n_tx": len(rec["txids"])}

    tx = rec["txs"][pos]
    branch = merkle_branch(rec["txids"], pos)
    if fold_branch(txid, pos, branch) != rec["merkle_root"]:
        sys.exit("internal error: branch does not fold to the root")

    return {
        "found": True,
        "txid": txid[::-1].hex(),
        "height": height,
        "block_hash": rec["block_hash"][::-1].hex(),
        "merkle_root": rec["merkle_root"][::-1].hex(),
        "position": pos,
        "n_tx": len(rec["txids"]),
        "class": CLASS_NAME[tx["flag"]],
        "kept_bytes": len(tx["body"]) if tx["body"] is not None else 0,
        "body": tx["body"].hex() if tx["body"] is not None else None,
        "body_merkle_covered": tx["flag"] == FLAG_WHOLE,
        "branch": [h.hex() for h in branch],
    }


# -------------------------------------------------------------------- print


def report(r):
    if not r["found"]:
        print(f"NOT IN THIS BLOCK")
        print(f"  height      {r['height']:,}")
        print(f"  block       {r['block_hash']}")
        print(f"  holds       {r['n_tx']:,} transactions, none with that txid")
        print()
        print("  Check the height. Your own node has it:")
        print("    bitcoin-cli getrawtransaction <txid> 1 | grep blockhash")
        print("    bitcoin-cli getblockheader <blockhash> | grep height")
        return 1

    print(f"txid          {r['txid']}")
    print(f"height        {r['height']:,}")
    print(f"block         {r['block_hash']}")
    print(f"position      {r['position']:,} of {r['n_tx']:,}")
    print(f"class         {r['class']}")

    if r["class"] == "STRIPPED":
        print("kept          nothing — the txid only")
        print()
        print("  Every output of this transaction was a data carrier, so the")
        print("  whole transaction went. It moved no value. The txid stays")
        print("  because the block's merkle root is computed over txids, and")
        print("  the block must still verify.")
    else:
        print(f"kept          {r['kept_bytes']:,} bytes")

    print()
    print(f"merkle branch ({len(r['branch'])} hashes)")
    for h in r["branch"]:
        print(f"  {h}")

    print()
    print("CHECK IT")
    print("  Fold that branch over the txid and you get this block's merkle")
    print(f"  root:  {r['merkle_root']}")
    print("  Compare it against the header your own node holds:")
    print(f"    bitcoin-cli getblockheader {r['block_hash']} | grep merkleroot")
    print()

    if r["class"] == "RETAINED WHOLE":
        print("  This transaction is stored untouched, and its txid is derived")
        print("  from the bytes above rather than stored beside them. So the")
        print("  branch proves the bytes, not just the identifier. Nothing")
        print("  here has to be taken on trust.")
    elif r["class"] == "MODIFIED":
        print("  CAREFUL: the branch proves this TXID is in this block. It")
        print("  does NOT prove the kept bytes match it, and cannot — a")
        print("  modified body no longer hashes to its own txid. That is the")
        print("  format working as designed, not a gap in it.")
        print()
        print("  So do not believe the bytes. Diff them against your node:")
        print("    bitcoin-cli getrawtransaction <txid>")
        print("  What is missing from this copy is exactly what this node")
        print("  declined to keep. If something else differs, say so loudly.")
    else:
        print("  There are no bytes to check here, only the identifier.")

    print()
    print("  This node cannot show you what it dropped. Those bytes are gone,")
    print("  which is the point of the project rather than a limitation of it.")
    return 0


# ----------------------------------------------------------------- selftest


def _mkrec(header, entries):
    """Build one store record. entries: [(flag, txid_or_None, body_or_None)]"""
    parts = [header, write_varint(len(entries))]
    for flag, txid, body in entries:
        if flag == FLAG_STRIPPED:
            parts.append(bytes([flag]) + txid)
        elif flag == FLAG_MODIFIED:
            parts.append(bytes([flag]) + txid + write_varint(len(body)) + body)
        else:
            parts.append(bytes([flag]) + write_varint(len(body)) + body)
    parts.append(write_varint(0))
    body = dsha(header) + b"".join(parts)
    return (STORE_MAGIC + struct.pack("<H", STORE_VERSION)
            + struct.pack("<I", len(body) + 32) + dsha(body) + body)


def _header_for(txids, nonce=0):
    root = merkle_root(txids)
    return (struct.pack("<I", 1) + b"\x11" * 32 + root
            + struct.pack("<III", 1700000000, 0x1d00ffff, nonce))


def selftest():
    checks, passed = [], 0

    def check(name, ok):
        nonlocal passed
        checks.append(name)
        passed += bool(ok)
        print(f"  [{'ok' if ok else 'FAIL'}] {name}")

    print("merkle")
    # A branch must fold back to the root, at every width, from every leaf.
    # Odd widths are where the duplicate-last-node rule bites.
    all_ok = True
    for n in range(1, 18):
        txids = [dsha(bytes([i])) for i in range(n)]
        root = merkle_root(txids)
        for i in range(n):
            if fold_branch(txids[i], i, merkle_branch(txids, i)) != root:
                all_ok = False
    check("branch folds to root for every leaf, widths 1-17", all_ok)

    one = [dsha(b"\x01")]
    check("single-tx block has an empty branch and is its own root",
          merkle_branch(one, 0) == [] and merkle_root(one) == one[0])

    three = [dsha(bytes([i])) for i in range(3)]
    check("odd width duplicates the last node",
          merkle_root(three) == dsha(dsha(three[0] + three[1])
                                     + dsha(three[2] + three[2])))

    txids4 = [dsha(bytes([i])) for i in range(4)]
    check("a wrong leaf does not fold to the root",
          fold_branch(dsha(b"\xff"), 0, merkle_branch(txids4, 0))
          != merkle_root(txids4))
    check("the right leaf at the wrong position does not fold either",
          fold_branch(txids4[0], 1, merkle_branch(txids4, 0))
          != merkle_root(txids4))

    print("\nstore round-trip")
    d = tempfile.mkdtemp(prefix="txq")

    # Three transactions, one of each class. The whole one is a real
    # (non-segwit) transaction so its txid is genuinely derived.
    whole = bytes.fromhex(
        "01000000" "01" + "00" * 32 + "ffffffff" "00" "ffffffff"
        "01" "00f2052a01000000" "00" "00000000")
    whole_txid = dsha(body_legacy(whole))
    mod_txid = dsha(b"modified")
    strip_txid = dsha(b"stripped")
    mod_body = b"\x01\x00\x00\x00short body that no longer hashes to its txid"

    txids = [whole_txid, mod_txid, strip_txid]
    hdr = _header_for(txids)
    rec = _mkrec(hdr, [(FLAG_WHOLE, None, whole),
                       (FLAG_MODIFIED, mod_txid, mod_body),
                       (FLAG_STRIPPED, strip_txid, None)])

    # A second block, so the index has to get ordinals right.
    txids2 = [dsha(b"other")]
    rec2 = _mkrec(_header_for(txids2, nonce=1), [(FLAG_STRIPPED,
                                                  txids2[0], None)])

    with open(os.path.join(d, "mblk00000.dat"), "wb") as f:
        f.write(rec + rec2)
    with open(os.path.join(d, "state.json"), "w") as f:
        json.dump({"version": 1, "height": 101, "records": 2,
                   "hash": "00" * 32}, f)

    idx = build_index(d, quiet=True)
    check("index finds both records", len(idx) == 2)
    check("base height derived from state.json",
          base_height(d, idx) == 100)

    r = lookup(d, 100, whole_txid, quiet=True)
    check("whole tx found", r["found"] and r["class"] == "RETAINED WHOLE")
    check("whole tx returns its bytes", r["body"] == whole.hex())
    check("whole tx body is merkle-covered", r["body_merkle_covered"])
    check("whole tx branch folds to the stored root",
          fold_branch(whole_txid, r["position"],
                      [bytes.fromhex(h) for h in r["branch"]])
          == hdr[36:68])

    r = lookup(d, 100, mod_txid, quiet=True)
    check("modified tx found", r["found"] and r["class"] == "MODIFIED")
    check("modified tx returns the kept body",
          r["kept_bytes"] == len(mod_body))
    # The load-bearing honesty check: we must never claim the branch proves a
    # modified body. It does not, and the report text depends on this flag.
    check("modified body is NOT claimed as merkle-covered",
          r["body_merkle_covered"] is False)
    check("modified body really does not hash to its txid",
          dsha(body_legacy(mod_body)) != mod_txid)

    r = lookup(d, 100, strip_txid, quiet=True)
    check("stripped tx found", r["found"] and r["class"] == "STRIPPED")
    check("stripped tx returns no body",
          r["body"] is None and r["kept_bytes"] == 0)
    check("stripped tx still carries a branch", len(r["branch"]) > 0)

    r = lookup(d, 101, txids2[0], quiet=True)
    check("second record resolves at the next height", r["found"])

    r = lookup(d, 100, dsha(b"absent"), quiet=True)
    check("absent txid reports not-found rather than guessing",
          r["found"] is False)

    print("\ncache")
    c1 = load_cache(d)
    check("cache was written", bool(c1))
    idx2 = build_index(d, quiet=True)
    check("cached index matches the cold one", idx2 == idx)

    # Append a third record; the cache must extend, not go stale.
    txids3 = [dsha(b"third")]
    rec3 = _mkrec(_header_for(txids3, nonce=2), [(FLAG_STRIPPED,
                                                  txids3[0], None)])
    with open(os.path.join(d, "mblk00000.dat"), "ab") as f:
        f.write(rec3)
    idx3 = build_index(d, quiet=True)
    check("appended record is picked up", len(idx3) == 3)
    check("earlier offsets unchanged by the append", idx3[:2] == idx)

    with open(cache_path(d), "wb") as f:
        f.write(b"garbage")
    check("a corrupt cache rebuilds instead of failing",
          build_index(d, quiet=True) == idx3)

    # Under the status-page unit the store is read-only, so the cache has to
    # land somewhere else or the index rebuilds on every refresh.
    alt = tempfile.mkdtemp(prefix="txqc")
    os.environ["MONETARY_CACHE"] = alt
    try:
        check("cache redirects out of the store when asked",
              os.path.dirname(cache_path(d)) == alt)
        check("redirected cache still indexes correctly",
              build_index(d, quiet=True) == idx3)
        check("redirected cache was actually written",
              os.path.exists(cache_path(d)))
        check("two stores do not collide in one cache dir",
              cache_path(d) != cache_path(alt))
    finally:
        del os.environ["MONETARY_CACHE"]

    print("\ncorruption")
    bad = bytearray(rec)
    bad[-1] ^= 0xFF
    try:
        parse_record(bytes(bad))
        check("a flipped body byte is caught by the digest", False)
    except ValueError:
        check("a flipped body byte is caught by the digest", True)

    # Trailing garbage is how a torn write looks. Stop, do not misparse.
    p = os.path.join(d, "mblk00001.dat")
    with open(p, "wb") as f:
        f.write(rec + b"\x00" * 40)
    offs, _ = scan_offsets(p)
    check("scanning stops at trailing garbage", len(offs) == 1)

    print(f"\n{passed}/{len(checks)} passed")
    return 0 if passed == len(checks) else 1


# --------------------------------------------------------------------- main


def main():
    ap = argparse.ArgumentParser(
        description="what this monetary node holds for one transaction")
    ap.add_argument("--store")
    ap.add_argument("--height", type=int)
    ap.add_argument("--txid")
    ap.add_argument("--base-height", type=int,
                    help="height of the first record, if state.json is absent")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()

    if a.selftest:
        return selftest()
    if not (a.store and a.height is not None and a.txid):
        ap.error("--store, --height and --txid are required "
                 "(or use --selftest)")

    t = a.txid.strip().lower()
    if len(t) != 64 or any(ch not in "0123456789abcdef" for ch in t):
        sys.exit("txid must be 64 hex characters")
    # Bitcoin displays txids byte-reversed. Everything internal is raw order.
    txid = bytes.fromhex(t)[::-1]

    r = lookup(a.store, a.height, txid, a.base_height, quiet=a.json)
    if a.json:
        print(json.dumps(r, indent=1))
        return 0 if r["found"] else 1
    return report(r)


if __name__ == "__main__":
    sys.exit(main())
