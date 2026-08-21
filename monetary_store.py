#!/usr/bin/env python3
"""
monetary_store.py — the monetary block storage format: write, read, verify.

Takes real Bitcoin blocks, strips every spam carrier, writes the result to disk
in a defined format, reads it back, and proves the block still verifies against
its header from the persisted data alone.

This is the specification a node implementation would follow. Everything before
this measured what stripping saves; this defines what a monetary node actually
stores and proves it round-trips.

WHY IT WORKS: a block's merkle root is computed over txids. The store keeps the
32-byte txid of every transaction it modifies or discards. Nothing needs to
re-derive those from transaction data, so the data can go and the block still
verifies against real proof-of-work. Fabricated txids produce a mismatching
root and are rejected, so the stored list cannot be forged.

FORMAT (mblk*.dat), per block record:

    magic          4    b"MBLK"
    version        2    format version, currently 1
    record length  4    bytes following this field
    body digest   32    SHA256d over everything after this field
    block hash    32    for indexing; not trusted, recomputed from header
    header        80    unmodified
    tx count       varint
    per transaction:
        flag       1    0 = retained whole, 1 = modified, 2 = stripped
        txid      32    present when flag is 1 or 2
        length     varint  } present when flag is 0 or 1
        tx bytes   n      }
    filter count   varint
    per filter entry (one per dropped output):
        txid      32
        vout       varint
        amount     8
        height     4
        script     varint length + bytes

Filter entries carry everything needed to validate a future spend of a dropped
output locally, with no peer involvement.

WHAT THE MERKLE ROOT DOES NOT COVER. Retained whole transactions are protected
by the merkle root: corrupt one byte and its computed txid changes and the root
no longer matches. Modified transaction bodies and filter entries are not — the
txid is stored rather than derived, so it keeps matching whatever happens to the
body beneath it. Those parts are covered by the body digest instead. That is
local integrity only: it detects corruption, not a peer that sends a
consistent-but-false record. Cross-node agreement is the job of the chained
commitment C, which is compared between nodes and makes divergence visible.

CHAINSTATE: dust outputs are retained in block storage — dropping a 42-byte
output to add an 80-byte filter entry would cost more than it saves. They are
excluded at the chainstate layer instead, where the saving is real. This tool
reports how many it identifies so both layers can be accounted for.

Usage:
    python3 monetary_store.py --blocks /path/to/bitcoin/blocks \\
        --start 800000 --end 800100 --out /tmp/mstore

    # verify a previously written store without rewriting it
    python3 monetary_store.py --verify /tmp/mstore

    # build the block index and stop, so later runs start immediately
    python3 monetary_store.py --blocks /path/to/bitcoin/blocks --index-only

The block index is cached (default ~/.monetary_index.bin) and updated
incrementally: only new or changed blk*.dat files are rescanned, so the full
index is built once rather than on every run.

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
STORE_MAGIC = b"MBLK"
STORE_VERSION = 1
INDEX_MAGIC = b"MIDX"
INDEX_VERSION = 1
GENESIS = bytes.fromhex(
    "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000")

OP_0, OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4 = 0x00, 0x4C, 0x4D, 0x4E
OP_IF, OP_NOTIF, OP_ENDIF, OP_RETURN = 0x63, 0x64, 0x68, 0x6A
OP_CHECKMULTISIG = 0xAE

FLAG_WHOLE, FLAG_MODIFIED, FLAG_STRIPPED = 0, 1, 2

# secp256k1 field prime
SECP_P = 2**256 - 2**32 - 977

INSCRIPTION_START = 767430
DUST_THRESHOLD = 1000

# index record: hash(32) prev(32) file_idx(H) offset(Q) size(I)
IDX_REC = struct.Struct("<32s32sHQI")


def dsha(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def write_varint(n):
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


# ---------------------------------------------------------------- curve check


def on_curve(x_bytes):
    """
    Is this a real secp256k1 x-coordinate?

    A valid compressed public key has an x for which y² = x³ + 7 has a
    solution mod p. Data stuffed into a key position satisfies that only by
    chance, roughly half the time — so this alone is a weak signal per key,
    but across the several keys of a bare multisig output it is decisive.
    """
    x = int.from_bytes(x_bytes, "big")
    if x >= SECP_P:
        return False
    y2 = (pow(x, 3, SECP_P) + 7) % SECP_P
    # Euler's criterion: y2 is a quadratic residue iff y2^((p-1)/2) == 1
    return pow(y2, (SECP_P - 1) // 2, SECP_P) == 1


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
        self.path, self.key = path, key
        self.fh = open(path, "rb", buffering=1024 * 1024)

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


# ---------------------------------------------------------------- block index


def scan_file(path, key, file_idx):
    """Return [(hash, prev, file_idx, offset, size), ...] for one blk file."""
    out = []
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
            out.append((dsha(hdr), hdr[4:36], file_idx, off, size))
            bf.seek(off + size)
    finally:
        bf.close()
    return out


def load_index_cache(path):
    """Returns (files, records) or (None, None). files is [(path, size)]."""
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


def save_index_cache(path, files, blob):
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
    os.replace(tmp, path)


def build_index(blocks_dir, key, cache_path):
    """
    Index every block, reusing a cache where the underlying file is unchanged.

    Only new or grown blk*.dat files are rescanned. On a node that has added a
    few files since the last run this takes seconds rather than an hour.
    """
    paths = sorted(glob.glob(os.path.join(blocks_dir, "blk*.dat")))
    if not paths:
        sys.exit(f"no blk*.dat in {blocks_dir}")
    current = [(p, os.path.getsize(p)) for p in paths]

    cached_files, cached_blob = load_index_cache(cache_path)
    reusable = {}
    if cached_files is not None:
        sizes = {p: sz for p, sz in current}
        for i, (p, sz) in enumerate(cached_files):
            if sizes.get(p) == sz:
                reusable[i] = p

    idx_of = {p: i for i, (p, _s) in enumerate(current)}
    kept = bytearray()
    if reusable and cached_blob:
        n = len(cached_blob) // IDX_REC.size
        for r in range(n):
            off = r * IDX_REC.size
            h, prev, fi, o, sz = IDX_REC.unpack_from(cached_blob, off)
            p = reusable.get(fi)
            if p is None:
                continue
            kept += IDX_REC.pack(h, prev, idx_of[p], o, sz)

    reused_paths = set(reusable.values())
    todo = [(i, p) for i, (p, _s) in enumerate(current) if p not in reused_paths]

    if todo:
        print(f"indexing {len(todo)} of {len(current)} files"
              f"{' (XOR)' if key else ''}"
              f"{f', reusing {len(reused_paths)} from cache' if reused_paths else ''}"
              "...", flush=True)
        t0 = time.time()
        for n, (fi, p) in enumerate(todo, 1):
            for rec in scan_file(p, key, fi):
                kept += IDX_REC.pack(*rec)
            if n % 100 == 0 or n == len(todo):
                el = time.time() - t0
                rate = n / el if el else 0
                eta = (len(todo) - n) / rate if rate else 0
                print(f"  {n}/{len(todo)}  {len(kept)//IDX_REC.size:,} blocks  "
                      f"{el:.0f}s elapsed, ~{eta:.0f}s left", flush=True)
        if cache_path:
            save_index_cache(cache_path, current, bytes(kept))
            print(f"index cached to {cache_path}", flush=True)
    else:
        print(f"block index loaded from cache ({len(kept)//IDX_REC.size:,} "
              f"blocks, {len(current)} files)", flush=True)

    return bytes(kept), current


def height_map(blob, files, max_height):
    """Walk prev-hash links from genesis to build height -> location."""
    by_hash, children = {}, {}
    n = len(blob) // IDX_REC.size
    for r in range(n):
        h, prev, fi, off, sz = IDX_REC.unpack_from(blob, r * IDX_REC.size)
        by_hash[h] = (files[fi][0], off, sz)
        children.setdefault(prev, []).append(h)

    if GENESIS not in by_hash:
        sys.exit("genesis not found in index")

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
    return by_hash, heights


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

    def done(self):
        return self.p >= len(self.d)


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
            if i >= n:
                raise ValueError("truncated")
            ln = script[i]; i += 1
            if i + ln > n:
                raise ValueError("truncated")
            data = script[i:i + ln]; i += ln
        elif op == OP_PUSHDATA2:
            if i + 2 > n:
                raise ValueError("truncated")
            ln = struct.unpack_from("<H", script, i)[0]; i += 2
            if i + ln > n:
                raise ValueError("truncated")
            data = script[i:i + ln]; i += ln
        elif op == OP_PUSHDATA4:
            if i + 4 > n:
                raise ValueError("truncated")
            ln = struct.unpack_from("<I", script, i)[0]; i += 4
            if i + ln > n:
                raise ValueError("truncated")
            data = script[i:i + ln]; i += ln
        yield op, data


# ---------------------------------------------------------------- classifying


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
    """
    Bare multisig carrying data rather than real keys.

    Stamps prefix their fake keys with 02/03 so the outputs look standard, so
    a prefix check is useless. The reliable test is whether each key is
    actually a point on secp256k1. Real keys always are; stuffed data is a
    coin flip per key, so an output with several keys is caught with high
    probability.
    """
    if not script or script[-1] != OP_CHECKMULTISIG:
        return False
    try:
        pushes = [d for _op, d in iter_script(script) if d is not None]
    except ValueError:
        return False
    keys = [k for k in pushes if len(k) in (33, 65)]
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


def classify_output(script, value, height, op_return_limit):
    """
    Returns (kind, reason).

    kind is 'spam' for data carriers whose bytes are dropped from block
    storage, 'dust' for economically abandoned outputs that are retained in
    blocks but excluded from chainstate, or 'monetary'.
    """
    if script and script[0] == OP_RETURN:
        if len(script) > op_return_limit:
            return "spam", "op_return"
        return "monetary", ""
    if is_data_multisig(script):
        return "spam", "multisig"
    if (value < DUST_THRESHOLD and height >= INSCRIPTION_START
            and len(script) == 34 and script[0] == 0x51 and script[1] == 0x20):
        return "dust", "p2tr_dust"
    return "monetary", ""


# ---------------------------------------------------------------- stripping


def strip_block(raw, height, op_return_limit, scriptsig_limit):
    """
    Produce the stored representation of a block.

    Returns (record_bytes, stats). The record is self-describing and can be
    read back by read_record() without reference to the original block.
    """
    c = Cursor(raw)
    header = c.take(80)
    n_tx = c.varint()

    tx_parts = []
    filter_entries = []
    txids = []
    st = {"whole": 0, "modified": 0, "stripped": 0, "dust_outputs": 0,
          "envelope": 0, "op_return": 0, "multisig": 0, "scriptsig": 0}

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
        out_monetary = 0
        dropped_outs = []
        for vout in range(n_out):
            amount = c.u64()
            spk = c.take(c.varint())
            kind, reason = classify_output(spk, amount, height, op_return_limit)
            if kind == "spam":
                dropped_outs.append((vout, amount, spk))
                st[reason] = st.get(reason, 0) + len(spk)
            elif kind == "dust":
                st["dust_outputs"] += 1
                out_monetary += 1     # retained in blocks, dropped in chainstate
            else:
                out_monetary += 1
        io_end = c.p

        envelope_bytes = 0
        if segwit:
            for _ in range(n_in):
                count = c.varint()
                items = [c.take(c.varint()) for _ in range(count)]
                if is_taproot_script_path(items):
                    envelope_bytes += envelope_payload(items[-2])
        c.take(4)
        tx_end = c.p

        legacy = (raw[tx_start:tx_start + 4] + raw[io_start:io_end]
                  + raw[tx_end - 4:tx_end]) if segwit else raw[tx_start:tx_end]
        txid = dsha(legacy)
        txids.append(txid)

        st["envelope"] += envelope_bytes
        st["scriptsig"] += scriptsig_spam
        for vout, amount, spk in dropped_outs:
            filter_entries.append((txid, vout, amount, height, spk))

        touched = bool(envelope_bytes or dropped_outs or scriptsig_spam)

        if touched and out_monetary == 0:
            st["stripped"] += 1
            tx_parts.append(bytes([FLAG_STRIPPED]) + txid)
        elif touched:
            st["modified"] += 1
            body = rebuild_without(raw, tx_start, io_start, io_end, tx_end,
                                   dropped_outs)
            tx_parts.append(bytes([FLAG_MODIFIED]) + txid
                            + write_varint(len(body)) + body)
        else:
            st["whole"] += 1
            body = raw[tx_start:tx_end]
            tx_parts.append(bytes([FLAG_WHOLE])
                            + write_varint(len(body)) + body)

    payload = [header, write_varint(n_tx)] + tx_parts
    payload.append(write_varint(len(filter_entries)))
    for txid, vout, amount, h, spk in filter_entries:
        payload.append(txid + write_varint(vout) + struct.pack("<Q", amount)
                       + struct.pack("<I", h) + write_varint(len(spk)) + spk)

    body = dsha(header) + b"".join(payload)
    record = (STORE_MAGIC + struct.pack("<H", STORE_VERSION)
              + struct.pack("<I", len(body) + 32) + dsha(body) + body)

    st["filter_entries"] = len(filter_entries)
    st["original"] = len(raw)
    st["stored"] = len(record)
    st["txids"] = txids
    st["merkle_root"] = header[36:68]
    return record, st


def rebuild_without(raw, tx_start, io_start, io_end, tx_end, dropped):
    """
    Reserialise a transaction in legacy form with the dropped outputs removed.

    Witness data is not carried into the store for modified transactions: it is
    either spam, or signature material already verified when the block was
    connected.
    """
    dropped_vouts = {v for v, _a, _s in dropped}
    c = Cursor(raw[io_start:io_end])

    out = [raw[tx_start:tx_start + 4]]           # version
    n_in = c.varint()
    inputs = [write_varint(n_in)]
    for _ in range(n_in):
        start = c.p
        c.take(32); c.take(4)
        c.take(c.varint())
        c.take(4)
        inputs.append(c.d[start:c.p])
    out.extend(inputs)

    n_out = c.varint()
    kept = []
    for vout in range(n_out):
        start = c.p
        c.u64()
        c.take(c.varint())
        if vout not in dropped_vouts:
            kept.append(c.d[start:c.p])
    out.append(write_varint(len(kept)))
    out.extend(kept)
    out.append(raw[tx_end - 4:tx_end])           # locktime
    return b"".join(out)


# ---------------------------------------------------------------- reading


def read_record(data, pos, verify_digest=True):
    """Parse one stored block record. Returns (parsed, next_pos)."""
    if data[pos:pos + 4] != STORE_MAGIC:
        raise ValueError(f"bad magic at {pos}")
    version = struct.unpack_from("<H", data, pos + 4)[0]
    if version != STORE_VERSION:
        raise ValueError(f"unsupported store version {version}")
    length = struct.unpack_from("<I", data, pos + 6)[0]
    digest = data[pos + 10:pos + 42]
    end = pos + 10 + length
    body = data[pos + 42:end]
    if verify_digest and dsha(body) != digest:
        raise ValueError(f"body digest mismatch at {pos} — record corrupt")
    c = Cursor(body)

    stored_hash = c.take(32)
    header = c.take(80)
    n_tx = c.varint()

    txids = []
    for _ in range(n_tx):
        flag = c.u8()
        if flag == FLAG_STRIPPED:
            txids.append(c.take(32))
        elif flag == FLAG_MODIFIED:
            txids.append(c.take(32))
            c.take(c.varint())
        elif flag == FLAG_WHOLE:
            body_tx = c.take(c.varint())
            txids.append(dsha(body_legacy(body_tx)))
        else:
            raise ValueError(f"unknown tx flag {flag}")

    filters = []
    for _ in range(c.varint()):
        txid = c.take(32)
        vout = c.varint()
        amount = struct.unpack("<Q", c.take(8))[0]
        h = struct.unpack("<I", c.take(4))[0]
        spk = c.take(c.varint())
        filters.append((txid, vout, amount, h, spk))

    return {
        "block_hash": stored_hash, "header": header, "txids": txids,
        "filters": filters, "merkle_root": header[36:68],
    }, end


def body_legacy(body):
    """Strip witness from a stored whole transaction to get its txid preimage."""
    c = Cursor(body)
    c.take(4)
    if c.peek(2) != b"\x00\x01":
        return body
    c.take(2)
    io_start = c.p
    n_in = c.varint()
    for _ in range(n_in):
        c.take(32); c.take(4); c.take(c.varint()); c.take(4)
    for _ in range(c.varint()):
        c.u64(); c.take(c.varint())
    io_end = c.p
    return body[:4] + body[io_start:io_end] + body[-4:]


def merkle_root(txids):
    if not txids:
        return b"\x00" * 32
    level = list(txids)
    while len(level) > 1:
        if len(level) & 1:
            level.append(level[-1])
        level = [dsha(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def verify_store(path):
    """Read every record back and verify each block against its own header."""
    files = sorted(glob.glob(os.path.join(path, "mblk*.dat")))
    if not files:
        sys.exit(f"no mblk*.dat in {path}")
    ok = bad = corrupt = 0
    filters = 0
    t0 = time.time()
    for f in files:
        data = open(f, "rb").read()
        pos = 0
        while pos < len(data):
            try:
                rec, pos = read_record(data, pos)
            except ValueError as e:
                corrupt += 1
                print(f"  CORRUPT record in {os.path.basename(f)}: {e}",
                      file=sys.stderr)
                break          # cannot resynchronise mid-file
            if dsha(rec["header"]) != rec["block_hash"]:
                bad += 1
                print("  block hash mismatch", file=sys.stderr)
                continue
            if merkle_root(rec["txids"]) == rec["merkle_root"]:
                ok += 1
            else:
                bad += 1
                print(f"  MERKLE MISMATCH in {os.path.basename(f)}",
                      file=sys.stderr)
            filters += len(rec["filters"])
    print()
    print(f"verified from disk in {time.time()-t0:.1f}s")
    print(f"  blocks verified     {ok:,}")
    print(f"  blocks failed       {bad:,}")
    print(f"  records corrupt     {corrupt:,}")
    print(f"  filter entries      {filters:,}")
    return ok, bad + corrupt


# ---------------------------------------------------------------- main


def human(n):
    for u in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:,.1f} {u}"
        n /= 1024
    return f"{n:,.1f} PB"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--blocks")
    ap.add_argument("--start", type=int)
    ap.add_argument("--end", type=int)
    ap.add_argument("--out", help="directory to write the monetary store into")
    ap.add_argument("--verify", help="verify an existing store and exit")
    ap.add_argument("--index-only", action="store_true",
                    help="build and cache the block index, then stop")
    ap.add_argument("--index-cache",
                    default=os.path.expanduser("~/.monetary_index.bin"))
    ap.add_argument("--op-return-limit", type=int, default=83)
    ap.add_argument("--scriptsig-limit", type=int, default=1650)
    ap.add_argument("--file-size", type=int, default=128 * 1024 * 1024)
    ap.add_argument("--progress", type=int, default=1000,
                    help="print a line every N blocks")
    args = ap.parse_args()

    if args.verify:
        ok, bad = verify_store(args.verify)
        sys.exit(0 if bad == 0 else 1)

    if not args.blocks:
        sys.exit("need --blocks (or --verify)")

    key = load_xor_key(args.blocks)
    blob, files = build_index(args.blocks, key, args.index_cache)

    if args.index_only:
        n = len(blob) // IDX_REC.size
        print(f"index built: {n:,} blocks across {len(files)} files")
        return

    if args.start is None or args.end is None or not args.out:
        sys.exit("need --start, --end and --out")

    by_hash, heights = height_map(blob, files, args.end)
    if args.end not in heights:
        sys.exit(f"--end {args.end} not reachable (tip is "
                 f"{max(heights) if heights else 'unknown'})")

    os.makedirs(args.out, exist_ok=True)
    tot = {"original": 0, "stored": 0, "whole": 0, "modified": 0,
           "stripped": 0, "dust_outputs": 0, "filter_entries": 0,
           "envelope": 0, "op_return": 0, "multisig": 0, "scriptsig": 0}
    merkle_ok = merkle_bad = 0

    file_idx = 0
    out = open(os.path.join(args.out, f"mblk{file_idx:05d}.dat"), "wb")
    written = 0

    open_path, bf = None, None
    t0 = time.time()
    n_blocks = args.end - args.start + 1
    print(f"stripping {n_blocks:,} blocks...", flush=True)

    try:
        for i, height in enumerate(range(args.start, args.end + 1), 1):
            path, off, size = by_hash[heights[height]]
            if path != open_path:
                if bf:
                    bf.close()
                bf = BlockFile(path, key)
                open_path = path

            raw = bf.read_at(off, size)
            record, st = strip_block(raw, height, args.op_return_limit,
                                     args.scriptsig_limit)

            if merkle_root(st["txids"]) == st["merkle_root"]:
                merkle_ok += 1
            else:
                merkle_bad += 1
                print(f"  MERKLE MISMATCH at {height}", file=sys.stderr)

            if written + len(record) > args.file_size:
                out.close()
                file_idx += 1
                out = open(os.path.join(args.out,
                                        f"mblk{file_idx:05d}.dat"), "wb")
                written = 0
            out.write(record)
            written += len(record)

            for k in tot:
                tot[k] += st.get(k, 0)

            if i % args.progress == 0 or i == n_blocks:
                el = time.time() - t0
                rate = i / el if el else 0
                print(f"  {i:,}/{n_blocks:,} blocks  height {height:,}  "
                      f"{human(tot['stored'])} written  "
                      f"{el:.0f}s, ~{(n_blocks-i)/rate if rate else 0:.0f}s left",
                      flush=True)

    finally:
        if bf:
            bf.close()
        out.close()

    o, s = tot["original"], tot["stored"]
    dropped = (tot["envelope"] + tot["op_return"] + tot["multisig"]
               + tot["scriptsig"])

    print()
    print("=" * 66)
    print(f"wrote blocks {args.start:,} .. {args.end:,} to {args.out}")
    print("=" * 66)
    print(f"elapsed               {time.time()-t0:.1f}s")
    print(f"transactions whole    {tot['whole']:,}")
    print(f"             modified {tot['modified']:,}")
    print(f"             stripped {tot['stripped']:,}")
    print(f"filter entries        {tot['filter_entries']:,}")
    print()
    print("spam removed")
    print(f"  inscription witness {human(tot['envelope'])}")
    print(f"  OP_RETURN >limit    {human(tot['op_return'])}")
    print(f"  data multisig       {human(tot['multisig'])}")
    print(f"  oversized scriptSig {human(tot['scriptsig'])}")
    print(f"  total               {human(dropped)}")
    print()
    print(f"dust outputs found    {tot['dust_outputs']:,}  "
          f"(retained in blocks, excluded from chainstate)")
    print()
    print(f"original blocks       {human(o)}")
    print(f"monetary store        {human(s)}   ({s/o*100:.2f}%)")
    print(f"saved                 {human(o-s)}   ({(o-s)/o*100:.2f}%)")
    print()
    print(f"merkle verified in memory  {merkle_ok:,} ok, {merkle_bad:,} failed")
    print()
    print("now verifying from disk, reading nothing but the store...")
    ok, bad = verify_store(args.out)
    print()
    if bad == 0 and merkle_bad == 0:
        print(f"All {ok:,} blocks were reconstructed from the monetary store")
        print("alone and verified against their own headers. The store is")
        print("sufficient: every block remains provably part of the chain")
        print("with all spam removed.")


if __name__ == "__main__":
    main()
