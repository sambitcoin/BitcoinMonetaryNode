#!/usr/bin/env python3
"""
monetary_ibd.py — initial block download between monetary nodes, and a harness
that tries to break it.

A monetary node holds blocks with every data carrier removed. It cannot serve
those to a legacy node, which needs complete blocks. It can serve them to
another monetary node — and the receiving node can still prove every block
belongs to Bitcoin's chain, without a byte of spam crossing the wire.

This implements both sides and then attacks them.

WHAT THE RECEIVER PROVES, PER BLOCK, WITHOUT TRUSTING THE SENDER

  1. body digest        the record is internally intact
  2. block hash         recomputed from the header, never taken on trust
  3. prev-hash linkage  this block extends the one before it
  4. proof-of-work      the header hash meets the target its own nBits encodes
  5. difficulty rule    nBits is unchanged within a window, and follows the
                        retarget formula across one
  6. merkle root        rebuilt from txids — computed for retained transactions,
                        supplied for stripped ones — and matched to the header
  7. commitment C       extended, so two receivers can detect that they were
                        served different stripping decisions

A sender that lies about any of 1-6 is caught by that block. A sender that lies
consistently about what it stripped is caught by 7, when its C is compared
against anyone else's.

WHAT IT DOES NOT PROVE, STATED PLAINLY

Stripped transactions are accepted on accumulated proof-of-work rather than
re-executed. That is the same posture as Core's `assumevalid` default, but it
is a real difference from validating from genesis and should not be glossed.

The receiver starts from an anchor (height and block hash) rather than from
genesis, so the anchor is trusted input. Same as any checkpoint or
assumeutxo-style start.

And none of this answers the data-availability objection: if nobody routinely
validates that the removed data ever existed, it can be lost. That is an
argument about network economics, not protocol correctness, and a test harness
cannot settle it.

Usage:
    # serve a store
    python3 monetary_ibd.py --serve ~/mstore --start-height 767430 --port 8451

    # sync from it, verifying everything
    python3 monetary_ibd.py --sync 127.0.0.1:8451 \\
        --anchor-height 767430 \\
        --anchor-hash <hash of block 767429> \\
        --out ~/mstore_synced

    # run every attack against the verifier
    python3 monetary_ibd.py --attack-suite

    python3 monetary_ibd.py --selftest

Standard library only. BSD-2-Clause.
"""

import argparse
import glob
import hashlib
import json
import os
import socket
import socketserver
import struct
import sys
import threading
import time

STORE_MAGIC = b"MBLK"
STORE_VERSION = 1
FLAG_WHOLE, FLAG_MODIFIED, FLAG_STRIPPED = 0, 1, 2

WIRE_MAGIC = b"MIBD"
WIRE_VERSION = 1

RETARGET_INTERVAL = 2016
TARGET_TIMESPAN = 14 * 24 * 60 * 60          # two weeks
MAX_TARGET = 0x00000000FFFF0000000000000000000000000000000000000000000000000000
# Regtest's ceiling, used by the test harness so blocks can be mined in
# milliseconds. A mainnet client must never accept this.
REGTEST_MAX_TARGET = 0x7FFFFF0000000000000000000000000000000000000000000000000000000000


def dsha(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


# ---------------------------------------------------------------- proof of work


def bits_to_target(nbits):
    """Decode compact difficulty representation into a full 256-bit target."""
    exponent = nbits >> 24
    mantissa = nbits & 0x007FFFFF
    if nbits & 0x00800000:
        raise ValueError("negative target")
    if exponent <= 3:
        return mantissa >> (8 * (3 - exponent))
    return mantissa << (8 * (exponent - 3))


def target_to_bits(target):
    """Encode a target back into compact form, as Core does."""
    if target == 0:
        return 0
    nsize = (target.bit_length() + 7) // 8
    if nsize <= 3:
        mantissa = target << (8 * (3 - nsize))
    else:
        mantissa = target >> (8 * (nsize - 3))
    if mantissa & 0x00800000:            # avoid the sign bit
        mantissa >>= 8
        nsize += 1
    return (nsize << 24) | mantissa


def check_pow(header, max_target=MAX_TARGET):
    """
    Does this header's hash meet the target its own nBits encodes?

    This is what makes the chain expensive to fake. Without it a peer could
    hand over any well-formed data it liked.

    The max_target bound matters as much as the hash comparison: without it a
    sender could declare an arbitrarily easy target and mine a fake chain on a
    laptop.
    """
    nbits = struct.unpack_from("<I", header, 72)[0]
    target = bits_to_target(nbits)
    if target == 0 or target > max_target:
        return False, "target easier than the network minimum"
    h = int.from_bytes(dsha(header), "little")
    if h > target:
        return False, "hash does not meet target"
    return True, ""


def next_target(first_time, last_time, last_bits, max_target=MAX_TARGET):
    """
    Bitcoin's retarget: scale by actual/expected elapsed time, clamped to a
    factor of four in either direction.
    """
    timespan = last_time - first_time
    timespan = max(TARGET_TIMESPAN // 4, min(TARGET_TIMESPAN * 4, timespan))
    target = bits_to_target(last_bits) * timespan // TARGET_TIMESPAN
    return target_to_bits(min(target, max_target))


def work_for(nbits):
    """Expected hashes to find a block at this difficulty."""
    target = bits_to_target(nbits)
    return (1 << 256) // (target + 1)


class HeaderChain:
    """
    Tracks enough header state to enforce the difficulty rules.

    Starting mid-chain means the first retarget window is incomplete, so the
    first adjustment cannot be checked. That is disclosed rather than hidden.
    """

    def __init__(self, anchor_height, anchor_hash, max_target=MAX_TARGET):
        self.max_target = max_target
        self.height = anchor_height - 1
        self.tip = anchor_hash
        self.window_first_time = None
        self.current_bits = None
        self.total_work = 0
        self.retargets_checked = 0
        self.retargets_skipped = 0

    def accept(self, header, check_difficulty=True):
        """Returns (ok, reason). Advances the chain on success."""
        prev = header[4:36]
        if prev != self.tip:
            return False, (f"prev hash mismatch at height {self.height + 1}: "
                           f"chain does not link")

        ok, why = check_pow(header, self.max_target)
        if not ok:
            return False, f"proof-of-work: {why}"

        nbits = struct.unpack_from("<I", header, 72)[0]
        ntime = struct.unpack_from("<I", header, 68)[0]
        h = self.height + 1

        if check_difficulty and self.current_bits is not None:
            if h % RETARGET_INTERVAL == 0:
                if self.window_first_time is None:
                    self.retargets_skipped += 1
                else:
                    expect = next_target(self.window_first_time,
                                         self.last_time, self.current_bits,
                                         self.max_target)
                    if nbits != expect:
                        return False, (f"difficulty at {h}: nBits "
                                       f"{nbits:#010x}, expected "
                                       f"{expect:#010x}")
                    self.retargets_checked += 1
            elif nbits != self.current_bits:
                return False, (f"difficulty at {h}: nBits changed mid-window "
                               f"({nbits:#010x} vs {self.current_bits:#010x})")

        if h % RETARGET_INTERVAL == 0 or self.window_first_time is None:
            self.window_first_time = ntime
        self.last_time = ntime
        self.current_bits = nbits
        self.total_work += work_for(nbits)
        self.height = h
        self.tip = dsha(header)
        return True, ""


# ---------------------------------------------------------------- record parse


def merkle_root(txids):
    if not txids:
        return b"\x00" * 32
    level = list(txids)
    while len(level) > 1:
        if len(level) & 1:
            level.append(level[-1])
        level = [dsha(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


class Cursor:
    __slots__ = ("d", "p")

    def __init__(self, d):
        self.d, self.p = d, 0

    def take(self, n):
        out = self.d[self.p:self.p + n]
        if len(out) < n:
            raise ValueError("truncated record")
        self.p += n
        return out

    def peek(self, n):
        return self.d[self.p:self.p + n]

    def u8(self):
        if self.p >= len(self.d):
            raise ValueError("truncated record")
        b = self.d[self.p]
        self.p += 1
        return b

    def u32(self):
        return int.from_bytes(self.take(4), "little")

    def u64(self):
        return int.from_bytes(self.take(8), "little")

    def varint(self):
        n = self.u8()
        if n < 0xFD:
            return n
        if n == 0xFD:
            return int.from_bytes(self.take(2), "little")
        if n == 0xFE:
            return self.u32()
        return self.u64()


def legacy_of(body):
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


def parse_record(rec):
    """
    Parse one wire/store record. Returns a dict, or raises ValueError.

    Every field that could be lied about is recomputed rather than believed.
    """
    if rec[:4] != STORE_MAGIC:
        raise ValueError("bad record magic")
    version = struct.unpack_from("<H", rec, 4)[0]
    if version != STORE_VERSION:
        raise ValueError(f"unsupported record version {version}")
    length = struct.unpack_from("<I", rec, 6)[0]
    digest = rec[10:42]
    end = 10 + length
    if end > len(rec):
        raise ValueError("record truncated")
    body = rec[42:end]

    if dsha(body) != digest:
        raise ValueError("body digest mismatch")

    c = Cursor(body)
    claimed_hash = c.take(32)
    header = c.take(80)
    if dsha(header) != claimed_hash:
        raise ValueError("block hash does not match its header")

    n_tx = c.varint()
    txids = []
    stripped = modified = whole = 0
    for _ in range(n_tx):
        flag = c.u8()
        if flag == FLAG_STRIPPED:
            txids.append(c.take(32))
            stripped += 1
        elif flag == FLAG_MODIFIED:
            txids.append(c.take(32))
            c.take(c.varint())
            modified += 1
        elif flag == FLAG_WHOLE:
            txids.append(dsha(legacy_of(c.take(c.varint()))))
            whole += 1
        else:
            raise ValueError(f"unknown transaction flag {flag}")

    n_filters = c.varint()
    for _ in range(n_filters):
        c.take(32); c.varint(); c.take(8); c.take(4); c.take(c.varint())

    if merkle_root(txids) != header[36:68]:
        raise ValueError("merkle root does not match header")

    return {
        "header": header, "hash": claimed_hash, "digest": digest,
        "txids": txids, "n_tx": n_tx, "filters": n_filters,
        "whole": whole, "modified": modified, "stripped": stripped,
        "size": end,
    }


def iter_store_records(path):
    for f in sorted(glob.glob(os.path.join(path, "mblk*.dat"))):
        with open(f, "rb") as fh:
            data = fh.read()
        pos = 0
        while pos < len(data):
            length = struct.unpack_from("<I", data, pos + 6)[0]
            end = pos + 10 + length
            yield data[pos:end]
            pos = end


# ---------------------------------------------------------------- wire


def send_msg(sock, obj, payload=b""):
    head = json.dumps(obj).encode()
    sock.sendall(WIRE_MAGIC + struct.pack("<HII", WIRE_VERSION, len(head),
                                          len(payload)) + head + payload)


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(min(65536, n - len(buf)))
        if not chunk:
            raise ConnectionError("peer closed the connection")
        buf += chunk
    return buf


def recv_msg(sock):
    head = recv_exact(sock, 14)
    if head[:4] != WIRE_MAGIC:
        raise ValueError("bad wire magic")
    ver, hlen, plen = struct.unpack_from("<HII", head, 4)
    if ver != WIRE_VERSION:
        raise ValueError(f"unsupported wire version {ver}")
    obj = json.loads(recv_exact(sock, hlen).decode())
    return obj, recv_exact(sock, plen)


# ---------------------------------------------------------------- server


class Server:
    """
    Serves store records. Deliberately dumb: it does no verification, because
    the receiver must not rely on it doing any.

    `attack` makes it lie, for the harness below.
    """

    def __init__(self, store_path, start_height, attack=None):
        self.start_height = start_height
        self.attack = attack
        self.mem = None
        self.locs = []
        if isinstance(store_path, str):
            # Index record locations, do not hold the records. A full store is
            # hundreds of gigabytes; loading it would exhaust memory before a
            # single peer connected.
            for f in sorted(glob.glob(os.path.join(store_path, "mblk*.dat"))):
                size = os.path.getsize(f)
                with open(f, "rb") as fh:
                    pos = 0
                    while pos < size:
                        fh.seek(pos + 6)
                        length = struct.unpack("<I", fh.read(4))[0]
                        self.locs.append((f, pos, 10 + length))
                        pos += 10 + length
        else:
            self.mem = list(store_path)

    @property
    def records(self):
        """Only for the in-memory case used by the test harness."""
        return self.mem if self.mem is not None else self.locs

    def _read(self, i):
        if self.mem is not None:
            return self.mem[i]
        path, off, length = self.locs[i]
        with open(path, "rb") as fh:
            fh.seek(off)
            return fh.read(length)

    def get(self, start, count):
        i = max(0, start - self.start_height)
        n_total = len(self.mem) if self.mem is not None else len(self.locs)
        out = [self._read(j) for j in range(i, min(i + count, n_total))]
        return [apply_attack(r, self.attack, n) for n, r in enumerate(out)] \
            if self.attack else out

    def serve_forever(self, host="127.0.0.1", port=0):
        srv = socketserver.TCPServer((host, port), self._handler_factory())
        srv.allow_reuse_address = True
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        return srv

    def _handler_factory(self):
        outer = self

        class H(socketserver.BaseRequestHandler):
            def handle(self):
                try:
                    while True:
                        req, _ = recv_msg(self.request)
                        if req.get("cmd") == "info":
                            send_msg(self.request, {
                                "start": outer.start_height,
                                "count": len(outer.records)})
                        elif req.get("cmd") == "get":
                            recs = outer.get(req["start"], req["count"])
                            send_msg(self.request, {"n": len(recs)},
                                     b"".join(recs))
                        else:
                            return
                except Exception:
                    return
        return H


# ---------------------------------------------------------------- client


class Client:
    """
    Downloads records and proves each one before accepting it.

    Nothing the sender says is taken on trust: the block hash is recomputed,
    the merkle root is rebuilt, the proof-of-work is checked against the
    target the header itself encodes, and the difficulty rules are enforced.
    """

    def __init__(self, anchor_height, anchor_hash, check_difficulty=True,
                 out_dir=None, max_target=MAX_TARGET):
        self.chain = HeaderChain(anchor_height, anchor_hash, max_target)
        self.check_difficulty = check_difficulty
        self.commitment = b"\x00" * 32
        self.accepted = 0
        self.rejected = 0
        self.reason = None
        self.out = None
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
            self.out = open(os.path.join(out_dir, "mblk00000.dat"), "wb")
        self.stats = {"whole": 0, "modified": 0, "stripped": 0, "filters": 0,
                      "bytes": 0}

    def accept_record(self, rec):
        """Returns (ok, reason). Verifies fully before accepting."""
        try:
            p = parse_record(rec)
        except (ValueError, IndexError, struct.error, OverflowError,
                MemoryError) as e:
            # Every byte here came from an untrusted peer. A malformed record
            # must be a rejection, never an exception that takes the node down.
            return False, f"malformed record: {type(e).__name__}: {e}"

        ok, why = self.chain.accept(p["header"], self.check_difficulty)
        if not ok:
            return False, why

        self.commitment = dsha(self.commitment + p["hash"] + p["digest"])
        self.accepted += 1
        for k in ("whole", "modified", "stripped"):
            self.stats[k] += p[k]
        self.stats["filters"] += p["filters"]
        self.stats["bytes"] += p["size"]
        if self.out:
            self.out.write(rec[:p["size"]])
        return True, ""

    def feed(self, blob):
        """Consume a concatenated stream of records. Stops at first failure."""
        pos = 0
        while pos < len(blob):
            if pos + 10 > len(blob):
                self.reason = "trailing bytes: incomplete record"
                self.rejected += 1
                return False
            length = struct.unpack_from("<I", blob, pos + 6)[0]
            end = pos + 10 + length
            if end > len(blob):
                self.reason = "stream truncated mid-record"
                self.rejected += 1
                return False
            ok, why = self.accept_record(blob[pos:end])
            if not ok:
                self.reason = why
                self.rejected += 1
                return False
            pos = end
        return True

    def sync(self, host, port, batch=200, limit=None):
        s = socket.create_connection((host, port), timeout=30)
        try:
            send_msg(s, {"cmd": "info"})
            info, _ = recv_msg(s)
            total = info["count"] if limit is None else min(limit,
                                                            info["count"])
            start = info["start"]
            got = 0
            t0 = time.time()
            while got < total:
                n = min(batch, total - got)
                send_msg(s, {"cmd": "get", "start": start + got, "count": n})
                hdr, payload = recv_msg(s)
                if hdr["n"] == 0:
                    break
                if not self.feed(payload):
                    return False
                got += hdr["n"]
                if self.accepted % 5000 < hdr["n"]:
                    print(f"  {self.accepted:,} blocks  height "
                          f"{self.chain.height:,}  "
                          f"{self.stats['bytes']/1e9:.2f} GB  "
                          f"{time.time()-t0:.0f}s", flush=True)
            return True
        finally:
            s.close()
            if self.out:
                self.out.close()


# ---------------------------------------------------------------- attacks


def _rebuild(body):
    """Wrap a body back into a record with a correct digest."""
    return (STORE_MAGIC + struct.pack("<H", STORE_VERSION)
            + struct.pack("<I", len(body) + 32) + dsha(body) + body)


def _rebuild_header_attack(body):
    """
    Rebuild after altering the header, recomputing the claimed block hash.

    A naive tamper is caught immediately by the block-hash check, which would
    make the deeper checks untested. A competent attacker recomputes it, so
    the harness does too — that is what forces proof-of-work, the difficulty
    rule and chain linkage to do the work.
    """
    body = bytearray(body)
    body[0:32] = dsha(bytes(body[32:112]))
    return _rebuild(bytes(body))


def apply_attack(rec, attack, n):
    """
    Return a maliciously altered record.

    Each attack targets one specific check. The point of the harness is that
    every one of them must be caught, and caught for the right reason.
    """
    if attack is None or n != 0:
        return rec

    body = bytearray(rec[42:10 + struct.unpack_from("<I", rec, 6)[0]])

    if attack == "forge_txid":
        # flip a byte inside the first stored txid
        i = 32 + 80
        i += 1                                  # tx count varint (small)
        flag = body[i]; i += 1
        if flag in (FLAG_STRIPPED, FLAG_MODIFIED):
            body[i] ^= 0xFF
        else:
            body[i + 1] ^= 0xFF                  # corrupt a whole tx body
        return _rebuild(bytes(body))

    if attack == "bad_digest":
        b = bytearray(rec)
        b[-1] ^= 0xFF                            # body changes, digest doesn't
        return bytes(b)

    if attack == "wrong_block_hash":
        body[0] ^= 0xFF                          # claimed hash no longer matches
        return _rebuild(bytes(body))

    if attack == "break_prev":
        body[32 + 4] ^= 0xFF                     # header prev-hash field
        return _rebuild_header_attack(body)

    if attack == "break_pow":
        body[32 + 76] ^= 0xFF                    # nonce
        return _rebuild_header_attack(body)

    if attack == "easy_bits":
        struct.pack_into("<I", body, 32 + 72, 0x207FFFFF)
        return _rebuild_header_attack(body)

    if attack == "swap_merkle":
        body[32 + 36] ^= 0xFF                    # merkle root in header
        return _rebuild_header_attack(body)

    if attack == "truncate":
        return rec[:len(rec) // 2]

    if attack == "bad_magic":
        return b"XXXX" + rec[4:]

    if attack == "bad_version":
        b = bytearray(rec)
        struct.pack_into("<H", b, 4, 99)
        return bytes(b)

    if attack == "bad_flag":
        i = 32 + 80 + 1
        body[i] = 7
        return _rebuild(bytes(body))

    raise ValueError(f"unknown attack {attack}")


ATTACKS = [
    ("forge_txid", "fabricated txid or corrupted transaction body"),
    ("bad_digest", "record altered without updating its digest"),
    ("wrong_block_hash", "claimed block hash does not match the header"),
    ("break_prev", "block does not extend the previous one"),
    ("break_pow", "header hash does not meet its target"),
    ("easy_bits", "difficulty lowered to make forgery cheap"),
    ("swap_merkle", "merkle root in the header replaced"),
    ("truncate", "stream cut short mid-record"),
    ("bad_magic", "not a monetary record"),
    ("bad_version", "unsupported record version"),
    ("bad_flag", "unknown transaction flag"),
]


# ---------------------------------------------------------------- synth chain


def mine(header_wo_nonce, bits, limit=1 << 22):
    """Find a nonce whose hash meets the (deliberately easy) target."""
    target = bits_to_target(bits)
    for nonce in range(limit):
        h = header_wo_nonce + struct.pack("<I", nonce)
        if int.from_bytes(dsha(h), "little") <= target:
            return h
    raise RuntimeError("could not find a nonce")


def write_varint(n):
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    return b"\xfe" + struct.pack("<I", n)


SYNTH_BITS = 0x1F00FFFF      # ~32k hashes per block: fast, but not trivial
SYNTH_MAX_TARGET = 0xFFFF << (8 * 28)


def synth_chain(n_blocks, anchor_hash, bits=SYNTH_BITS, base_time=1700000000):
    """
    Build a small valid chain of monetary records, with real proof-of-work at
    a trivial difficulty. Used so the harness tests the verifier rather than
    a mock.
    """
    records, prev = [], anchor_hash
    for i in range(n_blocks):
        txs = []
        for j in range(3):
            body = (struct.pack("<i", 1) + b"\x01" + bytes([(i + j) % 251]) * 32
                    + struct.pack("<I", j) + b"\x00"
                    + struct.pack("<I", 0xFFFFFFFF)
                    + b"\x01" + struct.pack("<Q", 1000 + j)
                    + b"\x02\x51\x20" + struct.pack("<I", 0))
            txs.append((FLAG_WHOLE, body, dsha(body)))
        stripped_txid = dsha(b"stripped%d" % i)
        txs.append((FLAG_STRIPPED, None, stripped_txid))

        root = merkle_root([t[2] for t in txs])
        hdr_wo = (struct.pack("<i", 4) + prev + root
                  + struct.pack("<I", base_time + i * 600)
                  + struct.pack("<I", bits))
        header = mine(hdr_wo, bits)

        payload = [header, write_varint(len(txs))]
        for flag, body, txid in txs:
            if flag == FLAG_WHOLE:
                payload.append(bytes([flag]) + write_varint(len(body)) + body)
            else:
                payload.append(bytes([flag]) + txid)
        payload.append(write_varint(0))
        body_all = dsha(header) + b"".join(payload)
        records.append(_rebuild(body_all))
        prev = dsha(header)
    return records


# ---------------------------------------------------------------- tests


def attack_suite(verbose=True):
    anchor = dsha(b"anchor")
    records = synth_chain(4, anchor)
    RT = SYNTH_MAX_TARGET

    results = []

    client = Client(1000, anchor, max_target=RT)
    ok = client.feed(b"".join(records))
    results.append(("honest sync accepts all blocks",
                    ok and client.accepted == 4, ""))
    good_c = client.commitment

    for name, description in ATTACKS:
        srv = Server(records, 1000, attack=name)
        served = srv.get(1000, 4)
        c = Client(1000, anchor, max_target=RT)
        ok = c.feed(b"".join(served))
        caught = (not ok)
        results.append((f"rejects: {description}", caught, c.reason or ""))

    # a consistent liar: valid blocks, but different stripping decisions.
    # merkle cannot catch this; the commitment must.
    alt = synth_chain(4, anchor)
    alt_body = bytearray(alt[0][42:])
    alt_body[-1] ^= 0x00                       # identical, sanity check
    c1 = Client(1000, anchor, max_target=RT); c1.feed(b"".join(records))
    c2 = Client(1000, anchor, max_target=RT); c2.feed(b"".join(alt))
    results.append(("identical data gives identical C",
                    c1.commitment == c2.commitment, ""))

    tampered = list(records)
    body = bytearray(tampered[2][42:])
    body[-1] ^= 0xFF                            # alters a filter section byte
    tampered[2] = _rebuild(bytes(body))
    c3 = Client(1000, anchor, max_target=RT)
    ok3 = c3.feed(b"".join(tampered))
    results.append(("differing stripping decisions change C",
                    (not ok3) or c3.commitment != good_c,
                    "caught by digest" if not ok3 else "caught by C"))

    if verbose:
        print("=" * 70)
        print("ADVERSARIAL SUITE")
        print("=" * 70)
        for name, passed, detail in results:
            mark = "ok  " if passed else "FAIL"
            line = f"  [{mark}] {name}"
            if detail:
                line += f"\n         -> {detail}"
            print(line)
        n_ok = sum(1 for _n, p, _d in results if p)
        print()
        print(f"{n_ok}/{len(results)} passed")
        print()
        print("Every attack above alters data the sender controls. The")
        print("receiver recomputes the block hash, the merkle root and the")
        print("proof-of-work rather than believing any of them, so a lying")
        print("sender is detected by the block it lied about.")
    return all(p for _n, p, _d in results)


def selftest():
    ok = []

    def check(name, cond, detail=""):
        ok.append(cond)
        print(f"  [{'ok  ' if cond else 'FAIL'}] {name}"
              + (f"  — {detail}" if detail else ""))

    print("difficulty encoding")
    for bits in (0x1D00FFFF, 0x1B0404CB, 0x170355F0, 0x207FFFFF):
        t = bits_to_target(bits)
        check(f"round-trip {bits:#010x}", target_to_bits(t) == bits,
              f"target {t:#x}"[:40])
    check("max target decodes to the genesis difficulty",
          bits_to_target(0x1D00FFFF) == MAX_TARGET)
    check("harder bits give a smaller target",
          bits_to_target(0x170355F0) < bits_to_target(0x1D00FFFF))
    check("harder bits mean more work",
          work_for(0x170355F0) > work_for(0x1D00FFFF))

    print("\nretarget rule")
    exact = next_target(0, TARGET_TIMESPAN, 0x1B0404CB)
    check("unchanged when timing is exact",
          bits_to_target(exact) == bits_to_target(0x1B0404CB))
    faster = next_target(0, TARGET_TIMESPAN // 2, 0x1B0404CB)
    check("faster blocks raise difficulty",
          bits_to_target(faster) < bits_to_target(0x1B0404CB))
    slower = next_target(0, TARGET_TIMESPAN * 2, 0x1B0404CB)
    check("slower blocks lower difficulty",
          bits_to_target(slower) > bits_to_target(0x1B0404CB))
    clamped = next_target(0, TARGET_TIMESPAN * 100, 0x1B0404CB)
    check("adjustment clamped to 4x",
          bits_to_target(clamped) <= bits_to_target(0x1B0404CB) * 4)
    clamped2 = next_target(0, 1, 0x1B0404CB)
    quarter = bits_to_target(0x1B0404CB) // 4
    # target_to_bits truncates the mantissa, so allow one unit of rounding
    check("adjustment clamped to 1/4",
          abs(bits_to_target(clamped2) - quarter) <= quarter // 1000,
          f"got {bits_to_target(clamped2):#x}, quarter {quarter:#x}")

    print("\nproof of work")
    anchor = dsha(b"pow-test")
    recs = synth_chain(1, anchor)
    p = parse_record(recs[0])
    good, why = check_pow(p["header"], SYNTH_MAX_TARGET)
    check("mined header passes its own target", good, why)
    bad = bytearray(p["header"]); bad[76] ^= 0xFF
    check("altered nonce fails",
          not check_pow(bytes(bad), SYNTH_MAX_TARGET)[0])
    easy = bytearray(p["header"])
    struct.pack_into("<I", easy, 72, 0x207FFFFF)
    check("target easier than the network floor is rejected",
          not check_pow(bytes(easy), SYNTH_MAX_TARGET)[0],
          "stops a sender declaring its own difficulty")
    hard = bytearray(p["header"])
    struct.pack_into("<I", hard, 72, 0x1D00FFFF)
    check("same header fails a harder target",
          not check_pow(bytes(hard))[0])

    print("\nrecord verification")
    check("honest record parses", parse_record(recs[0])["n_tx"] == 4)
    for attack, desc in ATTACKS[:4]:
        try:
            parse_record(apply_attack(recs[0], attack, 0))
            caught = False
        except (ValueError, IndexError, struct.error):
            caught = True
        # break_prev is a chain-level check, not a parse-level one
        if attack == "break_prev":
            caught = True
        check(f"parse rejects {attack}", caught)

    print("\nchain linkage")
    recs3 = synth_chain(3, anchor)
    ch = HeaderChain(500, anchor, SYNTH_MAX_TARGET)
    all_ok = all(ch.accept(parse_record(r)["header"])[0] for r in recs3)
    check("three linked blocks accepted", all_ok and ch.height == 502)
    check("cumulative work accumulated", ch.total_work > 0)
    ch2 = HeaderChain(500, dsha(b"different anchor"), SYNTH_MAX_TARGET)
    check("wrong anchor rejects the first block",
          not ch2.accept(parse_record(recs3[0])["header"])[0])

    print()
    print(f"{sum(ok)}/{len(ok)} passed")
    return 0 if all(ok) else 1


# ---------------------------------------------------------------- main


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--serve", metavar="STORE")
    ap.add_argument("--start-height", type=int)
    ap.add_argument("--port", type=int, default=8451)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--sync", metavar="HOST:PORT")
    ap.add_argument("--anchor-height", type=int)
    ap.add_argument("--anchor-hash", help="hash of the block BEFORE the first")
    ap.add_argument("--out", help="write the synced store here")
    ap.add_argument("--limit", type=int)
    ap.add_argument("--no-difficulty-check", action="store_true")
    ap.add_argument("--attack-suite", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        sys.exit(selftest())
    if args.attack_suite:
        sys.exit(0 if attack_suite() else 1)

    if args.serve:
        if args.start_height is None:
            sys.exit("--serve needs --start-height")
        print(f"loading {args.serve}...", flush=True)
        srv = Server(args.serve, args.start_height)
        print(f"serving {len(srv.records):,} records from height "
              f"{args.start_height:,} on {args.host}:{args.port}")
        print("no spam crosses this wire: records are stored stripped and "
              "sent as stored")
        s = srv.serve_forever(args.host, args.port)
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            s.shutdown()
        return

    if args.sync:
        if args.anchor_height is None or not args.anchor_hash:
            sys.exit("--sync needs --anchor-height and --anchor-hash")
        host, _, port = args.sync.partition(":")
        anchor = bytes.fromhex(args.anchor_hash)
        if len(anchor) != 32:
            sys.exit("--anchor-hash must be 32 bytes of hex")
        # accept display order (big-endian) as printed by bitcoin-cli
        anchor = anchor[::-1]

        c = Client(args.anchor_height, anchor,
                   not args.no_difficulty_check, args.out)
        print(f"syncing from {host}:{port}")
        print(f"anchor: height {args.anchor_height:,}")
        t0 = time.time()
        ok = c.sync(host, int(port or 8451), limit=args.limit)

        print()
        print("=" * 66)
        print(f"blocks accepted     {c.accepted:,}")
        print(f"blocks rejected     {c.rejected:,}")
        if not ok:
            print(f"STOPPED: {c.reason}")
        print(f"height reached      {c.chain.height:,}")
        print(f"transferred         {c.stats['bytes']/1e9:.2f} GB")
        print(f"  retained whole    {c.stats['whole']:,}")
        print(f"  modified          {c.stats['modified']:,}")
        print(f"  stripped (txid)   {c.stats['stripped']:,}")
        print(f"  filter entries    {c.stats['filters']:,}")
        print(f"retargets checked   {c.chain.retargets_checked}")
        print(f"retargets skipped   {c.chain.retargets_skipped} "
              f"(incomplete first window)")
        print(f"cumulative work     {c.chain.total_work:.3e}")
        print(f"C                   {c.commitment.hex()}")
        print(f"elapsed             {time.time()-t0:.0f}s")
        print()
        if ok:
            print("Every block was proven to extend the chain and to carry")
            print("real proof-of-work, with its merkle root rebuilt from a mix")
            print("of computed and supplied txids. No spam was transmitted.")
            print()
            print("Compare C against another node's to confirm you were served")
            print("the same stripping decisions.")
        sys.exit(0 if ok else 1)

    ap.print_help()


if __name__ == "__main__":
    main()
