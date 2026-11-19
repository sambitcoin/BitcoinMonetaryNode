#!/usr/bin/env python3
"""
monetary_electrum.py — point Electrum at a monetary store.

The project's claim is that a node can drop the data carriers and still be a
real Bitcoin node. Until an ordinary wallet can verify its own history against
this store, that claim is something people take on trust. This closes it:
Electrum connects, and the balances and histories it shows were computed from
blocks that never held an inscription payload.

    python3 monetary_electrum.py --store ~/mstore --xpub zpub6r... --port 50001
    python3 monetary_electrum.py --store ~/mstore --watch addresses.txt
    python3 monetary_electrum.py --selftest

Then in Electrum: Tools -> Network -> Server, 127.0.0.1:50001:t

WHY THIS IS NOT electrs

electrs indexes every scripthash on the chain, which is well over 100 GB and
climbing. On the hardware this project targets that does not fit beside the
store, and it never will. So this indexes ONE WALLET. You supply an xpub; it
derives your addresses, makes a single pass over the store, and keeps an index
measured in kilobytes.

That is a smaller tool, and on one axis a better one: this node never learns
about anybody's addresses but yours, because it never indexes them. A public
electrs knows every address it serves. The cost is that this serves exactly one
wallet and cannot be shared.

WHAT IT CANNOT DO, STATED UP FRONT

Four limits, each of which would otherwise show up as a wallet bug:

  NO MEMPOOL        The store holds confirmed blocks. Unconfirmed transactions
                    do not exist here, so a payment someone just sent you is
                    invisible until it is mined. Electrum will show nothing,
                    not "pending".

  NO BROADCAST      Sending needs a node with peers. This has none, so
                    blockchain.transaction.broadcast returns an error and
                    Electrum will report that it could not send. Use a
                    different server to spend; use this one to verify.

  MODIFIED BODIES   A transaction whose carrier output was removed no longer
                    hashes to its txid -- that is the format working as
                    designed. Electrum verifies the txids of transactions it
                    fetches, so handing one over would make Electrum call this
                    node a liar, correctly. transaction.get returns an error
                    for those instead, naming the reason.

  PARTIAL HISTORY   A store that begins above genesis cannot see coins received
                    below its start height, and will report a balance that is
                    WRONG rather than merely incomplete. That is dangerous
                    enough that the server refuses to start on a partial store
                    unless you pass --accept-partial-history.

UNKNOWN SCRIPTHASHES ARE AN ERROR, NOT AN EMPTY RESULT

A wallet asks about a scripthash; this server either indexed it or did not. An
unindexed one must not come back as an empty history, because an empty history
is indistinguishable from "you have no coins" and a wallet will believe it. So
unknown scripthashes return an error. A loud failure beats a confident zero.

This is why --xpub is better than --watch: Electrum walks ahead of your used
addresses by its gap limit, and asks about addresses you have never received
on. Derived from an xpub those are known-and-empty, which is true. From a
fixed address list they are unknown, and you get errors in the GUI.

Standard library only, plus wallet_check.py and tx_query.py beside it.
BSD-2-Clause.
"""

import argparse
import glob
import hashlib
import json
import os
import socketserver
import struct
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wallet_check as wc                                        # noqa: E402

SERVER_VERSION = "monetary-electrum 0.1.0-alpha"
PROTOCOL_MIN = "1.4"
PROTOCOL_MAX = "1.4.2"

STORE_MAGIC = b"MNB1"
FLAG_STRIPPED, FLAG_MODIFIED, FLAG_WHOLE = 0, 1, 2

# Sparrow checks this before it will trust a server, and a store that starts
# above genesis still knows which chain it is on -- chain_check.py proved it
# against this very hash. Reporting it is a statement about the chain, not a
# claim to hold block 0.
GENESIS_HASH = ("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a"
                "8ce26f")


# ------------------------------------------------------------- ripemd160
#
# hashlib has it only when the OpenSSL build enabled the legacy provider, and
# on current Debian it usually has not. A wallet server that cannot compute
# hash160 cannot derive a single address, so carry an implementation rather
# than discover this on the user's machine.

_RL = (
    list(range(16)) +
    [7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8] +
    [3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12] +
    [1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2] +
    [4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13])
_RR = (
    [5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12] +
    [6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2] +
    [15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13] +
    [8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14] +
    [12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11])
_SL = (
    [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8] +
    [7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12] +
    [11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5] +
    [11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12] +
    [9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6])
_SR = (
    [8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6] +
    [9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11] +
    [9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5] +
    [15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8] +
    [8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11])
_KL = (0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E)
_KR = (0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000)
_M32 = 0xFFFFFFFF


def _rol(x, n):
    x &= _M32
    return ((x << n) | (x >> (32 - n))) & _M32


def _f(j, x, y, z):
    if j < 16:
        return x ^ y ^ z
    if j < 32:
        return (x & y) | (~x & z)
    if j < 48:
        return (x | ~y) ^ z
    if j < 64:
        return (x & z) | (y & ~z)
    return x ^ (y | ~z)


def ripemd160(msg):
    try:
        return hashlib.new("ripemd160", msg).digest()
    except (ValueError, TypeError):
        pass

    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    ln = len(msg)
    msg = msg + b"\x80"
    msg += b"\x00" * ((56 - len(msg) % 64) % 64)
    msg += struct.pack("<Q", ln * 8)

    for off in range(0, len(msg), 64):
        X = struct.unpack("<16I", msg[off:off + 64])
        al, bl, cl, dl, el = h
        ar, br, cr, dr, er = h
        for j in range(80):
            rnd = j // 16
            t = _rol(al + _f(j, bl, cl, dl) + X[_RL[j]] + _KL[rnd], _SL[j])
            t = (t + el) & _M32
            al, bl, cl, dl, el = el, t, bl, _rol(cl, 10), dl
            t = _rol(ar + _f(79 - j, br, cr, dr) + X[_RR[j]] + _KR[rnd],
                     _SR[j])
            t = (t + er) & _M32
            ar, br, cr, dr, er = er, t, br, _rol(cr, 10), dr
        h = [(h[1] + cl + dr) & _M32, (h[2] + dl + er) & _M32,
             (h[3] + el + ar) & _M32, (h[4] + al + br) & _M32,
             (h[0] + bl + cr) & _M32]
    return struct.pack("<5I", *h)


def hash160(b):
    return ripemd160(hashlib.sha256(b).digest())


# ------------------------------------------------------------- secp256k1
#
# Public derivation only: K_i = K_par + G*I_L. No signing happens here and no
# private key is ever handled, which is the point of taking an xpub.

_P = 2 ** 256 - 2 ** 32 - 977
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
_G = (_GX, _GY)


def point_add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0] and (p[1] + q[1]) % _P == 0:
        return None
    if p == q:
        lam = 3 * p[0] * p[0] * pow(2 * p[1], _P - 2, _P) % _P
    else:
        lam = (q[1] - p[1]) * pow(q[0] - p[0], _P - 2, _P) % _P
    x = (lam * lam - p[0] - q[0]) % _P
    return (x, (lam * (p[0] - x) - p[1]) % _P)


def point_mul(k, p=_G):
    r, acc = None, p
    while k:
        if k & 1:
            r = point_add(r, acc)
        acc = point_add(acc, acc)
        k >>= 1
    return r


def ser_point(p):
    return bytes([2 + (p[1] & 1)]) + p[0].to_bytes(32, "big")


def parse_point(b):
    if len(b) != 33 or b[0] not in (2, 3):
        raise ValueError("not a compressed public key")
    x = int.from_bytes(b[1:], "big")
    v = (pow(x, 3, _P) + 7) % _P
    y = pow(v, (_P + 1) // 4, _P)
    if pow(y, 2, _P) != v:
        raise ValueError("public key is not on the curve")
    if (y & 1) != (b[0] & 1):
        y = _P - y
    return (x, y)


# ------------------------------------------------------------------ bip32

# Version bytes decide the script type. Electrum and most wallets use the
# SLIP-132 prefixes, so honour them rather than making the user say.
XPUB_KINDS = {
    0x0488B21E: "p2pkh",        # xpub
    0x049D7CB2: "p2sh-p2wpkh",  # ypub
    0x04B24746: "p2wpkh",       # zpub
    0x043587CF: "p2pkh",        # tpub   (testnet)
    0x044A5262: "p2sh-p2wpkh",  # upub
    0x045F1CF6: "p2wpkh",       # vpub
}


def b58encode_check(payload):
    """Base58Check. Used by the self-test to build a key without pasting one."""
    raw = payload + wc.dsha(payload)[:4]
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = wc.B58[r] + out
    for b in raw:
        if b:
            break
        out = wc.B58[0] + out
    return out


def decode_xpub(s):
    """Returns (kind, chain_code, pubkey_bytes). Raises ValueError."""
    raw = wc.b58decode_check(s)
    if raw is None or len(raw) != 78:
        raise ValueError("not a valid extended public key")
    version = struct.unpack(">I", raw[:4])[0]
    kind = XPUB_KINDS.get(version)
    if kind is None:
        raise ValueError("unrecognised extended-key prefix %08x" % version)
    chain = raw[13:45]
    key = raw[45:78]
    if key[0] not in (2, 3):
        raise ValueError("that is an extended PRIVATE key. Do not paste "
                         "private keys into anything. Use the xpub.")
    parse_point(key)
    return kind, chain, key


def ckd_pub(chain, key, index):
    """BIP32 public child derivation. Hardened indices are impossible here."""
    if index >= 0x80000000:
        raise ValueError("cannot derive a hardened child from a public key")
    import hmac
    data = key + struct.pack(">I", index)
    I = hmac.new(chain, data, hashlib.sha512).digest()
    il = int.from_bytes(I[:32], "big")
    if il >= _N:
        raise ValueError("derivation produced an invalid key; use next index")
    child = point_add(point_mul(il), parse_point(key))
    if child is None:
        raise ValueError("derivation produced the point at infinity")
    return I[32:], ser_point(child)


def script_for(kind, pubkey):
    h = hash160(pubkey)
    if kind == "p2pkh":
        return b"\x76\xa9\x14" + h + b"\x88\xac"
    if kind == "p2wpkh":
        return b"\x00\x14" + h
    if kind == "p2sh-p2wpkh":
        return b"\xa9\x14" + hash160(b"\x00\x14" + h) + b"\x87"
    raise ValueError("unknown script kind %r" % kind)


def derive_scripts(xpub, gap=100, chains=(0, 1)):
    """
    Returns {scripthash: "m/chain/i"} for the first `gap` of each chain.

    The gap limit matters: Electrum asks about addresses beyond your last used
    one, and anything not derived here comes back as an error rather than an
    empty history. Too small a gap looks like a broken server.
    """
    kind, chain_code, key = decode_xpub(xpub)
    out = {}
    for c in chains:
        cc, ck = ckd_pub(chain_code, key, c)
        for i in range(gap):
            try:
                _cc2, child = ckd_pub(cc, ck, i)
            except ValueError:
                continue
            spk = script_for(kind, child)
            out[wc.scripthash(spk)] = "m/%d/%d" % (c, i)
    return out


# ------------------------------------------------------------------- index


def iter_blocks(store, base_height):
    """
    Yield (height, header, txs) where txs is a list of
    (txid, vin, vout, body, flag). body is None for stripped transactions.

    Unlike wallet_check.iter_store this keeps the header and the raw body,
    because a wallet server has to serve both.
    """
    files = sorted(glob.glob(os.path.join(store, "mblk*.dat")))
    if not files:
        raise ValueError("no mblk*.dat in %s" % store)
    height = base_height
    for f in files:
        with open(f, "rb") as fh:
            data = fh.read()
        pos = 0
        while pos < len(data):
            if data[pos:pos + 4] != STORE_MAGIC:
                raise ValueError("%s: bad magic at %d"
                                 % (os.path.basename(f), pos))
            length = struct.unpack_from("<I", data, pos + 6)[0]
            end = pos + 10 + length
            if end > len(data):
                raise ValueError("%s: truncated record at %d — store is "
                                 "incomplete" % (os.path.basename(f), pos))
            digest = data[pos + 10:pos + 42]
            body = data[pos + 42:end]
            if wc.dsha(body) != digest:
                raise ValueError(
                    "%s: body digest mismatch at %d. The store is corrupt; "
                    "run monetary_store.py --verify before serving a wallet "
                    "from it." % (os.path.basename(f), pos))
            c = wc.Cursor(body)
            c.take(32)
            header = c.take(80)
            n_tx = c.varint()
            txs = []
            for _ in range(n_tx):
                flag = c.u8()
                if flag == FLAG_STRIPPED:
                    txs.append((c.take(32), [], [], None, flag))
                elif flag == FLAG_MODIFIED:
                    txid = c.take(32)
                    b = c.take(c.varint())
                    _t, vin, vout = wc.parse_tx(b)
                    txs.append((txid, vin, vout, b, flag))
                elif flag == FLAG_WHOLE:
                    b = c.take(c.varint())
                    txid, vin, vout = wc.parse_tx(b)
                    txs.append((txid, vin, vout, b, flag))
                else:
                    raise ValueError("unknown tx flag %d" % flag)

            filters = []
            for _ in range(c.varint()):
                t = c.take(32)
                v = c.varint()
                amt = struct.unpack("<Q", c.take(8))[0]
                c.take(4)
                spk = c.take(c.varint())
                filters.append((t, v, amt, spk))

            yield height, header, txs, filters
            height += 1
            pos = end


def merkle_branch(txids, idx):
    """Branch proving txids[idx] belongs under the root."""
    branch, level = [], list(txids)
    while len(level) > 1:
        if len(level) & 1:
            level.append(level[-1])
        branch.append(level[idx ^ 1])
        level = [wc.dsha(level[i] + level[i + 1])
                 for i in range(0, len(level), 2)]
        idx >>= 1
    return branch


class Index:
    """Everything the server can answer, built in one pass over the store."""

    def __init__(self, base_height):
        self.base_height = base_height
        self.headers = []                  # [80-byte header], from base
        self.history = {}                  # scripthash -> [(height, txid_hex)]
        self.utxos = {}                    # scripthash -> {(txid,n): (v, h)}
        self.txs = {}                      # txid_hex -> (height, body, flag)
        self.block_txids = {}              # height -> [txid] (watched blocks)
        self.labels = {}                   # scripthash -> derivation path
        self.stripped_touching = 0
        # What the dashboard's wallet view needs and the Electrum protocol
        # does not: how much each transaction moved, and when. A wallet GUI
        # that shows a list of txids and no amounts is not a wallet GUI.
        self.tx_delta = {}                 # txid_hex -> net sats for us
        self.tx_time = {}                  # txid_hex -> block unix time

    @property
    def tip(self):
        return self.base_height + len(self.headers) - 1

    def header_at(self, height):
        i = height - self.base_height
        if i < 0 or i >= len(self.headers):
            return None
        return self.headers[i]

    def balance(self, sh):
        return sum(v for v, _h in self.utxos.get(sh, {}).values())

    def status(self, sh):
        """Electrum's subscription status: a hash over the history."""
        h = self.history.get(sh)
        if not h:
            return None
        s = "".join("%s:%d:" % (txid, height) for height, txid in h)
        return hashlib.sha256(s.encode()).hexdigest()


class Interrupted(Exception):
    """Raised when a rebuild is cancelled, so a half-index is never served."""


def build_index(store, base_height, targets, progress=None,
                on_progress=None, stop=None):
    ix = Index(base_height)
    ix.labels = dict(targets)
    watched = {}            # (txid, vout) -> (scripthash, value)
    for sh in targets:
        ix.history[sh] = []
        ix.utxos[sh] = {}

    t0 = time.time()
    n = 0
    for height, header, txs, filters in iter_blocks(store, base_height):
        ix.headers.append(header)
        dropped = {}
        for txid, vout_i, amt, spk in filters:
            dropped.setdefault(txid, []).append((vout_i, amt, spk))

        block_time = struct.unpack_from("<I", header, 68)[0]
        hit_this_block = False
        for txid, vin, vout, body, flag in txs:
            if flag == FLAG_STRIPPED:
                continue
            touched = set()
            delta = 0

            for prev in vin:
                got = watched.pop(prev, None)
                if got:
                    sh, v = got
                    ix.utxos[sh].pop(prev, None)
                    touched.add(sh)
                    delta -= v

            for vout_i, amt, spk in list(vout) + dropped.get(txid, []):
                sh = wc.scripthash(spk)
                if sh in ix.history:
                    watched[(txid, vout_i)] = (sh, amt)
                    ix.utxos[sh][(txid, vout_i)] = (amt, height)
                    touched.add(sh)
                    delta += amt

            if touched:
                hit_this_block = True
                hx = txid[::-1].hex()
                ix.txs[hx] = (height, body, flag)
                ix.tx_delta[hx] = delta
                ix.tx_time[hx] = block_time
                for sh in touched:
                    if not ix.history[sh] or ix.history[sh][-1][1] != hx:
                        ix.history[sh].append((height, hx))

        if hit_this_block:
            ix.block_txids[height] = [t[0] for t in txs]

        n += 1
        if stop is not None and stop.is_set():
            raise Interrupted("index rebuild cancelled at height %d" % height)
        if on_progress is not None and n % 500 == 0:
            on_progress(n, height)
        if progress and n % progress == 0:
            print("  %d blocks  height %d  %.0fs"
                  % (n, height, time.time() - t0), flush=True)

    if on_progress is not None:
        on_progress(n, ix.tip)
    return ix


# ------------------------------------------------------------------ server


class RpcError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message


class Methods:
    """The Electrum protocol subset this store can answer honestly."""

    def __init__(self, index, store_path, partial):
        self.ix = index
        self.store_path = store_path
        self.partial = partial

    # -- housekeeping

    def server_version(self, *a):
        return [SERVER_VERSION, PROTOCOL_MAX]

    def server_banner(self, *a):
        ix = self.ix
        lines = [
            SERVER_VERSION,
            "",
            "Serving a MONETARY STORE: Bitcoin blocks with the data carriers",
            "removed. Every block here was verified against its own header.",
            "",
            "  heights   %d to %d" % (ix.base_height, ix.tip),
            "  wallet    %d scripthashes indexed" % len(ix.history),
            "",
            "This server has no mempool and cannot broadcast. Unconfirmed",
            "payments are invisible; use another server to send.",
        ]
        if self.partial:
            lines += [
                "",
                "PARTIAL HISTORY. This store starts at %d, not at genesis."
                % ix.base_height,
                "Coins received below that height are NOT counted. Any",
                "balance shown is a lower bound, not your balance.",
            ]
        return "\n".join(lines)

    def server_ping(self, *a):
        return None

    def server_donation_address(self, *a):
        return ""

    def server_features(self, *a):
        return {
            "server_version": SERVER_VERSION,
            "protocol_min": PROTOCOL_MIN,
            "protocol_max": PROTOCOL_MAX,
            "genesis_hash": GENESIS_HASH,
            "hash_function": "sha256",
            "pruning": self.ix.base_height or None,
        }

    def server_peers_subscribe(self, *a):
        return []

    # -- chain

    def headers_subscribe(self, *a):
        h = self.ix.header_at(self.ix.tip)
        return {"hex": h.hex(), "height": self.ix.tip}

    def _checkpoint(self, cp_height, height):
        """
        Electrum's header-chain checkpoint: a merkle proof that the header at
        `height` sits under the root of every header from 0 to cp_height.

        Sparrow asks for this to satisfy itself that the server is not
        inventing a chain. It needs every header from genesis, which a partial
        store does not have -- so say that plainly instead of returning a
        proof computed over a shorter chain, which would be a fabrication.
        """
        cp_height, height = int(cp_height), int(height)
        if self.ix.base_height != 0:
            raise RpcError(
                1,
                "this store starts at height %d, so it cannot build a "
                "checkpoint proof rooted at genesis. In Sparrow, clear the "
                "server's checkpoint verification, or use a store derived "
                "from block 0." % self.ix.base_height)
        if cp_height > self.ix.tip or height > cp_height:
            raise RpcError(1, "cp_height %d out of range (tip %d)"
                           % (cp_height, self.ix.tip))
        leaves = [wc.dsha(self.ix.header_at(i))
                  for i in range(0, cp_height + 1)]
        branch = merkle_branch(leaves, height)
        level = list(leaves)
        while len(level) > 1:
            if len(level) & 1:
                level.append(level[-1])
            level = [wc.dsha(level[i] + level[i + 1])
                     for i in range(0, len(level), 2)]
        return ([b[::-1].hex() for b in branch], level[0][::-1].hex())

    def block_header(self, height, cp_height=0):
        h = self.ix.header_at(int(height))
        if h is None:
            raise RpcError(1, "height %s is outside this store (%d..%d)"
                           % (height, self.ix.base_height, self.ix.tip))
        if not cp_height:
            return h.hex()
        branch, root = self._checkpoint(cp_height, height)
        return {"header": h.hex(), "branch": branch, "root": root}

    def block_headers(self, start_height, count, cp_height=0):
        start, count = int(start_height), min(int(count), 2016)
        out = b""
        for i in range(start, start + count):
            h = self.ix.header_at(i)
            if h is None:
                break
            out += h
        res = {"hex": out.hex(), "count": len(out) // 80, "max": 2016}
        if cp_height and res["count"]:
            branch, root = self._checkpoint(cp_height, start + res["count"] - 1)
            res["branch"], res["root"] = branch, root
        return res

    def estimatefee(self, *a):
        # -1 is the protocol's "I do not know". Inventing a number here would
        # have wallets build underpaying transactions.
        return -1

    def relayfee(self, *a):
        return 0.00001

    def fee_histogram(self, *a):
        return []

    # -- wallet

    def _known(self, sh):
        if sh not in self.ix.history:
            raise RpcError(
                1,
                "this server indexes one wallet and that scripthash is not "
                "in it. It is NOT empty — it is unknown. Restart with an "
                "--xpub covering it, or a larger --gap.")
        return sh

    def get_history(self, sh):
        self._known(sh)
        return [{"tx_hash": txid, "height": height}
                for height, txid in self.ix.history[sh]]

    def get_mempool(self, sh):
        self._known(sh)
        return []

    def get_balance(self, sh):
        self._known(sh)
        return {"confirmed": self.ix.balance(sh), "unconfirmed": 0}

    def listunspent(self, sh):
        self._known(sh)
        out = []
        for (txid, n), (value, height) in sorted(
                self.ix.utxos[sh].items(), key=lambda kv: kv[1][1]):
            out.append({"tx_hash": txid[::-1].hex(), "tx_pos": n,
                        "height": height, "value": value})
        return out

    def scripthash_subscribe(self, sh):
        self._known(sh)
        return self.ix.status(sh)

    def scripthash_unsubscribe(self, sh):
        return True

    # -- transactions

    def transaction_get(self, txid, verbose=False):
        if verbose:
            # Verbose means the decoded form bitcoind builds, which needs a
            # chain-wide txid index this store does not carry. Most Electrum
            # servers decline it too, and Sparrow falls back to raw.
            raise RpcError(1, "verbose transaction.get is not supported; "
                              "request the raw form")
        got = self.ix.txs.get(txid)
        if got is None:
            raise RpcError(
                1,
                "transaction %s is not in this wallet's index. This server "
                "indexes the scripthashes it was given, not the whole chain, "
                "so transactions unrelated to this wallet cannot be fetched."
                % txid)
        height, body, flag = got
        if flag == FLAG_MODIFIED:
            raise RpcError(
                1,
                "this node removed a data carrier from %s, so the stored "
                "bytes no longer hash to that txid. Handing them over would "
                "fail your wallet's own check, correctly. The txid is proven "
                "in the block by transaction.get_merkle; the body is not "
                "available here." % txid)
        if body is None:
            raise RpcError(1, "%s was stored as a txid only" % txid)
        return body.hex()

    def transaction_get_merkle(self, txid, height=0):
        got = self.ix.txs.get(txid)
        if got is None:
            raise RpcError(1, "transaction %s is not in this wallet's index"
                           % txid)
        h = got[0]
        txids = self.ix.block_txids.get(h)
        if txids is None:
            raise RpcError(1, "no txid list retained for height %d" % h)
        raw = bytes.fromhex(txid)[::-1]
        try:
            pos = txids.index(raw)
        except ValueError:
            raise RpcError(1, "%s is not in block %d" % (txid, h))
        return {"block_height": h, "pos": pos,
                "merkle": [b[::-1].hex() for b in merkle_branch(txids, pos)]}

    def transaction_broadcast(self, raw):
        raise RpcError(
            1,
            "a monetary store has no peers and no mempool, so this server "
            "cannot broadcast. Switch Electrum to a server with a node "
            "behind it to send, then switch back to verify.")


ROUTES = {
    "server.version": "server_version",
    "server.banner": "server_banner",
    "server.ping": "server_ping",
    "server.donation_address": "server_donation_address",
    "server.features": "server_features",
    "server.peers.subscribe": "server_peers_subscribe",
    "blockchain.headers.subscribe": "headers_subscribe",
    "blockchain.block.header": "block_header",
    "blockchain.block.headers": "block_headers",
    "blockchain.estimatefee": "estimatefee",
    "blockchain.relayfee": "relayfee",
    "mempool.get_fee_histogram": "fee_histogram",
    "blockchain.scripthash.get_history": "get_history",
    "blockchain.scripthash.get_mempool": "get_mempool",
    "blockchain.scripthash.get_balance": "get_balance",
    "blockchain.scripthash.listunspent": "listunspent",
    "blockchain.scripthash.subscribe": "scripthash_subscribe",
    "blockchain.scripthash.unsubscribe": "scripthash_unsubscribe",
    "blockchain.transaction.get": "transaction_get",
    "blockchain.transaction.get_merkle": "transaction_get_merkle",
    "blockchain.transaction.broadcast": "transaction_broadcast",
}


def dispatch(methods, req):
    """One JSON-RPC request in, one response dict out. Never raises."""
    rid = req.get("id")
    name = req.get("method")
    params = req.get("params", [])
    target = ROUTES.get(name)
    if target is None:
        return {"jsonrpc": "2.0", "id": rid,
                "error": {"code": -32601,
                          "message": "unsupported method %s" % name}}
    try:
        if isinstance(params, dict):
            result = getattr(methods, target)(**params)
        else:
            result = getattr(methods, target)(*params)
        return {"jsonrpc": "2.0", "id": rid, "result": result}
    except RpcError as e:
        return {"jsonrpc": "2.0", "id": rid,
                "error": {"code": e.code, "message": e.message}}
    except TypeError as e:
        return {"jsonrpc": "2.0", "id": rid,
                "error": {"code": -32602, "message": "bad params: %s" % e}}
    except Exception as e:                                  # noqa: BLE001
        return {"jsonrpc": "2.0", "id": rid,
                "error": {"code": -32603,
                          "message": "%s: %s" % (type(e).__name__, e)}}


class Handler(socketserver.StreamRequestHandler):
    timeout = 300

    def handle(self):
        methods = self.server.methods
        for line in self.rfile:
            line = line.strip()
            if not line:
                continue
            try:
                req = json.loads(line)
            except ValueError:
                self.wfile.write(b'{"jsonrpc":"2.0","id":null,"error":'
                                 b'{"code":-32700,"message":"parse error"}}\n')
                continue
            batch = req if isinstance(req, list) else [req]
            out = [dispatch(methods, r) for r in batch]
            payload = out if isinstance(req, list) else out[0]
            try:
                self.wfile.write((json.dumps(payload) + "\n").encode())
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                return


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


# ----------------------------------------------------------------- service
#
# Everything above is usable from a command line. Ordinary people do not use
# a command line, so this wraps it in something a web page can drive: give it
# an xpub, it indexes in the background and reports progress, and starts
# listening only once the index is complete.
#
# "Only once complete" is the important part. A half-built index answers
# get_balance with a number that is too small, and a wallet showing a
# too-small balance is worse than a wallet showing an error.


WALLET_FILE = "wallet.json"

STATE_IDLE = "idle"
STATE_INDEXING = "indexing"
STATE_READY = "ready"
STATE_ERROR = "error"


class WalletService:
    """
    One wallet, indexed from the store and served over the Electrum protocol.

    Thread-safe for the UI's purposes: configure() and status() may be called
    from request threads while a rebuild runs.
    """

    def __init__(self, store, base_height, data_dir,
                 host="0.0.0.0", port=50001, partial=None):
        self.store = store
        self.base_height = base_height
        self.data_dir = data_dir
        self.host = host
        self.port = port
        self.partial = (base_height > 0) if partial is None else partial
        self.expected = store_expected_blocks(store)

        self._lock = threading.Lock()
        self._state = STATE_IDLE
        self._error = None
        self._done = 0
        self._at_height = 0
        self._started = None
        self._index = None
        self._srv = None
        self._thread = None
        self._stop = None
        self.xpub = None
        self.gap = 100

    # -- persistence

    @property
    def config_path(self):
        return os.path.join(self.data_dir, WALLET_FILE)

    def load(self):
        """Restore a configured wallet across restarts. Never raises."""
        try:
            with open(self.config_path) as f:
                d = json.load(f)
        except (OSError, ValueError):
            return False
        xpub = d.get("xpub")
        if not isinstance(xpub, str) or not xpub:
            return False
        gap = d.get("gap")
        self.gap = gap if isinstance(gap, int) and 1 <= gap <= 2000 else 100
        self.xpub = xpub
        return True

    def save(self):
        tmp = self.config_path + ".tmp"
        with open(tmp, "w") as f:
            json.dump({"xpub": self.xpub, "gap": self.gap}, f)
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, self.config_path)

    def forget(self):
        """Remove the wallet and stop serving it."""
        self._cancel()
        with self._lock:
            self.xpub = None
            self._index = None
            self._state = STATE_IDLE
            self._error = None
            self._done = 0
        try:
            os.remove(self.config_path)
        except OSError:
            pass
        self._stop_server()

    # -- lifecycle

    def configure(self, xpub, gap=100):
        """
        Validate and start indexing. Returns (ok, message).

        Validation happens before anything is saved or any thread starts, so
        a typo comes back as a message on the page rather than a background
        failure the user has to go hunting for.
        """
        xpub = (xpub or "").strip()
        if not xpub:
            return False, "Paste an extended public key (xpub, ypub or zpub)."
        try:
            gap = int(gap)
        except (TypeError, ValueError):
            return False, "Gap limit must be a number."
        if not 1 <= gap <= 2000:
            return False, "Gap limit must be between 1 and 2000."
        try:
            targets = derive_scripts(xpub, gap=gap)
        except ValueError as e:
            return False, str(e)
        if not targets:
            return False, "That key derived no addresses."

        self._cancel()
        self._stop_server()
        with self._lock:
            self.xpub = xpub
            self.gap = gap
            self._state = STATE_INDEXING
            self._error = None
            self._done = 0
            self._at_height = self.base_height
            self._started = time.time()
            self._index = None
            self._stop = threading.Event()
        try:
            self.save()
        except OSError as e:
            with self._lock:
                self._state = STATE_ERROR
                self._error = "cannot write %s: %s" % (self.config_path, e)
            return False, self._error

        self._thread = threading.Thread(
            target=self._run, args=(targets, self._stop), daemon=True)
        self._thread.start()
        return True, ("Indexing %d addresses. This reads the whole store "
                      "once and can take hours on slow hardware; the page "
                      "shows progress." % len(targets))

    def resume(self):
        """Start indexing a wallet restored by load()."""
        if not self.xpub:
            return False, "No wallet configured."
        return self.configure(self.xpub, self.gap)

    def _cancel(self):
        stop, t = self._stop, self._thread
        if stop is not None:
            stop.set()
        if t is not None and t.is_alive() and t is not threading.current_thread():
            t.join(timeout=30)

    def _run(self, targets, stop):
        def on_progress(n, height):
            with self._lock:
                self._done = n
                self._at_height = height
        try:
            ix = build_index(self.store, self.base_height, targets,
                             on_progress=on_progress, stop=stop)
        except Interrupted:
            return
        except Exception as e:                              # noqa: BLE001
            with self._lock:
                self._state = STATE_ERROR
                self._error = "%s: %s" % (type(e).__name__, e)
            return
        if stop.is_set():
            return
        with self._lock:
            self._index = ix
            self._state = STATE_READY
            self._error = None
        try:
            self._start_server(ix)
        except OSError as e:
            with self._lock:
                self._state = STATE_ERROR
                self._error = "cannot listen on %s:%d: %s" % (
                    self.host, self.port, e)

    def _start_server(self, ix):
        self._stop_server()
        srv = Server((self.host, self.port), Handler)
        srv.methods = Methods(ix, self.store, partial=self.partial)
        self._srv = srv
        threading.Thread(target=srv.serve_forever, daemon=True).start()

    def _stop_server(self):
        srv, self._srv = self._srv, None
        if srv is not None:
            try:
                srv.shutdown()
                srv.server_close()
            except Exception:                               # noqa: BLE001
                pass

    # -- reporting

    def view(self, limit=50):
        """
        Everything a read-only wallet page shows: balance, transactions with
        amounts and dates, and the addresses with coins on them.

        Read-only is not a limitation to apologise for here. This server has
        no mempool and no peers, so it could not broadcast a spend even if it
        held a key -- and it holds no key, because an xpub cannot produce
        one. There is nothing to sign with and nowhere to send it.
        """
        ix = self._index
        if ix is None:
            return None

        seen, rows = set(), []
        for sh, hist in ix.history.items():
            for height, txid in hist:
                if txid in seen:
                    continue
                seen.add(txid)
                flag = ix.txs.get(txid, (None, None, None))[2]
                rows.append({
                    "txid": txid,
                    "height": height,
                    "time": ix.tx_time.get(txid),
                    "amount": ix.tx_delta.get(txid, 0),
                    "modified": flag == FLAG_MODIFIED,
                })
        rows.sort(key=lambda r: (r["height"], r["txid"]), reverse=True)

        addrs = []
        for sh, label in sorted(ix.labels.items(), key=lambda kv: kv[1]):
            bal = ix.balance(sh)
            n = len(ix.history.get(sh, []))
            if bal or n:
                addrs.append({"path": label, "balance": bal, "txs": n,
                              "scripthash": sh})

        return {
            "balance": sum(ix.balance(s) for s in ix.history),
            "transactions": rows[:limit],
            "total_transactions": len(rows),
            "addresses": addrs,
            "modified_count": sum(1 for r in rows if r["modified"]),
        }

    def status(self):
        with self._lock:
            total = max(0, (self._index.tip - self.base_height + 1)
                        if self._index else 0)
            d = {
                "state": self._state,
                "error": self._error,
                "xpub": self.xpub,
                "gap": self.gap,
                "port": self.port,
                "partial": self.partial,
                "base_height": self.base_height,
                "blocks_done": self._done,
                "at_height": self._at_height,
                "expected": self.expected,
                "elapsed": (time.time() - self._started)
                           if self._started else 0,
            }
            ix = self._index

        # Percentage and a finish estimate, but only once there is enough of
        # a sample to mean anything. A "2 seconds remaining" that turns into
        # six hours is worse than no estimate.
        if d["state"] == STATE_READY:
            d["percent"] = 100.0
        elif self.expected and d["blocks_done"]:
            d["percent"] = min(99.9, 100.0 * d["blocks_done"] / self.expected)
            if d["elapsed"] > 30:
                rate = d["blocks_done"] / d["elapsed"]
                if rate > 0:
                    d["eta"] = max(0, (self.expected - d["blocks_done"])
                                   / rate)
        else:
            d["percent"] = 0.0
        if ix is not None:
            d["tip"] = ix.tip
            d["blocks"] = total
            d["addresses"] = len(ix.history)
            d["used"] = sum(1 for v in ix.history.values() if v)
            d["balance"] = sum(ix.balance(s) for s in ix.history)
            d["transactions"] = len(ix.txs)
        return d


# ---------------------------------------------------------------- selftest


def _selftest():
    bad = [0]

    def check(name, cond):
        print(("PASS  " if cond else "FAIL  ") + name)
        if not cond:
            bad[0] = 1

    # -- ripemd160 against the published vectors. Everything downstream --
    # addresses, scripts, scripthashes -- is wrong if these are wrong, and
    # wrong in a way that looks like "the wallet has no coins".
    check("ripemd160 of empty",
          ripemd160(b"").hex() ==
          "9c1185a5c5e9fc54612808977ee8f548b2258d31")
    check("ripemd160 of abc",
          ripemd160(b"abc").hex() ==
          "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc")
    check("ripemd160 of message digest",
          ripemd160(b"message digest").hex() ==
          "5d0689ef49d2fae572b881b123a85ffa21595f36")
    check("ripemd160 of a..z",
          ripemd160(b"abcdefghijklmnopqrstuvwxyz").hex() ==
          "f71c27109c692c1b56bbdceb5b9d2865b3708dbc")
    # Crosses the 64-byte block boundary, which is where a padding bug hides.
    check("ripemd160 of 8x alphanumeric",
          ripemd160(b"1234567890" * 8).hex() ==
          "9b752e45573d4b39f4dbd3323cab82bf63326bfb")

    # -- curve arithmetic. Verified by its own algebra rather than by a
    # memorised vector, which would only test my recall.
    check("G is on the curve",
          (_GY * _GY - _GX ** 3 - 7) % _P == 0)
    check("point_mul(1) is G", point_mul(1) == _G)
    check("point_mul(2) is G+G", point_mul(2) == point_add(_G, _G))
    a, b = 1234567, 7654321
    check("G*(a+b) == G*a + G*b",
          point_mul(a + b) == point_add(point_mul(a), point_mul(b)))
    check("G*n is infinity", point_mul(_N) is None)
    check("serialise/parse round-trips",
          parse_point(ser_point(point_mul(a))) == point_mul(a))
    check("parity encoded in the prefix",
          ser_point(point_mul(a))[0] in (2, 3))

    # -- BIP32. CKDpub must agree with what CKDpriv would have produced:
    #    k_i = I_L + k_par  =>  K_i = G*I_L + K_par.
    import hmac as _hmac
    k_par = 0x0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
    chain = bytes(range(32))
    K_par = ser_point(point_mul(k_par))
    _cc, K_child = ckd_pub(chain, K_par, 7)
    I = _hmac.new(chain, K_par + struct.pack(">I", 7),
                  hashlib.sha512).digest()
    k_child = (int.from_bytes(I[:32], "big") + k_par) % _N
    check("ckd_pub matches ckd_priv",
          K_child == ser_point(point_mul(k_child)))
    check("chain code advances", _cc == I[32:])

    try:
        ckd_pub(chain, K_par, 0x80000000)
        check("hardened derivation refused", False)
    except ValueError:
        check("hardened derivation refused", True)

    # -- script construction
    pk = ser_point(point_mul(a))
    h = hash160(pk)
    check("p2pkh shape",
          script_for("p2pkh", pk) == b"\x76\xa9\x14" + h + b"\x88\xac")
    check("p2wpkh shape", script_for("p2wpkh", pk) == b"\x00\x14" + h)
    check("p2sh-p2wpkh wraps the witness program",
          script_for("p2sh-p2wpkh", pk) ==
          b"\xa9\x14" + hash160(b"\x00\x14" + h) + b"\x87")
    check("script kinds differ",
          len({script_for(k, pk) for k in
               ("p2pkh", "p2wpkh", "p2sh-p2wpkh")}) == 3)

    # -- an xprv must be refused rather than quietly used
    try:
        decode_xpub("not an xpub at all")
        check("garbage xpub refused", False)
    except ValueError:
        check("garbage xpub refused", True)

    # -- index and protocol, over a synthetic two-block store
    spk = script_for("p2wpkh", pk)
    sh = wc.scripthash(spk)
    other = script_for("p2wpkh", ser_point(point_mul(b)))

    def tx(vins, vouts):
        out = struct.pack("<I", 1) + wc_varint(len(vins))
        for t, n in vins:
            out += t + struct.pack("<I", n) + wc_varint(0) + b"\xff" * 4
        out += wc_varint(len(vouts))
        for amt, s in vouts:
            out += struct.pack("<Q", amt) + wc_varint(len(s)) + s
        return out + struct.pack("<I", 0)

    def wc_varint(n):
        if n < 0xFD:
            return bytes([n])
        return b"\xfd" + struct.pack("<H", n)

    funding = tx([(b"\x00" * 32, 0xFFFFFFFF)], [(50000, spk)])
    f_txid = wc.dsha(funding)
    unrelated = tx([(b"\x11" * 32, 0)], [(7000, other)])
    spending = tx([(f_txid, 0)], [(40000, other)])

    def record(header, entries):
        body = b"\x00" * 32 + header + wc_varint(len(entries))
        for flag, payload in entries:
            if flag == FLAG_WHOLE:
                body += bytes([flag]) + wc_varint(len(payload)) + payload
            elif flag == FLAG_MODIFIED:
                txid, b2 = payload
                body += bytes([flag]) + txid + wc_varint(len(b2)) + b2
            else:
                body += bytes([flag]) + payload
        body += wc_varint(0)
        return (STORE_MAGIC + struct.pack("<H", 1)
                + struct.pack("<I", len(body) + 32) + wc.dsha(body) + body)

    def header_for(txids):
        level = list(txids)
        while len(level) > 1:
            if len(level) & 1:
                level.append(level[-1])
            level = [wc.dsha(level[i] + level[i + 1])
                     for i in range(0, len(level), 2)]
        root = level[0]
        return (struct.pack("<I", 1) + b"\x00" * 32 + root
                + struct.pack("<III", 0, 0x207FFFFF, 0))

    import tempfile
    d = tempfile.mkdtemp()
    ids1 = [f_txid, wc.dsha(unrelated)]
    ids2 = [wc.dsha(spending)]
    mod_txid = b"\xab" * 32
    ids2 = [wc.dsha(spending), mod_txid]
    with open(os.path.join(d, "mblk00000.dat"), "wb") as fh:
        fh.write(record(header_for(ids1),
                        [(FLAG_WHOLE, funding), (FLAG_WHOLE, unrelated)]))
        fh.write(record(header_for(ids2),
                        [(FLAG_WHOLE, spending),
                         (FLAG_MODIFIED, (mod_txid, tx([(f_txid, 1)],
                                                       [(10, spk)])))]))

    ix = build_index(d, 500000, {sh: "m/0/0"})
    check("both blocks indexed", len(ix.headers) == 2)
    check("tip height", ix.tip == 500001)
    check("history has funding, spend and the modified tx",
          len(ix.history[sh]) == 3)
    check("funding recorded at its height",
          ix.history[sh][0] == (500000, f_txid[::-1].hex()))
    check("spent output left the utxo set",
          (f_txid, 0) not in ix.utxos[sh])
    check("balance is the modified tx's output only",
          ix.balance(sh) == 10)
    check("unrelated transaction not indexed",
          wc.dsha(unrelated)[::-1].hex() not in ix.txs)
    check("txids retained for watched blocks only",
          set(ix.block_txids) == {500000, 500001})
    check("status is stable", ix.status(sh) == ix.status(sh))
    check("status is None for an untouched scripthash",
          Index(0).status("deadbeef") is None)

    m = Methods(ix, d, partial=True)

    r = dispatch(m, {"id": 1, "method": "server.version",
                     "params": ["Electrum", "1.4"]})
    check("server.version answers", r["result"][1] == PROTOCOL_MAX)

    r = dispatch(m, {"id": 2, "method": "blockchain.headers.subscribe",
                     "params": []})
    check("headers.subscribe reports the tip",
          r["result"]["height"] == 500001)
    check("headers.subscribe returns 80 bytes",
          len(bytes.fromhex(r["result"]["hex"])) == 80)

    r = dispatch(m, {"id": 3, "method": "blockchain.scripthash.get_balance",
                     "params": [sh]})
    check("get_balance matches the index",
          r["result"] == {"confirmed": 10, "unconfirmed": 0})

    r = dispatch(m, {"id": 4, "method": "blockchain.scripthash.get_history",
                     "params": [sh]})
    check("get_history is in height order",
          [e["height"] for e in r["result"]] == [500000, 500001, 500001])

    r = dispatch(m, {"id": 5, "method": "blockchain.scripthash.listunspent",
                     "params": [sh]})
    check("listunspent has one entry", len(r["result"]) == 1)
    check("listunspent value", r["result"][0]["value"] == 10)

    # THE critical behaviour: unknown must not look like empty.
    r = dispatch(m, {"id": 6, "method": "blockchain.scripthash.get_balance",
                     "params": ["00" * 32]})
    check("unknown scripthash is an error, not a zero balance",
          "error" in r)
    check("the error says it is unknown rather than empty",
          "not" in r["error"]["message"] and "empty" in r["error"]["message"])
    r = dispatch(m, {"id": 7, "method": "blockchain.scripthash.get_history",
                     "params": ["00" * 32]})
    check("unknown scripthash history is an error too", "error" in r)

    r = dispatch(m, {"id": 8, "method": "blockchain.transaction.get",
                     "params": [f_txid[::-1].hex()]})
    check("whole transaction served as raw hex",
          r["result"] == funding.hex())

    r = dispatch(m, {"id": 9, "method": "blockchain.transaction.get",
                     "params": [mod_txid[::-1].hex()]})
    check("modified transaction is refused rather than mis-served",
          "error" in r)
    check("refusal explains the txid would not match",
          "hash" in r["error"]["message"])

    r = dispatch(m, {"id": 10, "method": "blockchain.transaction.get_merkle",
                     "params": [f_txid[::-1].hex(), 500000]})
    check("merkle proof returned", "result" in r)
    check("merkle position is correct", r["result"]["pos"] == 0)
    check("merkle block height is correct",
          r["result"]["block_height"] == 500000)
    # And the proof must actually fold to the root in the header.
    branch = [bytes.fromhex(x)[::-1] for x in r["result"]["merkle"]]
    cur, idx = f_txid, 0
    for sib in branch:
        cur = wc.dsha(cur + sib) if idx % 2 == 0 else wc.dsha(sib + cur)
        idx >>= 1
    check("merkle branch folds to the root in the header",
          cur == ix.header_at(500000)[36:68])

    # A modified transaction still gets a usable proof -- that is the point.
    r = dispatch(m, {"id": 11, "method": "blockchain.transaction.get_merkle",
                     "params": [mod_txid[::-1].hex(), 500001]})
    check("modified transaction still gets a merkle proof", "result" in r)

    r = dispatch(m, {"id": 12, "method": "blockchain.transaction.broadcast",
                     "params": ["00"]})
    check("broadcast refused", "error" in r)
    check("broadcast refusal explains why",
          "mempool" in r["error"]["message"])

    r = dispatch(m, {"id": 13, "method": "blockchain.estimatefee",
                     "params": [6]})
    check("estimatefee admits it does not know", r["result"] == -1)

    r = dispatch(m, {"id": 14, "method": "blockchain.block.header",
                     "params": [999999]})
    check("header outside the store is an error", "error" in r)

    r = dispatch(m, {"id": 15, "method": "blockchain.block.headers",
                     "params": [500000, 10]})
    check("block.headers returns what exists", r["result"]["count"] == 2)

    r = dispatch(m, {"id": 16, "method": "nonsense.method", "params": []})
    check("unknown method is a protocol error",
          r["error"]["code"] == -32601)

    r = dispatch(m, {"id": 17, "method": "blockchain.scripthash.get_balance",
                     "params": []})
    check("missing params is an error, not a crash", "error" in r)

    # -- Sparrow-specific paths
    r = dispatch(m, {"id": 18, "method": "server.features", "params": []})
    check("server.features reports the mainnet genesis hash",
          r["result"]["genesis_hash"] == GENESIS_HASH)
    check("server.features advertises the start height as pruning",
          r["result"]["pruning"] == 500000)

    r = dispatch(m, {"id": 19, "method": "blockchain.transaction.get",
                     "params": [f_txid[::-1].hex(), True]})
    check("verbose transaction.get declines rather than inventing a shape",
          "error" in r)

    r = dispatch(m, {"id": 20, "method": "blockchain.transaction.get",
                     "params": ["ee" * 32]})
    check("unknown txid explains the server indexes one wallet",
          "error" in r and "whole chain" in r["error"]["message"])

    # A partial store must refuse to build a checkpoint proof rather than
    # root one at its own first block and call it genesis.
    r = dispatch(m, {"id": 21, "method": "blockchain.block.header",
                     "params": [500000, 500001]})
    check("partial store refuses a checkpoint proof", "error" in r)
    check("checkpoint refusal names the start height",
          "500000" in r["error"]["message"])

    # On a genesis-rooted store the proof must be real: fold it and check.
    full = build_index(d, 0, {sh: "m/0/0"})
    mf = Methods(full, d, partial=False)
    r = dispatch(mf, {"id": 22, "method": "blockchain.block.header",
                      "params": [0, 1]})
    check("full store returns a checkpoint proof", "result" in r)
    leaf = wc.dsha(full.header_at(0))
    cur, idx = leaf, 0
    for x in r["result"]["branch"]:
        sib = bytes.fromhex(x)[::-1]
        cur = wc.dsha(cur + sib) if idx % 2 == 0 else wc.dsha(sib + cur)
        idx >>= 1
    check("checkpoint branch folds to the advertised root",
          cur[::-1].hex() == r["result"]["root"])
    check("checkpoint header is the one asked for",
          r["result"]["header"] == full.header_at(0).hex())

    r = dispatch(mf, {"id": 23, "method": "blockchain.block.headers",
                      "params": [0, 2, 1]})
    check("block.headers carries a root when cp_height is given",
          "root" in r["result"])

    r = dispatch(mf, {"id": 24, "method": "blockchain.block.header",
                      "params": [0, 99]})
    check("cp_height beyond the tip is an error", "error" in r)

    # -- the service layer the dashboard drives
    import tempfile as _tf
    dd = _tf.mkdtemp()

    svc = WalletService(d, 500000, dd, host="127.0.0.1", port=0)
    st = svc.status()
    check("service starts idle", st["state"] == STATE_IDLE)
    check("idle service reports no wallet", st["xpub"] is None)
    check("service knows it is partial", st["partial"] is True)

    ok, msg = svc.configure("", 100)
    check("empty xpub refused", not ok)
    ok, msg = svc.configure("xpub-nonsense", 100)
    check("malformed xpub refused with a reason", not ok and msg)
    check("a refused xpub is not saved",
          not os.path.exists(svc.config_path))

    # A real key, built here rather than pasted, so the test owns no secret.
    import hmac as _h2
    master_chain = bytes(range(32))
    master_pub = ser_point(point_mul(0x1234ABCD))
    ver = struct.pack(">I", 0x04B24746)                     # zpub
    payload = (ver + b"\x00" + b"\x00" * 4 + b"\x00" * 4
               + master_chain + master_pub)
    zpub = b58encode_check(payload)

    ok, msg = svc.configure(zpub, 0)
    check("gap limit of zero refused", not ok)
    ok, msg = svc.configure(zpub, 5)
    check("valid xpub accepted", ok)
    check("acceptance warns that indexing takes time",
          "hours" in msg)
    svc._thread.join(timeout=30)
    st = svc.status()
    check("service reaches ready", st["state"] == STATE_READY)
    check("ready service reports both chains derived",
          st["addresses"] == 10)
    check("ready service reports the tip", st["tip"] == 500001)
    check("ready service counted the blocks", st["blocks"] == 2)
    check("wallet persisted to disk", os.path.exists(svc.config_path))

    svc2 = WalletService(d, 500000, dd, host="127.0.0.1", port=0)
    check("a restart restores the configured wallet", svc2.load())
    check("restored gap limit survives", svc2.gap == 5)
    check("restored xpub survives", svc2.xpub == zpub)

    # The wallet view, against the index built from the synthetic store
    # above. The service's own key derives different addresses, so it has no
    # history to show -- correctly, but uselessly for this.
    vsvc = WalletService(d, 500000, dd, host="127.0.0.1", port=0)
    vsvc._index = ix
    v = vsvc.view()
    check("view reports a balance", v["balance"] == ix.balance(sh))
    check("view lists each transaction once",
          len(v["transactions"]) == len({r["txid"] for r in
                                         v["transactions"]}))
    check("view is newest first",
          [r["height"] for r in v["transactions"]] ==
          sorted((r["height"] for r in v["transactions"]), reverse=True))
    check("view carries block times",
          all(r["time"] is not None for r in v["transactions"]))
    check("view flags the modified transaction",
          v["modified_count"] == 1)
    # Amounts must net out: a receive is positive, the spend of it negative.
    amounts = sorted(r["amount"] for r in v["transactions"])
    check("a receive is positive", max(amounts) > 0)
    check("a spend is negative", min(amounts) < 0)
    check("the deltas sum to the balance",
          sum(r["amount"] for r in v["transactions"]) == v["balance"])
    check("view lists only addresses that were used",
          all(a["txs"] or a["balance"] for a in v["addresses"]))
    check("view honours its limit",
          len(vsvc.view(limit=1)["transactions"]) == 1)
    check("but still reports the true total",
          vsvc.view(limit=1)["total_transactions"] == 3)
    check("view is None before an index exists",
          WalletService(d, 0, dd).view() is None)

    # Progress reporting. The percentage is what the dashboard's bar is
    # driven by, so a wrong denominator is a bar that lies for hours.
    import tempfile as _tf3
    sd = _tf3.mkdtemp()
    check("no derived.json means no expected total",
          store_expected_blocks(sd) is None)
    with open(os.path.join(sd, "derived.json"), "w") as fh:
        json.dump({"start_height": 770000, "end_height": 972000}, fh)
    check("expected total is inclusive of both ends",
          store_expected_blocks(sd) == 202001)
    with open(os.path.join(sd, "derived.json"), "w") as fh:
        json.dump({"start_height": 10, "end_height": 5}, fh)
    check("a backwards range is refused rather than negative",
          store_expected_blocks(sd) is None)
    with open(os.path.join(sd, "derived.json"), "w") as fh:
        fh.write("{ not json")
    check("corrupt derived.json does not raise",
          store_expected_blocks(sd) is None)

    psvc = WalletService(d, 500000, dd, host="127.0.0.1", port=0)
    psvc.expected = 1000
    check("idle progress is zero", psvc.status()["percent"] == 0.0)
    psvc._state = STATE_INDEXING
    psvc._done, psvc._started = 250, time.time() - 10
    check("progress is a percentage of the expected total",
          abs(psvc.status()["percent"] - 25.0) < 0.01)
    check("no eta before there is a sample worth using",
          "eta" not in psvc.status())
    psvc._started = time.time() - 100
    check("an eta appears once the sample is long enough",
          psvc.status()["eta"] > 0)
    psvc._done = 1000
    check("the bar never reaches 100 while still indexing",
          psvc.status()["percent"] < 100.0)
    psvc._state = STATE_READY
    check("ready is 100", psvc.status()["percent"] == 100.0)

    svc.forget()
    check("forget clears the state", svc.status()["state"] == STATE_IDLE)
    check("forget removes the file", not os.path.exists(svc.config_path))
    check("a forgotten wallet does not reload",
          not WalletService(d, 500000, dd).load())

    broken = WalletService(os.path.join(dd, "nowhere"), 0, dd,
                           host="127.0.0.1", port=0)
    ok, _m = broken.configure(zpub, 2)
    check("configure accepts before discovering a bad store", ok)
    broken._thread.join(timeout=30)
    check("a missing store surfaces as an error state",
          broken.status()["state"] == STATE_ERROR)
    check("the error says what went wrong", broken.status()["error"])

    b = m.server_banner()
    check("banner warns about partial history", "PARTIAL HISTORY" in b)
    check("banner warns about the mempool", "no mempool" in b)
    b2 = Methods(ix, d, partial=False).server_banner()
    check("banner omits the partial warning on a full store",
          "PARTIAL HISTORY" not in b2)

    print("")
    print("ok" if bad[0] == 0 else "FAILURES")
    return bad[0]


# -------------------------------------------------------------------- main


def read_watch_file(path):
    out = {}
    with open(path) as f:
        for line in f:
            line = line.split("#")[0].strip()
            if not line:
                continue
            spk = wc.address_to_script(line)
            if spk is None:
                sys.exit("cannot parse address: %s" % line)
            out[wc.scripthash(spk)] = line
    return out


def store_expected_blocks(store):
    """
    How many blocks a full pass will cover, from derived.json.

    Needed only so the dashboard can show a percentage. Without it the page
    can show a rising block count and no sense of how far along it is, which
    on a job measured in hours is the difference between "working" and
    "hung". Returns None when the store did not record its range, and the
    page then falls back to the count alone rather than inventing a total.
    """
    p = os.path.join(store, "derived.json")
    try:
        with open(p) as f:
            d = json.load(f)
    except (OSError, ValueError):
        return None
    s, e = d.get("start_height"), d.get("end_height")
    if isinstance(s, int) and isinstance(e, int) and e >= s:
        return e - s + 1
    return None


def store_base_height(store):
    """Read the start height the derive recorded, if it left one."""
    for name in ("derived.json", "state.json"):
        p = os.path.join(store, name)
        if os.path.exists(p):
            try:
                with open(p) as f:
                    d = json.load(f)
                for k in ("start", "start_height", "base_height"):
                    if isinstance(d.get(k), int):
                        return d[k]
            except (ValueError, OSError):
                pass
    return None


def main():
    ap = argparse.ArgumentParser(
        description="Serve the Electrum protocol from a monetary store.")
    ap.add_argument("--store")
    ap.add_argument("--xpub", action="append", default=[],
                    help="extended PUBLIC key (xpub/ypub/zpub); repeatable")
    ap.add_argument("--gap", type=int, default=100,
                    help="addresses to derive per chain (default 100)")
    ap.add_argument("--watch", help="file of addresses, one per line")
    ap.add_argument("--start-height", type=int,
                    help="height of the store's first record")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=50001)
    ap.add_argument("--accept-partial-history", action="store_true")
    ap.add_argument("--progress", type=int, default=20000)
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()

    if a.selftest:
        return _selftest()
    if not a.store:
        return ap.error("--store is required (or --selftest)")
    if not a.xpub and not a.watch:
        return ap.error("need --xpub or --watch: this server indexes one "
                        "wallet, so it has to be told which")

    base = a.start_height
    if base is None:
        base = store_base_height(a.store)
    if base is None:
        sys.exit("cannot tell what height this store starts at. Pass "
                 "--start-height. Guessing would produce a wallet history "
                 "with every transaction at the wrong date.")

    if base > 0 and not a.accept_partial_history:
        sys.exit(
            "This store starts at height %d, not at genesis.\n"
            "\n"
            "A wallet served from it will not see coins received earlier,\n"
            "and will show a balance that is WRONG rather than obviously\n"
            "incomplete. If that is understood and intended, pass\n"
            "    --accept-partial-history\n" % base)

    targets = {}
    for x in a.xpub:
        try:
            got = derive_scripts(x, gap=a.gap)
        except ValueError as e:
            sys.exit("xpub rejected: %s" % e)
        print("derived %d scripts from %s...%s"
              % (len(got), x[:12], x[-6:]))
        targets.update(got)
    if a.watch:
        got = read_watch_file(a.watch)
        print("read %d addresses from %s" % (len(got), a.watch))
        targets.update(got)

    print("indexing %d scripthashes over the store..." % len(targets))
    t0 = time.time()
    try:
        ix = build_index(a.store, base, targets, progress=a.progress)
    except ValueError as e:
        sys.exit(str(e))
    print("indexed %d blocks (%d..%d) in %.0fs"
          % (len(ix.headers), ix.base_height, ix.tip, time.time() - t0))
    touched = sum(1 for v in ix.history.values() if v)
    print("  %d of %d scripthashes have history" % (touched, len(targets)))
    print("  total confirmed: %d sat"
          % sum(ix.balance(s) for s in ix.history))

    methods = Methods(ix, a.store, partial=base > 0)
    srv = Server((a.host, a.port), Handler)
    srv.methods = methods
    print("")
    print("listening on %s:%d" % (a.host, a.port))
    print("In Electrum: Tools -> Network -> Server -> %s:%d:t"
          % (a.host, a.port))
    print("Ctrl-C to stop.")
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nstopping")
        srv.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
