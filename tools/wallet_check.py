#!/usr/bin/env python3
"""
wallet_check.py — does a monetary store still answer wallet questions correctly?

Spam removal that breaks balances or transaction history is a storage
experiment, not a node. This computes balance and history for a set of
addresses directly from a monetary store, then asks an Electrum server the same
questions and diffs the answers.

The reference can be your own electrs/ElectrumX, or a public server. A public
server is arguably the stronger reference: someone else's node, indexing
complete block data, sharing no code or configuration with this project.

PRIVACY. Querying a public server reveals which scripthashes you are interested
in. For addresses sampled at random from an old block that means little. Never
point this at your own addresses.

WHAT TO TEST. Agreement on ordinary payments proves little. A good sample is
hostile: addresses that funded inscriptions, addresses that received
stamp-style bare multisig outputs, and addresses touched by fully stripped
transactions — those lost their inputs, so the link from a spent output to its
spending transaction is gone, and this is where that should surface.

METHOD. One pass over the store, bounded memory. For each transaction:

  - outputs paying a watched script are recorded and their outpoints watched
  - inputs spending a watched outpoint mark it spent

Chain order guarantees an output is seen before anything spends it, so a single
pass suffices and no UTXO database is needed.

The scan and the comparison are separate steps. Scan once with --json, then
compare as often as you like without re-reading 247 GB.

KNOWN LIMITS, stated up front so a disagreement is not mistaken for a bug:

  - Fully stripped transactions retain only a txid. Their inputs and outputs
    are unavailable, so a spend recorded only there cannot be seen. This is the
    gap being measured.
  - Dropped outputs are recovered from filter entries, so spam outputs paying a
    watched script are still counted.
  - Heights are derived by counting records from --start-height, since the
    store does not record a height per block. Records are written in chain
    order, so this is exact provided the store is contiguous.
  - Balances count only outputs created within the scanned range. An address
    funded before --start-height will differ legitimately. Compare in-range
    history counts, which is what this tool reports.

Usage:
    # scan the store, save the result
    python3 wallet_check.py --store ~/mstore_test --start-height 900000 \\
        --addresses addr.txt --json scan.json

    # compare against a local server
    python3 wallet_check.py --compare scan.json --electrum 127.0.0.1:50001

    # compare against a public server over TLS
    python3 wallet_check.py --compare scan.json \\
        --electrum electrum.blockstream.info:50002 --ssl

    # both at once
    python3 wallet_check.py --store ~/mstore --start-height 767430 \\
        --addresses addr.txt --json scan.json \\
        --electrum electrum.blockstream.info:50002 --ssl

    python3 wallet_check.py --selftest

Standard library only. BSD-2-Clause.
"""

import argparse
import glob
import hashlib
import json
import os
import socket
import struct
import sys
import time

STORE_MAGIC = b"MBLK"
FLAG_WHOLE, FLAG_MODIFIED, FLAG_STRIPPED = 0, 1, 2

PUBLIC_SERVERS = [
    "electrum.blockstream.info:50002",
    "electrum.emzy.de:50002",
    "electrum.bitaroo.net:50002",
]


def sha256(b):
    return hashlib.sha256(b).digest()


def dsha(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def scripthash(spk):
    """Electrum's script hash: SHA256 of the scriptPubKey, byte-reversed."""
    return sha256(spk)[::-1].hex()


# ---------------------------------------------------------------- addresses

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def b58decode_check(s):
    n = 0
    for ch in s:
        i = B58.find(ch)
        if i < 0:
            raise ValueError(f"bad base58 character {ch!r}")
        n = n * 58 + i
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    pad = len(s) - len(s.lstrip("1"))
    raw = b"\x00" * pad + raw
    if len(raw) < 5:
        raise ValueError("too short")
    body, checksum = raw[:-4], raw[-4:]
    if dsha(body)[:4] != checksum:
        raise ValueError("bad base58 checksum")
    return body


def bech32_polymod(values):
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= gen[i] if ((top >> i) & 1) else 0
    return chk


def bech32_hrp_expand(hrp):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def bech32_decode(addr):
    if addr.lower() != addr and addr.upper() != addr:
        raise ValueError("mixed case")
    addr = addr.lower()
    pos = addr.rfind("1")
    if pos < 1 or pos + 7 > len(addr):
        raise ValueError("bad separator")
    hrp, data_part = addr[:pos], addr[pos + 1:]
    data = []
    for c in data_part:
        i = BECH32.find(c)
        if i < 0:
            raise ValueError(f"bad bech32 character {c!r}")
        data.append(i)
    chk = bech32_polymod(bech32_hrp_expand(hrp) + data)
    if chk == 1:
        const = "bech32"
    elif chk == 0x2BC830A3:
        const = "bech32m"
    else:
        raise ValueError("bad bech32 checksum")
    return hrp, data[:-6], const


def convertbits(data, frm, to, pad=True):
    acc = bits = 0
    ret = []
    maxv = (1 << to) - 1
    for value in data:
        acc = (acc << frm) | value
        bits += frm
        while bits >= to:
            bits -= to
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (to - bits)) & maxv)
    elif not pad and (bits >= frm or ((acc << (to - bits)) & maxv)):
        raise ValueError("bad padding")
    return ret


def address_to_script(addr):
    """Return the scriptPubKey for a mainnet address."""
    if addr.lower().startswith("bc1"):
        hrp, data, const = bech32_decode(addr)
        if hrp != "bc":
            raise ValueError(f"not mainnet: {hrp}")
        ver = data[0]
        prog = bytes(convertbits(data[1:], 5, 8, False))
        if ver == 0:
            if const != "bech32":
                raise ValueError("v0 must use bech32")
            if len(prog) not in (20, 32):
                raise ValueError("bad v0 program length")
            return bytes([0x00, len(prog)]) + prog
        if const != "bech32m":
            raise ValueError("v1+ must use bech32m")
        return bytes([0x50 + ver, len(prog)]) + prog

    body = b58decode_check(addr)
    ver, payload = body[0], body[1:]
    if ver == 0x00:                     # P2PKH
        return b"\x76\xa9\x14" + payload + b"\x88\xac"
    if ver == 0x05:                     # P2SH
        return b"\xa9\x14" + payload + b"\x87"
    raise ValueError(f"unsupported address version {ver}")


# ---------------------------------------------------------------- store


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


def parse_tx(body):
    """
    Extract inputs and outputs from a stored transaction body.

    Handles both forms the store writes: whole transactions keep their original
    serialisation and may be SegWit-marked; modified transactions are written in
    legacy form with witness already discarded.
    """
    c = Cursor(body)
    c.take(4)
    segwit = c.peek(2) == b"\x00\x01"
    if segwit:
        c.take(2)

    io_start = c.p
    n_in = c.varint()
    vin = []
    for _ in range(n_in):
        prev_txid = c.take(32)
        prev_vout = c.u32()
        c.take(c.varint())
        c.take(4)
        vin.append((prev_txid, prev_vout))

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
    c.take(4)

    legacy = (body[:4] + body[io_start:io_end] + body[c.p - 4:c.p]) if segwit \
        else body[:c.p]
    return dsha(legacy), vin, vout


def iter_store(path, start_height):
    """
    Yield (height, txs, filters) per block, in chain order.

    txs is a list of (txid, vin, vout, complete). complete is False for fully
    stripped transactions, whose inputs and outputs are unavailable.
    """
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
            c.take(32)                       # block hash
            c.take(80)                       # header
            n_tx = c.varint()

            txs = []
            for _ in range(n_tx):
                flag = c.u8()
                if flag == FLAG_STRIPPED:
                    txs.append((c.take(32), [], [], False))
                elif flag == FLAG_MODIFIED:
                    txid = c.take(32)
                    body = c.take(c.varint())
                    _t, vin, vout = parse_tx(body)
                    txs.append((txid, vin, vout, True))
                elif flag == FLAG_WHOLE:
                    body = c.take(c.varint())
                    txid, vin, vout = parse_tx(body)
                    txs.append((txid, vin, vout, True))
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


def scan(path, start_height, targets, progress=10000):
    """
    One pass over the store, collecting everything touching the target scripts.

    targets maps scripthash -> address label.
    """
    watched = {}          # (txid, vout) -> (scripthash, amount)
    result = {sh: {"address": a, "confirmed": 0, "utxos": 0, "history": {}}
              for sh, a in targets.items()}
    stripped_seen = 0
    blocks = 0
    t0 = time.time()

    for height, txs, filters in iter_store(path, start_height):
        dropped = {}
        for txid, vout_i, amount, _h, spk in filters:
            dropped.setdefault(txid, []).append((vout_i, amount, spk))

        for txid, vin, vout, complete in txs:
            if not complete:
                stripped_seen += 1
                continue

            for prev_txid, prev_vout in vin:
                hit = watched.pop((prev_txid, prev_vout), None)
                if hit:
                    sh, amount = hit
                    result[sh]["confirmed"] -= amount
                    result[sh]["utxos"] -= 1
                    result[sh]["history"][txid[::-1].hex()] = height

            for vout_i, amount, spk in list(vout) + dropped.get(txid, []):
                sh = scripthash(spk)
                if sh in result:
                    watched[(txid, vout_i)] = (sh, amount)
                    result[sh]["confirmed"] += amount
                    result[sh]["utxos"] += 1
                    result[sh]["history"][txid[::-1].hex()] = height

        blocks += 1
        if blocks % progress == 0:
            el = time.time() - t0
            print(f"  {blocks:,} blocks  height {height:,}  {el:.0f}s  "
                  f"watching {len(watched):,} outpoints", flush=True)

    return {
        "store": os.path.abspath(path),
        "start_height": start_height,
        "blocks": blocks,
        "end_height": start_height + blocks - 1,
        "stripped_transactions": stripped_seen,
        "scan_seconds": round(time.time() - t0, 1),
        "addresses": result,
    }


# ---------------------------------------------------------------- electrum


class Electrum:
    """
    Minimal Electrum protocol client.

    Speaks the JSON-RPC that electrs, ElectrumX and Fulcrum all implement, so
    any of them serves as a reference. Public servers use TLS on port 50002.
    """

    def __init__(self, hostport, use_ssl=False, timeout=30):
        host, _, port = hostport.partition(":")
        port = int(port or (50002 if use_ssl else 50001))
        sock = socket.create_connection((host, port), timeout=timeout)
        if use_ssl:
            import ssl as _ssl
            # Public Electrum servers commonly present self-signed
            # certificates. We are reading public chain data and comparing it
            # against a local store, so the certificate chain is not what the
            # result rests on.
            ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        self.sock = sock
        self.fh = sock.makefile("rwb")
        self.n = 0

    def call(self, method, params):
        self.n += 1
        req = json.dumps({"id": self.n, "method": method,
                          "params": params}) + "\n"
        self.fh.write(req.encode())
        self.fh.flush()
        line = self.fh.readline()
        if not line:
            raise IOError("server closed the connection")
        resp = json.loads(line)
        if resp.get("error"):
            raise IOError(f"server error: {resp['error']}")
        return resp["result"]

    def tip(self):
        r = self.call("blockchain.headers.subscribe", [])
        return r.get("height", 0)

    def balance(self, sh):
        return self.call("blockchain.scripthash.get_balance", [sh])

    def history(self, sh):
        return self.call("blockchain.scripthash.get_history", [sh])

    def close(self):
        try:
            self.fh.close()
            self.sock.close()
        except Exception:
            pass


def compare(scanned, hostport, use_ssl):
    start = scanned["start_height"]
    end = scanned["end_height"]

    print(f"connecting to {hostport}{' over TLS' if use_ssl else ''}...")
    el = Electrum(hostport, use_ssl)
    try:
        tip = el.tip()
        print(f"reference tip: {tip:,}")
        if tip < end:
            print(f"WARNING: the reference is only synced to {tip:,} but the "
                  f"store covers up to {end:,}.")
            print("Disagreements above the reference tip would be the "
                  "reference's fault, not the store's.")
        print()

        agree = differ = 0
        for sh, r in scanned["addresses"].items():
            print("=" * 70)
            print(r["address"])
            store_hist = r["history"]
            print(f"  store      balance {r['confirmed']:,} sat   "
                  f"utxos {r['utxos']:,}   history {len(store_hist):,} tx "
                  f"(heights {start:,}-{end:,})")

            try:
                eb = el.balance(sh)
                eh = el.history(sh)
            except Exception as e:
                print(f"  query failed: {e}")
                continue

            in_range = [h for h in eh
                        if start <= h.get("height", 0) <= end]
            print(f"  reference  balance {eb.get('confirmed', 0):,} sat   "
                  f"history {len(eh):,} tx total, {len(in_range):,} in range")

            ref_txids = {h["tx_hash"] for h in in_range}
            missing = ref_txids - set(store_hist)
            extra = set(store_hist) - ref_txids

            if not missing and not extra:
                agree += 1
                print("  MATCH — in-range history identical")
            else:
                differ += 1
                print(f"  DIFFERS — {len(missing)} missing from store, "
                      f"{len(extra)} extra in store")
                for tx in list(missing)[:5]:
                    h = next(x["height"] for x in in_range
                             if x["tx_hash"] == tx)
                    print(f"    missing: {tx}  height {h:,}")
                for tx in list(extra)[:5]:
                    print(f"    extra:   {tx}  height "
                          f"{store_hist[tx]:,}")

        print()
        print("=" * 70)
        print(f"agree {agree}   differ {differ}")
        print()
        if differ == 0 and agree:
            print("The monetary store returned the same transaction history as")
            print("an independent Electrum server reading complete block data,")
            print("for every address tested. Spam removal did not damage what a")
            print("wallet depends on.")
        print()
        print("Lifetime balances are not compared: the store covers one height")
        print("range, so an address funded earlier differs legitimately. The")
        print("in-range history comparison is the meaningful one.")
    finally:
        el.close()


# ---------------------------------------------------------------- selftest


def selftest():
    ok = []

    def check(name, cond, detail=""):
        ok.append(cond)
        print(f"  [{'ok  ' if cond else 'FAIL'}] {name}"
              + (f"  — {detail}" if detail else ""))

    print("address decoding")
    spk = address_to_script("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
    check("P2PKH decodes to the right script shape",
          spk[:3] == b"\x76\xa9\x14" and spk[-2:] == b"\x88\xac"
          and len(spk) == 25)

    spk = address_to_script("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
    check("P2WPKH matches BIP173 vector",
          spk.hex() == "0014751e76e8199196d454941c45d1b3a323f1433bd6")

    spk = address_to_script(
        "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3")
    check("P2WSH decodes to 34 bytes", len(spk) == 34 and spk[0] == 0x00)

    spk = address_to_script(
        "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0")
    check("P2TR uses bech32m and OP_1", spk[0] == 0x51 and len(spk) == 34)

    for bad_addr, why in [
            ("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5", "bad checksum"),
            ("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj1",
             "bech32m enforced")]:
        try:
            address_to_script(bad_addr)
            caught = False
        except ValueError:
            caught = True
        check(f"{why} rejected", caught)

    print("\nscript hashing")
    spk = bytes.fromhex("0014751e76e8199196d454941c45d1b3a323f1433bd6")
    check("scripthash is reversed sha256",
          scripthash(spk) == sha256(spk)[::-1].hex())

    print("\ntransaction parsing")
    tx = (struct.pack("<i", 1) + b"\x01" + b"\xaa" * 32 + struct.pack("<I", 0)
          + b"\x00" + struct.pack("<I", 0xFFFFFFFF)
          + b"\x01" + struct.pack("<Q", 5000) + b"\x02\x51\x20"
          + struct.pack("<I", 0))
    txid, vin, vout = parse_tx(tx)
    check("legacy tx parses",
          len(vin) == 1 and len(vout) == 1 and vout[0][1] == 5000)
    check("txid is double sha of the legacy body", txid == dsha(tx))

    base = (struct.pack("<i", 1) + b"\x01" + b"\xbb" * 32
            + struct.pack("<I", 0) + b"\x00" + struct.pack("<I", 0xFFFFFFFF)
            + b"\x01" + struct.pack("<Q", 9000) + b"\x02\x51\x20")
    legacy = base + struct.pack("<I", 0)
    swit = (struct.pack("<i", 1) + b"\x00\x01" + base[4:]
            + b"\x01\x04" + b"\xcc" * 4 + struct.pack("<I", 0))
    txid2, vin2, vout2 = parse_tx(swit)
    check("segwit tx parses", len(vin2) == 1 and vout2[0][1] == 9000)
    check("segwit txid excludes witness", txid2 == dsha(legacy))

    print()
    print(f"{sum(ok)}/{len(ok)} passed")
    return 0 if all(ok) else 1


# ---------------------------------------------------------------- main


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--store")
    ap.add_argument("--start-height", type=int)
    ap.add_argument("--addresses", help="file with one address per line")
    ap.add_argument("--json", help="write scan results here")
    ap.add_argument("--compare", metavar="JSON",
                    help="compare a saved scan instead of rescanning")
    ap.add_argument("--electrum", help="host:port of an Electrum server")
    ap.add_argument("--ssl", action="store_true",
                    help="use TLS (public servers, usually port 50002)")
    ap.add_argument("--list-servers", action="store_true")
    ap.add_argument("--progress", type=int, default=10000)
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        sys.exit(selftest())

    if args.list_servers:
        print("Public Electrum servers (TLS, use --ssl):")
        for s in PUBLIC_SERVERS:
            print(f"  {s}")
        print()
        print("Querying a public server reveals which scripthashes you are")
        print("interested in. Use sampled addresses, never your own.")
        return

    if args.compare:
        with open(args.compare) as f:
            scanned = json.load(f)
        if not args.electrum:
            sys.exit("--compare needs --electrum")
        compare(scanned, args.electrum, args.ssl)
        return

    if not (args.store and args.start_height is not None and args.addresses):
        sys.exit("need --store, --start-height and --addresses "
                 "(or --compare, --selftest, --list-servers)")

    addrs = []
    with open(args.addresses) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                addrs.append(line)
    if not addrs:
        sys.exit("no addresses in the file")

    targets = {}
    for a in addrs:
        try:
            targets[scripthash(address_to_script(a))] = a
        except ValueError as e:
            print(f"skipping {a}: {e}", file=sys.stderr)
    if not targets:
        sys.exit("no usable addresses")

    print(f"watching {len(targets)} addresses")
    print(f"store      {args.store}")
    print(f"from       height {args.start_height:,}")
    print()

    scanned = scan(args.store, args.start_height, targets, args.progress)

    print()
    print(f"scanned {scanned['blocks']:,} blocks "
          f"({scanned['start_height']:,}-{scanned['end_height']:,}) "
          f"in {scanned['scan_seconds']:.0f}s")
    print(f"fully stripped transactions encountered: "
          f"{scanned['stripped_transactions']:,}")
    print()

    touched = 0
    for _sh, r in scanned["addresses"].items():
        if r["history"]:
            touched += 1
            print(f"  {r['address']}  balance {r['confirmed']:,} sat  "
                  f"{len(r['history'])} tx")
    print()
    print(f"{touched} of {len(targets)} addresses had activity in range")

    if args.json:
        with open(args.json, "w") as f:
            json.dump(scanned, f, indent=1)
        print(f"scan written to {args.json}")

    if args.electrum:
        print()
        compare(scanned, args.electrum, args.ssl)


if __name__ == "__main__":
    main()
