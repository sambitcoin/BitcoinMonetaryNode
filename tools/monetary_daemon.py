#!/usr/bin/env python3
"""
monetary_daemon.py — keep a monetary store current with the chain.

Follows a Bitcoin Knots or Core node, strips each new block once it is buried,
appends it to the store, and extends the commitment C. This is the piece that
turns a set of measurement tools into something a node operator runs.

ARCHITECTURE: the daemon never validates anything. Knots does that, completely,
exactly as it does today. The daemon reads blocks the node has already accepted
and decides only what to keep. No script interpreter, no consensus code, no way
for a classifier bug to become a chain split.

STRIP AT DEPTH, NOT AT THE TIP

Blocks are held unstripped until they are `--depth` confirmations deep. This is
not caution for its own sake — it buys three things:

  Reorg safety, for free. A reorg shallower than the depth never touches the
  store, so there is no rollback path to get wrong. Deeper reorgs are detected
  and the daemon stops rather than guessing.

  Commit-output removal becomes possible. An inscription's commit sits in an
  earlier block than the reveal that identifies it. Stripping at the tip cannot
  know; stripping at depth can look forward across the buffer. (Measured at
  4.97 GB era-wide; not yet implemented here — see NEXT below.)

  A stable C. The commitment chains over body digests, so it can only be
  extended over blocks that will not change.

STATE

`state.json` beside the store holds the last stripped height and hash, the
running C, and the format version. The store itself is the source of truth: on
start the daemon verifies the state matches the store's actual tail and refuses
to run if they disagree, rather than silently appending to a store it does not
understand.

NEXT (not implemented, stated so nobody assumes otherwise)

  - Commit-output removal. The depth buffer makes it possible; the stripping
    logic in monetary_store.py does not do it yet. Doing so changes C, so it
    needs a format version bump rather than a quiet edit.
  - Serving IBD from the daemon process. Today `monetary_ibd.py --serve` runs
    separately against the same store.

Usage:
    python3 monetary_daemon.py --test-rpc --rpc-port 9332 --rpc-user x \\
        --rpc-password y

    python3 monetary_daemon.py --store ~/mstore --start-height 962293 \\
        --rpc-port 9332 --rpc-user x --rpc-password y --depth 6

    python3 monetary_daemon.py --status --store ~/mstore

Standard library only, plus monetary_store.py in the same directory.
BSD-2-Clause.
"""

import argparse
import base64
import glob
import hashlib
import json
import os
import struct
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from monetary_store import strip_block, merkle_root
except ImportError:
    sys.exit("monetary_store.py must be in the same directory")

STATE_VERSION = 1
STORE_MAGIC = b"MBLK"


def dsha(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


# ---------------------------------------------------------------- rpc


class RPC:
    """Minimal Bitcoin JSON-RPC client."""

    def __init__(self, host="127.0.0.1", port=8332, user=None, password=None,
                 cookie=None, timeout=120):
        self.url = f"http://{host}:{port}"
        self.timeout = timeout
        if cookie:
            with open(cookie) as f:
                user, _, password = f.read().strip().partition(":")
        if user is None:
            raise ValueError("need --rpc-user/--rpc-password or --rpc-cookie")
        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        self.auth = f"Basic {token}"
        self.n = 0

    def call(self, method, *params):
        self.n += 1
        body = json.dumps({"jsonrpc": "1.0", "id": self.n,
                           "method": method, "params": list(params)}).encode()
        req = urllib.request.Request(self.url, data=body, headers={
            "Content-Type": "application/json", "Authorization": self.auth})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                out = json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            detail = e.read().decode()[:200]
            raise IOError(f"RPC {method} HTTP {e.code}: {detail}")
        except urllib.error.URLError as e:
            raise IOError(f"RPC {method} unreachable: {e.reason}")
        if out.get("error"):
            raise IOError(f"RPC {method}: {out['error']}")
        return out["result"]

    def block_count(self):
        return self.call("getblockcount")

    def block_hash(self, height):
        return self.call("getblockhash", height)

    def raw_block(self, blockhash):
        return bytes.fromhex(self.call("getblock", blockhash, 0))


# ---------------------------------------------------------------- store tail


def store_files(path):
    return sorted(glob.glob(os.path.join(path, "mblk*.dat")))


def store_tail(path):
    """
    Return (record_count, last_block_hash, last_file, size) by walking the
    store's final file. The store is the source of truth for where we are.
    """
    files = store_files(path)
    if not files:
        return 0, None, None, 0
    count = 0
    last_hash = None
    for f in files:
        size = os.path.getsize(f)
        with open(f, "rb") as fh:
            pos = 0
            while pos < size:
                fh.seek(pos)
                # magic 4 | version 2 | length 4 | digest 32 | block hash 32
                head = fh.read(74)
                if len(head) < 74 or head[:4] != STORE_MAGIC:
                    break
                length = struct.unpack_from("<I", head, 6)[0]
                last_hash = head[42:74]
                count += 1
                pos += 10 + length
    return count, last_hash, files[-1], os.path.getsize(files[-1])


# ---------------------------------------------------------------- state


def state_path(store):
    return os.path.join(store, "state.json")


def load_state(store):
    p = state_path(store)
    if not os.path.exists(p):
        return None
    with open(p) as f:
        st = json.load(f)
    if st.get("version") != STATE_VERSION:
        sys.exit(f"state.json version {st.get('version')} not understood")
    return st


def save_state(store, st):
    st["version"] = STATE_VERSION
    tmp = state_path(store) + ".tmp"
    with open(tmp, "w") as f:
        json.dump(st, f, indent=1)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, state_path(store))


# ---------------------------------------------------------------- daemon


class Daemon:
    def __init__(self, rpc, store, depth, op_return_limit, scriptsig_limit,
                 file_size, poll):
        self.rpc = rpc
        self.store = store
        self.depth = depth
        self.op_return_limit = op_return_limit
        self.scriptsig_limit = scriptsig_limit
        self.file_size = file_size
        self.poll = poll
        os.makedirs(store, exist_ok=True)

        self.state = load_state(store)
        count, tail_hash, _f, _s = store_tail(store)

        if self.state is None:
            if count:
                sys.exit(
                    f"{store} holds {count:,} records but has no state.json.\n"
                    "Refusing to append to a store whose position is unknown. "
                    "Run with --adopt --start-height N to take ownership.")
            self.state = {"height": None, "hash": None,
                          "commitment": "00" * 32, "records": 0}
        else:
            # The store is authoritative. If state.json disagrees with what is
            # actually on disk, something wrote to one and not the other.
            if count != self.state["records"]:
                sys.exit(
                    f"state.json says {self.state['records']:,} records, store "
                    f"holds {count:,}. Refusing to continue: fix or re-adopt.")
            if tail_hash and self.state["hash"] and \
                    tail_hash.hex() != self.state["hash"]:
                sys.exit("state.json tip does not match the store's last "
                         "record. Refusing to continue.")

        self.stats = {"stripped": 0, "bytes_in": 0, "bytes_out": 0,
                      "spam": 0, "started": time.time()}

    # ---------------------------------------------------------- writing

    def _open_target(self):
        files = store_files(self.store)
        if files and os.path.getsize(files[-1]) < self.file_size:
            return files[-1]
        n = len(files)
        return os.path.join(self.store, f"mblk{n:05d}.dat")

    def append(self, record):
        path = self._open_target()
        with open(path, "ab") as f:
            f.write(record)
            f.flush()
            os.fsync(f.fileno())

    # ---------------------------------------------------------- stripping

    def process(self, height, blockhash_hex):
        raw = self.rpc.raw_block(blockhash_hex)
        header = raw[:80]
        block_hash = dsha(header)

        # The node gave us this block; check it is the one we asked for and
        # that it extends what we already have. Cheap, and catches a reorg
        # that happened between our query and our fetch.
        if block_hash[::-1].hex() != blockhash_hex:
            raise IOError(f"node returned a different block at {height}")
        if self.state["hash"] and header[4:36][::-1].hex() != self.state["hash"]:
            return "reorg"

        record, st = strip_block(raw, height, self.op_return_limit,
                                 self.scriptsig_limit)

        if merkle_root(st["txids"]) != st["merkle_root"]:
            raise IOError(f"merkle mismatch at height {height} — refusing")

        self.append(record)

        body = record[42:]
        self.state["commitment"] = dsha(
            bytes.fromhex(self.state["commitment"]) + dsha(header) + dsha(body)
        ).hex()
        self.state["height"] = height
        self.state["hash"] = block_hash[::-1].hex()
        self.state["records"] += 1
        save_state(self.store, self.state)

        self.stats["stripped"] += 1
        self.stats["bytes_in"] += st["original"]
        self.stats["bytes_out"] += st["stored"]
        self.stats["spam"] += (st["envelope"] + st["op_return"]
                               + st["multisig"] + st["scriptsig"])
        return "ok"

    # ---------------------------------------------------------- main loop

    def catch_up(self, start_height):
        tip = self.rpc.block_count()
        target = tip - self.depth
        nxt = (self.state["height"] + 1) if self.state["height"] is not None \
            else start_height
        if nxt > target:
            return 0, tip
        done = 0
        for h in range(nxt, target + 1):
            bh = self.rpc.block_hash(h)
            result = self.process(h, bh)
            if result == "reorg":
                raise SystemExit(
                    f"Reorg deeper than --depth {self.depth} detected at "
                    f"height {h}. The store holds a block the node no longer "
                    "has. Stopping rather than guessing — this needs a "
                    "rollback path that does not exist yet.")
            done += 1
            if done % 100 == 0:
                print(f"  {h:,}  {self.stats['bytes_out']/1e9:.2f} GB stored",
                      flush=True)
        return done, tip

    def run(self, start_height, once=False):
        print(f"store    {self.store}")
        print(f"depth    {self.depth} confirmations")
        if self.state["height"] is not None:
            print(f"resuming at height {self.state['height']:,}")
        else:
            print(f"starting at height {start_height:,}")
        print(f"C        {self.state['commitment']}")
        print()

        while True:
            try:
                done, tip = self.catch_up(start_height)
            except IOError as e:
                print(f"  {e}; retrying in {self.poll}s", file=sys.stderr,
                      flush=True)
                time.sleep(self.poll)
                continue

            if done:
                saved = self.stats["bytes_in"] - self.stats["bytes_out"]
                pct = saved / self.stats["bytes_in"] * 100 \
                    if self.stats["bytes_in"] else 0
                print(f"{time.strftime('%H:%M:%S')}  +{done} blocks  "
                      f"height {self.state['height']:,}  tip {tip:,}  "
                      f"saved {saved/1e6:.1f} MB ({pct:.2f}%)  "
                      f"C {self.state['commitment'][:16]}...", flush=True)
            if once:
                return
            time.sleep(self.poll)


# ---------------------------------------------------------------- selftest


def selftest():
    ok = []

    def check(name, cond, detail=""):
        ok.append(cond)
        print(f"  [{'ok  ' if cond else 'FAIL'}] {name}"
              + (f"  — {detail}" if detail else ""))

    import tempfile

    print("state persistence")
    d = tempfile.mkdtemp()
    save_state(d, {"height": 5, "hash": "aa" * 32, "commitment": "bb" * 32,
                   "records": 5})
    st = load_state(d)
    check("round-trips", st["height"] == 5 and st["records"] == 5)
    check("version stamped", st["version"] == STATE_VERSION)

    print("\nstore tail walking")
    def rec(payload):
        body = dsha(b"hdr") + payload
        return (STORE_MAGIC + struct.pack("<H", 1)
                + struct.pack("<I", len(body) + 32) + dsha(body) + body)
    d2 = tempfile.mkdtemp()
    r1, r2 = rec(b"one" * 40), rec(b"two" * 60)
    open(os.path.join(d2, "mblk00000.dat"), "wb").write(r1 + r2)
    count, last, _f, _s = store_tail(d2)
    check("counts records", count == 2, f"{count}")
    check("reads last block hash", last == dsha(b"hdr"))

    d3 = tempfile.mkdtemp()
    open(os.path.join(d3, "mblk00000.dat"), "wb").write(r1)
    open(os.path.join(d3, "mblk00001.dat"), "wb").write(r2 + r1)
    count3, _l, _f, _s = store_tail(d3)
    check("spans multiple files", count3 == 3, f"{count3}")

    count0, last0, _f, _s = store_tail(tempfile.mkdtemp())
    check("empty store is zero, not an error",
          count0 == 0 and last0 is None)

    print("\ncommitment chaining")
    c = bytes(32)
    for i in range(3):
        c = dsha(c + dsha(bytes([i])) + dsha(bytes([i + 10])))
    c2 = bytes(32)
    for i in range(3):
        c2 = dsha(c2 + dsha(bytes([i])) + dsha(bytes([i + 10])))
    check("deterministic", c == c2)
    c3 = bytes(32)
    for i in (0, 2, 1):
        c3 = dsha(c3 + dsha(bytes([i])) + dsha(bytes([i + 10])))
    check("order sensitive", c3 != c)

    print("\nrefusal conditions")
    d4 = tempfile.mkdtemp()
    open(os.path.join(d4, "mblk00000.dat"), "wb").write(r1)
    # a store with records but no state must be refused, not adopted silently
    has_records = store_tail(d4)[0] > 0 and load_state(d4) is None
    check("records without state is detectable", has_records)
    save_state(d4, {"height": 1, "hash": "cc" * 32,
                    "commitment": "00" * 32, "records": 99})
    mismatch = store_tail(d4)[0] != load_state(d4)["records"]
    check("record count mismatch is detectable", mismatch)

    print()
    print(f"{sum(ok)}/{len(ok)} passed")
    return 0 if all(ok) else 1


# ---------------------------------------------------------------- main


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--store")
    ap.add_argument("--start-height", type=int)
    ap.add_argument("--depth", type=int, default=6,
                    help="confirmations before a block is stripped")
    ap.add_argument("--rpc-host", default="127.0.0.1")
    ap.add_argument("--rpc-port", type=int, default=8332)
    ap.add_argument("--rpc-user")
    ap.add_argument("--rpc-password")
    ap.add_argument("--rpc-cookie")
    ap.add_argument("--poll", type=int, default=30, help="seconds between polls")
    ap.add_argument("--op-return-limit", type=int, default=83)
    ap.add_argument("--scriptsig-limit", type=int, default=1650)
    ap.add_argument("--file-size", type=int, default=128 * 1024 * 1024)
    ap.add_argument("--once", action="store_true",
                    help="catch up and exit rather than following")
    ap.add_argument("--adopt", action="store_true",
                    help="take ownership of an existing store with no state")
    ap.add_argument("--test-rpc", action="store_true")
    ap.add_argument("--status", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        sys.exit(selftest())

    if args.status:
        if not args.store:
            sys.exit("--status needs --store")
        st = load_state(args.store)
        count, last, _f, _s = store_tail(args.store)
        print(f"store          {args.store}")
        print(f"records on disk{count:>12,}")
        if st:
            print(f"state height   {st['height']:>12,}")
            print(f"state records  {st['records']:>12,}")
            print(f"C              {st['commitment']}")
            print(f"consistent     "
                  f"{'yes' if count == st['records'] else 'NO — do not run'}")
        else:
            print("state          none (store not adopted)")
        return

    if args.test_rpc:
        rpc = RPC(args.rpc_host, args.rpc_port, args.rpc_user,
                  args.rpc_password, args.rpc_cookie)
        tip = rpc.block_count()
        bh = rpc.block_hash(tip)
        raw = rpc.raw_block(bh)
        print(f"connected to {args.rpc_host}:{args.rpc_port}")
        print(f"tip height   {tip:,}")
        print(f"tip hash     {bh}")
        print(f"block size   {len(raw):,} bytes")
        print(f"header check {'ok' if dsha(raw[:80])[::-1].hex() == bh else 'FAILED'}")
        return

    if not args.store:
        sys.exit("need --store")

    if args.adopt:
        count, last, _f, _s = store_tail(args.store)
        if args.start_height is None:
            sys.exit("--adopt needs --start-height (height of the FIRST record)")
        if not count:
            sys.exit("nothing to adopt: store is empty")
        last_height = args.start_height + count - 1
        print(f"adopting {count:,} records, first at {args.start_height:,}, "
              f"last at {last_height:,}")
        print("NOTE: C is set to zero. It does not describe the existing")
        print("records — recompute with monetary_commit.py if you need it.")
        save_state(args.store, {"height": last_height,
                                "hash": last.hex() if last else None,
                                "commitment": "00" * 32, "records": count})
        print("adopted. state.json written.")
        return

    rpc = RPC(args.rpc_host, args.rpc_port, args.rpc_user, args.rpc_password,
              args.rpc_cookie)
    d = Daemon(rpc, args.store, args.depth, args.op_return_limit,
               args.scriptsig_limit, args.file_size, args.poll)
    if d.state["height"] is None and args.start_height is None:
        sys.exit("new store needs --start-height")
    try:
        d.run(args.start_height, args.once)
    except KeyboardInterrupt:
        print("\nstopped. state saved.")


if __name__ == "__main__":
    main()
