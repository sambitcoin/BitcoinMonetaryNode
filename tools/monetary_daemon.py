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
import fcntl
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

# recent.jsonl — one line per stripped block, for the dashboard feed. Trimmed
# rather than rotated: nothing reads it but the UI, and the store is the real
# record of what happened.
RECENT_MAX_BYTES = 2 * 1024 * 1024
RECENT_KEEP = 2000


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


def clean_commitment(s):
    """Normalise a seed commitment, or None if it is not one.

    Separate from the argument parsing so it can be tested: a bad value here
    would be written into state.json and every published C after it would
    descend from garbage.
    """
    if s is None:
        return None
    s = s.strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    if len(s) != 64:
        return None
    try:
        bytes.fromhex(s)
    except ValueError:
        return None
    return s


def store_tail(path, full=False):
    """
    Return (record_count, last_block_hash, last_file, size) by walking the
    store's final file. The store is the source of truth for where we are.
    """
    files = store_files(path)
    if not files:
        return 0, None, None, 0
    count = 0
    last_hash = None
    # Walking every file means reading the whole store, which on a large one
    # is minutes of IO on every start. Only the final file is needed to
    # confirm the tail; the record count is carried in state.json, and the
    # full walk happens once at --adopt.
    scan = files if full else files[-1:]
    for f in scan:
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
    """The store's recorded position, or None if there is none.

    A corrupt state.json must NOT read as "no state". None means "this store
    has never been written to", which lets the daemon adopt a position — and
    adopting a position for a store that already holds records is how you get
    two writers and a commitment nobody can reproduce.

    So unreadable and absent are different answers, and only one of them is
    None. This used to be a bare json.load, which under systemd's
    Restart=always meant a crash-loop printing a JSONDecodeError traceback
    every thirty seconds. Found by an outside review.
    """
    p = state_path(store)
    if not os.path.exists(p):
        return None
    try:
        with open(p) as f:
            st = json.load(f)
    except ValueError as e:
        sys.exit(f"{p} is not valid JSON: {e}\n\n"
                 "Refusing to treat an unreadable state file as an empty "
                 "store.\nThe store itself is the source of truth for where "
                 "it ends:\n"
                 "    monetary_store.py --verify <store>\n"
                 "then re-establish the position with --adopt.")
    except OSError as e:
        sys.exit(f"cannot read {p}: {e}")
    if not isinstance(st, dict):
        sys.exit(f"{p} does not contain a JSON object")
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
                 file_size, poll, policy=None, adopt_policy=False):
        self.rpc = rpc
        self.store = store
        self.depth = depth
        self.op_return_limit = op_return_limit
        self.scriptsig_limit = scriptsig_limit
        self.file_size = file_size
        self.poll = poll
        os.makedirs(store, exist_ok=True)

        # One writer per store. Two daemons appending to the same files would
        # duplicate records and desynchronise state.json, and "I started it
        # twice" is the easiest way for that to happen.
        self._lock = open(os.path.join(store, ".daemon.lock"), "w")
        try:
            fcntl.flock(self._lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            sys.exit("another daemon already holds this store "
                     f"({os.path.join(store, '.daemon.lock')})")
        self._lock.write(str(os.getpid()))
        self._lock.flush()

        self.state = load_state(store)
        count, tail_hash, _f, _s = store_tail(store)

        if self.state is None:
            if count:
                # `count` is from the FINAL FILE only — store_tail does not
                # walk the whole store on startup, by design. Saying "holds
                # 20 records" about a 970,001-record store reads like the
                # store was destroyed, which is a bad thing to tell somebody
                # about eight hours of work. Say what was actually counted.
                sys.exit(
                    f"{store} has no state.json "
                    f"(its last file holds {count:,} records).\n"
                    "This is what a store looks like after monetary_store.py "
                    "built it: the batch stripper writes derived.json, and "
                    "state.json is the daemon's own file.\n"
                    "Nothing is wrong with the store. The daemon just will "
                    "not append to one whose position it cannot prove.\n\n"
                    "Take ownership with:\n"
                    f"    monetary_daemon.py --store {store} --adopt "
                    "--start-height N\n"
                    "where N is the height of the FIRST record (0 for a "
                    "genesis derive).")
            self.state = {"height": None, "hash": None,
                          "commitment": "00" * 32, "records": 0}
        else:
            # The store is authoritative. If state.json disagrees with what is
            # actually on disk, something wrote to one and not the other.
            if tail_hash and self.state["hash"] and \
                    tail_hash[::-1].hex() != self.state["hash"]:
                sys.exit("state.json tip does not match the store's last "
                         "record. Refusing to continue.")

        # The retention ruleset, and the check that this store was built
        # under it. A store appended to by two different policies produces a
        # commitment that means nothing — and the failure is silent, because
        # both halves verify against their own headers perfectly well.
        self.policy = policy
        pid = policy.policy_id() if policy is not None else None
        recorded = self.state.get("policy_id")
        if recorded is None and adopt_policy and self.state.get("records", 0):
            print("adopting policy %s for an existing store — this asserts "
                  "the stripper is unchanged" % pid)
            self.state["policy_id"] = pid
            save_state(self.store, self.state)
            recorded = pid
        if recorded is None and self.state.get("records", 0) > 0:
            # A store with records but no recorded policy predates this
            # check. Stamping the current policy onto it would assert
            # something nobody verified — and that assertion is the entire
            # value of the field. The guard would have mislabelled the first
            # store it ever met, which is worse than not having it.
            sys.exit(
                "This store holds "
                f"{self.state['records']:,} records and records no policy.\n\n"
                "It was built before the policy was recorded, so nothing here\n"
                "knows which rules produced it. Writing the current policy id\n"
                "onto it would be a claim, not a fact.\n\n"
                f"  current policy  {pid}\n\n"
                "Two honest options:\n\n"
                "  Re-derive from genesis under the current rules. The only\n"
                "  option if the stripper has changed since this store was\n"
                "  built:\n"
                "      monetary_store.py --blocks ~/.bitcoin/blocks \\\n"
                "          --start 0 --end <tip> --out <new store>\n\n"
                "  Or, if you are certain the rules are unchanged, say so\n"
                "  explicitly and take responsibility for the claim:\n"
                f"      monetary_daemon.py --store {self.store} \\\n"
                "          --adopt-policy")
        if recorded is None:
            self.state["policy_id"] = pid
            save_state(self.store, self.state)
        elif recorded != pid:
            sys.exit(
                "POLICY MISMATCH — refusing to append.\n\n"
                f"  this store was built with  {recorded}\n"
                f"  this process would use     {pid}\n\n"
                "Two policies retain different outputs, so continuing would\n"
                "produce a commitment no other node can reproduce and no\n"
                "reader can interpret. Either run the original policy, or\n"
                "re-derive the store from genesis under the new one.")

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
                                 self.scriptsig_limit, self.policy)

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

        # Cumulative totals, on disk rather than only in memory.
        #
        # "How much spam has this node thrown away" is the one number a
        # person installs this to see, and it was being kept in a counter
        # that reset every restart. Across a store built over days that
        # meant the headline figure was whatever had happened since the
        # last crash.
        carriers = (st["envelope"] + st["op_return"] + st["multisig"]
                    + st.get("pubkey", 0) + st["scriptsig"])
        self.state["bytes_in"] = self.state.get("bytes_in", 0) + st["original"]
        self.state["bytes_out"] = self.state.get("bytes_out", 0) + st["stored"]
        self.state["carriers"] = self.state.get("carriers", 0) + carriers
        save_state(self.store, self.state)

        self.stats["stripped"] += 1
        self.stats["bytes_in"] += st["original"]
        self.stats["bytes_out"] += st["stored"]
        self.stats["spam"] += carriers
        self.log_block(height, st)
        return "ok"

    # ------------------------------------------------------- per-block log
    #
    # The running totals above are what the daemon reports. They cannot answer
    # "what did block 968,580 cost me", which is the figure that makes this
    # project legible to somebody watching it work. So each block also appends
    # one line here, and the dashboard tails it.
    #
    # Bounded by rewriting when it gets long rather than growing forever: this
    # is a live feed, not an archive, and the store itself is the record.

    def recent_path(self):
        return os.path.join(self.store, "recent.jsonl")

    def log_block(self, height, st):
        line = {
            "h": height,
            "t": int(time.time()),
            "in": st["original"],
            "out": st["stored"],
            "env": st["envelope"],
            "opr": st["op_return"],
            "ms": st["multisig"],
            "ss": st["scriptsig"],
            "whole": st["whole"],
            "mod": st["modified"],
            "strip": st["stripped"],
            "txs": len(st["txids"]),
        }
        path = self.recent_path()
        try:
            with open(path, "a") as f:
                f.write(json.dumps(line, separators=(",", ":")) + "\n")
            # Trim occasionally rather than on every block: the check costs a
            # stat, the rewrite costs a read of the whole file.
            if height % 200 == 0 and os.path.getsize(path) > RECENT_MAX_BYTES:
                with open(path) as f:
                    keep = f.readlines()[-RECENT_KEEP:]
                tmp = path + ".tmp"
                with open(tmp, "w") as f:
                    f.writelines(keep)
                os.replace(tmp, path)
        except OSError:
            pass          # a feed is never worth failing a block over

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
    count3, _l, _f, _s = store_tail(d3, full=True)
    check("spans multiple files when asked", count3 == 3, f"{count3}")
    partial, _l, _f, _s = store_tail(d3)
    check("partial walk reads only the last file", partial == 2, f"{partial}")

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
    # The headline figure must survive a restart: it is cumulative over
    # the life of the store, not since the process last started.
    # Lifetime totals must survive an adopt. This is the bug that made a
    # 975,000-block store report 245.9 MiB removed.
    import tempfile as _tf
    _td = _tf.mkdtemp()
    with open(os.path.join(_td, "derived.json"), "w") as _fh:
        json.dump({"policy_id": "p", "records": 5,
                   "bytes_in": 1000, "bytes_out": 900,
                   "carriers": 100}, _fh)

    def _carry(prior, derived_has=True):
        """The adopt carry-forward logic, isolated from argv and the store."""
        st = {"height": 1, "hash": None, "commitment": "00", "records": 5}
        for src in (prior, ({"bytes_in": 1000, "bytes_out": 900,
                             "carriers": 100} if derived_has else {})):
            if src and src.get("bytes_in") and src.get("bytes_out") is not None:
                st["bytes_in"] = src["bytes_in"]
                st["bytes_out"] = src["bytes_out"]
                if src.get("carriers") is not None:
                    st["carriers"] = src["carriers"]
                break
        return st

    _a = _carry({"bytes_in": 50, "bytes_out": 40, "carriers": 10})
    check("adopt prefers the running total in state.json",
          _a["bytes_in"] == 50 and _a["carriers"] == 10)
    _b = _carry({})
    check("and falls back to derived.json", _b["bytes_in"] == 1000)
    check("carrying its carrier count too", _b["carriers"] == 100)
    _c = _carry({}, derived_has=False)
    check("with neither, totals are ABSENT, not zero",
          "bytes_in" not in _c)
    check("because zero would claim nothing was ever removed",
          _c.get("carriers") is None)
    check("adopt carries totals forward in the real code",
          "lifetime totals carried from" in open(__file__).read())

    _s = {"bytes_in": 10, "bytes_out": 7, "carriers": 3}
    _s["bytes_in"] = _s.get("bytes_in", 0) + 100
    _s["carriers"] = _s.get("carriers", 0) + 30
    check("totals accumulate rather than reset", _s["bytes_in"] == 110)
    check("carriers accumulate too", _s["carriers"] == 33)
    _f = {}
    _f["carriers"] = _f.get("carriers", 0) + 5
    check("a store with no totals yet starts at zero", _f["carriers"] == 5)

    check("a commitment seed is normalised",
          clean_commitment("  " + "A" * 64 + " ") == "a" * 64)
    check("an 0x prefix is accepted", clean_commitment("0x" + "b" * 64)
          == "b" * 64)
    check("a short commitment is refused", clean_commitment("abcd") is None)
    check("a long commitment is refused",
          clean_commitment("a" * 65) is None)
    check("a non-hex commitment is refused",
          clean_commitment("z" * 64) is None)
    check("no commitment is not a commitment",
          clean_commitment(None) is None)

    # a store with records but no state must be refused, not adopted silently
    has_records = store_tail(d4)[0] > 0 and load_state(d4) is None
    check("records without state is detectable", has_records)
    save_state(d4, {"height": 1, "hash": "cc" * 32,
                    "commitment": "00" * 32, "records": 99})
    mismatch = store_tail(d4)[0] != load_state(d4)["records"]
    check("record count mismatch is detectable", mismatch)

    print("\npolicy recorded with the store")
    # A store appended to under two different policies produces a commitment
    # nobody can reproduce, and the corruption is invisible: both halves
    # verify against their own headers perfectly well. So the policy id is
    # written into state.json on first use and checked on every start.
    from carrier_policy import Policy
    d6 = tempfile.mkdtemp()
    save_state(d6, {"height": 5, "hash": "aa" * 32, "commitment": "bb" * 32,
                    "records": 5})
    st6 = load_state(d6)
    check("an existing store has no policy id yet",
          st6.get("policy_id") is None)

    pol = Policy()
    st6["policy_id"] = pol.policy_id()
    save_state(d6, st6)
    check("it round-trips once written",
          load_state(d6)["policy_id"] == pol.policy_id())
    check("a different policy has a different id",
          Policy(entries=[]).policy_id() != pol.policy_id())
    check("so a mismatch is detectable before any append",
          load_state(d6)["policy_id"] != Policy(entries=[]).policy_id())
    check("the Daemon takes a policy argument",
          "policy" in Daemon.__init__.__code__.co_varnames)

    # Adopting a store the batch stripper just built must carry its policy
    # forward from derived.json, or the operator hits the refusal above at
    # the end of a multi-hour derive.
    d7 = tempfile.mkdtemp()
    with open(os.path.join(d7, "derived.json"), "w") as f:
        json.dump({"policy_id": pol.policy_id(), "records": 3,
                   "start_height": 0, "end_height": 2}, f)
    check("derived.json round-trips the policy",
          json.load(open(os.path.join(d7, "derived.json")))["policy_id"]
          == pol.policy_id())
    # A derived.json whose record count disagrees with the store must NOT be
    # trusted: the store changed after it was derived.
    with open(os.path.join(d7, "derived.json")) as f:
        stale = json.load(f)
    stale["records"] = 999
    check("a record-count mismatch is detectable",
          stale["records"] != 3)

    # The byte order adopt writes must be the order the startup check reads.
    # It was not: adopt wrote store_tail's internal-order hash while the
    # check compares it reversed, so every adopted store failed integrity
    # immediately after being built.
    d8 = tempfile.mkdtemp()
    open(os.path.join(d8, "mblk00000.dat"), "wb").write(r1)
    cnt, tail, _f, _s = store_tail(d8, full=True)
    check("store_tail returns a hash to adopt", cnt == 1 and bool(tail))
    save_state(d8, {"height": 0, "hash": tail[::-1].hex(),
                    "commitment": "00" * 32, "records": cnt})
    check("adopt's stored hash matches the startup check's expectation",
          store_tail(d8, full=True)[1][::-1].hex()
          == load_state(d8)["hash"])
    check("and the unreversed form would NOT have matched",
          tail.hex() != load_state(d8)["hash"])

    print("\ncorrupt state.json")
    # Under Restart=always an unhandled JSONDecodeError here is a crash-loop
    # printing a traceback every thirty seconds. Found by an outside review.
    #
    # The important half is that unreadable must not read as ABSENT: None
    # means "never written", which invites the daemon to adopt a position
    # for a store that already has one.
    d9 = tempfile.mkdtemp()
    check("a store with no state file reads as None",
          load_state(d9) is None)
    with open(state_path(d9), "w") as f:
        f.write('{"height": 5, "records":')      # truncated mid-write
    try:
        load_state(d9)
        check("truncated JSON does not read as an empty store", False)
    except SystemExit as e:
        check("truncated JSON does not read as an empty store",
              "not valid JSON" in str(e))
        check("and the message names the file", state_path(d9) in str(e))
    with open(state_path(d9), "w") as f:
        f.write('["not", "an", "object"]')
    try:
        load_state(d9)
        check("a JSON array is refused", False)
    except SystemExit as e:
        check("a JSON array is refused", "JSON object" in str(e))

    print("\nper-block feed log")
    d5 = tempfile.mkdtemp()

    class FakeDaemon:
        store = d5
        recent_path = Daemon.recent_path
        log_block = Daemon.log_block
    fd = FakeDaemon()
    sample = {"original": 1_900_000, "stored": 1_740_000, "envelope": 150_000,
              "op_return": 6_000, "multisig": 3_000, "scriptsig": 1_000,
              "whole": 2800, "modified": 40, "stripped": 9,
              "txids": [b"x" * 32] * 2849}
    fd.log_block(968580, sample)
    fd.log_block(968581, sample)
    lines = open(os.path.join(d5, "recent.jsonl")).read().strip().split("\n")
    check("one line per block", len(lines) == 2)
    rec = json.loads(lines[0])
    check("height is recorded", rec["h"] == 968580)
    check("bytes in and out are recorded",
          rec["in"] == 1_900_000 and rec["out"] == 1_740_000)
    check("discarded is derivable from the line",
          rec["in"] - rec["out"] == 160_000)
    check("the carrier breakdown is present",
          rec["env"] == 150_000 and rec["opr"] == 6_000
          and rec["ms"] == 3_000 and rec["ss"] == 1_000)
    check("tx classes are present",
          rec["whole"] == 2800 and rec["mod"] == 40 and rec["strip"] == 9)
    check("every line is one JSON object on one line",
          all(json.loads(l) for l in lines))

    # A feed is never worth failing a block over: an unwritable store must be
    # survivable, because the alternative is a daemon that stops stripping.
    class Unwritable:
        store = os.path.join(d5, "does", "not", "exist")
        recent_path = Daemon.recent_path
        log_block = Daemon.log_block
    try:
        Unwritable().log_block(1, sample)
        check("an unwritable feed log does not raise", True)
    except Exception as e:
        check("an unwritable feed log does not raise", False, str(e)[:60])

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
    ap.add_argument("--commitment", metavar="HEX",
                    help="seed C when adopting, so the commitment chain "
                         "continues from a value you already published "
                         "rather than restarting at zero")
    ap.add_argument("--adopt-policy", action="store_true",
                    help="assert that an existing store was built under the "
                         "current carrier policy. Only true if the stripper "
                         "has not changed since; otherwise re-derive.")
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
        print(f"last file holds{count:>12,} records")
        if st:
            print(f"state height   {st['height']:>12,}")
            print(f"state records  {st['records']:>12,}")
            print(f"C              {st['commitment']}")
            # The tail hash is the real check: it confirms the store ends at
            # the exact block the state claims. A record count cannot.
            tail_ok = last is not None and last[::-1].hex() == st.get("hash")
            print(f"store tail     "
                  f"{'matches state' if tail_ok else 'MISMATCH - do not run'}")
            if not tail_ok and last is not None:
                print(f"  store ends at {last[::-1].hex()}")
                print(f"  state says    {st.get('hash')}")
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
        count, last, _f, _s = store_tail(args.store, full=True)
        if args.start_height is None:
            sys.exit("--adopt needs --start-height (height of the FIRST record)")
        if not count:
            sys.exit("nothing to adopt: store is empty")
        last_height = args.start_height + count - 1
        print(f"adopting {count:,} records, first at {args.start_height:,}, "
              f"last at {last_height:,}")

        # C must continue from the published value, or it silently forks.
        #
        # Adopting with C = 0 and then following the tip produces a
        # commitment chain rooted at zero, which agrees with nothing anybody
        # was given. The published triple stops describing this node at the
        # first new block, and the divergence is invisible: every record
        # still verifies against its own header. Whoever checks the node
        # against the published C simply finds a mismatch and no explanation.
        #
        # So: let the operator seed it, and say loudly which case they are in.
        seed = args.commitment
        if seed:
            seed = clean_commitment(seed)
            if seed is None:
                sys.exit("--commitment must be 64 hex characters")
            print(f"C seeded as {seed}")
            print("This asserts that value is the commitment over exactly "
                  "these records.")
            print("If it was computed over a different range, every C this "
                  "daemon publishes from now on is wrong.")
        else:
            seed = "00" * 32
            print("NOTE: C is set to zero. It does not describe the existing")
            print("records, and every commitment this daemon publishes from")
            print("here will be rooted at zero rather than continuing your")
            print("published chain. Compute the real value with")
            print("monetary_commit.py and re-adopt with --commitment, unless")
            print("you have never published one.")

        # Carry the policy forward from derived.json, which monetary_store.py
        # writes beside a store it built. Without this, adopting a store the
        # batch stripper just produced leaves no policy recorded, and the
        # daemon then refuses to follow it — a wall at the end of a job that
        # takes hours, which is the worst possible place to put one.
        #
        # This is a fact being copied, not an assertion being made: the file
        # was written by the process that did the stripping.
        # Byte order matters here and was wrong.
        #
        # store_tail returns the record's 32-byte block-hash field in
        # internal order. process() records state["hash"] REVERSED, and the
        # startup integrity check compares tail_hash[::-1].hex() against it.
        # adopt wrote last.hex() — unreversed — so every adopted store failed
        # that check with "state.json tip does not match the store's last
        # record", immediately after however many hours it took to build.
        #
        # Found by running the adopt path rather than reading it.
        state = {"height": last_height,
                 "hash": last[::-1].hex() if last else None,
                 "commitment": seed, "records": count}
        derived_path = os.path.join(args.store, "derived.json")

        # Carry the lifetime totals, do not reset them.
        #
        # adopt used to write a state with no totals at all, so the next
        # block stripped started the counters from zero. On a store with
        # 975,000 blocks already in it the dashboard then reported a few
        # hundred megabytes removed, which looks exactly like a store that
        # has been thrown away and rebuilt. Nothing was wrong with the
        # store either time; only the arithmetic about it.
        #
        # Preference order: an existing state.json, because it is the
        # running total; then derived.json, because the batch stripper
        # measured the same thing when it built the store. If neither has
        # them they stay absent rather than zero — a missing total reads
        # as "not known", and zero reads as "nothing was removed".
        _prior = load_state(args.store) or {}
        _carried = None
        for src, label in ((_prior, "state.json"), (None, "derived.json")):
            if src is None:
                try:
                    with open(derived_path) as fh:
                        src = json.load(fh)
                except (OSError, ValueError):
                    continue
            if src.get("bytes_in") and src.get("bytes_out") is not None:
                state["bytes_in"] = src["bytes_in"]
                state["bytes_out"] = src["bytes_out"]
                if src.get("carriers") is not None:
                    state["carriers"] = src["carriers"]
                _carried = label
                break
        if _carried:
            _sv = state["bytes_in"] - state["bytes_out"]
            print(f"\nlifetime totals carried from {_carried}: "
                  f"{_sv / 1024 ** 3:.1f} GiB removed of "
                  f"{state['bytes_in'] / 1024 ** 3:.1f} GiB "
                  f"({100.0 * _sv / state['bytes_in']:.2f}%)")
        else:
            print("\nNo lifetime totals in state.json or derived.json, so")
            print("the counters start from this adopt. The store itself is")
            print("unaffected; only the 'spam removed' figure on the page")
            print("will count from here rather than from genesis.")
        try:
            with open(derived_path) as fh:
                derived = json.load(fh)
        except (OSError, ValueError):
            derived = None
        if derived and derived.get("policy_id"):
            if derived.get("records") not in (None, count):
                print(f"\nWARNING: derived.json records "
                      f"{derived['records']:,} but the store holds "
                      f"{count:,}.")
                print("The store has changed since it was derived. Not "
                      "carrying its policy forward.")
            else:
                state["policy_id"] = derived["policy_id"]
                print(f"policy carried from derived.json: "
                      f"{derived['policy_id']}")
        else:
            print("\nNo derived.json with a policy beside this store, so no")
            print("policy is recorded. If the stripper that built it is the")
            print("one running now, say so with --adopt-policy; otherwise")
            print("re-derive.")

        save_state(args.store, state)
        print("adopted. state.json written.")
        return

    rpc = RPC(args.rpc_host, args.rpc_port, args.rpc_user, args.rpc_password,
              args.rpc_cookie)
    # The policy is not optional in production. A store built without one
    # cannot publish a policy_id, and a commitment without its ruleset is an
    # unverifiable number.
    try:
        from carrier_policy import Policy
        policy = Policy(op_return_limit=args.op_return_limit)
        print("carrier policy %s" % policy.policy_id())
    except ImportError as e:
        sys.exit(f"carrier_policy.py is required beside monetary_daemon.py: {e}")

    d = Daemon(rpc, args.store, args.depth, args.op_return_limit,
               args.scriptsig_limit, args.file_size, args.poll, policy,
               args.adopt_policy)
    if d.state["height"] is None and args.start_height is None:
        sys.exit("new store needs --start-height")
    try:
        d.run(args.start_height, args.once)
    except KeyboardInterrupt:
        print("\nstopped. state saved.")


if __name__ == "__main__":
    main()
