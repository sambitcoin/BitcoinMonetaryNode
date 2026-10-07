#!/usr/bin/env python3
"""
tip_race.py — when two blocks arrive at the same height, which one was
cleaner, and which one did the network keep?

    python3 tip_race.py --rpc-cookie ~/.bitcoin/.cookie --watch
    python3 tip_race.py --rpc-cookie ~/.bitcoin/.cookie --once
    python3 tip_race.py --tally
    python3 tip_race.py --selftest

WHAT THIS IS NOT, STATED FIRST BECAUSE IT MATTERS MOST.

This does not choose a chain. It cannot. It has no path to Core's chain
selection, holds no opinion Core can act on, and writes nothing bitcoind
reads. Bitcoin picks the tip with the most work and breaks ties by first
seen, and this node obeys that without exception.

That restraint is the whole design. A node that waited thirty seconds and
then preferred the cleaner block of equal work would be choosing a different
chain from everyone else, and would fork off the moment its choice lost. For
a project whose claim is "every consensus rule, enforced, with the data
discarded afterwards", a reorg policy would be the one change that broke the
claim. So the window here is a stopwatch, not a tiebreak.

WHAT IT DOES. `getchaintips` reports every tip this node knows about,
including stale ones it saw and then abandoned. A race shows up as two tips
at the same height: one `active`, one `valid-fork` or `valid-headers`. When
that happens, both blocks are measured with the same stripper the store uses,
and the result is written down:

    height, both hashes, carrier bytes in each, which one survived

Over time that answers a question nobody publishes: when the network had a
choice between a clean block and a block stuffed with data, which did it
keep? The honest answer may well be "the one that arrived first, every time,
because that is how Bitcoin works" — in which case this records that, and
that is still a finding.

LIMITS, SO NOBODY OVERREADS THE NUMBERS.
  - This sees only races this node witnessed. A race settled before the
    announcement reached you over Tor is invisible here, and Tor adds
    latency, so this undercounts. It is one node's view, not a survey.
  - A stale tip reported as `headers-only` cannot be measured: the node has
    the header but never got the block. Those are recorded as unmeasured
    rather than guessed at.
  - Races are rare. Expect a handful a month, not a chart.

Standard library only. BSD-2-Clause.
"""

import argparse
import base64
import json
import os
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from monetary_store import strip_block, dsha
except ImportError as e:            # pragma: no cover
    sys.exit(f"tip_race.py needs monetary_store.py beside it: {e}")

RACES_MAX_BYTES = 512 * 1024
RACES_KEEP = 500
POLL_SECONDS = 20
# Statuses getchaintips uses for a tip that is not the active one.
STALE_STATUSES = ("valid-fork", "valid-headers", "headers-only",
                  "invalid", "unknown")


# --------------------------------------------------------------------- rpc


class RPC:
    def __init__(self, url, cookie_path):
        self.url = url
        self.cookie_path = cookie_path
        self.n = 0

    def _auth(self):
        with open(self.cookie_path) as f:
            return base64.b64encode(f.read().strip().encode()).decode()

    def call(self, method, *params):
        self.n += 1
        body = json.dumps({"jsonrpc": "1.0", "id": self.n,
                           "method": method, "params": list(params)})
        req = urllib.request.Request(
            self.url, data=body.encode(),
            headers={"Content-Type": "application/json",
                     "Authorization": "Basic " + self._auth()})
        with urllib.request.urlopen(req, timeout=60) as r:
            out = json.loads(r.read())
        if out.get("error"):
            raise IOError(str(out["error"]))
        return out["result"]

    def raw_block(self, blockhash):
        return bytes.fromhex(self.call("getblock", blockhash, 0))


# ----------------------------------------------------------------- measure


def carrier_bytes(raw, height, op_return_limit=83, scriptsig_limit=1650):
    """Carrier content of one block, using the store's own stripper.

    Deliberately the same code path as the store rather than a lookalike: a
    second implementation would drift, and then the published races would be
    measured by rules the published commitment was not."""
    _, st = strip_block(raw, height, op_return_limit, scriptsig_limit)
    return {
        "carriers": st["envelope"] + st["op_return"] + st["multisig"]
                    + st["scriptsig"],
        "envelope": st["envelope"],
        "op_return": st["op_return"],
        "multisig": st["multisig"],
        "scriptsig": st["scriptsig"],
        "size": st["original"],
        "txs": len(st["txids"]),
        "whole": st["whole"],
        "modified": st["modified"],
        "stripped": st["stripped"],
    }


def find_races(tips, depth=10):
    """Heights where more than one tip exists. -> [(height, [tip, ...])].

    getchaintips gives one entry per tip. The active tip is status 'active';
    everything else this node saw and abandoned. Two entries at one height
    is a race."""
    if not tips:
        return []
    active = [t for t in tips if t.get("status") == "active"]
    if not active:
        return []
    top = max(t.get("height", 0) for t in active)

    by_height = {}
    for t in tips:
        h = t.get("height")
        if not isinstance(h, int):
            continue
        if h < top - depth or h > top:
            continue
        by_height.setdefault(h, []).append(t)

    out = []
    for h in sorted(by_height):
        group = by_height[h]
        if len(group) > 1:
            out.append((h, group))
    return out


# ------------------------------------------------------------------- store


def races_path(store):
    return os.path.join(store, "races.jsonl")


def load_races(store):
    path = races_path(store)
    out = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line.startswith("{"):
                    continue
                try:
                    out.append(json.loads(line))
                except ValueError:
                    continue
    except OSError:
        return []
    return out


def record_race(store, rec):
    """Append one race. Bounded; a feed is never worth failing over."""
    path = races_path(store)
    try:
        os.makedirs(store, exist_ok=True)
        with open(path, "a") as f:
            f.write(json.dumps(rec, separators=(",", ":")) + "\n")
        if os.path.getsize(path) > RACES_MAX_BYTES:
            with open(path) as f:
                keep = f.readlines()[-RACES_KEEP:]
            tmp = path + ".tmp"
            with open(tmp, "w") as f:
                f.writelines(keep)
            os.replace(tmp, path)
        return True
    except OSError:
        return False


def tally(races):
    """The published number: when the network had a choice, what did it keep?

    'Cleaner won' counts only races where both blocks were measurable AND
    their carrier loads actually differed. A race between two equally clean
    blocks says nothing about preference and is counted separately rather
    than padding either side."""
    t = {"races": 0, "measured": 0, "unmeasured": 0, "ties": 0,
         "cleaner_won": 0, "dirtier_won": 0, "bytes_kept": 0,
         "bytes_discarded_by_network": 0}
    for r in races:
        t["races"] += 1
        win, lose = r.get("winner"), r.get("loser")
        if not win or not lose or win.get("carriers") is None \
                or lose.get("carriers") is None:
            t["unmeasured"] += 1
            continue
        t["measured"] += 1
        w, l = win["carriers"], lose["carriers"]
        t["bytes_kept"] += w
        t["bytes_discarded_by_network"] += l
        if w == l:
            t["ties"] += 1
        elif w < l:
            t["cleaner_won"] += 1
        else:
            t["dirtier_won"] += 1
    decided = t["cleaner_won"] + t["dirtier_won"]
    t["decided"] = decided
    t["cleaner_won_pct"] = (t["cleaner_won"] / decided * 100) if decided else None
    return t


# ------------------------------------------------------------------ watcher


class Watcher:
    """Polls getchaintips and records races as they resolve.

    A race is held open for `window` seconds before being written down, so
    the recorded winner is the tip the node settled on rather than whichever
    one it happened to hold mid-reorg."""

    def __init__(self, rpc, store, window=30, depth=10):
        self.rpc = rpc
        self.store = store
        self.window = window
        self.depth = depth
        self.open = {}          # height -> {first_seen, tips{hash: tip}}
        self.done = set()       # heights already written
        self.measured = {}      # blockhash -> measurement or None

    def measure(self, tip):
        h = tip.get("hash")
        if h in self.measured:
            return self.measured[h]
        result = None
        # headers-only means the node has the header and never got the block.
        # Nothing to measure, and inventing a figure would be worse than a
        # gap in the data.
        if tip.get("status") != "headers-only":
            try:
                raw = self.rpc.raw_block(h)
                result = carrier_bytes(raw, tip.get("height", 0))
            except Exception:
                result = None
        self.measured[h] = result
        return result

    def poll(self):
        """-> list of races written this poll."""
        tips = self.rpc.call("getchaintips")
        now = time.time()
        written = []

        for height, group in find_races(tips, self.depth):
            if height in self.done:
                continue
            entry = self.open.setdefault(height,
                                         {"first_seen": now, "tips": {}})
            for t in group:
                entry["tips"][t.get("hash")] = t
                self.measure(t)

            if now - entry["first_seen"] < self.window:
                continue

            rec = self.finish(height, entry, tips)
            if rec:
                if record_race(self.store, rec):
                    written.append(rec)
                self.done.add(height)
            self.open.pop(height, None)

        # Forget races that have fallen out of the examined range.
        for h in list(self.open):
            if all(h != hh for hh, _ in find_races(tips, self.depth)):
                self.open.pop(h, None)
        return written

    def finish(self, height, entry, tips):
        """Write down who won. The winner is whatever is on the active chain.

        Read from the node rather than decided here — which is the point. The
        node's answer is Bitcoin's answer, and this tool only reports it."""
        live = {t.get("hash"): t for t in tips}
        winner_hash = None
        for h in entry["tips"]:
            st = (live.get(h) or {}).get("status")
            if st == "active":
                winner_hash = h
        if winner_hash is None:
            # The active tip has moved past this height, so neither of these
            # IS the tip any more. Ask the node which one it kept.
            for h in entry["tips"]:
                try:
                    if self.rpc.call("getblockheader", h).get(
                            "confirmations", -1) > 0:
                        winner_hash = h
                        break
                except Exception:
                    continue
        if winner_hash is None:
            return None

        losers = [h for h in entry["tips"] if h != winner_hash]
        if not losers:
            return None

        def side(h):
            m = self.measured.get(h) or {}
            return {"hash": h, "status": (live.get(h) or {}).get("status"),
                    "carriers": m.get("carriers"), "size": m.get("size"),
                    "txs": m.get("txs"), "envelope": m.get("envelope"),
                    "op_return": m.get("op_return"),
                    "multisig": m.get("multisig"),
                    "scriptsig": m.get("scriptsig")}

        return {"h": height, "t": int(time.time()),
                "window": self.window,
                "winner": side(winner_hash),
                "loser": side(losers[0]),
                "others": [side(h) for h in losers[1:]]}

    def run(self, once=False):
        while True:
            try:
                for rec in self.poll():
                    describe(rec)
            except Exception as e:
                print(f"  poll failed: {str(e)[:120]}", file=sys.stderr)
            if once:
                return
            time.sleep(POLL_SECONDS)


def human(n):
    if n is None:
        return "?"
    for unit, size in (("GB", 1e9), ("MB", 1e6), ("KB", 1e3)):
        if n >= size:
            return f"{n / size:.1f} {unit}"
    return f"{n} B"


def describe(rec):
    w, l = rec["winner"], rec["loser"]
    print(f"race at height {rec['h']:,}")
    print(f"  kept      {w['hash'][:20]}…  carriers {human(w['carriers'])}")
    print(f"  discarded {l['hash'][:20]}…  carriers {human(l['carriers'])}")
    if w["carriers"] is None or l["carriers"] is None:
        print("  one side was never received as a full block — unmeasured")
    elif w["carriers"] < l["carriers"]:
        print("  the cleaner block survived")
    elif w["carriers"] > l["carriers"]:
        print("  the dirtier block survived")
    else:
        print("  both carried the same amount; the race says nothing")
    print("  this node did not influence that outcome and could not")


# ----------------------------------------------------------------- selftest


def selftest():
    checks, passed = [], 0

    def ck(name, ok, extra=""):
        nonlocal passed
        checks.append(name)
        passed += bool(ok)
        print("  [%s] %s%s" % ("ok  " if ok else "FAIL", name,
                               "" if ok else "  <- " + str(extra)))

    print("race detection")
    tips = [{"height": 100, "hash": "a" * 64, "status": "active"}]
    ck("a single tip is not a race", find_races(tips) == [])

    tips = [{"height": 100, "hash": "a" * 64, "status": "active"},
            {"height": 100, "hash": "b" * 64, "status": "valid-fork"}]
    r = find_races(tips)
    ck("two tips at one height is a race",
       len(r) == 1 and r[0][0] == 100 and len(r[0][1]) == 2)

    tips = [{"height": 100, "hash": "a" * 64, "status": "active"},
            {"height": 97, "hash": "b" * 64, "status": "valid-fork"}]
    ck("tips at different heights are not a race", find_races(tips) == [])

    # A stale tip far below the active chain is an old fork, not a race at
    # the tip, and counting it would inflate every published figure.
    tips = [{"height": 100, "hash": "a" * 64, "status": "active"},
            {"height": 40, "hash": "b" * 64, "status": "valid-fork"},
            {"height": 40, "hash": "c" * 64, "status": "valid-fork"}]
    ck("old forks outside the depth window are ignored",
       find_races(tips, depth=10) == [])
    ck("widening the depth window finds them",
       len(find_races(tips, depth=100)) == 1)

    tips = [{"height": 100, "hash": "a" * 64, "status": "active"},
            {"height": 100, "hash": "b" * 64, "status": "valid-fork"},
            {"height": 100, "hash": "c" * 64, "status": "headers-only"}]
    ck("a three-way race is one race with three tips",
       len(find_races(tips)) == 1 and len(find_races(tips)[0][1]) == 3)

    ck("no active tip means no conclusion",
       find_races([{"height": 100, "hash": "a" * 64,
                    "status": "valid-fork"}]) == [])
    ck("malformed tips do not raise",
       find_races([{"status": "active"}, {"height": None}]) == [])

    print("\ntally")
    def race(win_c, lose_c):
        return {"h": 1, "winner": {"carriers": win_c},
                "loser": {"carriers": lose_c}}

    t = tally([race(0, 500000), race(0, 400000)])
    ck("cleaner winning twice reads as 100%",
       t["cleaner_won"] == 2 and t["cleaner_won_pct"] == 100.0)
    t = tally([race(500000, 0), race(0, 500000)])
    ck("one each reads as 50%", t["cleaner_won_pct"] == 50.0)
    t = tally([race(100, 100)])
    ck("an equal race is a tie, not a win for either",
       t["ties"] == 1 and t["cleaner_won"] == 0 and t["dirtier_won"] == 0)
    ck("a tie does not enter the percentage", t["cleaner_won_pct"] is None)
    t = tally([race(None, 500)])
    ck("an unmeasured side is excluded, not assumed",
       t["unmeasured"] == 1 and t["measured"] == 0)
    ck("no races gives no percentage rather than zero",
       tally([])["cleaner_won_pct"] is None)
    t = tally([race(10, 20)])
    ck("the network's discarded bytes are counted",
       t["bytes_kept"] == 10 and t["bytes_discarded_by_network"] == 20)

    print("\nmeasuring a block")
    # A real one-transaction block: coinbase with an OP_RETURN carrying more
    # than the 83-byte limit, so there is something to find.
    payload = b"\x6a\x4c\x90" + b"\xab" * 144        # OP_RETURN PUSHDATA1 144
    cb = (bytes.fromhex("01000000") + b"\x01" + b"\x00" * 32
          + b"\xff\xff\xff\xff" + b"\x04\x01\x02\x03\x04"
          + b"\xff\xff\xff\xff"
          + b"\x01" + (0).to_bytes(8, "little")
          + bytes([len(payload)]) + payload
          + bytes.fromhex("00000000"))
    txid = dsha(cb)
    header = (bytes.fromhex("01000000") + b"\x11" * 32 + txid
              + bytes.fromhex("00000000") + bytes.fromhex("ffff001d")
              + bytes.fromhex("00000000"))
    blk = header + b"\x01" + cb

    m = carrier_bytes(blk, 800000)
    ck("measures a block without raising", m["size"] == len(blk))
    ck("finds the oversized OP_RETURN", m["op_return"] > 0, m)
    ck("counts the transaction", m["txs"] == 1)
    ck("uses the same stripper as the store",
       m["carriers"] == (m["envelope"] + m["op_return"] + m["multisig"]
                         + m["scriptsig"]))

    print("\nrecording")
    import tempfile
    d = tempfile.mkdtemp(prefix="race")
    rec = {"h": 500, "t": 1, "winner": {"hash": "a" * 64, "carriers": 10},
           "loser": {"hash": "b" * 64, "carriers": 900}}
    ck("a race is written", record_race(d, rec))
    got = load_races(d)
    ck("and read back", len(got) == 1 and got[0]["h"] == 500)
    with open(races_path(d), "a") as f:
        f.write("not json\n\n")
    ck("a malformed line is skipped, not raised", len(load_races(d)) == 1)
    ck("a missing file is empty, not an error",
       load_races(os.path.join(d, "nope")) == [])
    ck("an unwritable store does not raise",
       record_race("/proc/nope/nope", rec) is False)

    print("\nthe restraint")
    # These are the guardrails. If a future edit ever reaches for an RPC that
    # could move this node's chain, these fail and say why.
    #
    # Only the code ABOVE the selftest is checked — the names appear below in
    # this very list, and a test that fails on its own expectations teaches
    # you to delete the test.
    full = open(os.path.abspath(__file__)).read()
    marker = "# " + "-" * 65 + " selftest"
    code = full.split(marker)[0]
    ck("the selftest marker was found, so the split is real",
       marker in full and len(code) < len(full))
    for forbidden in ("invalidateblock", "reconsiderblock", "preciousblock",
                      "setnetworkactive", "submitblock", "setban"):
        ck("never calls %s" % forbidden, forbidden not in code)
    ck("says in its own docs that it cannot choose a chain",
       "does not choose a chain" in code)
    ck("the winner is read from the node, not decided here",
       'status") == "active"' in code)
    ck("never writes to bitcoin.conf", "bitcoin.conf" not in code)

    # Stronger than a blocklist: enumerate every RPC this module actually
    # calls and require all of them to be read-only. A new call has to be
    # added to this allowlist deliberately, which is the moment to ask
    # whether it changes the node.
    import re as _re
    called = set(_re.findall(r'\.call\(\s*"([a-z]+)"', code))
    read_only = {"getchaintips", "getblock", "getblockheader"}
    ck("every RPC it calls is read-only", called <= read_only,
       sorted(called - read_only))
    ck("it does call the one that finds races", "getchaintips" in called)

    print("\n%d/%d passed" % (passed, len(checks)))
    return 0 if passed == len(checks) else 1


# --------------------------------------------------------------------- main


def read_monetary_conf(path):
    """raceobserve / racewindow / racedepth, as node_settings writes them."""
    out = {"raceobserve": 1, "racewindow": 30, "racedepth": 10}
    try:
        with open(path) as f:
            for line in f:
                s = line.strip()
                if not s or s.startswith("#") or "=" not in s:
                    continue
                k, v = s.split("=", 1)
                k = k.strip()
                if k in out:
                    try:
                        out[k] = int(v.strip())
                    except ValueError:
                        pass
    except OSError:
        pass
    return out


def main():
    ap = argparse.ArgumentParser(
        description="measure equal-height block races; never influence them")
    home = os.path.expanduser("~")
    ap.add_argument("--store", default=os.path.join(home, "mstore"))
    ap.add_argument("--rpc-url", default="http://127.0.0.1:8332")
    ap.add_argument("--rpc-cookie",
                    default=os.path.join(home, ".bitcoin", ".cookie"))
    ap.add_argument("--monetary-conf",
                    default=os.path.join(home, ".monetary", "monetary.conf"))
    ap.add_argument("--window", type=int, default=None)
    ap.add_argument("--depth", type=int, default=None)
    ap.add_argument("--watch", action="store_true")
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--tally", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()

    if a.selftest:
        return selftest()

    if a.tally:
        t = tally(load_races(a.store))
        print(f"races seen by this node      {t['races']:,}")
        print(f"  measurable                 {t['measured']:,}")
        print(f"  one side never received    {t['unmeasured']:,}")
        print(f"  equal carrier load         {t['ties']:,}")
        print(f"  cleaner block survived     {t['cleaner_won']:,}")
        print(f"  dirtier block survived     {t['dirtier_won']:,}")
        if t["cleaner_won_pct"] is not None:
            print(f"\n  of {t['decided']:,} races that actually differed, the "
                  f"cleaner block survived {t['cleaner_won_pct']:.1f}%")
        else:
            print("\n  no race yet where the two blocks differed in carrier "
                  "load.")
        print(f"\n  carrier bytes on kept blocks      {human(t['bytes_kept'])}")
        print("  carrier bytes the network dropped "
              f"{human(t['bytes_discarded_by_network'])}")
        print("\n  One node's view, over Tor, of a rare event. Races settled")
        print("  before the announcement reached this node are invisible")
        print("  here, so this undercounts. Not a survey.")
        return 0

    cfg = read_monetary_conf(a.monetary_conf)
    if not cfg["raceobserve"] and not (a.watch or a.once):
        print("raceobserve is 0 in %s — nothing to do" % a.monetary_conf)
        return 0
    window = a.window if a.window is not None else cfg["racewindow"]
    depth = a.depth if a.depth is not None else cfg["racedepth"]

    rpc = RPC(a.rpc_url, a.rpc_cookie)
    w = Watcher(rpc, a.store, window=window, depth=depth)
    print(f"watching for equal-height races · window {window}s · "
          f"depth {depth} blocks")
    print("this tool reports chain selection; it never participates in it")
    try:
        w.run(once=a.once)
    except KeyboardInterrupt:
        print("\nstopping")
    return 0


if __name__ == "__main__":
    sys.exit(main())
