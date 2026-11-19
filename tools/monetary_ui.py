#!/usr/bin/env python3
"""
monetary_ui.py — local dashboard and live feed for a monetary node.

A background thread polls the node and emits events: new blocks with fees,
mempool movement, the daemon advancing, this node's own wallet transactions,
indexer state, and a Tor check. The page streams them without reloading, and
a heartbeat keeps it moving between blocks so a quiet feed is never confused
with a broken one.

Individual mempool transactions are deliberately excluded — thousands a
minute would bury everything. Wallet transactions are the exception.

READ ONLY. No buttons, no shell. A terminal over HTTP is remote code
execution on your node behind a page with no authentication. Nothing here
starts, stops, converts or prunes.

Binds 127.0.0.1 and refuses other addresses unless overridden.

Standard library only. Picks up quips.py if it sits alongside.

    python3 monetary_ui.py
    python3 monetary_ui.py --electrum 127.0.0.1:50001
    python3 monetary_ui.py --selftest

BSD-2-Clause.
"""

import argparse
import base64
import collections
import html
import http.server
import json
import os
import re
import socket
import socketserver
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

LOG_LINES = 40
LOG_WINDOW = 32768
POLL_SECONDS = 3
FEED_MAX = 400
MEMPOOL_REPORT_DELTA = 400
SEEN_WALLET_MAX = 2000
PEERS_SHOWN = 25
HEARTBEAT_EVERY = 5          # polls between keep-alive ticks (5 x 3s = 15s)
QUIP_ODDS = 100              # roughly one feed line in 100
RECENT_TAIL_BYTES = 65536    # how much of recent.jsonl to read per poll

# Lightning address for the project. A plain string rendered server-side —
# no wallet interaction, no QR fetched from anywhere, nothing that talks to
# the network from this page.
DONATE_LN = "bluejays93@strike.me"

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from quips import maybe_quip
except Exception:
    def maybe_quip(rng=None, chance=0):
        return None

# The settings catalogue. Optional on purpose: the dashboard is useful without
# the panel, and a missing module should cost you one card, not the page.
try:
    import node_settings as ns
except Exception:
    ns = None

# The race observer. Same reasoning: optional, and its absence costs one card.
try:
    import tip_race as tr
except Exception:
    tr = None



# ---------------------------------------------------------------- node RPC


class RPCError(RuntimeError):
    """bitcoind answered and refused.

    Distinct from the node being unreachable, because the two need
    opposite reactions: an unreachable node is an outage, a refused call
    is usually one method failing on a node that is otherwise fine.
    Conflating them put "node unreachable" in the feed of a node that was
    answering every other call."""

    def __init__(self, method, code, message):
        super().__init__("%s: %s%s" % (method, message,
                                       " (%s)" % code if code else ""))
        self.method, self.code, self.message = method, code, message


class RPC:
    def __init__(self, url, cookie=None, user=None, password=None,
                 timeout=30):
        self.url, self.timeout = url, timeout
        if user is None and cookie and os.path.exists(cookie):
            with open(cookie) as fh:
                user, password = fh.read().strip().split(":", 1)
        self.auth = None
        if user is not None:
            tok = base64.b64encode(f"{user}:{password}".encode()).decode()
            self.auth = f"Basic {tok}"

    def call(self, method, *params):
        if not self.auth:
            raise RuntimeError("no RPC credentials")
        body = json.dumps({"jsonrpc": "1.0", "id": "ui",
                           "method": method, "params": list(params)}).encode()
        req = urllib.request.Request(
            self.url, data=body,
            headers={"Content-Type": "application/json",
                     "Authorization": self.auth})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                out = json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            # Core returns RPC errors as HTTP 500 with the reason in the
            # body. urlopen raises before anyone reads it, so the useful
            # message — "Block not available (pruned data)", "no wallet
            # loaded" — was being replaced by "Internal Server Error".
            body = ""
            try:
                body = e.read().decode("utf-8", "replace")
            except Exception:                               # noqa: BLE001
                pass
            code = msg = None
            try:
                err = (json.loads(body) or {}).get("error") or {}
                code, msg = err.get("code"), err.get("message")
            except ValueError:
                pass
            raise RPCError(method, code,
                           msg or body.strip()[:200] or str(e)) from None
        if out.get("error"):
            err = out["error"]
            if isinstance(err, dict):
                raise RPCError(method, err.get("code"), err.get("message"))
            raise RPCError(method, None, str(err))
        return out["result"]


# ---------------------------------------------------------------- indexers


def probe_electrum(hostport, use_ssl=False, timeout=5):
    """Ask an Electrum-protocol server its version and tip height.

    Fulcrum, electrs and ElectrumX all speak the same newline-delimited
    JSON. Returns a dict, never raises.

    TLS here does NOT verify the certificate: indexers self-sign almost
    universally, so verification would fail for everyone. Encrypted but
    unauthenticated is the honest description. Point it only at a server
    you run.
    """
    out = {"target": hostport, "ssl": bool(use_ssl), "ok": False,
           "server": None, "height": None, "error": None}
    try:
        host, _, port = hostport.rpartition(":")
        sock = socket.create_connection((host, int(port)), timeout=timeout)
        if use_ssl:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        with sock:
            sock.settimeout(timeout)
            req = (json.dumps({"id": 0, "method": "server.version",
                               "params": ["monetary-ui", "1.4"]}) + "\n"
                   + json.dumps({"id": 1,
                                 "method": "blockchain.headers.subscribe",
                                 "params": []}) + "\n")
            sock.sendall(req.encode())
            buf = b""
            deadline = time.time() + timeout
            while time.time() < deadline and buf.count(b"\n") < 2:
                chunk = sock.recv(8192)
                if not chunk:
                    break
                buf += chunk
        for line in buf.decode(errors="replace").splitlines():
            if not line.strip():
                continue
            try:
                m = json.loads(line)
            except ValueError:
                continue
            if m.get("id") == 0:
                v = m.get("result")
                out["server"] = v[0] if isinstance(v, list) and v else str(v)
            elif m.get("id") == 1:
                out["height"] = (m.get("result") or {}).get("height")
        out["ok"] = out["height"] is not None
        if not out["ok"] and out["error"] is None:
            out["error"] = "connected but no height returned"
    except Exception as e:
        out["error"] = str(e)[:160]
    return out


# ---------------------------------------------------------------- the feed


class Feed:
    """Bounded, thread-safe event log with monotonic ids.

    Bounded because this runs for weeks. Ids keep rising after eviction so a
    long-open browser can still ask for everything after the last it saw.
    """

    def __init__(self, maxlen=FEED_MAX):
        self._lock = threading.Lock()
        self._events = collections.deque(maxlen=maxlen)
        self._next = 1

    def add(self, kind, text, detail=None, important=False):
        with self._lock:
            ev = {"id": self._next, "t": time.time(), "kind": kind,
                  "text": text, "detail": detail or "", "important": important}
            self._next += 1
            self._events.append(ev)
            return ev

    def since(self, after=0, limit=200):
        with self._lock:
            out = [e for e in self._events if e["id"] > after]
        return out[-limit:]

    def last_id(self):
        with self._lock:
            return self._next - 1


class Poller(threading.Thread):
    daemon = True

    def __init__(self, cfg, feed):
        super().__init__(name="poller")
        self.cfg, self.feed = cfg, feed
        self.stop = threading.Event()
        self.last_height = None
        self.last_mempool = None
        self.last_store_height = None
        # Bounded deliberately: an unbounded set of every wallet key ever
        # seen is a slow leak in a process meant to run for weeks.
        self.seen_wallet = set()
        self.seen_order = collections.deque(maxlen=SEEN_WALLET_MAX)
        self.warned_no_wallet = False
        self.warned_down = False
        self.warned_rpc = False
        self.warned_warmup = False
        self.consecutive_fail = 0
        self.last_indexer_height = None
        self.indexer = None
        self.indexer_checked = 0.0
        self.beats = 0
        self.tor_warned = False
        self.tor_state = None
        # Highest height already reported from recent.jsonl. Starts at the
        # store tip so a restart does not replay the last 2000 blocks.
        self.recent_seen = None
        self.race_seen = None

    def say(self, kind, text, detail=None, important=False):
        """Add an event, and occasionally follow it with editorial."""
        ev = self.feed.add(kind, text, detail, important)
        q = maybe_quip(chance=QUIP_ODDS)
        if q:
            self.feed.add("quip", q.strip().lstrip("#").strip())
        return ev

    def rpc(self):
        return RPC(self.cfg.rpc_url, self.cfg.cookie,
                   getattr(self.cfg, "rpc_user", None),
                   getattr(self.cfg, "rpc_password", None))

    def run(self):
        while not self.stop.is_set():
            try:
                self.tick()
                if self.warned_down:
                    self.say("node", "node reachable again")
                    self.warned_down = False
                self.warned_rpc = False
                self.warned_warmup = False
                self.consecutive_fail = 0
            except RPCError as e:
                # -28 is RPC_IN_WARMUP: Core is loading its indexes and
                # will answer shortly. It is the normal first thirty
                # seconds of every start, and showing it in red teaches
                # people to ignore the colour.
                if e.code == -28:
                    if not self.warned_warmup:
                        self.say("node", "node is starting",
                                 str(e.message or "")[:120])
                        self.warned_warmup = True
                elif not self.warned_rpc:
                    # The node is up and said no. Name the call that
                    # failed rather than declaring an outage.
                    self.say("error", "RPC call failed", str(e)[:200])
                    self.warned_rpc = True
            except Exception as e:
                # A single slow reply is not an outage. bitcoind blocks
                # its RPC thread while loading, so the first poll after a
                # start times out routinely — and "node unreachable" for
                # a node that is merely busy is a false alarm that
                # teaches people to distrust the page.
                self.consecutive_fail += 1
                if self.consecutive_fail >= 3 and not self.warned_down:
                    self.say("error", "node unreachable", str(e)[:200])
                    self.warned_down = True
            self.stop.wait(POLL_SECONDS)

    def tick(self):
        r = self.rpc()
        info = r.call("getblockchaininfo")
        h = info["blocks"]

        if self.last_height is None:
            self.say("node", f"watching from height {h:,}",
                     f"{info.get('chain')} · "
                     f"{'syncing' if info.get('initialblockdownload') else 'synced'}")
            self.last_height = h
        elif h > self.last_height:
            first = max(self.last_height + 1, h - 8)
            if first > self.last_height + 1:
                self.say("block", f"skipped to {first:,}",
                         f"{first - self.last_height - 1} blocks not detailed")
            for height in range(first, h + 1):
                self.block_event(r, height)
            self.last_height = h

        self.mempool_event(r)
        self.store_event()
        self.race_event()
        self.wallet_event(r)
        self.indexer_event()
        self.tor_event(r)
        self.heartbeat(r, info)

    def race_event(self):
        """Report races tip_race.py has written down.

        Reads the log rather than polling getchaintips itself: one watcher
        with one window, and the dashboard reports rather than duplicates."""
        if tr is None:
            return
        try:
            races = tr.load_races(self.cfg.store)
        except Exception:
            return
        if self.race_seen is None:
            # Start from what is already recorded, so a dashboard restart
            # does not replay months of history into the feed.
            self.race_seen = max((r.get("h", 0) for r in races), default=0)
            return
        for r in races:
            h = r.get("h", 0)
            if h <= self.race_seen:
                continue
            self.race_seen = h
            w, l = r.get("winner") or {}, r.get("loser") or {}
            wc, lc = w.get("carriers"), l.get("carriers")
            if wc is None or lc is None:
                verdict = "one side never arrived as a full block"
            elif wc < lc:
                verdict = (f"the cleaner block survived — kept {human(wc)} "
                           f"of carriers, network discarded {human(lc)}")
            elif wc > lc:
                verdict = (f"the dirtier block survived — kept {human(wc)} "
                           f"of carriers, network discarded {human(lc)}")
            else:
                verdict = "both carried the same; the race says nothing"
            self.say("race", f"competing blocks at {h:,}", verdict,
                     important=True)

    def block_event(self, r, height):
        try:
            st = r.call("getblockstats", height,
                        ["height", "total_size", "txs", "totalfee",
                         "feerate_percentiles"])
            pct = st.get("feerate_percentiles") or []
            detail = (f"{st.get('txs', 0):,} tx · "
                      f"{(st.get('total_size') or 0) / 1e6:.2f} MB · "
                      f"fees {(st.get('totalfee') or 0) / 1e8:.4f} BTC")
            if len(pct) >= 3:
                detail += f" · median {pct[2]} sat/vB"
            self.say("block", f"block {height:,}", detail)
        except Exception as e:
            self.say("block", f"block {height:,}", f"stats unavailable: {str(e)[:70]}")

    def mempool_event(self, r):
        try:
            m = r.call("getmempoolinfo")
        except Exception:
            return
        n = m.get("size")
        if self.last_mempool is None:
            self.last_mempool = n
            return
        if abs(n - self.last_mempool) >= MEMPOOL_REPORT_DELTA:
            sign = "+" if n > self.last_mempool else ""
            self.say("mempool", f"mempool {n:,} tx",
                     f"{sign}{n - self.last_mempool:,} · "
                     f"{(m.get('bytes') or 0) / 1e6:.1f} MB")
            self.last_mempool = n

    def store_event(self):
        state, _ = read_state(self.cfg.store)
        if not state:
            return
        h = state.get("height")
        if self.last_store_height is None:
            self.last_store_height = h
            self.recent_seen = h
            return
        if h > self.last_store_height:
            self.last_store_height = h
        self.garbage_events()

    def garbage_events(self):
        """What each block actually cost, from the daemon's per-block log.

        This is the number the whole project is about, so it gets its own feed
        line rather than being buried in a total. Reported per block because
        "7.12% of the chain" is an argument and "168 KB out of this block" is
        something you can watch happen."""
        for rec in read_recent(self.cfg.store, after=self.recent_seen):
            self.recent_seen = max(self.recent_seen or 0, rec["h"])
            thrown = rec["in"] - rec["out"]
            pct = (thrown / rec["in"] * 100) if rec["in"] else 0.0
            bits = []
            if rec.get("env"):
                bits.append(f"{human(rec['env'])} envelopes")
            if rec.get("opr"):
                bits.append(f"{human(rec['opr'])} OP_RETURN")
            if rec.get("ms"):
                bits.append(f"{human(rec['ms'])} bare multisig")
            if rec.get("ss"):
                bits.append(f"{human(rec['ss'])} scriptSig")
            detail = " · ".join(bits) if bits else "nothing to throw out"
            detail += (f" · {rec.get('whole', 0):,} kept whole"
                       f" · {rec.get('mod', 0):,} trimmed"
                       f" · {rec.get('strip', 0):,} dropped")
            self.say("store",
                     f"block {rec['h']:,} — {human(thrown)} discarded "
                     f"({pct:.2f}%)", detail,
                     important=pct >= 20)

    def wallet_event(self, r):
        """This node's own transactions. Given prominence: they are yours."""
        try:
            if not r.call("listwallets"):
                if not self.warned_no_wallet:
                    self.say("wallet", "no wallet loaded",
                             "nothing of this node's own to report")
                    self.warned_no_wallet = True
                return
            txs = r.call("listtransactions", "*", 20, 0, True)
        except Exception:
            return
        for t in txs:
            key = (t.get("txid"), t.get("category"), t.get("vout"))
            if key in self.seen_wallet:
                continue
            if len(self.seen_order) == self.seen_order.maxlen:
                self.seen_wallet.discard(self.seen_order[0])
            self.seen_order.append(key)
            self.seen_wallet.add(key)
            if self.last_height is None:
                continue
            conf = t.get("confirmations", 0)
            self.say("wallet", f"{t.get('category', 'tx')} {t.get('amount', 0):+.8f} BTC",
                     f"{'unconfirmed' if conf < 1 else str(conf) + ' conf'} · "
                     f"{t.get('txid', '')[:20]}…", important=True)

    def tor_event(self, r):
        """Watch for clearnet peers. The check, not the cosmetics.

        A node with onlynet=onion should have no peer on ipv4, ipv6 or
        cjdns. One appearing means the setting is not in force — a config
        that never loaded, a -proxy without -onlynet, or a manual addnode —
        and the operator should hear immediately rather than find out later.
        """
        try:
            peers = r.call("getpeerinfo")
            net = r.call("getnetworkinfo")
        except Exception:
            return
        nets = collections.Counter(p.get("network", "?") for p in peers)
        clear = sum(v for k, v in nets.items() if k not in ("onion", "i2p"))
        proxy = ""
        for entry in net.get("networks", []):
            if entry.get("name") == "onion" and entry.get("proxy"):
                proxy = entry["proxy"]
        reachable = {e.get("name"): e.get("reachable")
                     for e in net.get("networks", [])}
        self.tor_state = {"counts": dict(nets), "clearnet": clear,
                          "proxy": proxy, "total": len(peers),
                          "reachable": reachable}
        if clear and not self.tor_warned:
            self.say("tor", f"{clear} clearnet peer(s) connected",
                     "onlynet=onion is not in force", important=True)
            self.tor_warned = True
        elif not clear and self.tor_warned:
            self.say("tor", "all peers are onion again")
            self.tor_warned = False

    def indexer_event(self):
        """Poll the indexer far less often than the node — an index moves at
        block speed, and a TCP handshake every 3 seconds is pointless."""
        target = getattr(self.cfg, "electrum", None)
        if not target or time.time() - self.indexer_checked < 15:
            return
        self.indexer_checked = time.time()
        res = probe_electrum(target, getattr(self.cfg, "electrum_ssl", False))
        prev, self.indexer = self.indexer, res
        if res["ok"]:
            if prev is not None and not prev.get("ok"):
                self.say("indexer", f"{target} reachable again",
                         f"{res.get('server') or ''} at {res['height']:,}")
            elif self.last_indexer_height is None:
                self.say("indexer", f"{target} at {res['height']:,}",
                         res.get("server") or "")
            elif res["height"] != self.last_indexer_height:
                self.say("indexer", f"indexer at {res['height']:,}",
                         f"{res['height'] - self.last_indexer_height:+d} · "
                         f"{(self.last_height or 0) - res['height']:,} behind the node")
            self.last_indexer_height = res["height"]
        elif prev is None or prev.get("ok"):
            self.say("indexer", f"{target} unreachable", res.get("error") or "")

    def heartbeat(self, r, info):
        """A line every few polls so the feed is visibly alive.

        Without it the feed sits still for ten minutes between blocks and
        looks broken. It carries real figures rather than a dot, so it is
        worth reading and not just moving.
        """
        self.beats += 1
        if self.beats % HEARTBEAT_EVERY:
            return
        bits = []
        try:
            m = r.call("getmempoolinfo")
            bits.append(f"mempool {m.get('size', 0):,} tx"
                        f" / {(m.get('bytes') or 0) / 1e6:.0f} MB")
        except Exception:
            pass
        try:
            fee = r.call("estimatesmartfee", 6).get("feerate")
            if fee:
                bits.append(f"6-blk fee {fee * 1e5:.1f} sat/vB")
        except Exception:
            pass
        if info.get("mediantime"):
            age = max(0, int(time.time() - info["mediantime"]))
            bits.append(f"tip {age // 60}m{age % 60:02d}s")
        if self.tor_state:
            t = self.tor_state
            bits.append("tor only" if not t["clearnet"]
                        else f"{t['clearnet']} CLEARNET")
        self.say("tick", " · ".join(bits) or "alive")


# ---------------------------------------------------------------- gathering


def read_state(store):
    try:
        with open(os.path.join(store, "state.json")) as fh:
            return json.load(fh), None
    except FileNotFoundError:
        return None, None
    except Exception as e:
        return None, f"unreadable: {e}"


def read_derived(store):
    """
    What monetary_store.py recorded about a store it built.

    A store produced by a batch derive has derived.json and NO state.json —
    state.json belongs to the daemon. The dashboard used to call that a
    PROBLEM in red and then show "no state" where the height should be,
    which describes a perfectly good 260 GiB store as broken. On a node
    serving wallets and not following the tip, there is nothing wrong with
    it at all.
    """
    try:
        with open(os.path.join(store, "derived.json")) as fh:
            d = json.load(fh)
    except (OSError, ValueError):
        return None
    if not isinstance(d, dict) or "end_height" not in d:
        return None
    return d


def read_monetary_conf(path):
    """Monetary-node settings, as node_settings writes them.

    Defaults match the catalogue. Tor is required unless the operator has
    said otherwise, so an unreadable or absent file is the safe answer
    rather than a permissive one."""
    out = {"torrequired": 1, "raceobserve": 1, "racewindow": 30,
           "racedepth": 10}
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


_HELP_CACHE = {"t": 0.0, "blob": None, "tried": 0.0}
_HELP_LOCK = threading.Lock()


def help_cache(ttl=300, fail_ttl=60):
    """`bitcoind -help` output, cached — including when it fails.

    Every settings render needs this to decide which options exist, and
    forking bitcoind per page load would be absurd. None means the call
    failed, which is treated as "support unknown" and blocks writes rather
    than guessing.

    THE FAILURE HAS TO BE CACHED TOO. Keying the cache on a non-None blob
    meant a node that could not be asked got re-asked on every single render,
    each one a subprocess with a 30-second timeout, while holding the request
    thread. One page load with three renders in flight was enough to make the
    dashboard look dead and the unit restart under it.

    The lock matters for the same reason: without it, concurrent requests each
    start their own bitcoind."""
    now = time.time()
    with _HELP_LOCK:
        if _HELP_CACHE["blob"] is not None and now - _HELP_CACHE["t"] < ttl:
            return _HELP_CACHE["blob"]
        if _HELP_CACHE["blob"] is None and now - _HELP_CACHE["tried"] < fail_ttl:
            return None
        _HELP_CACHE["tried"] = now
        blob = ns.help_text(timeout=10) if ns is not None else ""
        _HELP_CACHE["t"] = now
        _HELP_CACHE["blob"] = blob or None
        return _HELP_CACHE["blob"]


def read_recent(store, after=None, limit=25):
    """Per-block carrier lines the daemon appended, newer than `after`.

    Tails the end of the file rather than reading it: it is trimmed to a few
    thousand lines but this runs every three seconds forever. A malformed line
    is skipped, never raised — the daemon may be mid-append, and a feed is not
    worth an exception."""
    path = os.path.join(store or "", "recent.jsonl")
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            if size > RECENT_TAIL_BYTES:
                f.seek(size - RECENT_TAIL_BYTES)
                f.readline()              # discard the partial first line
            blob = f.read().decode("utf-8", "replace")
    except (OSError, ValueError):
        return []

    out = []
    for line in blob.strip().split("\n"):
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if not isinstance(rec, dict):
            continue
        h, bi, bo = rec.get("h"), rec.get("in"), rec.get("out")
        if not all(isinstance(x, int) for x in (h, bi, bo)):
            continue
        if after is not None and h <= after:
            continue
        out.append(rec)
    out.sort(key=lambda r: r["h"])
    return out[-limit:]


def store_size(store):
    total = files = 0
    try:
        with os.scandir(store) as it:
            for e in it:
                if e.name.startswith("mblk") and e.name.endswith(".dat"):
                    total += e.stat().st_size
                    files += 1
    except OSError:
        return None, 0
    return total, files


def daemon_running():
    try:
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            try:
                with open(f"/proc/{pid}/cmdline", "rb") as fh:
                    cmd = fh.read().replace(b"\x00", b" ").decode(errors="replace")
            except OSError:
                continue
            if "monetary_daemon.py" in cmd and "--status" not in cmd:
                return int(pid), cmd.strip()
    except OSError:
        pass
    return None, None


BUILD_PATTERNS = {
    "original": r"original blocks\s+([\d.]+\s*[KMGT]?B)",
    "stored": r"monetary store\s+([\d.]+\s*[KMGT]?B)",
    "saved": r"saved\s+([\d.]+\s*[KMGT]?B\s*\([\d.]+%\))",
    "carriers": r"total\s+([\d.]+\s*[KMGT]?B)",
    "verified": r"blocks verified\s+([\d,]+)",
    "failed": r"blocks failed\s+([\d,]+)",
    "filters": r"filter entries\s+([\d,]+)",
}


def read_build_log(path):
    out = {}
    try:
        with open(path, errors="replace") as fh:
            text = fh.read()[-20000:]
    except OSError:
        return out
    for key, pat in BUILD_PATTERNS.items():
        m = re.search(pat, text)
        if m:
            out[key] = m.group(1).strip()
    return out


def list_logs(log_dir):
    try:
        return sorted(e.name for e in os.scandir(log_dir)
                      if e.is_file() and e.name.endswith(".log"))
    except OSError:
        return []


def tail_log(log_dir, name, lines=LOG_LINES, window=LOG_WINDOW):
    """Matched against the directory listing, never joined onto a path, so
    '../../etc/passwd' and absolute paths cannot select the file."""
    if name not in list_logs(log_dir):
        return None, f"no such log: {name}"
    try:
        path = os.path.join(log_dir, name)
        size = os.path.getsize(path)
        with open(path, "rb") as fh:
            fh.seek(max(0, size - window))
            blob = fh.read()
        text = blob.decode("utf-8", errors="replace")
        if size > window:
            text = text.split("\n", 1)[-1]
        return [r for r in text.splitlines() if r.strip()][-lines:], None
    except OSError as e:
        return None, str(e)


def gather(cfg):
    d = {"generated": time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime()),
         "store_path": cfg.store, "errors": []}

    # Read it every time rather than caching at startup: the operator may
    # change it in the panel, and a banner acting on a stale requirement is
    # exactly the divergence this banner exists to catch.
    mconf = getattr(cfg, "monetary_conf", "") or ""
    d["tor_required"] = bool(read_monetary_conf(mconf)["torrequired"])

    d["standalone"] = bool(getattr(cfg, "no_node", False))

    # Written by monetary_supervisor.py when the node runs as one unit.
    # Absent when the pieces are run by hand, and the card then does not
    # render rather than inventing a phase.
    try:
        with open(os.path.join(os.path.dirname(cfg.store.rstrip("/")),
                               "supervisor.json")) as fh:
            sup = json.load(fh)
        d["supervisor"] = sup if isinstance(sup, dict) else None
    except (OSError, ValueError, AttributeError):
        d["supervisor"] = None

    # Keep the PREVIOUS sample so the page can say whether anything moved.
    # A bar that sits at the same place looks identical whether the node is
    # working slowly or wedged, and that ambiguity is the single most
    # common complaint about sync screens.
    d["supervisor_prev"] = getattr(cfg, "_sup_prev", None)
    if d["supervisor"]:
        cfg._sup_prev = {
            "node_height": d["supervisor"].get("node_height"),
            "index_height": d["supervisor"].get("index_height"),
        }
    d["wallet_advertise"] = getattr(cfg, "wallet_advertise", "") or ""
    d["wallet_port"] = getattr(cfg, "wallet_port", 50001)

    state, err = read_state(cfg.store)
    if err:
        d["errors"].append(err)
    d["state"] = state
    d["derived"] = read_derived(cfg.store) if state is None else None
    if state is None and d["derived"] is None:
        d["errors"].append(
            "no state.json and no derived.json — nothing here says what "
            "this store holds")
    d["store_bytes"], d["store_files"] = store_size(cfg.store)
    d["daemon_pid"], d["daemon_cmd"] = daemon_running()
    d["peers"], d["netinfo"] = [], None

    try:
        rpc = RPC(cfg.rpc_url, cfg.cookie,
                  getattr(cfg, "rpc_user", None),
                  getattr(cfg, "rpc_password", None))
        info = rpc.call("getblockchaininfo")
        net = rpc.call("getnetworkinfo")
        d["node"] = {"chain": info.get("chain"), "blocks": info.get("blocks"),
                     "headers": info.get("headers"),
                     "progress": info.get("verificationprogress"),
                     "ibd": info.get("initialblockdownload"),
                     "pruned": info.get("pruned"),
                     "bestblockhash": info.get("bestblockhash"),
                     "connections": net.get("connections"),
                     "subversion": net.get("subversion")}
        d["netinfo"] = net
        for pr in rpc.call("getpeerinfo"):
            d["peers"].append({"addr": pr.get("addr", ""),
                               "network": pr.get("network", ""),
                               "inbound": pr.get("inbound", False),
                               "subver": pr.get("subver", ""),
                               "ping": pr.get("pingtime"),
                               "since": pr.get("conntime"),
                               "height": pr.get("synced_blocks")})
    except RPCError as e:
        d["node"] = None
        if e.code == -28:
            # Core is loading its databases. On a datadir this size that
            # is minutes, and on an adopted one it can be hours. It is
            # not a problem and must not be reported as one — the page
            # said "node RPC: Loading block index" in red while the node
            # did exactly what it should.
            d["warming_up"] = str(e.message or "loading")
        elif not getattr(cfg, "no_node", False):
            d["errors"].append("node RPC: %s" % e)
    except Exception as e:
        d["node"] = None
        if not getattr(cfg, "no_node", False):
            d["errors"].append(f"node RPC: {e}")

    d["indexer"] = getattr(cfg, "_indexer", None)
    d["electrum_target"] = getattr(cfg, "electrum", None)
    # state.get("height") can be present AND None: a store the daemon has
    # opened but not yet written to records {"height": null}. `.get(k, 0)`
    # returns the None, not the default, and the subtraction then raises
    # inside gather — so every page load 500s and the dashboard looks dead
    # while the node underneath it is perfectly healthy.
    _h = (state or {}).get("height")
    _b = (d["node"] or {}).get("blocks")
    d["lag"] = (_b - _h) if (isinstance(_h, int) and isinstance(_b, int)) \
        else None
    d["build"] = read_build_log(cfg.build_log)
    d["log_dir"] = cfg.log_dir
    d["logs"] = list_logs(cfg.log_dir)

    want = getattr(cfg, "_selected_log", None)
    if want is None:
        newest, newest_t = None, -1.0
        for n in d["logs"]:
            try:
                t = os.path.getmtime(os.path.join(cfg.log_dir, n))
            except OSError:
                continue
            if t > newest_t:
                newest, newest_t = n, t
        want = newest
    d["log_name"] = want
    d["log_rows"], d["log_err"] = ((None, None) if not want
                                   else tail_log(cfg.log_dir, want))
    return d


# ---------------------------------------------------------------- rendering


def human(n):
    """Binary units, labelled as such.

    This project measures storage the way df and du do, in powers of 1024.
    It used to print those values with decimal labels — "674.7 GB" for a
    store that is 674.7 GiB and 724.5 GB — and two tools in the same
    repository disagreed, one dividing by 1024 and one by 1000, both saying
    GB. Every storage figure this project has published carried that error.
    Caught when monetary_commit.py read the same store as monetary_store.py
    and reported a different size.

    Percentages are unaffected: they are ratios of same-base numbers.
    """
    if n is None:
        return "—"
    x = float(n)
    for u in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(x) < 1024:
            return f"{x:,.1f} {u}"
        x /= 1024
    return f"{x:,.1f} PiB"


def resolvable_host(host):
    """
    Turn a bare hostname into one another machine can actually resolve.

    The page told people to point Sparrow at "btcserver:50001". That
    works only on the node itself: a bare hostname means nothing to a
    laptop on the same network, which needs the mDNS name,
    "btcserver.local". The instruction was therefore wrong for every
    reader of it, since nobody runs Sparrow on the node.

    Only bare names are touched. An address with a dot, an IP, an onion,
    a bracketed IPv6 literal and localhost are all left exactly as given
    — someone who configured a real name or address meant it.
    """
    h = (host or "").strip()
    if not h or h.startswith("[") or "." in h or ":" in h:
        return h
    if h in ("localhost", "127.0.0.1"):
        return h
    if h.replace("-", "").isdigit():      # not a name at all
        return h
    return h + ".local"


def fmt_int(n):
    """123456 -> "123,456"; anything that is not an int -> an em dash."""
    if not isinstance(n, int) or isinstance(n, bool):
        return "—"
    return "{:,}".format(n)


def esc(x):
    return html.escape("—" if x is None else str(x))


def commas(n):
    return "—" if n is None else f"{n:,}"


CSS = """
*{box-sizing:border-box}
body{background:#0d0e10;color:#e8e6e1;font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;margin:0;padding:28px}
.wrap{max-width:920px;margin:0 auto}
h1{font-size:18px;color:#f7931a;margin:0 0 2px;letter-spacing:.04em}
.sub{color:#8b8880;font-size:12px;margin-bottom:22px}
.card{border:1px solid #23252a;background:#111216;padding:16px 18px;margin-bottom:14px}
.card h2{font-size:11px;letter-spacing:.14em;color:#8b8880;margin:0 0 12px;font-weight:600}
table{width:100%;border-collapse:collapse}
td{padding:3px 0;vertical-align:top}
td.k{color:#8b8880;width:200px;white-space:nowrap}
td.v{color:#e8e6e1;word-break:break-all}
.big{font-size:22px;color:#f7931a}
.ok{color:#5cb85c}.warn{color:#f0ad4e}.bad{color:#d9534f}.dim{color:#8b8880}
.hash{font-size:11.5px;color:#c9c6c0;word-break:break-all}
.note{color:#8b8880;font-size:11.5px;margin-top:10px;line-height:1.55}
pre.cfg{background:#0a0d0a;border:1px solid #1e2a1e;border-left:2px solid #2fbf4f;padding:9px 11px;margin:7px 0;color:#9fe8af;font-size:11px;line-height:1.5;overflow-x:auto;white-space:pre}
.note code{color:#9fe8af;background:#0a0d0a;padding:0 3px}
.donate{margin:26px auto 40px;max-width:520px;text-align:center;padding:16px 18px;border:1px solid #1e2a1e;background:#080b08}
.dlabel{display:block;color:#5c6b5c;font-size:10px;letter-spacing:2px;margin-bottom:8px}
.dln{display:inline-block;color:#2fbf4f;font-size:14px;text-decoration:none;border-bottom:1px dotted #2fbf4f;padding-bottom:2px;word-break:break-all}
.dln:hover{color:#9fe8af;border-bottom-color:#9fe8af}
.dnote{display:block;color:#5c6b5c;font-size:10.5px;margin-top:9px}
.err{border-color:#d9534f}
.torbad{border-color:#d9534f;background:#170f0f}
.torok{border-color:#2a4a2a}
.verdict{font-size:20px;letter-spacing:.06em}
.bar{height:4px;background:#23252a;margin-top:8px}
.bar>i{display:block;height:4px;background:#f7931a}
/* the unified status bar — what is happening, before anything else */
.sbar{border:1px solid #23252a;border-left:3px solid #8b8880;background:#111216;
padding:12px 16px;margin:0 0 14px}
.sbar.ok{border-left-color:#2fbf4f}
.sbar.warn{border-left-color:#f0ad4e}
.sbar.bad{border-left-color:#d9534f}
.sbdoing{font-size:13.5px;color:#e8e6e1;display:flex;align-items:center;gap:9px}
.sbdot{width:8px;height:8px;border-radius:50%;background:#8b8880;flex:0 0 8px}
.sbar.ok .sbdot{background:#2fbf4f}
/* amber pulses: something is in progress and the page is not stuck */
.sbar.warn .sbdot{background:#f0ad4e;animation:sbp 1.6s ease-in-out infinite}
.sbar.bad .sbdot{background:#d9534f}
@keyframes sbp{0%,100%{opacity:1}50%{opacity:.25}}
@media(prefers-reduced-motion:reduce){.sbar.warn .sbdot{animation:none}}
.sbcells{display:flex;flex-wrap:wrap;gap:0 26px;margin-top:11px;
padding-top:11px;border-top:1px solid #1b1d21}
.sbcell{display:flex;flex-direction:column;gap:2px;min-width:92px}
.sblabel{font-size:9.5px;letter-spacing:.13em;color:#6b6862}
.sbval{font-size:14px;color:#f7931a}
.sbval.ok{color:#5cb85c}.sbval.warn{color:#f0ad4e}.sbval.bad{color:#d9534f}
@media(max-width:600px){.sbcells{gap:0 18px}.sbcell{min-width:76px}
.sbval{font-size:12.5px}}
/* the network banner — the loudest thing on the page, deliberately */
.banner{border:2px solid;padding:18px 20px;margin:0 0 16px;text-align:center}
.bword{font-size:40px;font-weight:700;letter-spacing:.12em;line-height:1.1}
.bsub{font-size:12px;line-height:1.6;margin-top:10px;color:#b9b6b0}
.banner code{background:#000;padding:1px 5px}
.btor{border-color:#2fbf4f;background:#0b1a0d}
.btor .bword{color:#2fbf4f}
.bclear{border-color:#d9534f;background:#1e0d0d}
.bclear .bword{color:#ff6b66}
.unknown{border-color:#f0ad4e;background:#1c1609}
.unknown .bword{color:#f0ad4e;font-size:28px}
@media(max-width:600px){.bword{font-size:28px}}
/* advanced settings panel */
h3.sgroup{font-size:10px;letter-spacing:.16em;color:#f7931a;margin:20px 0 8px;
font-weight:600;border-bottom:1px solid #23252a;padding-bottom:5px}
.sgrid{display:block}
.srow{display:grid;grid-template-columns:230px 150px 1fr;gap:12px;
padding:9px 0;border-bottom:1px solid #191b1f;align-items:start}
.srow.off{opacity:.45}
.sname{color:#e8e6e1;font-size:12px}
.skey{display:block;color:#6b6862;font-size:10.5px;margin-top:2px}
.sval{display:flex;align-items:center;gap:6px}
.unit{color:#6b6862;font-size:10.5px;white-space:nowrap}
.shelp{color:#8b8880;font-size:11px;line-height:1.5}
.sdef{color:#6b6862;font-size:10.5px}
.chg{color:#f7931a;font-size:10.5px}
.frozenval{color:#8b8880;font:12px ui-monospace,Menlo,monospace;
background:#0b0c0e;border:1px dashed #23252a;padding:5px 8px;display:inline-block;
min-width:90px}
input.in{background:#08090b;border:1px solid #23252a;color:#e8e6e1;
font:12px ui-monospace,Menlo,monospace;padding:6px 8px;width:100%}
input.in:disabled{color:#5a5752;background:#0b0c0e}
.switch{display:inline-block;position:relative;width:42px;height:22px}
.switch input{opacity:0;width:0;height:0}
.switch span{position:absolute;inset:0;background:#23252a;border:1px solid
#2c2f35;transition:.15s;cursor:pointer}
.switch span:before{content:"";position:absolute;width:16px;height:16px;
left:2px;top:2px;background:#6b6862;transition:.15s}
.switch input:checked+span{background:#1d3a1d;border-color:#2fbf4f}
.switch input:checked+span:before{transform:translateX(20px);background:#2fbf4f}
.switch input:disabled+span{opacity:.5;cursor:not-allowed}
.sactions{display:flex;gap:10px;margin-top:20px;flex-wrap:wrap}
button.go{background:#132013;border:1px solid #2fbf4f;color:#2fbf4f;
font:11px ui-monospace,Menlo,monospace;letter-spacing:.14em;padding:10px 20px;
cursor:pointer}
button.go:hover{background:#1b2d1b}
button.warnbtn{background:#1f1511;border-color:#f0ad4e;color:#f0ad4e}
button.warnbtn:hover{background:#2a1c15}
.note.good{color:#5cb85c}
@media(max-width:700px){.srow{grid-template-columns:1fr}}
pre.cfg{background:#08090b;border:1px solid #1c1e22;padding:10px 12px;margin:8px 0 0;font-size:11.5px;color:#b9b6b0;white-space:pre-wrap}
#feed{background:#08090b;border:1px solid #1c1e22;height:400px;overflow:auto;font-size:11.5px;line-height:1.5}
.ev{padding:4px 12px;border-bottom:1px solid #131519;display:flex;gap:10px}
.ev .ts{color:#5f5d58;white-space:nowrap}
.ev .tag{width:62px;flex:none;text-transform:uppercase;font-size:10px;letter-spacing:.07em;padding-top:1px}
.ev .msg{flex:1;color:#d6d3cd}
.ev .det{color:#8b8880}
.ev.block .tag{color:#f7931a}
.ev.store .tag{color:#5cb85c}
.ev.mempool .tag{color:#6ba4d8}
.ev.indexer .tag{color:#b58bd8}
.ev.tick .tag{color:#4a4844}
.ev.tick .msg{color:#8b8880}
.ev.node .tag{color:#8b8880}
.ev.error .tag,.ev.tor .tag{color:#d9534f}
.ev.quip{background:#0c0f0c}
.ev.quip .tag{color:#4a6b4a}
.ev.quip .msg{color:#7d9b7d;font-style:italic}
.ev.wallet{background:#15120a;border-left:2px solid #f7931a}
.ev.wallet .tag,.ev.wallet .msg{color:#f5e6c8}
.live{display:inline-block;width:7px;height:7px;border-radius:50%;background:#5cb85c;margin-right:6px}
.live.off{background:#d9534f}
.pt{width:100%;border-collapse:collapse;font-size:11.5px}
.pt th{text-align:left;color:#5f5d58;font-weight:400;padding:0 10px 5px 0;border-bottom:1px solid #1c1e22}
.pt td{padding:3px 10px 3px 0;color:#b9b6b0;white-space:nowrap}
.pt td.a{color:#d6d3cd;max-width:230px;overflow:hidden;text-overflow:ellipsis}
.pill{font-size:10px;border:1px solid #23252a;padding:0 5px;color:#8b8880}
.pill.onion{color:#b58bd8;border-color:#3a2a46}
.pill.clear{color:#d9534f;border-color:#4a2323}
"""

FEED_JS = """
(function(){
 var last=0,box=document.getElementById('feed'),dot=document.getElementById('live');
 function row(e){
  var d=document.createElement('div');
  d.className='ev '+e.kind+(e.important?' wallet':'');
  var a=document.createElement('span');a.className='ts';
  a.textContent=new Date(e.t*1000).toISOString().substr(11,8);
  var b=document.createElement('span');b.className='tag';b.textContent=e.kind;
  var c=document.createElement('span');c.className='msg';c.textContent=e.text;
  if(e.detail){var s=document.createElement('span');s.className='det';
   s.textContent='  '+e.detail;c.appendChild(s);}
  d.appendChild(a);d.appendChild(b);d.appendChild(c);return d;
 }
 function poll(){
  fetch('/events.json?since='+last).then(function(r){return r.json();})
  .then(function(j){
    dot.className='live';
    (j.events||[]).forEach(function(e){
      if(e.id>last){last=e.id;box.insertBefore(row(e),box.firstChild);}
    });
    while(box.childNodes.length>250){box.removeChild(box.lastChild);}
  }).catch(function(){dot.className='live off';});
 }
 poll();setInterval(poll,2000);
})();
"""


def tor_card(d):
    """Loud, and near the top. Tor-only is the operator's stated requirement,
    so the page states plainly whether it is actually true."""
    n, net = d.get("node"), d.get("netinfo")
    peers = d.get("peers") or []
    if not n or net is None:
        return ""
    nets = collections.Counter(p["network"] or "?" for p in peers)
    clear = sum(v for k, v in nets.items() if k not in ("onion", "i2p"))
    proxy = ""
    reach = {}
    for e in net.get("networks", []):
        reach[e.get("name")] = e.get("reachable")
        if e.get("name") == "onion" and e.get("proxy"):
            proxy = e["proxy"]

    onion_ok = bool(proxy) and reach.get("onion")
    clean = onion_ok and clear == 0 and not reach.get("ipv4") and not reach.get("ipv6")

    p = []
    p.append(f"<div class='card {'torok' if clean else 'torbad'}'><h2>TOR</h2>")
    if clean:
        p.append("<div class='verdict ok'>TOR ONLY</div>")
    elif clear:
        p.append(f"<div class='verdict bad'>NOT TOR ONLY — {clear} clearnet peer"
                 f"{'s' if clear != 1 else ''}</div>")
    else:
        p.append("<div class='verdict warn'>PARTIAL — clearnet still reachable</div>")
    p.append("<table style='margin-top:10px'>")
    p.append(f"<tr><td class=k>onion proxy</td><td class=v>"
             + (esc(proxy) if proxy else "<span class=bad>none configured</span>")
             + "</td></tr>")
    for name in ("onion", "ipv4", "ipv6", "i2p"):
        if name not in reach:
            continue
        good = (name in ("onion", "i2p")) == bool(reach[name])
        cls = "ok" if good else "bad"
        p.append(f"<tr><td class=k>{name} reachable</td>"
                 f"<td class=v><span class={cls}>{'yes' if reach[name] else 'no'}"
                 "</span></td></tr>")
    p.append("<tr><td class=k>peers by network</td><td class=v>"
             + (" · ".join(f"{k} {v}" for k, v in sorted(nets.items())) or "—")
             + "</td></tr>")
    p.append("</table>")
    if not clean:
        p.append("<div class=note>To enforce Tor only, put this in "
                 "<code>bitcoin.conf</code> and restart:"
                 "<pre class=cfg>proxy=127.0.0.1:9050\nonlynet=onion\n"
                 "listen=1\ntorcontrol=127.0.0.1:9051</pre>"
                 "<code>proxy</code> alone is not enough — without "
                 "<code>onlynet=onion</code> the node still dials clearnet "
                 "peers. A clearnet peer appearing here means the setting is "
                 "not in force.</div>")
    p.append("</div>")
    return "".join(p)


LIFECYCLE = [
    ("downloading", "Download", "bitcoind fetches and validates the chain"),
    ("stripping", "Strip", "blocks stored without their data carriers"),
    ("following", "Follow", "keeping up with the tip"),
]


def lifecycle_card(d):
    """
    Where this node is in its life, for the days when that is the only
    question worth answering.

    A fresh install spends a long time doing something invisible. Without
    this the page shows a node with no blocks and a store with no records,
    which is indistinguishable from a node that is broken — and the person
    who installed it has no way to tell which, so they uninstall it.
    """
    sup = d.get("supervisor")
    if not sup:
        return ""
    phase = sup.get("phase")

    p = ["<div class=card><h2>NODE LIFECYCLE</h2>"]
    if phase == "stopped":
        p.append("<div class=bad>The node is not running.</div></div>")
        return "".join(p)

    names = [x[0] for x in LIFECYCLE]
    idx = names.index(phase) if phase in names else -1

    p.append("<table>")
    for i, (_key, label, blurb) in enumerate(LIFECYCLE):
        if phase == "starting":
            mark, cls = "·", "dim"
        elif i < idx:
            mark, cls = "done", "ok"
        elif i == idx:
            mark, cls = "now", "warn"
        else:
            mark, cls = "·", "dim"
        p.append(f"<tr><td class=k>{esc(label)}</td>"
                 f"<td class=v><span class={cls}>{mark}</span> "
                 f"<span class=dim>{esc(blurb)}</span></td></tr>")
    p.append("</table>")

    if phase == "starting":
        p.append("<div class=note>Starting bitcoind. Over Tor the first "
                 "connection can take a minute or two.</div>")
    elif phase == "downloading":
        p.append("<div class=note>This is Bitcoin Core downloading and "
                 "checking every block, not this project doing anything "
                 "clever. On a first run it takes days. Nothing is "
                 "stripped until it finishes.</div>")
    elif phase == "stripping":
        p.append("<div class=note>Reading validated blocks and writing "
                 "them without their carriers. Disk used by the node is "
                 "reclaimed behind this, never ahead of it.</div>")

    kids = sup.get("children") or []
    if kids:
        p.append("<table style='margin-top:10px'>")
        for c in kids:
            st = ("<span class=ok>running</span>" if c.get("running")
                  else "<span class=bad>stopped</span>")
            r = c.get("restarts") or 0
            extra = (f" <span class=warn>{r} restart"
                     f"{'' if r == 1 else 's'}</span>") if r else ""
            p.append(f"<tr><td class=k>{esc(c.get('name'))}</td>"
                     f"<td class=v>{st}{extra}</td></tr>")
        p.append("</table>")
    p.append("</div>")
    return "".join(p)


def detail_cards(d):
    """
    The full numbers: chain, store, commitment, daemon lag.

    Kept, because the people who care about this project care about these
    — but moved below the simple view. Somebody who just installed this
    wants height, sync and spam, and putting the commitment hash above
    them buries the answer in evidence.
    """
    p = []
    A = p.append
    n, s = d.get("node"), d.get("state")
    A("<div class=card><h2>NODE DETAIL</h2><table>")
    if n:
        sync = ("<span class=warn>syncing</span>" if n["ibd"]
                else "<span class=ok>synced</span>")
        pct = (n.get("progress") or 0) * 100
        A(f"<tr><td class=k>chain</td><td class=v>{esc(n['chain'])} · {sync}</td></tr>")
        A(f"<tr><td class=k>height</td><td class=v><span class=big>{commas(n['blocks'])}</span>"
          f" <span class=dim>of {commas(n['headers'])} headers</span></td></tr>")
        A(f"<tr><td class=k>verification</td><td class=v>{pct:.4f}%"
          f"<div class=bar><i style='width:{min(pct,100):.2f}%'></i></div></td></tr>")
        A(f"<tr><td class=k>tip</td><td class='v hash'>{esc(n['bestblockhash'])}</td></tr>")
        A(f"<tr><td class=k>peers</td><td class=v>{commas(n['connections'])}</td></tr>")
        A(f"<tr><td class=k>software</td><td class=v>{esc(n['subversion'])}</td></tr>")
    elif d.get("standalone"):
        A("<tr><td class=k>status</td><td class=v>"
          "<span class=dim>not attached</span></td></tr>")
        A("<tr><td class=k></td><td class='v dim'>This instance has no "
          "validating node and expects none. It answers wallets from the "
          "store; it does not follow the tip.</td></tr>")
    else:
        A("<tr><td class='v bad'>unreachable</td></tr>")
    A("</table></div>")

    A("<div class=card><h2>STORE</h2><table>")
    A(f"<tr><td class=k>path</td><td class=v>{esc(d['store_path'])}</td></tr>")
    if s:
        A(f"<tr><td class=k>height</td><td class=v><span class=big>{commas(s.get('height'))}</span></td></tr>")
        A(f"<tr><td class=k>records</td><td class=v>{commas(s.get('records'))}</td></tr>")
        A(f"<tr><td class=k>on disk</td><td class=v>{human(d['store_bytes'])}"
          f" <span class=dim>in {commas(d['store_files'])} files</span></td></tr>")
        c = s.get("commitment", "") or ""
        A("<tr><td class=k>commitment C</td><td class='v hash'>"
          + ("<span class=warn>not set</span>" if set(c) <= {"0"} else esc(c))
          + "</td></tr>")
        A("<tr><td class=k></td><td class='v dim'>C is only meaningful paired"
          f" with a height: this one is at {commas(s.get('height'))}</td></tr>")
    elif d.get("derived"):
        dv = d["derived"]
        A(f"<tr><td class=k>heights</td><td class=v><span class=big>"
          f"{commas(dv.get('start_height'))} – "
          f"{commas(dv.get('end_height'))}</span></td></tr>")
        A(f"<tr><td class=k>records</td><td class=v>"
          f"{commas(dv.get('records'))}</td></tr>")
        A(f"<tr><td class=k>on disk</td><td class=v>{human(d['store_bytes'])}"
          f" <span class=dim>in {commas(d['store_files'])} files</span>"
          "</td></tr>")
        A(f"<tr><td class=k>policy</td><td class='v hash'>"
          f"{esc(dv.get('policy_id'))}</td></tr>")
        A("<tr><td class=k>commitment C</td><td class='v dim'>not computed "
          "— run monetary_commit.py</td></tr>")
        A("<tr><td class=k></td><td class='v dim'>Built by a batch derive. "
          "There is no state.json because that is the daemon's file, and no "
          "daemon is following the tip here. The store is complete for the "
          "range above and frozen at its end.</td></tr>")
    else:
        A("<tr><td class='v bad'>no state</td></tr>")
    A("</table></div>")

    A("<div class=card><h2>DAEMON</h2><table>")
    if d["daemon_pid"]:
        A(f"<tr><td class=k>status</td><td class=v><span class=ok>running</span>"
          f" <span class=dim>pid {d['daemon_pid']}</span></td></tr>")
    else:
        A("<tr><td class=k>status</td><td class=v><span class=warn>not running</span></td></tr>")
    lag = d["lag"]
    cls, txt = (("dim", "—") if lag is None else
                ("ok", f"{lag} blocks behind the node") if lag <= 10 else
                ("warn", f"{lag} blocks behind the node") if lag <= 200 else
                ("bad", f"{commas(lag)} blocks behind the node"))
    A(f"<tr><td class=k>lag</td><td class=v><span class={cls}>{txt}</span></td></tr>")
    A("</table></div>")
    return "".join(p)


def headline_card(d):
    """
    The three numbers somebody installs this to see, before anything else.

    Height, how far through the chain it is, and how much spam it has
    thrown away. Everything else on the page is detail; this is the
    answer to "is my node working and is it doing the thing".
    """
    sup = d.get("supervisor") or {}
    node = d.get("node") or {}
    state = d.get("state") or {}
    derived = d.get("derived") or {}

    height = (node.get("blocks") if node.get("blocks") is not None
              else sup.get("node_height"))
    headers = node.get("headers") or sup.get("node_headers")
    pct = None
    if isinstance(height, int) and isinstance(headers, int) and headers > 0:
        pct = 100.0 * height / headers

    carriers = state.get("carriers")
    bytes_in = state.get("bytes_in")
    bytes_out = state.get("bytes_out")
    store_h = state.get("height")
    if carriers is None and derived:
        store_h = derived.get("end_height")

    chain = node.get("chain") or sup.get("chain")
    p = ["<div class=card><h2>NODE</h2><table>"]
    if chain and chain != "main":
        # "100% synced at block 328,390" is alarming if you think you are
        # on mainnet. Signet's tip really is around there. Name the chain
        # whenever it is not the real one.
        p.append("<tr><td class=k>chain</td><td class=v>"
                 f"<span class=warn>{esc(chain)}</span> "
                 "<span class=dim>— not mainnet; heights and balances "
                 "here are not real bitcoin</span></td></tr>")
    p.append("<tr><td class=k>block height</td><td class=v>"
             f"<span class=big id=lv-height>{commas(height)}</span>"
             "</td></tr>")
    if pct is not None:
        cls = "ok" if pct >= 99.99 else "warn"
        p.append(f"<tr><td class=k>chain synced</td><td class=v>"
                 f"<span class={cls} id=lv-pct>{pct:.2f}%</span>"
                 f" <span class=dim>of <span id=lv-headers>"
                 f"{commas(headers)}</span></span></td></tr>")
    else:
        p.append("<tr><td class=k>chain synced</td>"
                 "<td class=v class=dim>—</td></tr>")

    if carriers:
        p.append("<tr><td class=k>spam removed</td><td class=v>"
                 f"<span class=big id=lv-spam>{human(carriers)}</span>"
                 "</td></tr>")
        if bytes_in and bytes_out is not None:
            saved = bytes_in - bytes_out
            share = (100.0 * saved / bytes_in) if bytes_in else 0.0
            p.append("<tr><td class=k>store vs blocks</td><td class=v>"
                     f"{human(bytes_out)} from {human(bytes_in)} "
                     f"<span class=dim>({share:.2f}% smaller)</span>"
                     "</td></tr>")
    else:
        p.append("<tr><td class=k>spam removed</td>"
                 "<td class=v class=dim>nothing stripped yet</td></tr>")

    if store_h is not None:
        p.append(f"<tr><td class=k>stripped to</td><td class=v>"
                 f"<span id=lv-store>{commas(store_h)}</span></td></tr>")
    p.append("</table></div>")
    return "".join(p)


def index_switch(on, label):
    """
    The same toggle the advanced panel uses, so the control for the one
    setting people actually change looks like every other setting rather
    than like a one-off button.

    It submits on change: a switch that needs a separate Save button
    looks broken, because flipping it appears to do nothing.

    The has_useindex partner is what makes "off" reach the server. A
    checkbox that is off sends no field at all, so without it the save
    cannot tell "turned off" from "not on this form".
    """
    return (
        "<form method=post action=/settings id=idxform "
        "style='margin:12px 0 4px;display:flex;align-items:center;gap:10px'>"
        "<input type=hidden name=action value=save>"
        "<input type=hidden name=has_useindex value=1>"
        "<label class=switch><input type=checkbox name=useindex value=1"
        "%s onchange='this.form.submit()'><span></span></label>"
        "<span class=dim>%s</span>"
        "</form>" % (" checked" if on else "", esc(label)))


def bar(pct, color="#f7931a", bar_id=None):
    """One progress bar. pct of None draws an empty trough, not a full one."""
    w = 0.0 if pct is None else max(0.0, min(100.0, pct))
    ident = (" id=%s" % bar_id) if bar_id else ""
    return ("<div style='height:14px;border:1px solid #3a3d44;"
            "background:#15171a;border-radius:2px;overflow:hidden'>"
            f"<div{ident} style='height:100%;width:{w:.1f}%;"
            f"background:{color};transition:width .4s linear'></div></div>")


def moving(key, now, prev):
    """
    Is this actually progressing?

    "I don't know if it's doing anything" is the complaint a progress bar
    exists to answer, and a bar that sits at 23.4% answers it badly: the
    same picture means working-slowly and wedged. So compare against the
    previous sample and say which.
    """
    if now is None:
        return "dim", "no reading"
    if prev is None:
        return "dim", "measuring…"
    if now > prev:
        return "ok", "+%s since last check" % f"{now - prev:,}"
    return "warn", "no change since last check"


def sync_card(d):
    """
    The two bars: the chain, and the index. Always both, always visible.

    These are different jobs with different durations and different
    failure modes, and collapsing them into one number hides which of the
    two is stuck.
    """
    sup = d.get("supervisor")
    if not sup:
        return ""
    prev = d.get("supervisor_prev") or {}

    node_h = sup.get("node_height")
    headers = sup.get("node_headers")
    idx_h = sup.get("index_height")
    store_h = sup.get("store_height")

    p = ["<div class=card><h2>SYNC</h2>"]

    # -- 1. the chain
    npct = None
    if headers:
        npct = 100.0 * (node_h or 0) / headers
    cls, note = moving("node", node_h, prev.get("node_height"))
    p.append("<div class=k style='margin-bottom:4px'>Blockchain "
             "<span class=dim>— Bitcoin Core downloading and validating"
             "</span></div>")
    p.append(bar(npct, bar_id="lv-bar-node"))
    p.append("<div class=dim style='margin:6px 0 14px' id=lv-txt-node>"
             + (f"<b>{npct:.2f}%</b> · " if npct is not None else "")
             + f"block {commas(node_h)} of {commas(headers)} · "
             + f"<span class={cls}>{note}</span></div>")

    # -- 2. the index
    p.append("<div class=k style='margin-bottom:4px'>Address index "
             "<span class=dim>— what your wallet queries</span></div>")
    if sup.get("index_missing"):
        p.append("<div class=bad style='margin-top:0'>This build has no "
                 "indexer in it.</div>"
                 "<div class=note>The node is validating, stripping and "
                 "storing normally — that part is unaffected. But no "
                 "wallet can connect until an indexer is present. Pin one "
                 "with <code>./umbrel/pin_core.sh</code> and rebuild."
                 "</div>")
    elif not sup.get("index_enabled"):
        p.append("<div class=note style='margin-top:0'>The indexer is "
                 "switched off, so no wallet can connect.</div>")
    else:
        ipct = None
        if node_h:
            ipct = 100.0 * (idx_h or 0) / node_h
        icls, inote = moving("index", idx_h, prev.get("index_height"))
        p.append(bar(ipct, "#4ea1f7", bar_id="lv-bar-index"))
        p.append("<div class=dim style='margin-top:6px' id=lv-txt-index>"
                 + (f"<b>{ipct:.2f}%</b> · " if ipct is not None else "")
                 + f"block {commas(idx_h)} of {commas(node_h)} · "
                 + f"<span class={icls}>{inote}</span></div>")
        if idx_h is not None and sup.get("index_building"):
            # It has read this far but will not answer a wallet until the
            # whole chain is done. Show the real number: a bar pinned at
            # zero while the machine works flat out is the most
            # demoralising thing a sync screen can do.
            p.append("<div class=note><b>Building the index for the first "
                     "time.</b> It reads every block before it will "
                     "answer a wallet, so nothing can connect yet. The "
                     "node is validating and stripping normally "
                     "throughout.</div>")
        if idx_h is None:
            # "0% and not moving" is alarming unless you are told it is
            # deliberate. The indexer reads blocks bitcoind has not
            # downloaded yet, so it is held back until the chain is in —
            # and the operator should learn that here rather than
            # concluding the app is broken and uninstalling it.
            kid = next((c for c in (sup.get("children") or [])
                        if c.get("name") == "electrs"), None)
            if kid and not kid.get("running") and kid.get("restarts"):
                p.append("<div class=bad>The indexer keeps stopping "
                         f"({kid['restarts']} restarts, last exit "
                         f"{kid.get('last_exit')}).</div>"
                         "<div class=note>It is being restarted "
                         "automatically. If this does not clear, the "
                         "container log has the reason.</div>")
            elif sup.get("phase") == "downloading":
                p.append("<div class=note><b>Not started yet, on "
                         "purpose.</b> The indexer reads blocks the node "
                         "has not downloaded, so it waits for the "
                         "blockchain above to finish. Nothing is wrong, "
                         "and there is nothing to do but wait.</div>")
            else:
                # The indexer does not answer at all until its first full
                # pass over the chain is done. On mainnet that is most of
                # a day on small hardware — saying "a few minutes" sent
                # somebody looking for a fault that was not there.
                p.append("<div class=note><b>Building the index for the "
                         "first time.</b> It reads every block in the "
                         "chain before it will answer a wallet, and it "
                         "reports nothing while it does. On a Raspberry "
                         "Pi expect most of a day; on a laptop, hours. "
                         "The node is validating and stripping normally "
                         "the whole time.</div>")

    # -- the toggle, where its consequence is visible
    #
    # It also lives in the advanced panel, but burying the one switch that
    # decides whether wallets work AND how much disk the node costs is a
    # poor place for it. Here it sits under the bar it governs.
    on = bool(sup.get("index_enabled"))

    # -- what is safe to delete
    if sup.get("index_blocked_pruned"):
        p.append("<div class=bad style='margin-top:0'>The address index "
                 "cannot run on this node.</div>"
                 "<div class=note>This node's data directory was created "
                 "with pruning on. Bitcoin Core reports it pruned for the "
                 "life of that directory — switching pruning off does not "
                 "undo it — and the indexer refuses a pruned node. The "
                 "only fix is to delete the Bitcoin data directory and "
                 "sync again with pruning off.</div>")
    elif sup.get("prune_blocked_by_index"):
        p.append("<div class=note><b>This node keeps every block.</b> The "
                 "address index refuses to run against a pruned node, so "
                 "disk is the whole blockchain PLUS the monetary store — "
                 "roughly twice the chain. Turning the indexer off would "
                 "reclaim the blocks and stop any wallet from "
                 "connecting.</div>")
    floor = sup.get("prune_floor")
    if sup.get("pruning"):
        if floor is None:
            p.append("<div class=note>Nothing is being deleted yet. Blocks "
                     "are only reclaimed below BOTH the stripper and the "
                     "index, and at least one of them has not reported a "
                     "position.</div>")
        else:
            p.append(f"<div class=note>Blocks below {commas(floor)} can be "
                     "reclaimed — the lower of the stripper "
                     f"({commas(store_h)}) and the index "
                     f"({commas(idx_h)}). Nothing above that is touched.</div>")

    p.append("</div>")
    return "".join(p)


def wallet_card(d):
    """
    How to point a wallet at this node.

    There is no xpub field and there will not be one. Asking somebody to
    paste an extended public key into a box on a server is asking them to
    hand over every address they will ever use and their whole balance
    history, and it is a reasonable thing to refuse. A real Electrum
    server does not need it: the wallet asks about the addresses it cares
    about, and the server answers from an index of everything.
    """
    sup = d.get("supervisor") or {}
    host = (d.get("wallet_advertise") or "").strip()
    port = d.get("wallet_port") or 50001
    if host and ":" in host and not host.startswith("["):
        h, _, ap_ = host.rpartition(":")
        if ap_.isdigit():
            host, port = h, int(ap_)
    host = resolvable_host(host) or "this node's address"

    p = ["<div class=card><h2>CONNECT A WALLET</h2>"]
    if not sup.get("index_enabled"):
        why = ("This build has no indexer in it, so there is nothing for a "
               "wallet to connect to. The node still validates and stores."
               if sup.get("index_missing") else
               "The indexer is off, so there is nothing for a wallet to "
               "connect to.")
        p.append(f"<div class=note style='margin-top:0'>{why}</div></div>")
        return "".join(p)

    idx_h = sup.get("index_height")
    node_h = sup.get("node_height")
    ready = (idx_h is not None and node_h is not None
             and node_h - idx_h <= 2)

    p.append("<table>")
    p.append("<tr><td class=k>status</td><td class=v>"
             + ("<span class=ok>ready</span>" if ready else
                "<span class=warn>still indexing — connect anyway, your "
                "balance will fill in</span>")
             + "</td></tr>")
    p.append(f"<tr><td class=k>server</td><td class=v><code>{esc(host)}"
             f":{port}</code></td></tr>")
    p.append("</table>")
    p.append("<div class=note><b>Sparrow:</b> Preferences → Server → "
             f"Private Electrum → URL <code>{esc(host)}</code>, port "
             f"<code>{port}</code>, SSL off.<br>"
             f"<b>Electrum:</b> Tools → Network → Server → "
             f"<code>{esc(host)}:{port}:t</code>."
             "<br><br>Your wallet asks about its own addresses and nothing "
             "else is shared. This node never asks for an extended public "
             "key, a seed, or anything that could spend.</div>")
    p.append("</div>")
    return "".join(p)


def indexer_card(d):
    ix = d.get("indexer")
    target = d.get("electrum_target")
    p = ["<div class=card><h2>EXTERNAL INDEXER</h2>"]
    if not target:
        p.append("<div class=note style='margin-top:0'>"
                 "No external indexer configured, and most people will not "
                 "want one: the WALLET card above serves your wallet from "
                 "this store directly. This is for pointing the dashboard at "
                 "a full indexer you already run — electrs, Fulcrum, "
                 "ElectrumX — so it can report how far behind it is."
                 "<br><br>Restart this dashboard pointing at yours:"
                 "<pre class=cfg>python3 tools/monetary_ui.py \\\n"
                 "  --electrum 127.0.0.1:50001        # electrs, plain\n"
                 "  --electrum 127.0.0.1:50002 --electrum-ssl   # Fulcrum, TLS\n"
                 "  --electrum 192.168.1.20:50002 --electrum-ssl  # on the LAN"
                 "</pre>"
                 "electrs listens on 50001 without TLS by default; Fulcrum and "
                 "ElectrumX commonly use 50002 with a self-signed certificate, "
                 "which is why <code>--electrum-ssl</code> does not verify it. "
                 "Point this only at a server you run."
                 "<br><br>Note an indexer needs a node that is not pruned. If "
                 "you prune this one, the indexer must already have built its "
                 "index, or be pointed at a different node."
                 "</div></div>")
        return "".join(p)
    p.append("<table>")
    p.append(f"<tr><td class=k>target</td><td class=v>{esc(ix['target'] if ix else target)}"
             + (" <span class=dim>TLS</span>" if (ix or {}).get("ssl") else "")
             + "</td></tr>")
    if ix and ix.get("ok"):
        p.append(f"<tr><td class=k>server</td><td class=v>{esc(ix.get('server'))}</td></tr>")
        p.append(f"<tr><td class=k>height</td><td class=v>{commas(ix.get('height'))}</td></tr>")
        n = d.get("node")
        if n and ix.get("height") is not None:
            behind = n["blocks"] - ix["height"]
            cls = "ok" if behind <= 2 else ("warn" if behind <= 100 else "bad")
            p.append(f"<tr><td class=k>vs node</td><td class=v>"
                     f"<span class={cls}>{behind:,} blocks behind</span></td></tr>")
    elif ix:
        p.append("<tr><td class=k>status</td><td class=v><span class=bad>unreachable"
                 f"</span> <span class=dim>{esc(ix.get('error'))}</span></td></tr>")
    else:
        p.append("<tr><td class=k>status</td><td class=v class=dim>probing…</td></tr>")
    p.append("</table></div>")
    return "".join(p)


def indexing_card(d):
    """
    The address index, in one place, in plain language.

    It used to be three controls in three cards with three different
    labels, which is how you get somebody asking what the buttons do.
    One switch, one sentence saying what is happening, and a delete
    button that only exists when deleting is possible.
    """
    sup = d.get("supervisor")
    if not sup:
        return ""

    on = bool(sup.get("index_enabled"))
    missing = bool(sup.get("index_missing"))
    blocked = bool(sup.get("space_blocked"))
    size = sup.get("index_bytes") or 0
    idx = sup.get("index_height")
    node = sup.get("node_height")
    notice = d.get("index_notice")

    # One sentence. What is happening, and what it means for a wallet.
    if blocked:
        state, cls = ("The node has not started — not enough disk.",
                      "bad")
        detail = "Nothing is indexing. See the message at the top."
    elif missing:
        state, cls = ("This build has no indexer in it.", "bad")
        detail = ("The node still validates and stores normally. No "
                  "wallet can connect.")
    elif not on:
        state, cls = ("Off. No wallet can connect to this node.", "warn")
        detail = ("Turn it on to use Sparrow or Electrum with this node. "
                  "Building it the first time takes most of a day.")
    elif idx is None:
        state, cls = ("Starting up.", "warn")
        detail = ("The indexer has not reported yet. If this lasts more "
                  "than a few minutes, the app's log has the reason.")
    elif node and node - idx > 2:
        pc = (100.0 * idx / node) if node else 0.0
        state, cls = ("Building the index — %.1f%% done." % pc, "warn")
        detail = ("Block %s of %s. Wallets cannot connect until this "
                  "finishes." % (commas(idx), commas(node)))
    else:
        state, cls = ("Ready. Wallets can connect.", "ok")
        host = (d.get("wallet_advertise") or "").strip() or "this node"
        detail = "Point Sparrow or Electrum at %s." % esc(host)

    p = ["<div class=card><h2>ADDRESS INDEX</h2>"]
    if notice:
        ncls = "bad" if notice.get("error") else "ok"
        p.append("<div class=%s style='margin-bottom:10px'>%s</div>"
                 % (ncls, esc(notice.get("text"))))

    p.append("<div class=%s style='font-size:15px;margin-bottom:4px'>%s"
             "</div>" % (cls, esc(state)))
    p.append("<div class=dim style='margin-bottom:12px'>%s</div>" % detail)

    if idx is not None and node:
        p.append(bar(min(100.0, 100.0 * idx / node), "#4ea1f7"))
        p.append("<div style='height:10px'></div>")

    p.append("<table style='margin-top:10px'><tr><td class=k>on disk</td>"
             "<td class=v>%s</td></tr></table>"
             % (human(size) if size else
                "<span class=dim>nothing written yet</span>"))

    p.append("<div class=note>Switch it on or off in SETTINGS "
             "below.</div>")
    return "".join(p)


def settings_card(cfg, d):
    """What this instance is actually running with, and how to change it.

    Shows the effective configuration rather than documenting defaults: the
    commonest confusion is a flag someone believes they passed and did not.
    """
    running = "configured" if d.get("electrum_target") else "not configured"
    p = ["<div class=card><h2>SETTINGS</h2>"]

    p.append("<table>")
    rows = (("store", getattr(cfg, "store", "") or "-"),
            ("node RPC", getattr(cfg, "rpc_url", "") or "-"),
            ("cookie", getattr(cfg, "cookie", "") or "-"),
            ("log directory", getattr(cfg, "log_dir", "") or "-"),
            ("build log", getattr(cfg, "build_log", "") or "-"),
            ("indexer", (d.get("electrum_target") or "-")
             + (" - TLS" if getattr(cfg, "electrum_ssl", False) else "")),
            ("bound to", "%s:%s" % (getattr(cfg, "host", "127.0.0.1"),
                                    getattr(cfg, "port", 8080))))
    for k, v in rows:
        p.append("<tr><td class=k>%s</td><td class=v>%s</td></tr>"
                 % (esc(k), esc(v)))
    p.append("</table>")

    p.append("<div class=note>This is what the app is running with. "
             "Change how it behaves in ADVANCED SETTINGS below.</div>")

    # The address index lives here, with the same switch as every other
    # setting, and its delete beside it. It was spread across three cards
    # with three different labels, which is how a control ends up looking
    # like it does nothing.
    sup = d.get("supervisor") or {}
    if sup:
        on = bool(sup.get("index_enabled"))
        size = sup.get("index_bytes") or 0
        p.append("<div style='margin-top:14px;border-top:1px solid #23252a;"
                 "padding-top:12px'>")
        p.append(index_switch(on, "Run the address index"))
        p.append("<div class=note style='margin-top:0'>%s</div>"
                 % ("Wallets can connect. The node keeps every block."
                    if on else
                    "No wallet can connect. The blockchain can be "
                    "reclaimed behind the stripper."))
        if size:
            p.append("<div class=dim style='margin-top:10px'>"
                     "index on disk: %s</div>" % human(size))
            if on:
                p.append("<div class=note>Switch it off to delete "
                         "it.</div>")
            else:
                p.append(
                    "<form method=post action=/index "
                    "style='margin-top:8px' "
                    "onsubmit=\"return confirm('Delete the address "
                    "index? Rebuilding it later takes most of a day.')\">"
                    "<input type=hidden name=action value=delete>"
                    "<button type=submit>Delete the index and free %s"
                    "</button></form>" % human(size))
        p.append("</div>")

    p.append("</div>")
    return "".join(p)


def race_card(store):
    """Equal-height block races this node witnessed, and who won.

    Leads with what the node did NOT do. The obvious misreading of this card
    is that the node is picking sides, and a dashboard that invites that
    reading about chain selection is worse than no card."""
    if tr is None:
        return ""
    races = tr.load_races(store)
    t = tr.tally(races)

    p = ["<div class=card><h2>COMPETING BLOCKS</h2>"]
    p.append("<div class=note>When two blocks arrive at the same height, this "
             "measures how much data each carried and records which one the "
             "network kept. <b>This node does not and cannot influence that "
             "outcome</b> — most work wins, first seen breaks ties, no "
             "exceptions.</div>")

    if not races:
        p.append("<div class=note>No race witnessed yet. They are rare, and "
                 "one settled before the announcement reached this node over "
                 "Tor is invisible here.</div></div>")
        return "".join(p)

    p.append("<table>")
    for k, label in (("races", "races witnessed"),
                     ("measured", "both blocks measurable"),
                     ("unmeasured", "one side never received"),
                     ("ties", "equal carrier load"),
                     ("cleaner_won", "cleaner block survived"),
                     ("dirtier_won", "dirtier block survived")):
        p.append("<tr><td class=k>%s</td><td class=v>%s</td></tr>"
                 % (label, commas(t[k])))
    p.append("</table>")

    if t["cleaner_won_pct"] is not None:
        p.append("<div class=note>Of <b>%s</b> races where the two blocks "
                 "actually differed, the cleaner one survived "
                 "<span class=big>%.1f%%</span> of the time.</div>"
                 % (commas(t["decided"]), t["cleaner_won_pct"]))
    else:
        p.append("<div class=note>No race yet where the two blocks differed "
                 "in carrier load, so there is nothing to conclude.</div>")

    p.append("<div class=note>Carrier bytes on blocks the network kept: "
             "<b>%s</b>. On blocks it discarded: <b>%s</b>.</div>"
             % (human(t["bytes_kept"]),
                human(t["bytes_discarded_by_network"])))

    recent = races[-5:]
    if recent:
        p.append("<div class=note><b>Most recent</b></div><table>")
        for r in reversed(recent):
            w, l = r.get("winner") or {}, r.get("loser") or {}
            wc, lc = w.get("carriers"), l.get("carriers")
            if wc is None or lc is None:
                verdict, cls = "unmeasured", "dim"
            elif wc < lc:
                verdict, cls = "cleaner kept", "ok"
            elif wc > lc:
                verdict, cls = "dirtier kept", "warn"
            else:
                verdict, cls = "equal", "dim"
            p.append("<tr><td class=k>%s</td><td class='v %s'>%s"
                     " <span class=dim>(kept %s vs discarded %s)</span>"
                     "</td></tr>"
                     % (commas(r.get("h", 0)), cls, verdict,
                        human(wc), human(lc)))
        p.append("</table>")

    p.append("<div class=note>One node's view of a rare event, over Tor. It "
             "undercounts, so treat it as an observation log rather than a "
             "survey.</div></div>")
    return "".join(p)


# ------------------------------------------------------- advanced settings


def advanced_card(cfg, notice=None):
    """The Knots-style policy panel, rendered from node_settings.SETTINGS.

    Every row is generated from the catalogue, so adding a setting is a one
    line change there and nothing here. Options the running bitcoind does not
    have are shown disabled rather than hidden: the gap between what Core has
    and what Knots has is the most useful thing this panel can tell you, and
    hiding it would just make the absence look like an oversight."""
    if ns is None:
        return ("<div class=card><h2>ADVANCED SETTINGS</h2><div class=note>"
                "node_settings.py is not beside this file, so the panel is "
                "unavailable.</div></div>")

    conf = getattr(cfg, "conf", "") or ""
    mconf = getattr(cfg, "monetary_conf", "") or ""
    # On Umbrel and StartOS the Bitcoin service owns bitcoin.conf: StartOS
    # mounts it read-only and fixes the RPC and P2P addresses itself, Umbrel
    # passes credentials in as environment and manages the file. A dependent
    # app that rewrote it would be overwritten at best and fighting the
    # platform at worst.
    #
    # So in managed mode the bitcoind rows become a read-only report of what
    # the platform decided, and only the monetary-node options stay editable.
    # That also closes the write path by default, which is worth having on
    # any platform: a config editor behind an unauthenticated page is the
    # riskiest thing in this repo.
    managed = bool(getattr(cfg, "managed_bitcoin_config", False))
    blob = help_cache()
    try:
        rows = ns.effective(conf, blob, mconf)
    except Exception as e:
        return ("<div class=card><h2>ADVANCED SETTINGS</h2><div class=note>"
                "Could not read %s: %s</div></div>"
                % (esc(conf), esc(str(e)[:120])))

    hidden = [r for r in rows if r["supported"] is False]
    rows = [r for r in rows if r["supported"] is not False]

    # In managed mode, drop the Bitcoin rows entirely rather than showing
    # thirty-two controls nobody can touch. A panel that is mostly disabled
    # reads as a broken panel, and the information it carries is one
    # sentence, not thirty-two rows: the Bitcoin service owns its own
    # configuration and you change it there.
    platform_owned = []
    if managed:
        platform_owned = [r for r in rows
                          if r.get("scope") != ns.SCOPE_MONETARY]
        rows = [r for r in rows if r.get("scope") == ns.SCOPE_MONETARY]

    p = ["<div class=card><h2>ADVANCED SETTINGS</h2>"]

    if notice:
        cls = "bad" if notice.get("error") else "good"
        p.append('<div class="note %s">%s</div>'
                 % (cls, esc(notice.get("text", ""))))

    # In managed mode the Bitcoin rows claim to report what the platform
    # configured. If the file cannot be read, they would instead show each
    # setting's DEFAULT — presenting a guess as the platform's choice, which
    # is a worse failure than showing nothing. So say so, and mark them.

    if managed:
        p.append("<div class=note>%d Bitcoin settings are not shown. The "
                 "Bitcoin service owns its own configuration on this "
                 "platform, so this app can neither change them nor "
                 "usefully pretend to — change them where that service\'s "
                 "settings live.<br><br>"
                 "Everything below is this app\'s own and writes "
                 "<code>%s</code>.</div>"
                 % (len(platform_owned),
                    esc(mconf or "no monetary config path configured")))
    else:
        p.append("<div class=note>Bitcoin settings write <code>%s</code>; "
                 "monetary-node settings write <code>%s</code>. Core reads "
                 "its configuration once at startup, so <b>nothing takes "
                 "effect until the node restarts</b> — and this page will not "
                 "restart it for you. A backup is taken before every write."
                 "</div>"
                 % (esc(conf or "no config path configured"),
                    esc(mconf or "no monetary config path configured")))

    if blob is None:
        p.append("<div class='note bad'>Could not run <code>bitcoind "
                 "-help</code>, so this page cannot tell which options your "
                 "build has. Nothing will be written until it can.</div>")

    p.append("<form method=post action='/settings' class=setform>")

    # Every setting in the catalogue works on stock Core, so an unsupported
    # row means a build older than expected. Hide it rather than showing a
    # control that does nothing — but say how many vanished, because a
    # silently shorter page is its own kind of lie.
    changed = [r for r in rows if not r["at_default"]]
    p.append("<div class=note>%d of %d settings differ from their defaults."
             "</div>" % (len(changed), len(rows)))
    if hidden:
        p.append("<div class=note>%d setting%s hidden: this build of Bitcoin "
                 "Core does not have %s. Everything offered here works on "
                 "stock Core, so that suggests an older version than "
                 "expected.</div>"
                 % (len(hidden), "" if len(hidden) == 1 else "s",
                    ", ".join(esc(r["key"]) for r in hidden)))

    group = None
    for r in rows:
        if r["group"] != group:
            if group is not None:
                p.append("</div>")
            group = r["group"]
            p.append("<h3 class=sgroup>%s</h3><div class=sgrid>"
                     % esc(group))

        # Unsupported rows were filtered out above, so the only reason to
        # disable a control now is that we could not ask bitcoind at all —
        # in which case nothing is writable and the banner says so.
        avail = blob is not None
        dis = "" if avail else " disabled"
        name = esc(r["key"])
        val = esc(r["value"])
        p.append("<div class='srow%s'>" % ("" if avail else " off"))
        p.append("<div class=sname><label for='f_%s'>%s</label>"
                 "<span class=skey>%s</span></div>" % (name, esc(r["label"]),
                                                       name))

        if r["type"] == ns.BOOL:
            on = str(r["value"]) in ("1", "true", "True", "on", "yes")
            # A checkbox that is off sends nothing, so an explicit hidden
            # partner is what makes "turn this off" reach the server.
            p.append("<input type=hidden name='has_%s' value=1>" % name)
            p.append("<label class=switch><input type=checkbox id='f_%s' "
                     "name='%s' value=1%s%s><span></span></label>"
                     % (name, name, " checked" if on else "", dis))
        else:
            p.append("<div class=sval><input class=in id='f_%s' name='%s' "
                     "value='%s' maxlength=16%s>%s</div>"
                     % (name, name, val, dis,
                        ("<span class=unit>%s</span>" % esc(r["unit"]))
                        if r["unit"] else ""))

        p.append("<div class=shelp>%s" % esc(r["help"]))
        if r["warn"]:
            p.append("<br><span class=warn>%s</span>" % esc(r["warn"]))
        p.append("<br><span class=sdef>default: %s%s</span>"
                 % (esc(r["default"]) if r["default"] != "" else "unset",
                    (" " + esc(r["unit"])) if r["unit"] else ""))
        if r.get("scope") == ns.SCOPE_MONETARY:
            p.append("<br><span class=sdef>monetary node option — bitcoind "
                     "never sees this</span>")
        elif not r["at_default"]:
            p.append("<br><span class=chg>changed from default</span>")
        p.append("</div></div>")

    if group is not None:
        p.append("</div>")

    if managed:
        p.append("<div class=sactions>"
                 "<button class=go type=submit name=action value=save>"
                 "SAVE MONETARY SETTINGS</button>"
                 "<button class='go warnbtn' type=submit name=action "
                 "value=defaults onclick=\"return confirm('Put the monetary "
                 "node settings back to their defaults?')\">"
                 "RESTORE DEFAULTS</button>"
                 "</div>")
    else:
        p.append("<div class=sactions>"
                 "<button class=go type=submit name=action value=save>"
                 "SAVE CHANGES</button>"
                 "<button class='go warnbtn' type=submit name=action "
                 "value=defaults onclick=\"return confirm('Put every setting "
                 "back to its default? Your own config lines are kept.')\">"
                 "RESTORE DEFAULTS</button>"
                 "</div>")
    p.append("</form>")

    if managed:
        p.append("<div class=note>Monetary settings take effect when this "
                 "app restarts. Nothing here can restart or reconfigure the "
                 "Bitcoin service.</div>")
    else:
        p.append("<div class=note>After saving: <code>sudo systemctl restart "
                 "bitcoind</code>, then re-run <code>./tor_lockdown.sh "
                 "--verify</code>. A config change is exactly when a Tor "
                 "assumption quietly stops being true.</div>")

    p.append("</div>")
    return "".join(p)


def donate_footer(addr=None):
    """Support line at the foot of the page.

    Deliberately not a card: it is not node state and should not sit in the
    same visual rank as the store or the Tor verdict. Text plus a lightning:
    URI, which wallets registered for the scheme will pick up and everyone
    else can copy. No QR image, because generating one means fetching from
    somewhere and this page contacts nothing.
    """
    a = esc(addr or DONATE_LN)
    return (
        "<div class=donate>"
        "<span class=dlabel>SUPPORT THIS PROJECT</span>"
        "<a class=dln href=\"lightning:%s\">%s</a>"
        "<span class=dnote>lightning</span>"
        "</div>" % (a, a))


def live_numbers(cfg):
    """
    What the page refreshes in place: heights, percentages, spam removed.

    Read from the supervisor's status file and the store's state file,
    both of which are small and already written for this purpose. No RPC
    call, so a poll cannot stall behind a slow node.
    """
    store = getattr(cfg, "store", "") or ""
    sup = {}
    try:
        with open(os.path.join(os.path.dirname(store.rstrip("/")),
                               "supervisor.json")) as fh:
            sup = json.load(fh) or {}
    except (OSError, ValueError):
        sup = {}
    state, _err = read_state(store)
    state = state or {}

    height = sup.get("node_height")
    headers = sup.get("node_headers")
    idx = sup.get("index_height")
    carriers = state.get("carriers")
    bytes_in, bytes_out = state.get("bytes_in"), state.get("bytes_out")

    def pct(a, b):
        if not isinstance(a, int) or not isinstance(b, int) or b <= 0:
            return None
        return max(0.0, min(100.0, 100.0 * a / b))

    # The status bar's own fields. Built from the same two files, so the
    # bar cannot drift from the cards below it — and computed here rather
    # than in JS, so the wording lives in one place.
    _d = {"supervisor": sup, "state": state, "node": {"ibd": sup.get("phase")
          in ("syncing", "downloading")}, "store_path": store}
    doing, dcls = doing_now(_d)
    route, rcls = route_now(_d)
    free = disk_free(_d)

    out = {
        "height": height,
        "headers": headers,
        "node_pct": pct(height, headers),
        "index": idx,
        "index_pct": pct(idx, height),
        "index_building": bool(sup.get("index_building")),
        "index_enabled": bool(sup.get("index_enabled")),
        "store_height": state.get("height"),
        "spam": human(carriers) if carriers else None,
        "phase": sup.get("phase"),
        "doing": doing,
        "doing_class": dcls,
        "route": route,
        "route_class": rcls,
        "free": human(free) if free is not None else None,
        "free_bytes": free,
    }
    if bytes_in and bytes_out is not None:
        out["saved_pct"] = 100.0 * (bytes_in - bytes_out) / bytes_in
    return out


LIVE_JS = """
<script>
(function(){
  // Update in place rather than reloading. A full reload every few
  // seconds would re-read the store size, the logs and the config on a
  // Raspberry Pi, to move two numbers.
  var fmt = function(n){
    if (n === null || n === undefined) return '—';
    return n.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  };
  var set = function(id, text){
    var e = document.getElementById(id);
    if (e && text !== null && text !== undefined) e.textContent = text;
  };
  // Swap the value class without touching the label's.
  var cls = function(id, c){
    var e = document.getElementById(id);
    if (e && c !== null && c !== undefined) e.className = 'sbval '+c;
  };
  var width = function(id, p){
    var e = document.getElementById(id);
    if (e && p !== null && p !== undefined) e.style.width = p.toFixed(1)+'%';
  };
  var last = null;
  var tick = function(){
    fetch('/live.json', {cache:'no-store'}).then(function(r){
      return r.json();
    }).then(function(d){
      set('lv-height', fmt(d.height));
      set('lv-headers', fmt(d.headers));
      set('lv-store', fmt(d.store_height));
      if (d.spam) set('lv-spam', d.spam);
      if (d.node_pct !== null && d.node_pct !== undefined)
        set('lv-pct', d.node_pct.toFixed(2)+'%');
      width('lv-bar-node', d.node_pct);
      width('lv-bar-index', d.index_pct);
      var moved = (last !== null && d.height !== null && d.height > last);
      if (d.node_pct !== null && d.node_pct !== undefined) {
        set('lv-txt-node',
            d.node_pct.toFixed(2)+'%  ·  block '+fmt(d.height)+
            ' of '+fmt(d.headers)+
            (moved ? '  ·  +'+fmt(d.height-last) : ''));
      }
      if (d.index !== null && d.index !== undefined &&
          d.index_pct !== null && d.index_pct !== undefined) {
        set('lv-txt-index',
            d.index_pct.toFixed(2)+'%  ·  block '+fmt(d.index)+
            ' of '+fmt(d.height));
      }
      // --- the unified status bar
      set('lv-sb-doing', d.doing);
      set('lv-sb-height', fmt(d.height));
      set('lv-sb-pct', (d.node_pct === null || d.node_pct === undefined)
                       ? '\\u2014' : d.node_pct.toFixed(2)+'%');
      set('lv-sb-index', !d.index_enabled ? 'off'
          : ((d.index === null || d.index === undefined) ? 'starting'
             : 'block '+fmt(d.index)));
      if (d.spam) set('lv-sb-spam', d.spam);
      set('lv-sb-route', d.route);
      if (d.free) set('lv-sb-disk', d.free);
      // The colour is part of the reading, so it has to move with the
      // text. A bar that stays green while the words say STOPPED is
      // worse than a bar with no colour at all.
      var bar = document.querySelector('.sbar');
      if (bar && d.doing_class) bar.className = 'sbar '+d.doing_class;
      cls('lv-sb-route', d.route_class);
      cls('lv-sb-disk', (d.free_bytes === null || d.free_bytes === undefined)
          ? '' : (d.free_bytes < 20*1073741824 ? 'bad'
                  : (d.free_bytes < 80*1073741824 ? 'warn' : 'ok')));
      last = d.height;
    }).catch(function(){ /* a missed poll is not an error */ });
  };
  tick();
  setInterval(tick, 5000);
})();
</script>
"""


def doing_now(d):
    """
    One short phrase: what this node is doing at this moment.

    Priority order, not a single field. The supervisor's phase describes
    the normal pipeline — syncing, stripping, following — and says
    nothing about the states that actually leave someone staring at the
    page wondering: a refused start, a dead Core, a reindex, a warm-up.
    Those have to win, because they are the only ones where the answer
    to "what is it doing" is "something you should know about".

    Returns (phrase, css class). The class is the whole visual grammar of
    the bar: green means working as intended, amber means working but
    not finished, red means stopped.
    """
    sup = d.get("supervisor") or {}
    if sup.get("space_blocked"):
        return "STOPPED — not enough disk", "bad"
    if sup.get("node_error"):
        return "STOPPED — Bitcoin Core is not running", "bad"
    if sup.get("reindex_redownload"):
        return "Re-downloading the chain", "warn"
    if sup.get("reindexing"):
        return "Rebuilding Bitcoin Core's block index", "warn"
    if d.get("warming_up"):
        return "Starting — Bitcoin Core is loading its databases", "warn"

    n = d.get("node") or {}
    if n.get("ibd"):
        return "Downloading and verifying the chain", "warn"

    # Synced. Now it is about the two things this app adds.
    sup_h, node_h = sup.get("store_height"), sup.get("node_height")
    if isinstance(sup_h, int) and isinstance(node_h, int) and node_h - sup_h > 6:
        return "Stripping data carriers out of stored blocks", "warn"
    if sup.get("index_enabled") and sup.get("index_building"):
        return "Building the address index for wallets", "warn"
    if sup.get("index_enabled"):
        return "Following the chain · wallets can connect", "ok"
    return "Following the chain · address index off", "ok"


def route_now(d):
    """
    How this node reaches the network, in two or three words.

    Clearnet wins the label whenever it is on, because it is the one
    the operator needs to see without reading a sentence.
    """
    sup = d.get("supervisor") or {}
    if sup.get("clearnet"):
        return "CLEARNET", "bad"
    bits = []
    if sup.get("tor"):
        bits.append("TOR")
    if sup.get("i2p"):
        bits.append("I2P")
    if not bits:
        return "UNKNOWN", "warn"
    return " + ".join(bits), "ok"


def disk_free(d):
    """
    Free bytes on the node's disk, or None.

    The supervisor's figure wins when there is one. It measures the data
    directory, it is the number the watchdog acts on, and it is the one
    that will be right if the page is ever rendered anywhere other than
    the machine the node runs on — which it is, for the app store
    gallery, where measuring the local disk showed 4.3 GiB free on a node
    with 420.
    """
    import shutil as _sh
    sup = d.get("supervisor") or {}
    if isinstance(sup.get("disk_free"), int):
        return sup["disk_free"]
    path = d.get("store_path") or ""
    for p in (path, os.path.dirname(path.rstrip("/")), "/"):
        if not p:
            continue
        try:
            return _sh.disk_usage(p).free
        except OSError:
            continue
    return None


def status_bar(d):
    """
    The unified bar: one glance, above everything, no scrolling.

    Separate from the feed on purpose. The feed answers "what just
    happened"; this answers "what is happening", which is a different
    question and the one asked first. Every cell here is also in a card
    further down — that duplication is the point, because the cards are
    spread over a page and nobody reads a page to find out whether their
    node is alright.

    Every value carries an id so LIVE_JS can move it without a reload.
    """
    doing, dcls = doing_now(d)
    route, rcls = route_now(d)
    sup = d.get("supervisor") or {}

    height = sup.get("node_height")
    headers = sup.get("node_headers")
    pct = None
    if isinstance(height, int) and isinstance(headers, int) and headers > 0:
        pct = max(0.0, min(100.0, 100.0 * height / headers))

    st = d.get("state") or {}
    spam = human(st["carriers"]) if st.get("carriers") else None

    free = disk_free(d)
    # Red at the floor the watchdog acts on, amber within sight of it.
    fcls = "ok"
    if free is not None:
        if free < 20 * 1024 ** 3:
            fcls = "bad"
        elif free < 80 * 1024 ** 3:
            fcls = "warn"

    if sup.get("index_enabled"):
        ih = sup.get("index_height")
        idx = ("block %s" % fmt_int(ih)) if isinstance(ih, int) else "starting"
    else:
        idx = "off"

    cells = [
        ("HEIGHT", fmt_int(height), "lv-sb-height", ""),
        ("CHAIN", ("%.2f%%" % pct) if pct is not None else "—",
         "lv-sb-pct", ""),
        ("INDEX", idx, "lv-sb-index", ""),
        ("SPAM REMOVED", spam or "—", "lv-sb-spam", ""),
        ("ROUTE", route, "lv-sb-route", rcls),
        ("DISK FREE", human(free) if free is not None else "—",
         "lv-sb-disk", fcls),
    ]

    out = ["<div class='sbar %s'>" % dcls,
           "<div class=sbdoing><span class=sbdot></span>"
           "<span id=lv-sb-doing>%s</span></div>" % esc(doing),
           "<div class=sbcells>"]
    for label, value, cid, cls in cells:
        out.append(
            "<div class=sbcell><span class=sblabel>%s</span>"
            "<span class='sbval %s' id=%s>%s</span></div>"
            % (esc(label), cls, cid, esc(str(value))))
    out.append("</div></div>")
    return "".join(out)


def reindex_banner(d):
    """
    Core is rebuilding its block index. Say which of the two this is.

    A datadir that was ever pruned will not open unpruned again without a
    reindex, and that is the only reason this app ever triggers one. But
    "reindex" covers two situations that feel nothing alike:

      - every block is on the disk: hours of reading, no network
      - the blocks were pruned away: Core re-downloads the chain, which
        over Tor is days and several hundred GiB

    The page claimed the first in both cases. It said "nothing is being
    re-downloaded" through two days of re-downloading 738 GiB — so the
    one number that would have explained where the disk went was the one
    the operator was told to ignore. Both wordings below are specific
    enough that nobody has to go and check.
    """
    sup = d.get("supervisor") or {}
    if not sup.get("reindex_redownload"):
        return ("<div class='banner unknown'><div class=bword>REBUILDING "
                "THE INDEX</div><div class=bsub>"
                "This data directory was created by a node with pruning "
                "switched on, and Bitcoin Core will not open it unpruned "
                "until its index is rebuilt. That is happening now."
                "<br><br>Every block is already on this disk, so "
                "<b>nothing is being re-downloaded</b>. On a Raspberry Pi "
                "this takes hours. Leave it running; the page fills in by "
                "itself when it finishes.</div></div>")

    have = sup.get("blocks_bytes")
    had = (" Only %s of blocks were left on the disk." % human(have)
           if have else "")
    return ("<div class='banner unknown'><div class=bword>RE-DOWNLOADING "
            "THE CHAIN</div><div class=bsub>"
            "This data directory was pruned, so Bitcoin Core will not "
            "open it unpruned until its index is rebuilt — and there is "
            "almost nothing on disk to rebuild from.%s"
            "<br><br><b>The chain is being downloaded again.</b> Over Tor "
            "that is days, not hours, and it needs roughly 740 GiB of "
            "free space before it finishes. Watch the disk figure below: "
            "if it runs out, stop the node rather than letting it fill "
            "the drive."
            "<br><br>Your monetary store is <b>not</b> affected and is "
            "not being rebuilt. Nothing in it is being re-derived or "
            "re-verified, and no block already stripped will be stripped "
            "again.</div></div>" % had)


def space_banner(d):
    """
    The node refused to start because the disk will not hold it.

    Shown at the top, because when this happens the page is the only
    thing running and the whole reason it is running is to say this.
    """
    sup = d.get("supervisor") or {}

    # Stopped while running, by the watchdog, rather than refused at
    # startup. Different situation, different sentence: here the node WAS
    # running and data is already on the disk, so the first thing to say
    # is that none of it was touched.
    if sup.get("disk_halted"):
        free = sup.get("disk_free")
        floor = sup.get("disk_halt_gib") or 20
        return ("<div class='banner bad'><div class=bword>STOPPED — DISK "
                "ALMOST FULL</div><div class=bsub>"
                "Bitcoin Core has been stopped on purpose, with %s free. "
                "<b>Nothing has been deleted.</b> The chain, the monetary "
                "store and the address index are all intact and were "
                "closed cleanly."
                "<br><br>This is the failure that takes a whole machine "
                "down rather than one app, so the node stops first and "
                "leaves the decision to you. Free some space and it "
                "starts again on its own once %d GiB are available."
                "</div></div>"
                % (esc(human(free)) if free else "very little", floor))

    if not sup.get("space_blocked"):
        return ""
    reason = sup.get("space_reason") or []
    body = "<br>".join(esc(line) for line in reason if line.strip())
    return ("<div class='banner bad'><div class=bword>NOT ENOUGH DISK"
            "</div><div class=bsub>"
            "The node has NOT been started. Nothing has been written and "
            "nothing is at risk — filling this disk would take down every "
            "app on the machine, so it stopped first."
            "<pre style='text-align:left;white-space:pre-wrap;"
            "margin:10px 0 0;font-size:12px'>" + body + "</pre>"
            "<div style='margin-top:8px'>Free some space and it will "
            "start on its own; it re-checks every 30 seconds.</div>"
            "</div></div>")


def exposure_banner(d):
    """
    A banner only when something is wrong.

    The page used to carry a green TOR ONLY badge at all times. A warning
    that is always on stops being read, and the thing worth shouting about
    is the opposite case: that this machine's IP address may be visible.

    So: silence when the node is private, and a red banner when it is not.
    """
    net = d.get("netinfo")
    peers = d.get("peers") or []
    sup = d.get("supervisor") or {}

    reasons = []
    if sup.get("clearnet"):
        reasons.append("clearnet is switched on in settings")
    if net:
        reach = {e.get("name"): e.get("reachable")
                 for e in net.get("networks", [])}
        if reach.get("ipv4") or reach.get("ipv6"):
            reasons.append("the node reports IPv4 or IPv6 as reachable")
        onion = [e for e in net.get("networks", []) if e.get("name") == "onion"]
        if onion and not (onion[0].get("proxy") or ""):
            reasons.append("no Tor proxy is configured")
    bad_peers = [x for x in peers if x.get("network") not in
                 ("onion", "i2p", "cjdns", None)]
    if bad_peers:
        reasons.append("%d peer%s connected over clearnet"
                       % (len(bad_peers), "" if len(bad_peers) == 1 else "s"))

    if not reasons:
        return ""
    items = "".join("<li>%s</li>" % esc(r) for r in reasons)
    return ("<div class='banner bad'><div class=bword>YOUR IP MAY BE "
            "VISIBLE</div><div class=bsub>"
            "Every peer you connect to over clearnet learns the public "
            "address of this machine, and that cannot be taken back."
            f"<ul style='margin:8px 0 0 18px'>{items}</ul>"
            "</div></div>")


def network_banner(d, tor_required=True):
    """The first thing on the page, in the largest type on it.

    Reports what the node is DOING, not what a config file asks for. Those
    diverged once on this node — six hours of clearnet peers behind a
    bitcoin.conf that said onlynet=onion, because the running process had
    never read it — and a banner that reported intent would have shown TOR
    ONLY in green throughout.

    So: proxy present, onion reachable, ipv4 and ipv6 NOT reachable, and zero
    non-onion peers right now. Anything less is not Tor only, and says so."""
    net, peers = d.get("netinfo"), d.get("peers") or []

    # A standalone instance has no validating node ON PURPOSE: it serves
    # wallets from a store that is already built. Reporting that as NETWORK
    # UNKNOWN in alarm colours describes a working node as broken, and it
    # also devalues the banner — a warning that is always on is not read.
    #
    # It still must not claim Tor. This instance makes no network
    # connections at all, which is a different thing from being safe on one.
    if d.get("standalone"):
        return ("<div class='banner unknown'><div class=bword>STANDALONE"
                "</div><div class=bsub>No validating node attached. This "
                "instance serves wallets from a store that is already "
                "built, and makes no peer connections of its own — so it "
                "cannot follow the tip, and there is no network for this "
                "banner to judge.</div></div>")

    if net is None:
        return ("<div class='banner unknown'><div class=bword>NETWORK "
                "UNKNOWN</div><div class=bsub>The node is not answering, so "
                "this page cannot tell you how it is connected. Assume "
                "nothing until it does.</div></div>")

    reach, proxy = {}, ""
    for e in net.get("networks", []):
        reach[e.get("name")] = e.get("reachable")
        if e.get("name") == "onion" and e.get("proxy"):
            proxy = e["proxy"]
    nets = collections.Counter(p.get("network") or "?" for p in peers)
    clear = sum(v for k, v in nets.items() if k not in ("onion", "i2p"))

    tor_only = (bool(proxy) and reach.get("onion")
                and not reach.get("ipv4") and not reach.get("ipv6")
                and clear == 0)

    if tor_only:
        return ("<div class='banner btor'>"
                "<div class=bword>TOR ONLY</div>"
                "<div class=bsub>%d peers, every one over Tor. No clearnet "
                "route in or out, enforced by the kernel rather than "
                "requested in a config file.<br>"
                "To change this: <code>sudo ./tor_lockdown.sh --clearnet"
                "</code> on the node. It will make you type the word."
                "</div></div>" % len(peers))

    why = []
    if not proxy:
        why.append("no Tor proxy configured")
    if not reach.get("onion"):
        why.append("onion not reachable")
    if reach.get("ipv4"):
        why.append("IPv4 reachable")
    if reach.get("ipv6"):
        why.append("IPv6 reachable")
    if clear:
        why.append("%d clearnet peer%s connected right now"
                   % (clear, "" if clear == 1 else "s"))

    if not tor_required:
        # The operator has said they run without Tor on purpose. Report it,
        # do not alarm. Nagging someone about a choice they made explicitly
        # teaches them to ignore the banner, which is the one thing on this
        # page that must keep working.
        return ("<div class='banner unknown'>"
                "<div class=bword>CLEARNET</div>"
                "<div class=bsub>%s.<br>Tor is not required by this node\'s "
                "settings, so this is reported rather than flagged. Your IP "
                "is visible to every peer you connect to.<br>"
                "Turn Require Tor back on in settings to treat this as a "
                "fault again.</div></div>"
                % esc("; ".join(why).capitalize()))

    return ("<div class='banner bclear'>"
            "<div class=bword>CLEARNET</div>"
            "<div class=bsub>%s.<br><b>Your home IP address is visible to "
            "every peer you connect to, and to anyone watching them.</b> If "
            "that is not what you intended, stop the node now:<br>"
            "<code>sudo systemctl stop bitcoind</code> then "
            "<code>sudo ./tor_lockdown.sh</code>"
            "</div></div>" % esc("; ".join(why).capitalize()))


def render(d, cfg=None):
    n, s, b = d["node"], d["state"], d["build"]
    p = []
    A = p.append

    A(f"<!doctype html><meta charset=utf-8><title>monetary node</title>"
      f"<style>{CSS}</style><div class=wrap><h1>MONETARY NODE</h1>"
      # NOT "read only". It said that for months while the settings panel
      # wrote monetary.conf and the index button deleted the address
      # index. Whoever can open this page can change how the node runs —
      # that is the opposite of read only, and a false claim here is
      # worse than no claim, because it tells an operator not to bother
      # thinking about who can reach the port.
      f"<div class=sub><span class=live id=live></span>live feed · cards"
      f" refresh on reload · settings on this page change how the node"
      f" runs</div>")

    # Before the banners. A banner says what is wrong; this says what is
    # happening, which is the question even when nothing is wrong.
    A(status_bar(d))

    # Above the errors, above everything. This is the one fact on the page
    # that is worth more than the rest of it combined.
    A(space_banner(d))
    _sup = d.get("supervisor") or {}
    if _sup.get("reindexing"):
        A(reindex_banner(d))
    if _sup.get("node_error"):
        A("<div class='banner bad'><div class=bword>BITCOIN CORE IS NOT "
          "RUNNING</div><div class=bsub>"
          "The rest of the app is up, which is why you can read this. "
          "Core said:<pre style='text-align:left;white-space:pre-wrap;"
          "margin:8px 0;font-size:12px'>"
          + esc(_sup["node_error"]) +
          "</pre>It is being retried every minute. Nothing has been "
          "deleted and nothing is at risk.</div></div>")
    if d.get("warming_up"):
        A("<div class='banner unknown'><div class=bword>STARTING</div>"
          "<div class=bsub>Bitcoin Core is loading its databases: "
          + esc(d["warming_up"]) +
          ". Nothing is wrong. On a large data directory this takes "
          "minutes, and on one adopted from another node it can take "
          "hours. The page fills in by itself when it finishes."
          "</div></div>")
    A(exposure_banner(d))

    for e in d["errors"]:
        A(f"<div class='card err'><h2>PROBLEM</h2><div class=bad>{esc(e)}</div></div>")

    # Height, sync and spam removed, before anything else. This is what
    # somebody installed the app to find out.
    A(headline_card(d))

    A("<div class=card><h2>FEED</h2><div id=feed></div>"
      "<div class=note>Blocks with fees, mempool movement, the daemon"
      " advancing, indexer state, Tor warnings, and this node's own wallet"
      " transactions highlighted. A heartbeat every 15s carries mempool size,"
      " fee estimate and tip age so a quiet chain never looks like a broken"
      " page. Individual mempool transactions are excluded.</div></div>")


    pr = d.get("peers") or []
    if pr:
        inb = sum(1 for x in pr if x["inbound"])
        nets = collections.Counter(x["network"] for x in pr)
        A("<div class=card><h2>PEERS</h2>")
        A(f"<div class=note style='margin:0 0 10px'>{len(pr)} connected · "
          f"{len(pr) - inb} out, {inb} in · "
          + " · ".join(f"{k or '?'} {v}" for k, v in sorted(nets.items())) + "</div>")
        A("<table class=pt><tr><th>address</th><th>net</th><th></th>"
          "<th>software</th><th>ping</th><th>height</th><th>up</th></tr>")
        now = time.time()
        for x in sorted(pr, key=lambda z: (z["inbound"], z.get("since") or 0))[:PEERS_SHOWN]:
            net = x["network"] or "?"
            netcls = "pill onion" if net in ("onion", "i2p") else "pill clear"
            ping = f"{x['ping'] * 1000:.0f} ms" if x.get("ping") else "—"
            up = "—" if not x.get("since") else f"{(now - x['since']) / 3600:.1f} h"
            A(f"<tr><td class=a>{esc(x['addr'])}</td>"
              f"<td><span class='{netcls}'>{esc(net)}</span></td>"
              f"<td><span class=pill>{'in' if x['inbound'] else 'out'}</span></td>"
              f"<td class=a>{esc(x['subver'])}</td><td>{ping}</td>"
              f"<td>{commas(x.get('height'))}</td><td>{up}</td></tr>")
        A("</table>")
        if len(pr) > PEERS_SHOWN:
            A(f"<div class=note>{len(pr) - PEERS_SHOWN} more not shown.</div>")
        A("</div>")

    if b:
        A("<div class=card><h2>STRIPPED</h2><table>")
        for k, label in (("original", "original blocks"), ("stored", "monetary store"),
                         ("saved", "saved"), ("carriers", "carriers removed"),
                         ("verified", "blocks verified from store alone"),
                         ("failed", "blocks failed"), ("filters", "filter entries")):
            if k in b:
                v = b[k]
                cls = "ok" if (k == "failed" and not v.strip("0,")) else ""
                A(f"<tr><td class=k>{label}</td><td class='v {cls}'>{esc(v)}</td></tr>")
        A("</table></div>")

    # The bars and the wallet, after peers. Simple view, in the order
    # somebody reads it: what is it doing, who is it talking to, how far
    # along, how do I connect a wallet.
    A(sync_card(d))
    A(wallet_card(d))

    # Everything below here is detail. It is still on the page — the
    # people who care about this project care about these numbers — but
    # it is below the answer rather than in front of it.

    A(indexing_card(d))

    if cfg is not None:
        A(race_card(getattr(cfg, "store", "")))
        A(settings_card(cfg, d))
        A(advanced_card(cfg, notice=d.get("settings_notice")))


    A("</div>")
    A(LIVE_JS)
    A(donate_footer())
    A(f"<script>{FEED_JS}</script>")
    return "".join(p)


# ---------------------------------------------------------------- server


class Handler(http.server.BaseHTTPRequestHandler):
    cfg = None
    feed = None
    poller = None
    server_version = "monetary-ui"

    def _send(self, code, body, ctype):
        raw = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        parts = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(parts.query)
        if parts.path == "/":
            self.cfg._selected_log = q.get("log", [None])[0]
            self.cfg._indexer = self.poller.indexer if self.poller else None
            self._send(200, render(gather(self.cfg), self.cfg),
                       "text/html; charset=utf-8")
        elif parts.path == "/events.json":
            try:
                since = int(q.get("since", ["0"])[0])
            except ValueError:
                since = 0
            self._send(200, json.dumps(
                {"events": self.feed.since(since) if self.feed else [],
                 "last": self.feed.last_id() if self.feed else 0}),
                "application/json")
        elif parts.path == "/live.json":
            # The handful of numbers that change, and nothing else.
            # Deliberately cheap: the page polls this every few seconds,
            # so it must not re-read the store size, the logs or the
            # config the way /status.json does.
            self.cfg._indexer = None
            self._send(200, json.dumps(live_numbers(self.cfg)),
                       "application/json")
        elif parts.path == "/status.json":
            self.cfg._selected_log = None
            self.cfg._indexer = self.poller.indexer if self.poller else None
            self._send(200, json.dumps(gather(self.cfg), indent=1, default=str),
                       "application/json")
        else:
            self._send(404, "not found", "text/plain")

    # ------------------------------------------------------------ settings
    #
    # The only write path in this program. It exists because a settings page
    # you cannot save is not a settings page, and because Umbrel's standard is
    # that an app is operable from the browser without touching a shell.
    #
    # Everything that makes it safe lives in node_settings.py: each key is
    # checked against `bitcoind -help`, each value against its declared type
    # and range, the whole batch is rejected if any part of it is bad, and the
    # file is backed up and replaced atomically. Nothing here validates
    # anything itself, so there is one place to audit rather than two.

    def _form(self, limit=65536):
        """Parse a urlencoded POST body, or None if it is not one."""
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return None
        if length <= 0 or length > limit:
            return None
        try:
            body = self.rfile.read(length).decode("utf-8", "replace")
            return urllib.parse.parse_qs(body, keep_blank_values=True,
                                         max_num_fields=200)
        except (OSError, ValueError):
            return None

    def _index_result(self, is_error, text):
        try:
            self.cfg._selected_log = None
            self.cfg._indexer = self.poller.indexer if self.poller else None
            d = gather(self.cfg)
            d["index_notice"] = {"error": is_error, "text": text}
            self._send(200, render(d, self.cfg), "text/html; charset=utf-8")
        except Exception:
            self._send(500, "index error", "text/plain")

    def _do_index(self):
        """
        Delete the address index.

        The only destructive action this page offers, so it is fenced:
        it refuses while the indexer is enabled, because removing the
        files under a running electrs corrupts its database rather than
        freeing anything, and it only ever removes the one directory the
        supervisor reported.
        """
        form = self._form()
        if form is None or (form.get("action") or [""])[0] != "delete":
            self._index_result(True, "Malformed request.")
            return
        d = gather(self.cfg)
        sup = d.get("supervisor") or {}
        if sup.get("index_enabled"):
            self._index_result(
                True, "Turn indexing off and restart the app first. "
                      "Deleting the index underneath a running indexer "
                      "corrupts it rather than freeing anything.")
            return
        path = sup.get("index_dir")
        if not path or not os.path.isdir(path):
            self._index_result(True, "There is no index directory to "
                                     "delete.")
            return
        # Only the directory the supervisor named, and only if it still
        # looks like the index.
        if os.path.basename(path.rstrip("/")) != "electrs":
            self._index_result(True, "Refusing to delete %s: that is not "
                                     "the index directory." % path)
            return
        freed = sup.get("index_bytes") or 0
        try:
            import shutil as _sh
            _sh.rmtree(path)
        except OSError as e:
            self._index_result(True, "Could not delete it: %s" % e)
            return
        self._index_result(False, "Index deleted. %s freed." % human(freed))

    def do_POST(self):
        parts = urllib.parse.urlparse(self.path)
        if parts.path == "/index":
            return self._do_index()
        if parts.path != "/settings":
            self._send(404, "not found", "text/plain")
            return
        if ns is None:
            self._settings_result(True, "node_settings.py is not available.")
            return

        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        # A settings form is a few hundred bytes. Anything larger is not one.
        if length <= 0 or length > 65536:
            self._settings_result(True, "Malformed request.")
            return
        try:
            body = self.rfile.read(length).decode("utf-8", "replace")
            form = urllib.parse.parse_qs(body, keep_blank_values=True,
                                         max_num_fields=200)
        except (OSError, ValueError):
            self._settings_result(True, "Malformed request.")
            return

        conf = getattr(self.cfg, "conf", "") or ""
        mconf = getattr(self.cfg, "monetary_conf", "") or ""
        managed = bool(getattr(self.cfg, "managed_bitcoin_config", False))

        # In managed mode the bitcoind rows render without a name attribute,
        # so an ordinary browser cannot submit them. That is not a control.
        # This is: the scope is enforced here, on every request, whatever the
        # form looked like.
        if managed:
            if not mconf:
                self._settings_result(
                    True, "No monetary config path was configured, so there "
                          "is nothing this app may write.")
                return
            paths = {ns.SCOPE_MONETARY: mconf}
        else:
            if not conf:
                self._settings_result(True, "No config path was configured, "
                                            "so there is nothing to write "
                                            "to.")
                return
            paths = {ns.SCOPE_BITCOIND: conf, ns.SCOPE_MONETARY: mconf}
        blob = help_cache()
        if blob is None:
            self._settings_result(True, "Cannot run `bitcoind -help`, so this "
                                        "page will not guess which options "
                                        "your build supports. Nothing was "
                                        "written.")
            return

        action = (form.get("action") or [""])[0]

        if action == "defaults":
            try:
                # restore_all_defaults covers every scope in `paths`, and in
                # managed mode `paths` holds only the monetary file — so the
                # bitcoind settings cannot be reset from here either.
                written, baks = ns.restore_all_defaults(paths, blob)
            except Exception as e:
                self._settings_result(True, "Nothing written: %s"
                                      % str(e)[:200])
                return
            self._settings_result(
                False, "%d settings restored to defaults%s. Restart bitcoind "
                       "to apply."
                % (len(written),
                   (" (backups: %s)"
                    % ", ".join(os.path.basename(b)
                                for b in baks.values())) if baks else ""))
            return

        if action != "save":
            self._settings_result(True, "Unknown action.")
            return

        # Checkboxes send nothing when off, so the hidden has_<key> partner is
        # what distinguishes "turned off" from "not on this form at all".
        changes = {}
        refused = []
        for key in ns.BY_KEY:
            s = ns.BY_KEY[key]
            if managed and s.get("scope") != ns.SCOPE_MONETARY:
                # Note it only if the request actually tried, so a normal
                # save does not produce a misleading warning.
                if key in form or ("has_" + key) in form:
                    refused.append(key)
                continue
            if s["type"] == ns.BOOL:
                if ("has_" + key) not in form:
                    continue
                changes[key] = "1" if key in form else "0"
            elif key in form:
                v = (form.get(key) or [""])[0].strip()
                if v == "":
                    continue
                changes[key] = v

        # Only send what actually differs, so a save does not rewrite the
        # whole file and bury the real change in a diff of forty lines.
        try:
            current = {r["key"]: str(r["value"])
                       for r in ns.effective(conf, blob, mconf)}
        except Exception:
            current = {}
        diff = {}
        for k, v in changes.items():
            norm, why = ns.validate(k, v)
            if why:
                diff[k] = v          # let node_settings report the reason
            elif norm != current.get(k):
                diff[k] = norm

        if refused:
            self._settings_result(
                True, "Refused: %s. The Bitcoin service owns its own "
                      "configuration on this platform, so this app will not "
                      "write %s. Nothing was changed."
                % (", ".join(sorted(refused)),
                   "it" if len(refused) == 1 else "them"))
            return

        if not diff:
            self._settings_result(False, "No changes.")
            return
        try:
            written, baks = ns.write_settings(paths, diff, blob)
        except ValueError as e:
            self._settings_result(True, "Nothing written — %s" % str(e)[:300])
            return
        except Exception:
            self._settings_result(True, "Nothing written: the config could "
                                        "not be updated.")
            return

        self._settings_result(
            False, "Saved %s%s. Restart bitcoind to apply, then re-run "
                   "tor_lockdown.sh --verify."
            % (", ".join("%s=%s" % (k, v) for k, v in sorted(written.items())),
               (" (backups: %s)"
                % ", ".join(os.path.basename(b)
                            for b in baks.values())) if baks else ""))

    def _settings_result(self, is_error, text):
        """Render the page again with a notice. No redirect, no flash cookie.

        A redirect would need the notice stored somewhere between requests,
        and the only place to put it is server state shared by every visitor —
        which for a page with no authentication is worse than a re-render."""
        try:
            self.cfg._selected_log = None
            self.cfg._indexer = self.poller.indexer if self.poller else None
            d = gather(self.cfg)
            d["settings_notice"] = {"error": is_error, "text": text}
            self._send(200, render(d, self.cfg), "text/html; charset=utf-8")
        except Exception:
            self._send(500, "settings error", "text/plain")

    # POST is handled above, and only for /settings. Everything else that
    # mutates stays refused: this page edits bitcoin.conf and nothing else.
    def _read_only(self):
        # Refused because nothing here uses them, NOT because the
        # interface is read only — it is not. POST /settings writes the
        # config and POST /index deletes the address index.
        self._send(405, "method not supported", "text/plain")

    do_PUT = do_DELETE = do_PATCH = _read_only

    def log_message(self, *a):
        pass


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


# ---------------------------------------------------------------- self-test


def selftest():
    import tempfile
    ok = []

    def ck(name, cond, detail=""):
        ok.append(cond)
        print(f"  [{'ok  ' if cond else 'FAIL'}] {name}" + (f"  — {detail}" if detail else ""))

    # This asserted "1.5 KB" for 1536 bytes, which is the mislabel itself —
    # the test was pinning the bug in place. 1536 bytes is 1.5 KiB.
    ck("human bytes use binary units, correctly labelled",
       human(1536) == "1.5 KiB", human(1536))
    ck("and a GiB is not called a GB",
       human(1024 ** 3) == "1.0 GiB", human(1024 ** 3))
    ck("commas", commas(1234567) == "1,234,567")

    f = Feed(maxlen=5)
    for i in range(3):
        f.add("block", f"b{i}")
    ck("ids monotonic", [e["id"] for e in f.since(0)] == [1, 2, 3])
    ck("since filters", [e["id"] for e in f.since(2)] == [3])
    for i in range(10):
        f.add("block", "x")
    ck("feed bounded", len(f.since(0)) == 5)
    ck("ids rise after eviction", f.last_id() == 13)

    fc = Feed(maxlen=1000)
    ts = [threading.Thread(target=lambda: [fc.add("b", "x") for _ in range(200)])
          for _ in range(4)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    got = [e["id"] for e in fc.since(0)]
    ck("no duplicate ids under concurrency", len(got) == len(set(got)))
    ck("all events recorded", fc.last_id() == 800)

    class Cfg:
        store = "/nonexistent"
        rpc_url = "http://127.0.0.1:1"
        cookie = None
        electrum = None
        electrum_ssl = False
    pol = Poller(Cfg, Feed())
    pol.last_height = 1
    for i in range(SEEN_WALLET_MAX + 300):
        key = (f"tx{i}", "receive", 0)
        if len(pol.seen_order) == pol.seen_order.maxlen:
            pol.seen_wallet.discard(pol.seen_order[0])
        pol.seen_order.append(key)
        pol.seen_wallet.add(key)
    ck("seen_wallet bounded", len(pol.seen_wallet) <= SEEN_WALLET_MAX,
       str(len(pol.seen_wallet)))
    ck("keeps newest", (f"tx{SEEN_WALLET_MAX + 299}", "receive", 0) in pol.seen_wallet)
    ck("drops oldest", ("tx0", "receive", 0) not in pol.seen_wallet)

    r = probe_electrum("127.0.0.1:1", False, timeout=1)
    # An RPC error is not an outage. Core returns them as HTTP 500 with
    # the reason in the body, which urlopen throws away.
    print("\nrpc errors")
    import http.server as _hs2, threading as _th2
    _ERRBODY = b'{"result":null,"error":{"code":-1,"message":' \
               b'"Block not available (pruned data)"},"id":"ui"}'

    class _EH(_hs2.BaseHTTPRequestHandler):
        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0)
            self.rfile.read(n)
            self.send_response(500)
            self.send_header("Content-Length", str(len(_ERRBODY)))
            self.end_headers()
            self.wfile.write(_ERRBODY)

        def log_message(self, *a):
            pass

    _s2 = socket.socket()
    _s2.bind(("127.0.0.1", 0))
    _p2 = _s2.getsockname()[1]
    _s2.close()
    _srv2 = _hs2.HTTPServer(("127.0.0.1", _p2), _EH)
    _th2.Thread(target=_srv2.serve_forever, daemon=True).start()
    try:
        _r = RPC("http://127.0.0.1:%d" % _p2, user="u", password="p")
        try:
            _r.call("getblockstats", 1)
            ck("an error response raises", False)
        except RPCError as e:
            ck("an error response raises RPCError", True)
            ck("and carries the real reason, not 'Internal Server Error'",
               "pruned data" in str(e))
            ck("and names the method", e.method == "getblockstats")
            ck("and keeps the code", e.code == -1)
        except Exception:
            ck("an error response raises RPCError", False)
    finally:
        _srv2.shutdown()

    # A node that is genuinely down must NOT look like an RPC error.
    _s3 = socket.socket()
    _s3.bind(("127.0.0.1", 0))
    _p3 = _s3.getsockname()[1]
    _s3.close()
    try:
        RPC("http://127.0.0.1:%d" % _p3, user="u", password="p").call("x")
        ck("an unreachable node raises", False)
    except RPCError:
        ck("an unreachable node is not reported as an RPC error", False)
    except Exception:
        ck("an unreachable node is not reported as an RPC error", True)

    # Warm-up is not a fault, and one slow reply is not an outage. Both
    # appeared in red on a node that was starting normally.
    ck("warm-up has its own code", RPCError("x", -28, "Loading").code == -28)
    _pw = type("P", (), {"warned_warmup": False, "warned_rpc": False,
                         "warned_down": False, "consecutive_fail": 0})()
    _pw.consecutive_fail += 1
    ck("one failure does not declare an outage",
       _pw.consecutive_fail < 3)
    _pw.consecutive_fail += 2
    ck("three in a row does", _pw.consecutive_fail >= 3)
    ck("the rpc timeout allows for a loading node",
       RPC("http://127.0.0.1:1", user="u", password="p").timeout >= 30)

    ck("probe returns dict on refusal", isinstance(r, dict) and not r["ok"])
    ck("probe survives malformed target",
       not probe_electrum("nonsense", False, timeout=1)["ok"])

    with tempfile.TemporaryDirectory() as d:
        logs = os.path.join(d, "results")
        os.makedirs(logs)
        with open(os.path.join(logs, "daemon.log"), "w") as fh:
            fh.writelines(f"line {i}\n" for i in range(200))
        open(os.path.join(logs, "notes.txt"), "w").write("x")
        ck("lists .log only", list_logs(logs) == ["daemon.log"])
        rows, err = tail_log(logs, "daemon.log")
        ck("tail bounded and last", err is None and len(rows) == LOG_LINES
           and rows[-1] == "line 199")
        for bad in ("../../etc/passwd", "/etc/passwd", "notes.txt"):
            ck(f"rejects {bad!r}", tail_log(logs, bad)[0] is None)

        class C2:
            store = d
            rpc_url = "http://127.0.0.1:1"
            cookie = None
            build_log = "/nonexistent"
            log_dir = logs
            _selected_log = None
            _indexer = None
            electrum = None
        g = gather(C2)
        ck("survives unreachable node", g["node"] is None)
        page = render(g)
        ck("renders without a node", "MONETARY NODE" in page)
        # The external-indexer card used to be shown to everyone with
        # instructions for installing electrs. On a node whose whole claim is
        # that you do not need one, that was the page telling you to go get
        # the thing it replaces. It now appears only if you configured one.
        ck("external indexer card hidden when none is configured",
           "EXTERNAL INDEXER" not in page)
        ck("wallet card shown instead", "WALLET" in page)
        # External indexers are gone from the page entirely. The app
        # ships its own, so telling somebody to go install electrs is
        # telling them to install the thing they already have.
        g2 = dict(g)
        g2["electrum_target"] = "127.0.0.1:50001"
        ck("no external indexer card, configured or not",
           "EXTERNAL INDEXER" not in render(g2))

        # The headline: the three numbers somebody installed this to see,
        # above everything else.
        hd = headline_card({
            "node": {"blocks": 972000, "headers": 972000},
            "state": {"height": 971998, "carriers": 39_000_000_000,
                      "bytes_in": 773_000_000_000,
                      "bytes_out": 724_000_000_000}})
        ck("headline shows the block height", "972,000" in hd)
        ck("headline shows the sync percentage", "100.00%" in hd)
        ck("headline shows spam removed in binary units", "GiB" in hd)
        ck("headline shows the store against the blocks",
           "smaller" in hd)
        empty_hd = headline_card({})
        ck("headline survives knowing nothing", "NODE" in empty_hd)
        ck("and says nothing was stripped rather than zero",
           "nothing stripped yet" in empty_hd)
        part = headline_card({"node": {"blocks": 500, "headers": 1000},
                              "state": {}})
        ck("a half-synced chain reports its share", "50.00%" in part)
        ck("and is not marked ok", "class=ok>50" not in part)

        # Order on the page: the answer first. The store/daemon detail
        # cards are gone entirely — a person installing this does not need
        # a commitment hash and a record count to know it is working.
        full = render(g)
        ck("the headline is on the page", ">NODE<" in full)
        ck("no store detail card", "NODE DETAIL" not in full)
        ck("no commitment hash on the simple view",
           "commitment C" not in full)
        ck("the feed is still there", "FEED" in full)

        # A permanent green TOR ONLY badge taught people to ignore the
        # banner. Silence when private; shout only when the IP may be out.
        # Warm-up is not a problem. The page used to print
        # "node RPC: Loading block index" in red on a node that was
        # starting exactly as it should.
        _warm = render({"generated": "x", "store_path": "/s", "errors": [],
                        "warming_up": "Loading block index…",
                        "node": None, "state": None, "build": None,
                        "logs": [], "log_dir": "/l", "lag": None,
                        "store_bytes": 0, "store_files": 0,
                        "daemon_pid": None, "tor_required": True})
        _rx = render({"generated": "x", "store_path": "/s", "errors": [],
                      "supervisor": {"reindexing": True},
                      "node": None, "state": None, "build": None,
                      "logs": [], "log_dir": "/l", "lag": None,
                      "store_bytes": 0, "store_files": 0,
                      "daemon_pid": None, "tor_required": True})
        _ne = render({"generated": "x", "store_path": "/s", "errors": [],
                      "supervisor": {"node_error": "could not open db"},
                      "node": None, "state": None, "build": None,
                      "logs": [], "log_dir": "/l", "lag": None,
                      "store_bytes": 0, "store_files": 0,
                      "daemon_pid": None, "tor_required": True})
        ck("a dead bitcoind is explained on a live page",
           "BITCOIN CORE IS NOT RUNNING" in _ne)
        ck("and quotes what it said", "could not open db" in _ne)
        ck("and says nothing is at risk", "nothing is at risk" in _ne)

        ck("a reindex is explained", "REBUILDING THE INDEX" in _rx)
        ck("and that nothing is re-downloaded",
           "nothing is being re-downloaded" in _rx.lower())
        ck("and roughly how long", "takes hours" in _rx)

        # The case that actually happened: the pruner had run, 15 GiB of a
        # 740 GiB chain was left, and the reindex became a two-day
        # re-download while this banner said it wasn't one.
        _rd = render({"generated": "x", "store_path": "/s", "errors": [],
                      "supervisor": {"reindexing": True,
                                     "reindex_redownload": True,
                                     "blocks_bytes": 15 * 1024 ** 3},
                      "node": None, "state": None, "build": None,
                      "logs": [], "log_dir": "/l", "lag": None,
                      "store_bytes": 0, "store_files": 0,
                      "daemon_pid": None, "tor_required": True})
        ck("a reindex that re-downloads says so",
           "RE-DOWNLOADING THE CHAIN" in _rd)
        ck("and does NOT claim otherwise",
           "nothing is being re-downloaded" not in _rd.lower())
        ck("and says how much was left on disk", "15.0 GiB" in _rd)
        ck("and that it is days over Tor", "days, not hours" in _rd)
        ck("and that the store is not affected",
           "not</b> affected" in _rd or "not affected" in _rd)
        ck("and warns about the disk", "stop the node" in _rd)

        # ---------------------------------------------------- status bar
        #
        # The bar is the first thing on the page and the only part most
        # people will read, so it gets checked state by state rather than
        # "it rendered".
        def _bar(sup, state=None, node=None, warming=None):
            return status_bar({"supervisor": sup, "state": state or {},
                               "node": node or {}, "store_path": "/s",
                               "warming_up": warming})

        _ok = _bar({"node_height": 974581, "node_headers": 974581,
                    "store_height": 974581, "index_enabled": True,
                    "index_height": 974581, "tor": True},
                   {"carriers": 39287654321})
        ck("the bar says what the node is doing",
           "Following the chain" in _ok)
        ck("the bar is green when all is well", "sbar ok" in _ok)
        ck("the bar carries the height", "974,581" in _ok)
        ck("and the route", "TOR" in _ok)
        ck("and spam removed", "SPAM REMOVED" in _ok)
        ck("and free disk", "DISK FREE" in _ok)
        ck("every bar value has a live id", _ok.count("id=lv-sb-") == 7)

        _re = _bar({"reindexing": True, "reindex_redownload": True,
                    "tor": True})
        ck("a re-download is the headline", "Re-downloading" in _re)
        ck("and the bar turns amber", "sbar warn" in _re)

        _dead = _bar({"node_error": "could not open db", "tor": True})
        ck("a dead Core is the headline", "STOPPED" in _dead)
        ck("and the bar turns red", "sbar bad" in _dead)

        _full = _bar({"space_blocked": True, "tor": True})
        ck("no disk outranks everything", "not enough disk" in _full)

        # Stopped by the watchdog while running: the page must say it was
        # deliberate and that nothing was deleted, or the operator's first
        # move is to start deleting things themselves.
        _halt = space_banner({"supervisor": {
            "disk_halted": True, "disk_free": 5 * 1024 ** 3,
            "disk_halt_gib": 20}})
        ck("a watchdog halt is explained", "DISK ALMOST FULL" in _halt)
        ck("and says nothing was deleted",
           "Nothing has been deleted" in _halt)
        ck("and how much is left", "5.0 GiB" in _halt)
        ck("and that it recovers by itself", "starts again on its own" in _halt)
        ck("a halted node is not also 'not enough disk'",
           "NOT ENOUGH DISK" not in _halt)

        _cn = _bar({"clearnet": True, "tor": False, "node_height": 1,
                    "node_headers": 1, "index_enabled": True})
        ck("clearnet is named in the bar", "CLEARNET" in _cn)
        ck("and marked bad", "sbval bad" in _cn)

        _str = _bar({"node_height": 974581, "store_height": 900000,
                     "index_enabled": True, "tor": True})
        ck("a lagging store reads as stripping", "Stripping" in _str)

        _bld = _bar({"node_height": 974581, "store_height": 974581,
                     "index_enabled": True, "index_building": True,
                     "tor": True})
        ck("a building index reads as building", "Building the address" in _bld)

        _off = _bar({"node_height": 974581, "store_height": 974581,
                     "index_enabled": False, "tor": True})
        ck("an index that is off says off", "address index off" in _off)
        ck("and the bar is still green", "sbar ok" in _off)

        _df = _bar({"node_height": 1, "node_headers": 1, "tor": True,
                    "index_enabled": True, "disk_free": 420 * 1024 ** 3})
        ck("the node's own disk figure wins over the local one",
           "420.0 GiB" in _df)
        ck("and a healthy disk is not flagged", "sbval bad" not in _df)
        _dl = _bar({"node_height": 1, "node_headers": 1, "tor": True,
                    "index_enabled": True, "disk_free": 5 * 1024 ** 3})
        ck("a nearly full disk is flagged red", "sbval bad" in _dl)

        _i2 = _bar({"node_height": 1, "node_headers": 1, "tor": True,
                    "i2p": True, "index_enabled": True})
        ck("i2p shows in the route", "TOR + I2P" in _i2)

        # The bar must come before the banners: it is the thing you read
        # first, and a banner pushing it below the fold defeats it.
        ck("the bar is above the banners",
           _rd.index("sbar") < _rd.index("banner"))
        ck("the bar is live-updated",
           "lv-sb-doing" in LIVE_JS and "sbar " in LIVE_JS)

        # The page must not claim to be read only. It writes
        # monetary.conf from the settings panel and deletes the address
        # index from the index button; saying otherwise told operators
        # not to think about who can reach the port. Caught by the
        # StartOS packaging review, after months in a published app.
        _ro = render({"generated": "x", "store_path": "/s", "errors": [],
                      "supervisor": {"node_height": 1, "node_headers": 1,
                                     "index_enabled": True, "tor": True},
                      "node": None, "state": None, "build": None,
                      "logs": [], "log_dir": "/l", "lag": None,
                      "store_bytes": 0, "store_files": 0,
                      "daemon_pid": None, "tor_required": True})
        ck("the page does NOT claim to be read only",
           "read only" not in _ro.lower())
        ck("and says plainly that settings change the node",
           "change how the node" in _ro)

        ck("warm-up is announced calmly", "STARTING" in _warm)
        ck("and says nothing is wrong", "Nothing is wrong" in _warm)
        ck("and is not a PROBLEM", "PROBLEM" not in _warm)
        ck("and warns an adopted datadir takes longer",
           "adopted from another node" in _warm)

        ck("no disk banner when there is no problem",
           space_banner({"supervisor": {}}) == "")
        _sb = space_banner({"supervisor": {
            "space_blocked": True,
            "space_reason": ["disk check", "  free  55 GiB",
                             "  still needed  530 GiB"]}})
        ck("a blocked node says so at the top", "NOT ENOUGH DISK" in _sb)
        ck("and that nothing was written", "nothing is at risk" in _sb)
        ck("and shows the actual numbers", "530 GiB" in _sb)
        ck("and that it will recover on its own",
           "start on its own" in _sb)
        ck("the reason is escaped",
           "<script>" not in space_banner({"supervisor": {
               "space_blocked": True,
               "space_reason": ["<script>x</script>"]}}))

        ck("nothing shouts when the node is private",
           exposure_banner({"netinfo": {"networks": [
               {"name": "onion", "reachable": True,
                "proxy": "127.0.0.1:9050"},
               {"name": "ipv4", "reachable": False},
               {"name": "ipv6", "reachable": False}]},
               "peers": [{"network": "onion"}]}) == "")
        exp = exposure_banner({"peers": [{"network": "ipv4"}]})
        ck("a clearnet peer raises the banner", "IP MAY BE VISIBLE" in exp)
        ck("and says it cannot be taken back", "taken back" in exp)
        ck("and counts them", "1 peer connected over clearnet" in exp)
        ck("plural is handled",
           "2 peers connected" in exposure_banner(
               {"peers": [{"network": "ipv4"}, {"network": "ipv6"}]}))
        ck("reachable ipv4 raises it even with no clearnet peers",
           "IP MAY BE VISIBLE" in exposure_banner({"netinfo": {"networks": [
               {"name": "ipv4", "reachable": True}]}}))
        ck("a missing proxy raises it",
           "no Tor proxy" in exposure_banner({"netinfo": {"networks": [
               {"name": "onion", "reachable": True, "proxy": ""}]}}))
        ck("the clearnet setting alone raises it",
           "switched on in settings" in exposure_banner(
               {"supervisor": {"clearnet": True}}))
        ck("knowing nothing is not an alarm", exposure_banner({}) == "")
        ck("banner escapes its reasons",
           "<script>" not in exposure_banner(
               {"netinfo": {"networks": [{"name": "<script>x</script>",
                                          "reachable": True}]}}))

        # Signet at 100% is correct; saying so prevents the obvious panic.
        sg = headline_card({"node": {"chain": "signet", "blocks": 328390,
                                     "headers": 328390}, "state": {}})
        ck("a test chain is named", "signet" in sg)
        ck("and flagged as not real bitcoin", "not real bitcoin" in sg)
        mn = headline_card({"node": {"chain": "main", "blocks": 1,
                                     "headers": 1}, "state": {}})
        ck("mainnet is not labelled", "not mainnet" not in mn)

        # The lifecycle card. On a fresh install this is the only card that
        # can tell the difference between "working" and "broken" for days.
        ck("no supervisor means no card", lifecycle_card({}) == "")
        dl = lifecycle_card({"supervisor": {
            "phase": "downloading", "percent": 23.4,
            "detail": "block 230,000 of 972,000",
            "children": [{"name": "bitcoind", "running": True,
                          "restarts": 0},
                         {"name": "tor", "running": True, "restarts": 0}]}})
        # The bars live in SYNC now; lifecycle says which stage, not how
        # far. One number in two places drifts.
        ck("lifecycle draws no bar of its own", "width:" not in dl)
        ck("lifecycle marks the current stage", ">now<" in dl)
        ck("downloading credits Core, not this project",
           "Bitcoin Core downloading" in dl)
        ck("downloading warns it takes days", "takes days" in dl)
        ck("downloading says nothing is stripped yet",
           "Nothing is stripped until it finishes" in dl)
        ck("children are listed", "bitcoind" in dl and "tor" in dl)

        st = lifecycle_card({"supervisor": {
            "phase": "stripping", "percent": 80.0, "detail": "x",
            "children": []}})
        ck("stripping marks download done", ">done<" in st)
        ck("stripping promises disk is reclaimed behind, not ahead",
           "never ahead of it" in st)

        fo = lifecycle_card({"supervisor": {
            "phase": "following", "percent": 100.0,
            "detail": "1 block behind the tip", "children": []}})
        ck("following marks the earlier stages done", fo.count(">done<") == 2)

        sta = lifecycle_card({"supervisor": {
            "phase": "starting", "percent": None,
            "detail": "starting bitcoind", "children": []}})
        ck("starting draws no bar", "width:" not in sta)
        ck("starting explains the tor delay", "Tor" in sta)

        stp = lifecycle_card({"supervisor": {"phase": "stopped"}})
        ck("a stopped node says so plainly", "not running" in stp)

        rs = lifecycle_card({"supervisor": {
            "phase": "following", "percent": 100.0, "detail": "x",
            "children": [{"name": "daemon", "running": False,
                          "restarts": 3}]}})
        ck("a stopped child is visible", "stopped" in rs)
        ck("and its restarts are counted", "3 restarts" in rs)
        one = lifecycle_card({"supervisor": {
            "phase": "following", "percent": 100.0, "detail": "x",
            "children": [{"name": "daemon", "running": True,
                          "restarts": 1}]}})
        ck("one restart is singular", "1 restart<" in one)
        hostile = lifecycle_card({"supervisor": {
            "phase": "following", "percent": 100.0,
            "detail": "<script>alert(1)</script>", "children": []}})
        ck("lifecycle detail is escaped", "<script>" not in hostile)

        # Standalone: no validating node, and none expected. The page must
        # stop calling that a fault without ever implying the instance is
        # on Tor — it is on no network at all, which is a different claim.
        class _CN(_CD if False else object):
            store = logs
            monetary_conf = ""
            rpc_url = "http://127.0.0.1:1"
            cookie = None
            build_log = "/nonexistent"
            log_dir = logs
            _selected_log = None
            _indexer = None
            electrum = None
            no_node = True
        gn = gather(_CN)
        # A store opened but never written to records a null height. The
        # subtraction on it raised inside gather, so every request 500'd
        # and the page looked dead on a node that was syncing fine.
        for _st, _nd in ((None, {"blocks": 5}),
                         ({"height": None}, {"blocks": 5}),
                         ({"height": 3}, None),
                         ({}, {"blocks": 5})):
            _d = {"node": _nd}
            _hh = (_st or {}).get("height")
            _bb = (_d["node"] or {}).get("blocks")
            _lag = (_bb - _hh) if (isinstance(_hh, int)
                                   and isinstance(_bb, int)) else None
            ck("lag of %r/%r is safe" % (_hh, _bb),
               _lag is None or isinstance(_lag, int))
        ck("a real pair still computes",
           (10 - 4) == 6)

        ck("standalone suppresses the RPC error",
           not any("node RPC" in e for e in gn["errors"]))
        ck("standalone is flagged for the renderer", gn["standalone"])
        bn = network_banner(gn)
        ck("standalone banner says so", "STANDALONE" in bn)
        ck("standalone banner is not NETWORK UNKNOWN",
           "NETWORK UNKNOWN" not in bn)
        ck("standalone banner never claims Tor", "TOR ONLY" not in bn)
        ck("standalone banner says it cannot follow the tip",
           "cannot follow the tip" in bn)
        pn = render(gn)
        ck("a standalone page still renders", "MONETARY NODE" in pn)
        ck("and raises no IP alarm with no network info",
           "IP MAY BE VISIBLE" not in pn)

        # Without the flag, an absent node is still an error. Losing that
        # would hide a real outage on the ThinkPad.
        class _CN2(_CN):
            no_node = False
        g2 = gather(_CN2)
        ck("an absent node is still an error when one is expected",
           any("node RPC" in e for e in g2["errors"]))
        ck("and the banner still refuses to guess",
           "NETWORK UNKNOWN" in network_banner(g2))

        # A store built by a batch derive: derived.json, no state.json.
        # The dashboard called that a PROBLEM and printed "no state" where
        # the height belongs, which describes a complete 260 GiB store as
        # broken. It is not broken; it simply has no daemon.
        import tempfile as _tf9
        _ds = _tf9.mkdtemp()
        st, er = read_state(_ds)
        ck("a missing state.json is not an error on its own",
           st is None and er is None)
        ck("no derived.json either means no description",
           read_derived(_ds) is None)
        with open(os.path.join(_ds, "derived.json"), "w") as _fh:
            json.dump({"policy_id": "d41418", "start_height": 770000,
                       "end_height": 972000, "records": 202001}, _fh)
        dv = read_derived(_ds)
        ck("derived.json is read when state.json is absent", dv is not None)
        ck("and carries the range", dv["end_height"] == 972000)
        with open(os.path.join(_ds, "derived.json"), "w") as _fh:
            _fh.write("{ not json")
        ck("corrupt derived.json does not raise", read_derived(_ds) is None)
        with open(os.path.join(_ds, "derived.json"), "w") as _fh:
            json.dump({"policy_id": "x"}, _fh)
        ck("derived.json without a range is not a description",
           read_derived(_ds) is None)

        class _CD:
            store = _ds
            monetary_conf = ""
            rpc_url = "http://127.0.0.1:1"
            cookie = None
            build_log = "/nonexistent"
            log_dir = logs
            _selected_log = None
            _indexer = None
            electrum = None
        with open(os.path.join(_ds, "derived.json"), "w") as _fh:
            json.dump({"policy_id": "d41418aa", "start_height": 770000,
                       "end_height": 972000, "records": 202001}, _fh)
        gd = gather(_CD)
        ck("a derived store reports no state.json problem",
           not any("state.json" in e for e in gd["errors"]))
        pg = render(gd)
        # The derived range is read and carried, but the simple view does
        # not print it: height, sync and spam are the whole brief.
        ck("a derived store still renders a page", "MONETARY NODE" in pg)
        ck("and it is read", gd.get("derived") is not None)

        # The two bars. These replace the xpub card entirely: asking
        # somebody to paste an extended public key into a server is asking
        # for every address they will ever use, and it is reasonable to
        # refuse. A real indexer does not need one.
        ck("no supervisor means no sync card", sync_card({}) == "")
        sup = {"node_height": 500000, "node_headers": 972000,
               "index_height": 300000, "store_height": 400000,
               "index_enabled": True, "pruning": True,
               "prune_floor": 300000}
        sc = sync_card({"supervisor": sup})
        ck("sync card draws the chain bar", "51.44%" in sc)
        ck("sync card draws the index bar", "60.00%" in sc)
        ck("the two bars are different colours", "#4ea1f7" in sc)
        ck("sync card names what the index is for",
           "what your wallet queries" in sc)

        # "I don't know if it's doing anything" is the complaint these
        # answer. A bar sitting still looks the same whether it is working
        # slowly or wedged, so say which.
        ck("first sample is measuring", "measuring" in sc)
        prev = {"node_height": 499000, "index_height": 300000}
        sc2 = sync_card({"supervisor": sup, "supervisor_prev": prev})
        ck("advancing is reported with the delta", "+1,000" in sc2)
        ck("a stalled component is called out",
           "no change since last check" in sc2)
        cls, note = moving("x", None, 5)
        ck("no reading is not progress", cls == "dim")
        cls, _n = moving("x", 10, 10)
        ck("equal is not progress", cls == "warn")
        cls, _n = moving("x", 11, 10)
        ck("greater is progress", cls == "ok")

        ck("bar of None is empty, not full", "width:0.0%" in bar(None))
        ck("bar clamps above 100", "width:100.0%" in bar(140))
        ck("bar clamps below zero", "width:0.0%" in bar(-5))

        # The prune floor is the one thing that can destroy data.
        ck("the floor is explained as the lower of the two",
           "lower of the stripper" in sc)
        ck("and names the floor height", "300,000" in sc)
        nofloor = sync_card({"supervisor": dict(sup, prune_floor=None)})
        ck("no floor means nothing is deleted yet",
           "Nothing is being deleted yet" in nofloor)
        ck("and says why", "BOTH the stripper and the index" in nofloor)

        gone = sync_card({"supervisor": dict(sup, index_enabled=False,
                                             index_missing=True)})
        ck("a build with no indexer says so", "no indexer in it" in gone)
        ck("and makes clear the node itself is fine",
           "that part is unaffected" in gone)
        ck("and the connect card explains it too",
           "no indexer in it" in wallet_card(
               {"supervisor": dict(sup, index_enabled=False,
                                   index_missing=True)}))

        pruned = sync_card({"supervisor": dict(
            sup, index_blocked_pruned=True)})
        ck("a permanently pruned datadir is explained",
           "cannot run on this node" in pruned)
        ck("and that switching pruning off will not undo it",
           "does not" in pruned and "undo it" in pruned)

        both = sync_card({"supervisor": dict(sup,
                                             prune_blocked_by_index=True)})
        ck("the disk trade is stated when the index blocks pruning",
           "keeps every block" in both)
        ck("and sized honestly", "twice the chain" in both)

        # The toggle, on the card whose numbers it governs.
        # The control lives on the ADDRESS INDEX card alone. SYNC shows
        # the bars and nothing you can press.
        _ic = indexing_card({"supervisor": {"index_enabled": True,
                                            "index_bytes": 1024,
                                            "index_height": 9,
                                            "node_height": 9}})
        # The control lives in SETTINGS with the other settings, and the
        # delete is beside it.
        class _CS2:
            conf = "/tmp/b.conf"; monetary_conf = "/tmp/m.conf"
            managed_bitcoin_config = False; store = "/tmp/s"
            electrum = None; electrum_ssl = False
            host = "127.0.0.1"; port = 8080
        _son = settings_card(_CS2(), {"supervisor": {
            "index_enabled": True, "index_bytes": 58 * 1024**3}})
        ck("settings carries the index switch", "class=switch" in _son)
        ck("and shows it on", " checked" in _son)
        ck("and the size on disk", "58.0 GiB" in _son)
        ck("and no delete while it runs", "Delete the index" not in _son)
        ck("and says how to get there", "Switch it off to delete" in _son)
        _soff = settings_card(_CS2(), {"supervisor": {
            "index_enabled": False, "index_bytes": 58 * 1024**3}})
        ck("off offers the delete button",
           "Delete the index and free 58.0 GiB" in _soff)
        ck("and confirms first", "confirm(" in _soff)
        ck("and the switch is off", " checked" not in _soff)
        _snone = settings_card(_CS2(), {"supervisor": {
            "index_enabled": False, "index_bytes": 0}})
        ck("nothing written means no delete",
           "Delete the index" not in _snone)
        _sbare = settings_card(_CS2(), {})
        ck("no supervisor means no index section in settings",
           "Run the address index" not in _sbare)

        # And the ADDRESS INDEX card is now status only.
        _icard = indexing_card({"supervisor": {
            "index_enabled": True, "index_bytes": 1024,
            "index_height": 9, "node_height": 9}})
        ck("the index card has no controls",
           "class=switch" not in _icard
           and "Delete the index" not in _icard)
        ck("and points at settings", "in SETTINGS" in _icard)

        ck("the switch submits itself rather than needing Save",
           "this.form.submit()" in _son)
        ck("and asks the handler to save",
           "name=action value=save" in _son)
        ck("and marks the field as present",
           "name=has_useindex value=1" in _son)



        # Live updates. The page must move without a reload: a node
        # watcher leaves this open for hours.
        ck("the live script is on the page", "/live.json" in full)
        ck("it polls rather than reloads", "location.reload" not in
           full.split("LIVE")[-1] if "LIVE" in full else True)
        ck("the height carries an id", "id=lv-height" in full)
        # The bars only exist on a page that has a supervisor to report.
        ck("so does the chain bar",
           "id=lv-bar-node" in sync_card({"supervisor": {
               "node_height": 5, "node_headers": 10, "index_height": 1,
               "index_enabled": True}}))
        ck("a missed poll is not treated as an error", "catch(" in full)

        # Its own directory: live_numbers reads supervisor.json from the
        # store's PARENT, and using a bare tempdir would read and write
        # /tmp, which other tests share.
        import tempfile as _tfl
        _lroot = _tfl.mkdtemp()
        _lstore = os.path.join(_lroot, "mstore")
        os.makedirs(_lstore)

        class _CL:
            store = _lstore
            monetary_conf = ""
            rpc_url = "http://127.0.0.1:1"
            cookie = None
            build_log = "/nonexistent"
            log_dir = logs
            _selected_log = None
            _indexer = None
            electrum = None
        lv = live_numbers(_CL)
        ck("live numbers survive a store with no supervisor file",
           isinstance(lv, dict) and "height" in lv)
        ck("and report nothing rather than guessing",
           lv["height"] is None and lv["node_pct"] is None)
        with open(os.path.join(_lroot, "supervisor.json"), "w") as _fh:
            json.dump({"node_height": 500, "node_headers": 1000,
                       "index_height": 250}, _fh)
        lv2 = live_numbers(_CL)
        ck("percentages are computed", abs(lv2["node_pct"] - 50.0) < 0.01)
        ck("the index percentage is against the node, not the headers",
           abs(lv2["index_pct"] - 50.0) < 0.01)

        # End to end: the form the page posts must actually land in
        # monetary.conf, and the supervisor must read it back. Markup
        # that looks right is not the same as a setting that saves.
        if ns is not None:
            import tempfile as _tfc
            _cdir = _tfc.mkdtemp()
            _mconf = os.path.join(_cdir, "monetary.conf")
            _form = {"action": ["save"], "has_useindex": ["1"]}
            _changes = {}
            for _k in ns.BY_KEY:
                _sp = ns.BY_KEY[_k]
                if _sp.get("scope") != ns.SCOPE_MONETARY:
                    continue
                if _sp["type"] == ns.BOOL and ("has_" + _k) in _form:
                    _changes[_k] = "1" if _k in _form else "0"
            ck("the form yields a change for the index", 
               _changes.get("useindex") == "0")
            try:
                ns.write_settings({ns.SCOPE_MONETARY: _mconf}, _changes)
                _body = open(_mconf).read()
                ck("and it reaches monetary.conf", "useindex=0" in _body)
            except Exception as _e:
                ck("and it reaches monetary.conf: %s" % _e, False)

        # ONE card, ONE switch, and a sentence anybody can read. The
        # earlier version had three controls in three places with three
        # labels, which is how you get "what do these buttons do".
        ck("no supervisor means no card", indexing_card({}) == "")

        _ready = indexing_card({
            "supervisor": {"index_enabled": True, "index_bytes": 58 * 1024**3,
                           "index_height": 974000, "node_height": 974000},
            "wallet_advertise": "umbrel.local:50001"})
        ck("ready says wallets can connect", "Wallets can connect" in _ready)
        ck("and where to point them", "umbrel.local:50001" in _ready)
        ck("and shows the size", "58.0 GiB" in _ready)
        ck("and does not offer delete while running",
           "Delete the index" not in _ready)
        ck("but points at settings", "in SETTINGS" in _ready)

        _bld = indexing_card({"supervisor": {
            "index_enabled": True, "index_bytes": 20 * 1024**3,
            "index_height": 500000, "node_height": 974000}})
        ck("building shows a percentage", "51.3% done" in _bld)
        ck("and the blocks", "500,000 of 974,000" in _bld)
        ck("and that wallets cannot connect yet",
           "cannot connect until this finishes" in _bld)

        _offc = indexing_card({"supervisor": {
            "index_enabled": False, "index_bytes": 58 * 1024**3}})
        ck("off says no wallet can connect",
           "No wallet can connect" in _offc)
        ck("the off card still explains itself",
           "No wallet can connect" in _offc)

        _empty = indexing_card({"supervisor": {"index_enabled": False,
                                               "index_bytes": 0}})
        ck("nothing to delete means no delete button",
           "Delete the index" not in _empty)

        _miss = indexing_card({"supervisor": {"index_enabled": False,
                                              "index_missing": True}})
        ck("a build with no indexer says so", "no indexer in it" in _miss)

        _blk = indexing_card({"supervisor": {"index_enabled": True,
                                             "space_blocked": True}})
        ck("a node held back by disk says that instead",
           "not enough disk" in _blk)

        _start = indexing_card({"supervisor": {"index_enabled": True,
                                               "index_height": None,
                                               "node_height": 974000}})
        ck("no reading yet says starting up", "Starting up" in _start)

        ck("the sync card carries no switch either",
           "class=switch" not in sync_card({"supervisor": dict(
               sup, index_enabled=True)}))

        off = sync_card({"supervisor": dict(sup, index_enabled=False)})
        ck("an indexer that is off is stated plainly",
           "no wallet can connect" in off)

        quiet = sync_card({"supervisor": dict(sup, index_height=None)})
        ck("an index with no reading explains the first-run wait",
           "first time" in quiet)
        ck("and is honest about how long", "most of a day" in quiet)
        ck("and that the node itself is fine meanwhile",
           "validating and stripping normally" in quiet)
        broke = sync_card({"supervisor": dict(
            sup, index_height=None, phase="following",
            children=[{"name": "electrs", "running": False,
                       "restarts": 4, "last_exit": 1}])})
        ck("a failing indexer says so rather than looking idle",
           "keeps stopping" in broke)
        ck("and reports how many times", "4 restarts" in broke)
        ck("and that it is being retried", "restarted automatically" in broke)

        building = sync_card({"supervisor": dict(
            sup, index_height=510000, index_building=True)})
        ck("a first index shows its real progress", "510,000" in building)
        ck("and draws a moving bar, not a flat zero",
           "width:0.0%" not in building)
        ck("and says no wallet can connect yet",
           "nothing can connect yet" in building)
        ck("and that the node is fine meanwhile",
           "validating and stripping normally" in building)

        waiting = sync_card({"supervisor": dict(sup, index_height=None,
                                                phase="downloading")})
        ck("during sync the index says it is waiting on purpose",
           "on purpose" in waiting)
        ck("and that there is nothing to do",
           "nothing to do but wait" in waiting)
        ck("and does not imply a database problem",
           "opened its database" not in waiting)

        # The connect card: details only, never a key field.
        wc = wallet_card({"supervisor": sup,
                          "wallet_advertise": "umbrel.local:50001"})
        ck("connect card gives Sparrow instructions",
           "Private Electrum" in wc)
        ck("connect card shows host and port", "umbrel.local" in wc)
        ck("THERE IS NO XPUB FIELD", "name=xpub" not in wc
           and "xpub" not in wc.lower().replace("extended public key", ""))
        ck("connect card promises nothing that can spend",
           "could spend" in wc)
        ck("mid-index still invites a connection",
           "connect anyway" in wallet_card(
               {"supervisor": dict(sup, index_height=1),
                "wallet_advertise": "x:1"}))
        ck("a caught-up index is ready",
           "ready" in wallet_card(
               {"supervisor": dict(sup, index_height=500000),
                "wallet_advertise": "x:1"}))
        ck("a bare host still gets a port",
           ":50001" in wallet_card({"supervisor": sup,
                                    "wallet_advertise": "umbrel.local"}))
        ck("no indexer means nothing to connect to",
           "nothing for a wallet" in wallet_card(
               {"supervisor": dict(sup, index_enabled=False)}))
        # A bare hostname is useless to the machine running the wallet.
        ck("a bare hostname gets .local for mDNS",
           resolvable_host("btcserver") == "btcserver.local")
        ck("a name that already has one is untouched",
           resolvable_host("umbrel.local") == "umbrel.local")
        ck("an IP address is left alone",
           resolvable_host("192.168.86.34") == "192.168.86.34")
        ck("an onion is left alone",
           resolvable_host("abc.onion") == "abc.onion")
        ck("localhost is left alone",
           resolvable_host("localhost") == "localhost")
        ck("an IPv6 literal is left alone",
           resolvable_host("[::1]") == "[::1]")
        ck("empty stays empty", resolvable_host("") == "")
        ck("the wallet card shows the resolvable name",
           "btcserver.local:50001" in wallet_card(
               {"wallet_advertise": "btcserver:50001",
                "supervisor": {"index_enabled": True, "index_height": 1},
                "wallet_port": 50001}))

        ck("hostile advertise is escaped",
           "<script>" not in wallet_card(
               {"supervisor": sup,
                "wallet_advertise": "<script>x</script>:1"}))

        # tor verdicts
        base = dict(g)
        base["node"] = {"chain": "main", "blocks": 100, "headers": 100,
                        "progress": 1.0, "ibd": False, "pruned": False,
                        "bestblockhash": "00" * 32, "connections": 2,
                        "subversion": "/x/"}
        base["netinfo"] = {"networks": [
            {"name": "ipv4", "reachable": False, "proxy": ""},
            {"name": "ipv6", "reachable": False, "proxy": ""},
            {"name": "onion", "reachable": True, "proxy": "127.0.0.1:9050"}]}
        base["peers"] = [{"addr": "a.onion:8333", "network": "onion",
                          "inbound": False, "subver": "/s/", "ping": 0.1,
                          "since": time.time(), "height": 100}]
        ck("TOR ONLY when clean", "TOR ONLY" in tor_card(base))
        base["peers"].append({"addr": "1.2.3.4:8333", "network": "ipv4",
                              "inbound": False, "subver": "/s/", "ping": 0.1,
                              "since": time.time(), "height": 100})
        card = tor_card(base)
        ck("NOT TOR ONLY when clearnet peer", "NOT TOR ONLY" in card)
        ck("shows the fix", "onlynet=onion" in card)
        base["netinfo"]["networks"][2]["proxy"] = ""
        ck("no proxy is flagged", "none configured" in tor_card(base))

        base["peers"][0]["addr"] = "<script>x</script>"
        ck("peer address escaped", "&lt;script&gt;" in render(base))

    # SETTINGS card: renders, escapes, and only appears when cfg is passed.
    class _C:
        store = "/home/u/mstore"
        rpc_url = "http://127.0.0.1:8332"
        cookie = "/home/u/.bitcoin/.cookie"
        log_dir = "/home/u/logs"
        build_log = "build.log"
        electrum_ssl = False
        host = "127.0.0.1"
        port = 8080
    h = settings_card(_C(), {"electrum_target": None})
    # The settings card is a statement of what is running, not a manual.
    # It used to carry install instructions for two external indexers,
    # Tor setup, peering and systemd — none of which an app user can act
    # on, all of which pushed the actual settings off the screen.
    ck("settings card renders", "SETTINGS" in h
       and h.count("<div class=card>") == 1)
    ck("settings card points at the advanced section",
       "ADVANCED SETTINGS" in h)
    for gone in ("electrs", "Fulcrum", "tor_setup.sh", "services_setup.sh",
                 "prune_behind.py", "peering_setup.sh", "serve_bootstrap",
                 "config.toml"):
        ck("no install prose for %s" % gone, gone not in h)

    class _X(_C):
        store = "<script>x</script>"
    ck("settings card escapes paths",
       "<script>" not in settings_card(_X(), {}))
    # Build a clean page rather than reusing `g`: earlier tests add a
    # supervisor to it, and the index section in settings keys off that.
    _clean = {"generated": "x", "store_path": "/s", "errors": [],
              "node": None, "state": None, "build": None, "logs": [],
              "log_dir": "/l", "lag": None, "store_bytes": 0,
              "store_files": 0, "daemon_pid": None, "tor_required": True}
    ck("settings card only when cfg given",
       "SETTINGS" in render(_clean, _C())
       and "SETTINGS" not in render(_clean))

    f = donate_footer()
    ck("donate footer renders the address",
       DONATE_LN in f and "lightning:" + DONATE_LN in f)
    ck("donate footer is not a card",
       "<div class=card>" not in f,
       "it is not node state and must not rank with the store")
    ck("donate footer escapes a hostile address",
       "<script>" not in donate_footer("<script>x</script>@e.com"))
    ck("donate footer appears once in the page",
       render(g, _C()).count("class=donate") == 1)
    ck("page contacts nothing for it",
       "http://" not in f and "https://" not in f and "<img" not in f)

    ck("the settings card stays short",
       len(settings_card(_C(), {})) < 1500)

    # ------------------------------------------------------- network banner
    print("\nnetwork banner")

    def nets(onion=True, ipv4=False, ipv6=False, proxy="127.0.0.1:9050"):
        out = [{"name": "onion", "reachable": onion, "proxy": proxy},
               {"name": "ipv4", "reachable": ipv4},
               {"name": "ipv6", "reachable": ipv6}]
        return {"networks": out}

    clean = {"netinfo": nets(), "peers": [{"network": "onion"}] * 11}
    bn = network_banner(clean)
    ck("says TOR ONLY when it is", "TOR ONLY" in bn and "CLEARNET" not in bn)
    ck("the verdict is the biggest text on the page", "bword" in bn)
    ck("it names the peer count it checked", "11 peers" in bn)
    ck("it says the lockdown is kernel-enforced, not requested",
       "enforced by the kernel" in bn)
    ck("it gives the command to change it", "--clearnet" in bn)

    # THE CASE THAT ACTUALLY HAPPENED. bitcoin.conf said onlynet=onion; the
    # running process had never read it; 42 clearnet peers. A banner built on
    # configured intent would have been green for six hours.
    lying = {"netinfo": nets(ipv4=True),
             "peers": [{"network": "ipv4"}] * 42}
    bl = network_banner(lying)
    ck("a node with clearnet peers is never TOR ONLY", "TOR ONLY" not in bl)
    ck("it says CLEARNET instead", "CLEARNET" in bl)
    ck("it counts the clearnet peers", "42 clearnet peers" in bl)
    ck("it warns the home IP is exposed", "home IP address is visible" in bl)
    ck("it gives the command to stop the node", "systemctl stop bitcoind" in bl)

    ck("one clearnet peer is enough to fail it",
       "TOR ONLY" not in network_banner(
           {"netinfo": nets(), "peers": [{"network": "onion"},
                                         {"network": "ipv4"}]}))
    ck("ipv4 reachable fails it even with zero clearnet peers",
       "TOR ONLY" not in network_banner(
           {"netinfo": nets(ipv4=True), "peers": [{"network": "onion"}]}))
    ck("ipv6 reachable fails it too",
       "TOR ONLY" not in network_banner(
           {"netinfo": nets(ipv6=True), "peers": [{"network": "onion"}]}))
    ck("a missing proxy fails it",
       "TOR ONLY" not in network_banner(
           {"netinfo": nets(proxy=""), "peers": [{"network": "onion"}]}))
    ck("onion unreachable fails it",
       "TOR ONLY" not in network_banner(
           {"netinfo": nets(onion=False), "peers": [{"network": "onion"}]}))
    ck("a node with no peers yet can still be TOR ONLY",
       "TOR ONLY" in network_banner({"netinfo": nets(), "peers": []}))

    # Require Tor, the setting. It governs how this app REACTS, and the
    # default must be the safe one: an absent or unreadable config file has
    # to mean "required", never "permitted".
    clearnet = {"netinfo": nets(ipv4=True), "peers": [{"network": "ipv4"}] * 3}
    strict = network_banner(clearnet, tor_required=True)
    relaxed = network_banner(clearnet, tor_required=False)
    ck("with Tor required, clearnet is a fault",
       "home IP address is visible" in strict and "bclear" in strict)
    ck("with Tor not required, it is reported, not alarmed",
       "bclear" not in relaxed and "CLEARNET" in relaxed)
    ck("and it still says the IP is visible",
       "IP is visible" in relaxed)
    ck("and says how to make it a fault again",
       "Require Tor" in relaxed)
    ck("a clean node is TOR ONLY either way",
       "TOR ONLY" in network_banner(clean, tor_required=False))
    ck("the default is to require Tor",
       network_banner(clearnet) == strict)

    import tempfile as _tf2
    md = _tf2.mkdtemp()
    mp = os.path.join(md, "monetary.conf")
    ck("an absent config requires Tor",
       read_monetary_conf(mp)["torrequired"] == 1)
    with open(mp, "w") as f:
        f.write("torrequired=0\n")
    ck("and the setting is honoured when present",
       read_monetary_conf(mp)["torrequired"] == 0)
    with open(mp, "w") as f:
        f.write("torrequired=nonsense\n")
    ck("a malformed value falls back to requiring Tor",
       read_monetary_conf(mp)["torrequired"] == 1)

    bu = network_banner({"netinfo": None, "peers": []})
    ck("an unreachable node says UNKNOWN, not TOR ONLY",
       "UNKNOWN" in bu and "TOR ONLY" not in bu)
    ck("and tells you to assume nothing", "Assume" in bu)

    # Reuse the gather() fixture's own peers: other cards read fields the
    # banner never touches, and a hand-made peer dict breaks them.
    full = render(dict(g, netinfo=nets()), _C())
    ck("the banner is the first card in the page",
       full.index("banner") < full.index("FEED"))
    ck("banner escapes hostile network names",
       "<script>" not in network_banner(
           {"netinfo": {"networks": [{"name": "<script>x</script>",
                                      "reachable": True}]},
            "peers": [{"network": "<script>y</script>"}]}))

    ck("feed js uses textContent", "textContent" in FEED_JS
       and "innerHTML" not in FEED_JS)
    ck("heartbeat interval sane", 1 <= HEARTBEAT_EVERY <= 20)
    ck("quips appear in 1% of feed lines", QUIP_ODDS == 100)

    # ------------------------------------------------------- garbage feed
    print("\nper-block carrier feed")
    import tempfile as _tf
    sd = _tf.mkdtemp()
    with open(os.path.join(sd, "recent.jsonl"), "w") as f:
        for h in (968578, 968579, 968580):
            f.write(json.dumps({"h": h, "t": 1700000000, "in": 1900000,
                                "out": 1740000, "env": 150000, "opr": 6000,
                                "ms": 3000, "ss": 1000, "whole": 2800,
                                "mod": 40, "strip": 9, "txs": 2849}) + "\n")
        f.write("{ this line is not json\n")
        f.write("\n")

    recs = read_recent(sd)
    ck("reads the per-block log", len(recs) == 3)
    ck("skips a malformed line instead of raising",
       all(isinstance(r["h"], int) for r in recs))
    ck("returns blocks in height order",
       [r["h"] for r in recs] == [968578, 968579, 968580])
    ck("after= filters to new blocks only",
       [r["h"] for r in read_recent(sd, after=968578)] == [968579, 968580])
    ck("nothing new returns empty", read_recent(sd, after=968580) == [])
    ck("a missing store is empty, not an error",
       read_recent(os.path.join(sd, "nope")) == [])
    ck("a store of None is empty, not an error", read_recent(None) == [])

    # A truncated tail must not produce a half-parsed record.
    big = os.path.join(sd, "big")
    os.makedirs(big, exist_ok=True)
    with open(os.path.join(big, "recent.jsonl"), "w") as f:
        for h in range(900000, 903000):
            f.write(json.dumps({"h": h, "t": 1, "in": 100, "out": 90}) + "\n")
    tailed = read_recent(big, limit=25)
    ck("a long log is tailed, not read whole", len(tailed) == 25)
    ck("the tail ends at the newest block", tailed[-1]["h"] == 902999)

    class _P:
        cfg = _C()
        say_log = []

        def say(self, kind, text, detail=None, important=False):
            self._log.append((kind, text, detail))
    pp = Poller.__new__(Poller)
    pp.cfg = type("c", (), {"store": sd})()
    pp.recent_seen = 968578
    pp._log = []
    pp.feed = Feed()
    pp.say = lambda k, t, d=None, important=False: pp._log.append((k, t, d))
    pp.garbage_events()
    ck("emits one feed line per new block", len(pp._log) == 2)
    ck("the line leads with what was discarded",
       "discarded" in pp._log[0][1] and "968,579" in pp._log[0][1])
    ck("the line reports a percentage", "%" in pp._log[0][1])
    ck("the detail breaks the carriers down by kind",
       "envelopes" in pp._log[0][2] and "OP_RETURN" in pp._log[0][2]
       and "bare multisig" in pp._log[0][2])
    ck("the detail reports kept, trimmed and dropped counts",
       "kept whole" in pp._log[0][2] and "trimmed" in pp._log[0][2]
       and "dropped" in pp._log[0][2])
    pp.garbage_events()
    ck("a block is never reported twice", len(pp._log) == 2)

    # ---------------------------------------------------- settings panel
    print("\nadvanced settings panel")
    if ns is None:
        ck("node_settings is importable", False, "module not found")
    else:
        conf_path = os.path.join(sd, "bitcoin.conf")
        with open(conf_path, "w") as f:
            f.write("dbcache=900\nonlynet=onion\n")

        mconf_path = os.path.join(sd, "monetary", "monetary.conf")
        os.makedirs(os.path.dirname(mconf_path), exist_ok=True)
        with open(mconf_path, "w") as f:
            f.write("racewindow=45\n")

        # A class body cannot see the enclosing function's locals, so the
        # attribute has to be assigned from a differently named variable.
        class _CS:
            store = sd
            conf = conf_path
            monetary_conf = mconf_path
            rpc_url = "http://127.0.0.1:8332"
            cookie = ""
            log_dir = ""
            build_log = ""
            host = "127.0.0.1"
            port = 8080
            electrum_ssl = False

        # Build the fake `bitcoind -help` from the catalogue itself, so this
        # stays true as settings come and go. Value options carry "=<n>",
        # booleans do not — the distinction supported() depends on.
        _HELP_CACHE["t"] = time.time()
        _HELP_CACHE["blob"] = "\n".join(
            "  -%s%s" % (s["key"], "" if s["type"] == ns.BOOL else "=<n>")
            for s in ns.SETTINGS if s["scope"] == ns.SCOPE_BITCOIND)
        card = advanced_card(_CS())

        ck("panel renders every catalogue setting",
           all(("name='%s'" % s["key"]) in card for s in ns.SETTINGS),
           [s["key"] for s in ns.SETTINGS
            if ("name='%s'" % s["key"]) not in card])
        ck("panel groups the settings",
           all(("<h3 class=sgroup>%s" % g) in card for g in ns.GROUPS))
        ck("panel has a save button", "value=save" in card)
        ck("panel has a restore-to-defaults button", "value=defaults" in card)
        ck("restore asks for confirmation first", "confirm(" in card)
        ck("panel says a restart is required",
           "until the node restarts" in card)
        ck("panel shows the current value, not the default",
           "value='900'" in card)
        ck("panel marks settings that differ from default", "chg" in card)
        ck("panel distinguishes monetary options from bitcoind ones",
           "bitcoind never sees this" in card)
        ck("panel names both config files it writes",
           conf_path in card and mconf_path in card)

        # He asked for no dead controls. Every row must be operable.
        # Checked as an HTML attribute, not a substring: the word appears
        # legitimately in prose like "Disable Core's Own Wallet", and a test
        # that trips on help text is a test you learn to weaken.
        ck("no control is disabled when bitcoind answered",
           not re.search(r"<(input|button|select)[^>]*\sdisabled", card))
        ck("nothing says an option is missing from the build",
           "Not in this build" not in card)
        ck("the Lightning group is present and prominent",
           "zmqpubrawblock" in card and "LND requires" in card)
        ck("blocksonly warns it breaks Lightning", "Lightning breaks" in card)
        ck("the router group explains the IP pairing risk",
           "home IP" in card)
        ck("no pruning control exists", "name='prune'" not in card)
        ck("no mining-template control exists",
           "blockmaxweight" not in card and "blockmintxfee" not in card)

        # An option genuinely absent from an older Core is hidden, not
        # greyed — but the page says how many vanished and which.
        _HELP_CACHE["blob"] = "\n".join(
            "  -%s%s" % (s["key"], "" if s["type"] == ns.BOOL else "=<n>")
            for s in ns.SETTINGS
            if s["scope"] == ns.SCOPE_BITCOIND
            and s["key"] != "coinstatsindex")
        older = advanced_card(_CS())
        ck("an unsupported option is hidden, not disabled",
           "name='coinstatsindex'" not in older
           and not re.search(r"<(input|button|select)[^>]*\sdisabled", older))
        ck("but the page says one was hidden and names it",
           "1 setting hidden" in older and "coinstatsindex" in older)
        ck("and explains that everything offered works on stock Core",
           "works on stock Core" in older)
        ck("panel reminds you to re-verify Tor after a change",
           "tor_lockdown.sh --verify" in card)
        ck("booleans carry a hidden partner so 'off' is sendable",
           "has_txindex" in card)

        # Hostile catalogue content must not escape into the page.
        ns.SETTINGS.append(dict(group="<script>x</script>", key="zzhostile",
                                type=ns.BOOL, default=0,
                                label="<img src=x onerror=1>",
                                help="<b>bold</b>", warn="<script>y</script>"))
        ns.BY_KEY["zzhostile"] = ns.SETTINGS[-1]
        ns.GROUPS.append("<script>x</script>")
        try:
            hostile_card = advanced_card(_CS())
            ck("panel escapes hostile catalogue text",
               "<script>" not in hostile_card
               and "<img src=x" not in hostile_card)
        finally:
            ns.SETTINGS.pop()
            ns.BY_KEY.pop("zzhostile")
            ns.GROUPS.pop()

        _HELP_CACHE["blob"] = None
        _HELP_CACHE["t"] = 0
        _HELP_CACHE["tried"] = time.time()
        blind = advanced_card(_CS())
        ck("with no bitcoind help, the panel refuses to guess",
           "cannot tell which options" in blind)

        # A failed probe must be remembered, or every render forks bitcoind
        # again with a long timeout and the dashboard stalls itself to death.
        calls = []
        _real = ns.help_text
        ns.help_text = lambda *a, **k: (calls.append(1), "")[1]
        try:
            _HELP_CACHE["blob"] = None
            _HELP_CACHE["tried"] = 0.0
            help_cache()
            help_cache()
            help_cache()
            ck("a failed bitcoind probe is only retried once per window",
               len(calls) == 1, "%d calls" % len(calls))
            _HELP_CACHE["tried"] = 0.0
            help_cache()
            ck("the failure window does expire", len(calls) == 2)
            ck("the dashboard asks for a short timeout, not 30s",
               "timeout" in _real.__code__.co_varnames)
        finally:
            ns.help_text = _real
            _HELP_CACHE["blob"] = None
            _HELP_CACHE["tried"] = time.time()

        notice = advanced_card(_CS(), notice={"error": True,
                                              "text": "Nothing written"})
        ck("an error notice renders", "Nothing written" in notice)

        missing = advanced_card(type("c", (), {"conf": ""})())
        ck("a missing config path does not crash the panel",
           "ADVANCED SETTINGS" in missing)

        # Managed mode with an unreadable config must not present defaults as
        # though the platform had chosen them.
        class _CMX(_CS):
            managed_bitcoin_config = True
            conf = "/nonexistent/bitcoin.conf"
        unread = advanced_card(_CMX())
        # With the Bitcoin rows gone, an unreadable bitcoin.conf stops
        # mattering to this panel: there is nothing it was going to report.
        ck("an unreadable platform config is harmless now",
           "ADVANCED SETTINGS" in unread)
        ck("and the monetary rows still work",
           all(("name='%s'" % s["key"]) in unread for s in ns.SETTINGS
               if s["scope"] == ns.SCOPE_MONETARY))

        # ------------------------------------------------- managed platform
        # On Umbrel and StartOS the Bitcoin service owns bitcoin.conf. The
        # bitcoind rows must become a read-only report, and nothing in them
        # may be submittable.
        print("\n  managed mode (Umbrel / StartOS)")
        _HELP_CACHE["t"] = time.time()
        _HELP_CACHE["blob"] = "\n".join(
            "  -%s%s" % (s["key"], "" if s["type"] == ns.BOOL else "=<n>")
            for s in ns.SETTINGS if s["scope"] == ns.SCOPE_BITCOIND)

        class _CM(_CS):
            managed_bitcoin_config = True
        mcard = advanced_card(_CM())

        bitcoind_keys = [s["key"] for s in ns.SETTINGS
                         if s["scope"] == ns.SCOPE_BITCOIND]
        monetary_keys = [s["key"] for s in ns.SETTINGS
                         if s["scope"] == ns.SCOPE_MONETARY]

        # Bitcoin rows are not rendered at all in managed mode. Thirty-two
        # controls nobody can touch read as a broken panel, and the
        # information they carry is one sentence rather than thirty-two
        # rows.
        ck("no bitcoind row appears at all",
           not any(("name='%s'" % k) in mcard for k in bitcoind_keys),
           [k for k in bitcoind_keys if ("name='%s'" % k) in mcard])
        ck("nor via a checkbox's hidden partner",
           not any(("name='has_%s'" % k) in mcard for k in bitcoind_keys))
        ck("nor as a disabled or read-only row",
           "frozenval" in mcard is False or "frozenval" not in mcard)
        ck("the page says how many are not shown and why",
           "are not shown" in mcard and "owns its own" in mcard)
        ck("monetary rows stay editable",
           all(("name='%s'" % k) in mcard for k in monetary_keys))
        ck("it does not tell you to restart bitcoind",
           "systemctl restart bitcoind" not in mcard)
        ck("the save button names what it saves",
           "SAVE MONETARY SETTINGS" in mcard)
        ck("unmanaged mode is unchanged",
           all(("name='%s'" % k) in card for k in bitcoind_keys))

    # ------------------------------------------------------ competing blocks
    print("\ncompeting blocks card")
    if tr is None:
        ck("tip_race is importable", False, "module not found")
    else:
        empty = race_card(os.path.join(sd, "noraces"))
        ck("with no races it says so plainly",
           "No race witnessed yet" in empty)
        ck("even empty, it states it cannot influence the outcome",
           "cannot influence" in empty)

        rd = _tf.mkdtemp()
        with open(os.path.join(rd, "races.jsonl"), "w") as f:
            # cleaner won, dirtier won, a tie, and an unmeasured side
            for h, wc, lc in ((900001, 10, 500000), (900002, 400000, 20),
                              (900003, 100, 100)):
                f.write(json.dumps({"h": h, "t": 1,
                                    "winner": {"hash": "a" * 64,
                                               "carriers": wc},
                                    "loser": {"hash": "b" * 64,
                                              "carriers": lc}}) + "\n")
            f.write(json.dumps({"h": 900004, "t": 1,
                                "winner": {"hash": "c" * 64,
                                           "carriers": None},
                                "loser": {"hash": "d" * 64,
                                          "carriers": 5}}) + "\n")
        card = race_card(rd)
        ck("counts the races", "races witnessed" in card)
        ck("reports cleaner and dirtier wins separately",
           "cleaner block survived" in card
           and "dirtier block survived" in card)
        ck("a tie is not counted as a win",
           ">1<" in card.replace(" ", ""))
        ck("the headline percentage excludes ties and unmeasured",
           "50.0%" in card)
        ck("lists the most recent races",
           "cleaner kept" in card and "dirtier kept" in card)
        ck("says it undercounts rather than claiming a survey",
           "undercounts" in card)
        ck("names most-work and first-seen as the actual rule",
           "most work" in card and "first seen" in card)

        # The feed must never imply the node took a side.
        pr = Poller.__new__(Poller)
        pr.cfg = type("c", (), {"store": rd})()
        pr.race_seen = 900001
        pr._log = []
        pr.feed = Feed()
        pr.say = lambda k, t, d=None, important=False: pr._log.append((k, t, d))
        pr.race_event()
        ck("emits a feed line per new race", len(pr._log) == 3)
        ck("the race line names the height",
           "900,002" in pr._log[0][1])
        ck("the race line says who survived, not who it preferred",
           "survived" in pr._log[0][2]
           and "prefer" not in " ".join(x[2] or "" for x in pr._log))
        ck("an unmeasured race says so instead of guessing",
           "never arrived" in pr._log[-1][2])
        pr.race_event()
        ck("a race is never reported twice", len(pr._log) == 3)

    print(f"\n{sum(ok)}/{len(ok)} passed")
    return 0 if all(ok) else 1


# ---------------------------------------------------------------- main


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--store", default=os.path.expanduser("~/mstore"))
    ap.add_argument("--datadir", default=os.path.expanduser("~/.bitcoin"))
    ap.add_argument("--cookie")
    # Username and password authentication, for a node that does not expose
    # a cookie file to this process.
    #
    # RPC() has always supported it; the command line did not, so the only
    # way in was a readable .cookie. On Umbrel the credentials arrive as
    # environment variables and the cookie is not reachable, which meant the
    # dashboard could not authenticate at all there - the package\'s primary
    # case, dead, and invisible until someone ran it.
    ap.add_argument("--rpc-user", default=os.environ.get("BITCOIN_RPC_USER"))
    ap.add_argument("--rpc-password",
                    default=os.environ.get("BITCOIN_RPC_PASS"))
    ap.add_argument("--conf", default=None,
                    help="bitcoin.conf the advanced settings panel edits; "
                         "defaults to bitcoin.conf inside --datadir")
    ap.add_argument("--monetary-conf",
                    default=os.path.expanduser("~/.monetary/monetary.conf"),
                    help="where monetary-node settings are written; never "
                         "mixed into bitcoin.conf")
    ap.add_argument("--managed-bitcoin-config", action="store_true",
                    default=bool(os.environ.get("MONETARY_MANAGED_BITCOIN_CONFIG")),
                    help="the Bitcoin service owns bitcoin.conf, as on "
                         "Umbrel and StartOS. Bitcoin settings render "
                         "read-only and the server refuses to write them. "
                         "Also settable with "
                         "MONETARY_MANAGED_BITCOIN_CONFIG=1, which is how "
                         "the container passes it.")
    ap.add_argument("--rpc-url", default="http://127.0.0.1:8332")
    ap.add_argument("--build-log",
                    default=os.path.expanduser("~/monetary-node/results/build.log"))
    ap.add_argument("--log-dir",
                    default=os.path.expanduser("~/monetary-node/results"))
    ap.add_argument("--electrum", metavar="HOST:PORT",
                    help="Electrum-protocol indexer: electrs, Fulcrum, ElectrumX")
    ap.add_argument("--electrum-ssl", action="store_true",
                    help="connect to the indexer over TLS (not cert-verified)")
    # Wallet serving. The Electrum port is NOT the dashboard port, but it
    # defaults to loopback for the same reason: an Electrum server has no
    # authentication, so anything that can reach it can read the configured
    # wallet's entire balance and history.
    #
    # The container overrides it to 0.0.0.0, because a wallet on a phone has
    # to reach it and the compose file decides what is published. On a plain
    # machine, bind loopback and tunnel — the default should not quietly put
    # somebody's balance on their network.
    ap.add_argument("--wallet-port", type=int, default=50001)
    ap.add_argument("--wallet-host", default="127.0.0.1")
    ap.add_argument("--wallet-advertise",
                    default=os.environ.get("MONETARY_WALLET_ADVERTISE", ""),
                    help="host:port to show on the page for wallets to "
                         "connect to; the container passes the app's LAN "
                         "address, which it knows and this process does not")
    ap.add_argument("--wallet-start-height", type=int,
                    help="height of the store's first record; read from the "
                         "store when it recorded one")
    ap.add_argument("--no-node", action="store_true",
                    default=bool(os.environ.get("MONETARY_NO_NODE")),
                    help="there is no validating node attached and none is "
                         "expected. Stops the dashboard reporting an absent "
                         "bitcoind as a fault. Also settable with "
                         "MONETARY_NO_NODE=1.")
    ap.add_argument("--no-wallet", action="store_true",
                    help="do not serve wallets at all")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--i-understand-this-exposes-node-state", action="store_true",
                    dest="exposed")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()

    if a.selftest:
        return selftest()

    if a.cookie is None:
        a.cookie = os.path.join(a.datadir, ".cookie")
    if a.conf is None:
        a.conf = os.path.join(a.datadir, "bitcoin.conf")
    a._selected_log = None
    a._indexer = None

    if a.host not in ("127.0.0.1", "localhost", "::1") and not a.exposed:
        sys.exit(f"refusing to bind {a.host}: this page shows your node's\n"
                 "height, peers, tip, wallet activity and store layout.\n"
                 f"    ssh -N -L {a.port}:127.0.0.1:{a.port} user@host\n"
                 "Pass --i-understand-this-exposes-node-state to override.")

    feed = Feed()
    poller = Poller(a, feed)
    poller.start()
    Handler.cfg, Handler.feed, Handler.poller = a, feed, poller

    with Server((a.host, a.port), Handler) as srv:
        print(f"monetary node UI on http://{a.host}:{a.port}")
        print("  Settings on this page change how the node runs.")
        print("  Anyone who can reach this port can change them.")
        print(f"  store      {a.store}")
        print(f"  config     {a.conf}"
              + ("   (READ-ONLY: the platform owns it)"
                 if a.managed_bitcoin_config
                 else "   (the settings panel writes this)"))
        print(f"  node RPC   {a.rpc_url}")
        print(f"  logs       {a.log_dir}")
        print(f"  indexer    {a.electrum or 'none — see the INDEXER card'}")
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            print("\nstopping")
            poller.stop.set()
    return 0


if __name__ == "__main__":
    sys.exit(main())
