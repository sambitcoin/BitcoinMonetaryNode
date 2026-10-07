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


class RPC:
    def __init__(self, url, cookie=None, user=None, password=None, timeout=10):
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
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            out = json.loads(r.read().decode())
        if out.get("error"):
            raise RuntimeError(out["error"])
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
        return RPC(self.cfg.rpc_url, self.cfg.cookie)

    def run(self):
        while not self.stop.is_set():
            try:
                self.tick()
                if self.warned_down:
                    self.say("node", "node reachable again")
                    self.warned_down = False
            except Exception as e:
                if not self.warned_down:
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
        return None, "no state.json — store not adopted by the daemon"
    except Exception as e:
        return None, f"unreadable: {e}"


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

    state, err = read_state(cfg.store)
    if err:
        d["errors"].append(err)
    d["state"] = state
    d["store_bytes"], d["store_files"] = store_size(cfg.store)
    d["daemon_pid"], d["daemon_cmd"] = daemon_running()
    d["peers"], d["netinfo"] = [], None

    try:
        rpc = RPC(cfg.rpc_url, cfg.cookie)
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
    except Exception as e:
        d["node"] = None
        d["errors"].append(f"node RPC: {e}")

    d["indexer"] = getattr(cfg, "_indexer", None)
    d["electrum_target"] = getattr(cfg, "electrum", None)
    d["lag"] = (d["node"]["blocks"] - state.get("height", 0)
                if state and d["node"] else None)
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
    if n is None:
        return "—"
    x = float(n)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if abs(x) < 1024:
            return f"{x:,.1f} {u}"
        x /= 1024
    return f"{x:,.1f} PB"


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


def indexer_card(d):
    ix = d.get("indexer")
    target = d.get("electrum_target")
    p = ["<div class=card><h2>INDEXER</h2>"]
    if not target:
        p.append("<div class=note style='margin-top:0'>"
                 "No indexer configured. A monetary node does not need one to "
                 "validate, but a wallet needs one to see its history. Any "
                 "Electrum-protocol server works — electrs, Fulcrum, ElectrumX."
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

    p.append("<div class=note><b>Connecting an indexer - %s.</b><br>"
             "A monetary node validates without one. A wallet needs one to "
             "find its own history.</div>" % running)

    p.append("<div class=note><b>electrs</b> - smallest index, about 40 GB, "
             "plain TCP on 50001.<pre class=cfg>"
             "# ~/.electrs/config.toml\n"
             "daemon_dir = &quot;/home/USER/.bitcoin&quot;\n"
             "db_dir     = &quot;/home/USER/electrs-db&quot;\n"
             "network    = &quot;bitcoin&quot;\n"
             "electrum_rpc_addr = &quot;127.0.0.1:50001&quot;\n"
             "\n"
             "electrs &amp;\n"
             "python3 monetary_ui.py --electrum 127.0.0.1:50001</pre>"
             "It reads the RPC cookie out of <code>daemon_dir</code>, so "
             "there are no credentials to copy anywhere.</div>")

    p.append("<div class=note><b>Fulcrum</b> - much faster lookups, about "
             "130 GB, TLS on 50002.<pre class=cfg>"
             "python3 monetary_ui.py --electrum 127.0.0.1:50002 "
             "--electrum-ssl</pre>"
             "<code>--electrum-ssl</code> encrypts but does not verify the "
             "certificate: indexers self-sign almost universally. Point it "
             "only at a server you run yourself.</div>")

    p.append("<div class=note><b>Order matters.</b> Every indexer needs a "
             "node that is not pruned. If you intend to run "
             "<code>prune_behind.py</code>, the index has to be built first "
             "- afterwards it cannot be rebuilt from this node.</div>")

    p.append("<div class=note><b>Tor</b> - run <code>./tor_setup.sh</code>, "
             "then restart the node. <code>proxy</code> alone is not enough; "
             "without <code>onlynet=onion</code> the node still dials "
             "clearnet peers. The card at the top of this page is the "
             "check.</div>")

    # Read the live values rather than describing defaults: a settings card
    # that states policy instead of state is how you end up certain a switch
    # is off while it is on.
    import os as _os
    _conf = _os.path.expanduser("~/.monetary/peering.conf")
    _serve = _onion = "0"
    try:
        for _l in open(_conf):
            if _l.startswith("serve_bootstrap="):
                _serve = _l.split("=", 1)[1].strip()
            elif _l.startswith("peering_onion="):
                _onion = _l.split("=", 1)[1].strip()
    except OSError:
        pass
    _on = _serve == "1"
    p.append("<div class=note><b>Serving other monetary nodes - %s.</b><br>"
             "Bootstrap serving is opt-in and starts off. It hands this "
             "store to another monetary node, which verifies every block "
             "against its own proof-of-work and checks the commitment, so "
             "nobody has to trust you - but a full bootstrap is hundreds of "
             "gigabytes from this laptop.<pre class=cfg>"
             "serve_bootstrap = %s   (127.0.0.1:8335)\n"
             "peering_onion   = %s   (reachable by other nodes over Tor)\n\n"
             "./peering_setup.sh --settings\n"
             "./peering_setup.sh --enable\n"
             "sudo ./peering_setup.sh</pre>"
             "%s<br><br>"
             "<b>It cannot serve a stock Bitcoin node, in any state.</b> "
             "This is the monetary sync protocol, not Bitcoin P2P, and once "
             "this node is pruned the blocks are gone and the witness data "
             "for modified transactions is gone permanently.</div>"
             % ("ON" if _on else "off", esc(_serve), esc(_onion),
                "Turning peering_onion on creates a third permanent onion "
                "address. It reveals no IP by itself, but it cannot be "
                "un-published."))

    p.append("<div class=note><b>Starting at boot</b> - "
             "<code>./services_setup.sh</code> installs systemd units for "
             "the node, the daemon and this dashboard, so all three come "
             "back after a reboot without anyone remembering to.</div>")

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
    blob = help_cache()
    try:
        rows = ns.effective(conf, blob, mconf)
    except Exception as e:
        return ("<div class=card><h2>ADVANCED SETTINGS</h2><div class=note>"
                "Could not read %s: %s</div></div>"
                % (esc(conf), esc(str(e)[:120])))

    p = ["<div class=card><h2>ADVANCED SETTINGS</h2>"]

    if notice:
        cls = "bad" if notice.get("error") else "good"
        p.append('<div class="note %s">%s</div>'
                 % (cls, esc(notice.get("text", ""))))

    p.append("<div class=note>Bitcoin settings write <code>%s</code>; "
             "monetary-node settings write <code>%s</code>. Core reads its "
             "configuration once at startup, so <b>nothing takes effect until "
             "the node restarts</b> — and this page will not restart it for "
             "you. A backup is taken before every write.</div>"
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
    hidden = [r for r in rows if r["supported"] is False]
    rows = [r for r in rows if r["supported"] is not False]

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

    p.append("<div class=sactions>"
             "<button class=go type=submit name=action value=save>"
             "SAVE CHANGES</button>"
             "<button class='go warnbtn' type=submit name=action "
             "value=defaults onclick=\"return confirm('Put every setting "
             "back to its default? Your own config lines are kept.')\">"
             "RESTORE DEFAULTS</button>"
             "</div>")
    p.append("</form>")

    p.append("<div class=note>After saving: <code>sudo systemctl restart "
             "bitcoind</code>, then re-run <code>./tor_lockdown.sh --verify"
             "</code>. A config change is exactly when a Tor assumption "
             "quietly stops being true.</div>")

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
        "<span class=dnote>lightning &middot; alpha software, "
        "no promises, no roadmap</span>"
        "</div>" % (a, a))


def network_banner(d):
    """The first thing on the page, in the largest type on it.

    Reports what the node is DOING, not what a config file asks for. Those
    diverged once on this node — six hours of clearnet peers behind a
    bitcoin.conf that said onlynet=onion, because the running process had
    never read it — and a banner that reported intent would have shown TOR
    ONLY in green throughout.

    So: proxy present, onion reachable, ipv4 and ipv6 NOT reachable, and zero
    non-onion peers right now. Anything less is not Tor only, and says so."""
    net, peers = d.get("netinfo"), d.get("peers") or []
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
      f"<div class=sub><span class=live id=live></span>live feed · cards"
      f" refresh on reload · read only</div>")

    # Above the errors, above everything. This is the one fact on the page
    # that is worth more than the rest of it combined.
    A(network_banner(d))

    for e in d["errors"]:
        A(f"<div class='card err'><h2>PROBLEM</h2><div class=bad>{esc(e)}</div></div>")

    A(tor_card(d))

    A("<div class=card><h2>FEED</h2><div id=feed></div>"
      "<div class=note>Blocks with fees, mempool movement, the daemon"
      " advancing, indexer state, Tor warnings, and this node's own wallet"
      " transactions highlighted. A heartbeat every 15s carries mempool size,"
      " fee estimate and tip age so a quiet chain never looks like a broken"
      " page. Individual mempool transactions are excluded.</div></div>")

    A("<div class=card><h2>NODE</h2><table>")
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

    A(indexer_card(d))

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

    if cfg is not None:
        A(race_card(getattr(cfg, "store", "")))
        A(settings_card(cfg, d))
        A(advanced_card(cfg, notice=d.get("settings_notice")))

    A("<div class=card><h2>NOT AVAILABLE HERE</h2><div class=note>"
      "No shell. This page edits <code>bitcoin.conf</code> and nothing else: "
      "it cannot start, stop, restart, convert or prune anything. A terminal "
      "over HTTP would be remote code execution on your node behind a page "
      "with no authentication, and pruning is irreversible."
      "</div></div>")

    A("</div>")
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

    def do_POST(self):
        parts = urllib.parse.urlparse(self.path)
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
        if not conf:
            self._settings_result(True, "No config path was configured, so "
                                        "there is nothing to write to.")
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
        for key in ns.BY_KEY:
            s = ns.BY_KEY[key]
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
        self._send(405, "this interface is read only", "text/plain")

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

    ck("human bytes", human(1536) == "1.5 KB")
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
        ck("indexer setup instructions shown", "--electrum 127.0.0.1:50001" in page)
        ck("mentions electrs and Fulcrum", "electrs" in page and "Fulcrum" in page)

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
    ck("settings card renders", "SETTINGS" in h and "electrs" in h
       and "prune_behind.py" in h and "tor_setup.sh" in h
       and "services_setup.sh" in h and h.count("<div class=card>") == 1)
    h2 = settings_card(_C(), {"electrum_target": "127.0.0.1:50001"})
    ck("settings reflects configured indexer",
       "127.0.0.1:50001" in h2 and "- configured." in h2
       and "not configured" in h)

    class _X(_C):
        store = "<script>x</script>"
    ck("settings card escapes paths",
       "<script>" not in settings_card(_X(), {}))
    ck("settings card only when cfg given",
       "SETTINGS" in render(g, _C()) and "SETTINGS" not in render(g))

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

    ck("settings card shows peering state",
       "serve_bootstrap" in settings_card(_C(), {})
       and "peering_onion" in settings_card(_C(), {}))
    ck("peering described as opt-in and off by default",
       "opt-in" in settings_card(_C(), {}).lower())
    ck("says it cannot serve a stock node",
       "stock Bitcoin node" in settings_card(_C(), {}))

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
    ap.add_argument("--conf", default=None,
                    help="bitcoin.conf the advanced settings panel edits; "
                         "defaults to bitcoin.conf inside --datadir")
    ap.add_argument("--monetary-conf",
                    default=os.path.expanduser("~/.monetary/monetary.conf"),
                    help="where monetary-node settings are written; never "
                         "mixed into bitcoin.conf")
    ap.add_argument("--rpc-url", default="http://127.0.0.1:8332")
    ap.add_argument("--build-log",
                    default=os.path.expanduser("~/monetary-node/results/build.log"))
    ap.add_argument("--log-dir",
                    default=os.path.expanduser("~/monetary-node/results"))
    ap.add_argument("--electrum", metavar="HOST:PORT",
                    help="Electrum-protocol indexer: electrs, Fulcrum, ElectrumX")
    ap.add_argument("--electrum-ssl", action="store_true",
                    help="connect to the indexer over TLS (not cert-verified)")
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
        print(f"monetary node UI on http://{a.host}:{a.port}   (read only)")
        print(f"  store      {a.store}")
        print(f"  config     {a.conf}   (the settings panel writes this)")
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
