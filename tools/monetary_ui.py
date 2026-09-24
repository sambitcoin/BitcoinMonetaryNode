#!/usr/bin/env python3
"""
monetary_ui.py — a local dashboard and live feed for a monetary node.

A background thread polls the node every few seconds and records events:
new blocks with their fee figures, mempool movement, the daemon advancing
through the store, and — given more prominence — transactions belonging to
this node's own wallet. The page streams those events without reloading.

Individual mempool transactions are deliberately NOT in the feed. There are
thousands a minute and they would bury everything worth seeing. Wallet
transactions are the exception, because those are yours.

READ ONLY. No buttons, no shell. A terminal over HTTP is remote code
execution on your node behind a page with no authentication. Nothing here
starts, stops, converts or prunes; pruning is irreversible and lives on the
command line.

Binds 127.0.0.1 and refuses other addresses unless overridden.

Standard library only.

    python3 monetary_ui.py
    python3 monetary_ui.py --selftest

then open http://127.0.0.1:8080

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

REFRESH_SECONDS = 10
LOG_LINES = 40
LOG_WINDOW = 32768
POLL_SECONDS = 3
FEED_MAX = 400
MEMPOOL_REPORT_DELTA = 400      # only note mempool moves bigger than this
SEEN_WALLET_MAX = 2000          # bound on remembered wallet tx keys
PEERS_SHOWN = 25


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

    Works with Fulcrum, electrs and ElectrumX alike -- they all speak the
    same newline-delimited JSON. Returns a dict, never raises.

    TLS here does NOT verify the certificate. Indexers are almost always
    self-signed and on your own machine or LAN, so verification would fail
    for everyone; the connection is encrypted but unauthenticated, which is
    the honest description. Do not point this at a server you do not run.
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
                   + json.dumps({"id": 1, "method": "blockchain.headers.subscribe",
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
                res = m.get("result") or {}
                out["height"] = res.get("height")
        out["ok"] = out["height"] is not None
        if not out["ok"] and out["error"] is None:
            out["error"] = "connected but no height returned"
    except Exception as e:
        out["error"] = str(e)[:160]
    return out


# ---------------------------------------------------------------- the feed


class Feed:
    """Bounded, thread-safe event log with monotonic ids.

    Bounded because this runs for weeks: an unbounded list is a slow memory
    leak. Ids are monotonic so a client can ask for "everything after n"
    without the server tracking who has seen what.
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


def sats(n):
    if n is None:
        return "—"
    return f"{n:,} sat"


class Poller(threading.Thread):
    """Watches the node and the store, turning changes into feed events."""

    daemon = True

    def __init__(self, cfg, feed):
        super().__init__(name="poller")
        self.cfg, self.feed = cfg, feed
        self.stop = threading.Event()
        self.last_height = None
        self.last_mempool = None
        self.last_store_height = None
        # Bounded on purpose. An unbounded set of every wallet key ever seen
        # is a slow leak in a process meant to run for weeks: the deque
        # evicts the oldest key as new ones arrive, and the set is only a
        # membership index over it.
        self.seen_wallet = set()
        self.seen_order = collections.deque(maxlen=SEEN_WALLET_MAX)
        self.warned_no_wallet = False
        self.warned_down = False
        self.last_indexer_height = None
        self.indexer = None
        self.indexer_checked = 0.0

    def rpc(self):
        return RPC(self.cfg.rpc_url, self.cfg.cookie)

    def run(self):
        while not self.stop.is_set():
            try:
                self.tick()
                if self.warned_down:
                    self.feed.add("node", "node reachable again")
                    self.warned_down = False
            except Exception as e:
                if not self.warned_down:
                    self.feed.add("error", "node unreachable", str(e)[:200])
                    self.warned_down = True
            self.stop.wait(POLL_SECONDS)

    def tick(self):
        r = self.rpc()
        info = r.call("getblockchaininfo")
        h = info["blocks"]

        if self.last_height is None:
            self.feed.add("node", f"watching from height {h:,}",
                          f"{info.get('chain')} · "
                          f"{'syncing' if info.get('initialblockdownload') else 'synced'}")
            self.last_height = h
        elif h > self.last_height:
            # Report every block we skipped, not just the newest, but cap it
            # so catching up after a pause does not flood the feed.
            first = max(self.last_height + 1, h - 8)
            if first > self.last_height + 1:
                self.feed.add("block", f"skipped to {first:,}",
                              f"{first - self.last_height - 1} blocks not detailed")
            for height in range(first, h + 1):
                self.block_event(r, height)
            self.last_height = h

        self.mempool_event(r)
        self.store_event()
        self.wallet_event(r)
        self.indexer_event()

    def indexer_event(self):
        """Poll the configured indexer, but far less often than the node.

        An Electrum query is a TCP connect and handshake; doing that every
        three seconds against your own Fulcrum is rude and pointless, since
        an index moves at block speed.
        """
        target = getattr(self.cfg, "electrum", None)
        if not target:
            return
        if time.time() - self.indexer_checked < 15:
            return
        self.indexer_checked = time.time()
        res = probe_electrum(target, getattr(self.cfg, "electrum_ssl", False))
        prev = self.indexer
        self.indexer = res
        if res["ok"]:
            if prev is not None and not prev.get("ok"):
                self.feed.add("indexer", f"{target} reachable again",
                              f"{res.get('server') or ''} at {res['height']:,}")
            elif self.last_indexer_height is None:
                self.feed.add("indexer", f"{target} at {res['height']:,}",
                              res.get("server") or "")
            elif res["height"] != self.last_indexer_height:
                delta = res["height"] - self.last_indexer_height
                self.feed.add("indexer", f"indexer at {res['height']:,}",
                              f"{delta:+d} · "
                              f"{(self.last_height or 0) - res['height']} behind the node")
            self.last_indexer_height = res["height"]
        elif prev is None or prev.get("ok"):
            self.feed.add("indexer", f"{target} unreachable",
                          res.get("error") or "")

    def block_event(self, r, height):
        try:
            st = r.call("getblockstats", height,
                        ["height", "total_size", "txs", "totalfee",
                         "feerate_percentiles", "subsidy"])
            fee = st.get("totalfee")
            pct = st.get("feerate_percentiles") or []
            median = pct[2] if len(pct) >= 3 else None
            detail = (f"{st.get('txs', 0):,} tx · "
                      f"{(st.get('total_size') or 0) / 1e6:.2f} MB · "
                      f"fees {(fee or 0) / 1e8:.4f} BTC")
            if median is not None:
                detail += f" · median {median} sat/vB"
            self.feed.add("block", f"block {height:,}", detail)
        except Exception as e:
            self.feed.add("block", f"block {height:,}",
                          f"stats unavailable: {str(e)[:80]}")

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
            direction = "+" if n > self.last_mempool else ""
            self.feed.add(
                "mempool", f"mempool {n:,} tx",
                f"{direction}{n - self.last_mempool:,} · "
                f"{(m.get('bytes') or 0) / 1e6:.1f} MB · "
                f"min relay {m.get('mempoolminfee', 0) * 1e5:.2f} sat/vB")
            self.last_mempool = n

    def store_event(self):
        state, _ = read_state(self.cfg.store)
        if not state:
            return
        h = state.get("height")
        if self.last_store_height is None:
            self.last_store_height = h
        elif h > self.last_store_height:
            self.feed.add("store", f"stripped to {h:,}",
                          f"+{h - self.last_store_height} blocks into the store")
            self.last_store_height = h

    def wallet_event(self, r):
        """This node's own transactions. Given prominence: they are yours."""
        try:
            wallets = r.call("listwallets")
        except Exception:
            return
        if not wallets:
            if not self.warned_no_wallet:
                self.feed.add("wallet", "no wallet loaded",
                              "nothing of this node's own to report")
                self.warned_no_wallet = True
            return
        try:
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
                continue          # first pass: prime without shouting
            conf = t.get("confirmations", 0)
            where = "unconfirmed" if conf < 1 else f"{conf} conf"
            amt = t.get("amount", 0)
            self.feed.add(
                "wallet",
                f"{t.get('category', 'tx')} {amt:+.8f} BTC",
                f"{where} · {t.get('txid', '')[:20]}…",
                important=True)


# ---------------------------------------------------------------- gathering


def read_state(store):
    try:
        with open(os.path.join(store, "state.json")) as fh:
            return json.load(fh), None
    except FileNotFoundError:
        return None, "no state.json — store not adopted by the daemon"
    except Exception as e:
        return None, f"unreadable: {e}"


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
    """Last `lines` of a log, by seeking rather than reading the whole file.

    `name` is matched against the directory listing rather than joined onto a
    path, so a client-supplied '../../.bitcoin/bitcoin.conf', an absolute
    path, or a symlink cannot select the file.
    """
    if name not in list_logs(log_dir):
        return None, f"no such log: {name}"
    path = os.path.join(log_dir, name)
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as fh:
            fh.seek(max(0, size - window))
            blob = fh.read()
        text = blob.decode("utf-8", errors="replace")
        if size > window:
            text = text.split("\n", 1)[-1]
        rows = [r for r in text.splitlines() if r.strip()]
        return rows[-lines:], None
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
    except Exception as e:
        d["node"] = None
        d["errors"].append(f"node RPC: {e}")

    d["peers"] = []
    if d["node"]:
        try:
            rpc = RPC(cfg.rpc_url, cfg.cookie)
            for pr in rpc.call("getpeerinfo"):
                d["peers"].append({
                    "addr": pr.get("addr", ""),
                    "network": pr.get("network", ""),
                    "inbound": pr.get("inbound", False),
                    "type": pr.get("connection_type", ""),
                    "subver": pr.get("subver", ""),
                    "ping": pr.get("pingtime"),
                    "since": pr.get("conntime"),
                    "sent": pr.get("bytessent", 0),
                    "recv": pr.get("bytesrecv", 0),
                    "height": pr.get("synced_blocks"),
                })
        except Exception as e:
            d["errors"].append(f"getpeerinfo: {e}")

    d["indexer"] = getattr(cfg, "_indexer", None)

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
.wrap{max-width:900px;margin:0 auto}
h1{font-size:18px;color:#f7931a;margin:0 0 2px;letter-spacing:.04em}
.sub{color:#8b8880;font-size:12px;margin-bottom:24px}
.card{border:1px solid #23252a;background:#111216;padding:16px 18px;margin-bottom:14px}
.card h2{font-size:11px;letter-spacing:.14em;color:#8b8880;margin:0 0 12px;font-weight:600}
table{width:100%;border-collapse:collapse}
td{padding:3px 0;vertical-align:top}
td.k{color:#8b8880;width:210px;white-space:nowrap}
td.v{color:#e8e6e1;word-break:break-all}
.big{font-size:22px;color:#f7931a}
.ok{color:#5cb85c}.warn{color:#f0ad4e}.bad{color:#d9534f}.dim{color:#8b8880}
.hash{font-size:11.5px;color:#c9c6c0;word-break:break-all}
.note{color:#8b8880;font-size:11.5px;margin-top:10px;line-height:1.5}
.err{border-color:#d9534f}
.bar{height:4px;background:#23252a;margin-top:8px}
.bar>i{display:block;height:4px;background:#f7931a}
.tabs{margin:-4px 0 10px}
.tab{display:inline-block;font-size:11px;color:#8b8880;text-decoration:none;border:1px solid #23252a;padding:2px 9px;margin:0 5px 5px 0}
.tab.on{color:#f7931a;border-color:#4a3a1c}
.term{background:#08090b;border:1px solid #1c1e22;padding:11px 13px;margin:0;font-size:11.5px;line-height:1.45;color:#b9b6b0;white-space:pre-wrap;word-break:break-word;max-height:360px;overflow:auto}
#feed{background:#08090b;border:1px solid #1c1e22;max-height:420px;overflow:auto;font-size:11.5px;line-height:1.5}
.ev{padding:5px 12px;border-bottom:1px solid #131519;display:flex;gap:10px}
.ev:last-child{border-bottom:none}
.ev .ts{color:#5f5d58;white-space:nowrap}
.ev .tag{width:66px;flex:none;text-transform:uppercase;font-size:10px;letter-spacing:.08em;padding-top:1px}
.ev .msg{flex:1;color:#d6d3cd}
.ev .det{color:#8b8880}
.ev.block .tag{color:#f7931a}
.ev.store .tag{color:#5cb85c}
.ev.mempool .tag{color:#6ba4d8}
.ev.node .tag{color:#8b8880}
.ev.error .tag{color:#d9534f}
.ev.indexer .tag{color:#b58bd8}
.ev.wallet{background:#15120a;border-left:2px solid #f7931a}
.ev.wallet .tag{color:#f7931a}
.ev.wallet .msg{color:#f5e6c8}
.live{display:inline-block;width:7px;height:7px;border-radius:50%;background:#5cb85c;margin-right:6px;vertical-align:1px}
.live.off{background:#d9534f}
.pt{width:100%;border-collapse:collapse;font-size:11.5px}
.pt th{text-align:left;color:#5f5d58;font-weight:400;padding:0 10px 5px 0;border-bottom:1px solid #1c1e22}
.pt td{padding:3px 10px 3px 0;color:#b9b6b0;white-space:nowrap}
.pt td.a{color:#d6d3cd;max-width:230px;overflow:hidden;text-overflow:ellipsis}
.pill{font-size:10px;border:1px solid #23252a;padding:0 5px;color:#8b8880}
.pill.in{color:#6ba4d8;border-color:#23374a}
.pill.onion{color:#b58bd8;border-color:#3a2a46}
"""

FEED_JS = """
(function(){
 var last=0, box=document.getElementById('feed'), dot=document.getElementById('live');
 function row(e){
  var d=document.createElement('div');
  d.className='ev '+e.kind+(e.important?' wallet':'');
  var t=new Date(e.t*1000).toISOString().substr(11,8);
  d.innerHTML='<span class="ts"></span><span class="tag"></span>'
             +'<span class="msg"></span>';
  d.children[0].textContent=t;
  d.children[1].textContent=e.kind;
  d.children[2].textContent=e.text;
  if(e.detail){var s=document.createElement('span');s.className='det';
   s.textContent='  '+e.detail;d.children[2].appendChild(s);}
  return d;
 }
 function poll(){
  fetch('/events.json?since='+last).then(function(r){return r.json();})
  .then(function(j){
    dot.className='live';
    (j.events||[]).forEach(function(e){
      if(e.id>last){last=e.id; box.insertBefore(row(e), box.firstChild);}
    });
    while(box.childNodes.length>300){box.removeChild(box.lastChild);}
  }).catch(function(){ dot.className='live off'; });
 }
 poll(); setInterval(poll,2000);
})();
"""


def render(d):
    n, s, b = d["node"], d["state"], d["build"]
    p = []
    A = p.append

    A(f"<!doctype html><meta charset=utf-8>"
      f"<title>monetary node</title><style>{CSS}</style>"
      f"<div class=wrap><h1>MONETARY NODE</h1>"
      f"<div class=sub><span class=live id=live></span>live · cards below"
      f" refresh on reload · read only</div>")

    for e in d["errors"]:
        A(f"<div class='card err'><h2>PROBLEM</h2><div class=bad>{esc(e)}</div></div>")

    A("<div class=card><h2>FEED</h2><div id=feed></div>"
      "<div class=note>New blocks with fees, mempool moves, the daemon"
      " advancing, and this node's own wallet transactions highlighted."
      " Individual mempool transactions are excluded — thousands a minute"
      " would bury everything worth seeing.</div></div>")

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
        if n["pruned"]:
            A("<tr><td class=k>pruned</td><td class=v><span class=warn>yes</span></td></tr>")
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
        zero = set(c) <= {"0"}
        A("<tr><td class=k>commitment C</td><td class='v hash'>"
          + ("<span class=warn>not set — recompute with monetary_commit.py</span>"
             if zero else esc(c)) + "</td></tr>")
        A("<tr><td class=k></td><td class='v dim'>C is only meaningful paired with"
          f" a height: this one is at {commas(s.get('height'))}</td></tr>")
    else:
        A("<tr><td class='v bad'>no state</td></tr>")
    A("</table></div>")

    A("<div class=card><h2>DAEMON</h2><table>")
    if d["daemon_pid"]:
        A(f"<tr><td class=k>status</td><td class=v><span class=ok>running</span>"
          f" <span class=dim>pid {d['daemon_pid']}</span></td></tr>")
    else:
        A("<tr><td class=k>status</td><td class=v><span class=warn>not running</span>"
          " — the store will fall behind</td></tr>")
    lag = d["lag"]
    if lag is None:
        cls, txt = "dim", "—"
    elif lag <= 10:
        cls, txt = "ok", f"{lag} blocks behind the node"
    elif lag <= 200:
        cls, txt = "warn", f"{lag} blocks behind the node"
    else:
        cls, txt = "bad", f"{commas(lag)} blocks behind the node"
    A(f"<tr><td class=k>lag</td><td class=v><span class={cls}>{txt}</span></td></tr>")
    A("<tr><td class=k></td><td class='v dim'>Some lag is by design: blocks are"
      " stripped only after the confirmation depth.</td></tr>")
    A("</table></div>")

    if b:
        A("<div class=card><h2>STRIPPED</h2><table>")
        for k, label in (("original", "original blocks"),
                         ("stored", "monetary store"),
                         ("saved", "saved"),
                         ("carriers", "carriers removed"),
                         ("verified", "blocks verified from store alone"),
                         ("failed", "blocks failed"),
                         ("filters", "filter entries")):
            if k in b:
                v = b[k]
                cls = "ok" if (k == "failed" and not v.strip("0,")) else ""
                A(f"<tr><td class=k>{label}</td><td class='v {cls}'>{esc(v)}</td></tr>")
        A("</table><div class=note>Read from the build log, not recomputed.</div></div>")

    ix = d.get("indexer")
    if ix:
        A("<div class=card><h2>INDEXER</h2><table>")
        A(f"<tr><td class=k>target</td><td class=v>{esc(ix['target'])}"
          + (" <span class=dim>TLS</span>" if ix.get("ssl") else "") + "</td></tr>")
        if ix.get("ok"):
            A(f"<tr><td class=k>server</td><td class=v>{esc(ix.get('server'))}</td></tr>")
            A(f"<tr><td class=k>height</td><td class=v>{commas(ix.get('height'))}</td></tr>")
            if n and ix.get("height") is not None:
                behind = n["blocks"] - ix["height"]
                cls = "ok" if behind <= 2 else ("warn" if behind <= 100 else "bad")
                A(f"<tr><td class=k>vs node</td><td class=v>"
                  f"<span class={cls}>{behind:,} blocks behind</span></td></tr>")
        else:
            A(f"<tr><td class=k>status</td><td class=v><span class=bad>unreachable</span>"
              f" <span class=dim>{esc(ix.get('error'))}</span></td></tr>")
        A("</table><div class=note>Any Electrum-protocol indexer — Fulcrum,"
          " electrs, ElectrumX. TLS here is encrypted but not certificate-verified,"
          " because indexers self-sign; point it only at a server you run.</div></div>")

    pr = d.get("peers") or []
    if pr:
        inb = sum(1 for x in pr if x["inbound"])
        nets = collections.Counter(x["network"] for x in pr)
        A("<div class=card><h2>PEERS</h2>")
        A(f"<div class=note style='margin:0 0 10px'>{len(pr)} connected · "
          f"{len(pr) - inb} out, {inb} in · "
          + " · ".join(f"{k or '?'} {v}" for k, v in sorted(nets.items()))
          + "</div>")
        A("<table class=pt><tr><th>address</th><th>net</th><th></th>"
          "<th>software</th><th>ping</th><th>height</th><th>up</th></tr>")
        now = time.time()
        shown = sorted(pr, key=lambda x: (x["inbound"], x.get("since") or 0))
        for x in shown[:PEERS_SHOWN]:
            d_in = "in" if x["inbound"] else ""
            pill = f"<span class='pill {d_in}'>{'in' if x['inbound'] else 'out'}</span>"
            net = x["network"] or "?"
            netcls = "pill onion" if net == "onion" else "pill"
            ping = f"{x['ping'] * 1000:.0f} ms" if x.get("ping") else "—"
            up = ("—" if not x.get("since")
                  else f"{(now - x['since']) / 3600:.1f} h")
            A(f"<tr><td class=a>{esc(x['addr'])}</td>"
              f"<td><span class='{netcls}'>{esc(net)}</span></td>"
              f"<td>{pill}</td>"
              f"<td class=a>{esc(x['subver'])}</td>"
              f"<td>{ping}</td><td>{commas(x.get('height'))}</td><td>{up}</td></tr>")
        A("</table>")
        if len(pr) > PEERS_SHOWN:
            A(f"<div class=note>{len(pr) - PEERS_SHOWN} more not shown.</div>")
        A("</div>")

    if d.get("logs"):
        A("<div class=card><h2>LOG</h2><div class=tabs>")
        for nm in d["logs"]:
            cls = "tab on" if nm == d["log_name"] else "tab"
            A(f"<a class='{cls}' href='/?log={urllib.parse.quote(nm, safe='')}'>{esc(nm)}</a>")
        A("</div>")
        if d.get("log_err"):
            A(f"<div class=bad>{esc(d['log_err'])}</div>")
        else:
            rows = d.get("log_rows") or []
            A("<pre class=term>" + ("\n".join(esc(r) for r in rows) or "(empty)") + "</pre>")
        A(f"<div class=note>Last {LOG_LINES} lines of {esc(d['log_name'])}."
          " A view of a file, not a shell: only files in"
          f" {esc(d['log_dir'])} can be opened.</div></div>")

    A("<div class=card><h2>NOT AVAILABLE HERE</h2><div class=note>"
      "No shell, no controls. This page cannot start, stop, convert or prune"
      " anything. A terminal over HTTP would be remote code execution on your"
      " node behind a page with no authentication; pruning is irreversible."
      "</div></div>")

    A(f"</div><script>{FEED_JS}</script>")
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
            self._send(200, render(gather(self.cfg)), "text/html; charset=utf-8")
        elif parts.path == "/events.json":
            try:
                since = int(q.get("since", ["0"])[0])
            except ValueError:
                since = 0
            evs = self.feed.since(since) if self.feed else []
            self._send(200, json.dumps({"events": evs,
                                        "last": self.feed.last_id() if self.feed else 0}),
                       "application/json")
        elif parts.path == "/status.json":
            self.cfg._selected_log = None
            self._send(200, json.dumps(gather(self.cfg), indent=1, default=str),
                       "application/json")
        else:
            self._send(404, "not found", "text/plain")

    def do_POST(self):
        self._send(405, "this interface is read only", "text/plain")

    do_PUT = do_DELETE = do_PATCH = do_POST

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

    ck("human bytes", human(1536) == "1.5 KB", human(1536))
    ck("human None", human(None) == "—")
    ck("commas", commas(1234567) == "1,234,567")

    f = Feed(maxlen=5)
    for i in range(3):
        f.add("block", f"block {i}")
    ck("ids are monotonic", [e["id"] for e in f.since(0)] == [1, 2, 3])
    ck("since filters", [e["id"] for e in f.since(2)] == [3])
    ck("last_id", f.last_id() == 3)
    for i in range(10):
        f.add("block", f"more {i}")
    ck("feed is bounded", len(f.since(0)) == 5, str(len(f.since(0))))
    ck("ids keep rising after eviction", f.last_id() == 13, str(f.last_id()))
    f.add("wallet", "received", important=True)
    ck("important survives round trip", f.since(13)[0]["important"] is True)

    threads = []
    fc = Feed(maxlen=1000)

    def spam():
        for _ in range(200):
            fc.add("block", "x")
    for _ in range(4):
        t = threading.Thread(target=spam)
        threads.append(t)
        t.start()
    for t in threads:
        t.join()
    got = [e["id"] for e in fc.since(0)]
    ck("no duplicate ids under concurrency", len(got) == len(set(got)), str(len(got)))
    ck("all events recorded", fc.last_id() == 800, str(fc.last_id()))

    log = """
original blocks       717.4 GB
saved                 51.1 GB   (7.12%)
  blocks verified     967,985
  blocks failed       0
"""
    with tempfile.TemporaryDirectory() as d:
        logs = os.path.join(d, "results")
        os.makedirs(logs)
        with open(os.path.join(logs, "daemon.log"), "w") as fh:
            for i in range(200):
                fh.write(f"line {i}\n")
        with open(os.path.join(logs, "build.log"), "w") as fh:
            fh.write(log)
        open(os.path.join(logs, "notes.txt"), "w").write("x")

        ck("lists .log only", list_logs(logs) == ["build.log", "daemon.log"])
        rows, err = tail_log(logs, "daemon.log")
        ck("tail last line", err is None and rows[-1] == "line 199")
        ck("tail bounded", len(rows) == LOG_LINES)
        for bad in ("../../etc/passwd", "/etc/passwd", "notes.txt",
                    "daemon.log/../../../etc/passwd"):
            r, e = tail_log(logs, bad)
            ck(f"rejects {bad!r}", r is None and e is not None)

        b = read_build_log(os.path.join(logs, "build.log"))
        ck("parses saved", b.get("saved", "").startswith("51.1 GB"))

        with open(os.path.join(d, "state.json"), "w") as fh:
            json.dump({"height": 967984, "records": 967985,
                       "commitment": "0" * 64}, fh)

        class C:
            store = d
            rpc_url = "http://127.0.0.1:1"
            cookie = None
            build_log = os.path.join(logs, "build.log")
            log_dir = logs
        g = gather(C)
        ck("survives unreachable node", g["node"] is None)
        ck("unreachable reported", any("RPC" in e for e in g["errors"]))

        page = render(g)
        ck("page renders", "MONETARY NODE" in page)
        ck("feed container present", 'id=feed' in page)
        ck("feed polls events.json", "events.json" in page)
        ck("zero commitment flagged", "not set" in page)
        ck("states it is not a shell", "not a shell" in page)

        with open(os.path.join(logs, "evil.log"), "w") as fh:
            fh.write("<script>alert(1)</script>\n")
        C._selected_log = "evil.log"
        page = render(gather(C))
        ck("log lines escaped", "&lt;script&gt;" in page and "<script>alert" not in page)

    # feed text reaches the browser via textContent, never innerHTML
    ck("feed js uses textContent", "textContent" in FEED_JS
       and "innerHTML=e.text" not in FEED_JS)

    # the wallet-key set must not grow without bound
    class FakeCfg:
        store = "/nonexistent"
        rpc_url = "http://127.0.0.1:1"
        cookie = None
        electrum = None
        electrum_ssl = False
    pol = Poller(FakeCfg, Feed())
    pol.last_height = 1
    for i in range(SEEN_WALLET_MAX + 500):
        key = ("tx%d" % i, "receive", 0)
        if len(pol.seen_order) == pol.seen_order.maxlen:
            pol.seen_wallet.discard(pol.seen_order[0])
        pol.seen_order.append(key)
        pol.seen_wallet.add(key)
    ck("seen_wallet is bounded", len(pol.seen_wallet) <= SEEN_WALLET_MAX,
       str(len(pol.seen_wallet)))
    ck("seen_wallet keeps the newest",
       ("tx%d" % (SEEN_WALLET_MAX + 499), "receive", 0) in pol.seen_wallet)
    ck("seen_wallet dropped the oldest",
       ("tx0", "receive", 0) not in pol.seen_wallet)

    # indexer probe must never raise, whatever it hits
    r = probe_electrum("127.0.0.1:1", False, timeout=1)
    ck("probe returns a dict on refusal", isinstance(r, dict) and not r["ok"])
    ck("probe records the error", bool(r["error"]))
    r = probe_electrum("not a host at all", False, timeout=1)
    ck("probe survives a malformed target", isinstance(r, dict) and not r["ok"])

    # peers and indexer render
    class C2:
        store = "/nonexistent"
        rpc_url = "http://127.0.0.1:1"
        cookie = None
        build_log = "/nonexistent"
        log_dir = "/nonexistent"
        _selected_log = None
        _indexer = {"target": "127.0.0.1:50002", "ssl": True, "ok": True,
                    "server": "Fulcrum 1.11.1", "height": 968300, "error": None}
    g2 = gather(C2)
    g2["node"] = {"chain": "main", "blocks": 968335, "headers": 968335,
                  "progress": 1.0, "ibd": False, "pruned": False,
                  "bestblockhash": "00" * 32, "connections": 3,
                  "subversion": "/Satoshi:31.1.0/"}
    g2["peers"] = [
        {"addr": "abc123.onion:8333", "network": "onion", "inbound": False,
         "type": "outbound-full-relay", "subver": "/Satoshi:28.0.0/",
         "ping": 0.42, "since": time.time() - 7200, "sent": 1, "recv": 2,
         "height": 968335},
        {"addr": "10.0.0.5:8333", "network": "ipv4", "inbound": True,
         "type": "inbound", "subver": "/Satoshi:27.0.0/", "ping": None,
         "since": time.time() - 60, "sent": 1, "recv": 2, "height": 968334},
    ]
    page2 = render(g2)
    ck("indexer card rendered", "INDEXER" in page2 and "Fulcrum" in page2)
    ck("indexer lag computed", "35 blocks behind" in page2)
    ck("peers card rendered", "PEERS" in page2 and "abc123.onion" in page2)
    ck("onion peers marked", "pill onion" in page2)
    ck("inbound marked", ">in<" in page2)
    g2["peers"][0]["addr"] = "<script>x</script>:8333"
    ck("peer address escaped", "&lt;script&gt;" in render(g2))

    print(f"\n{sum(ok)}/{len(ok)} passed")
    return 0 if all(ok) else 1


# ---------------------------------------------------------------- main


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--store", default=os.path.expanduser("~/mstore"))
    ap.add_argument("--datadir", default=os.path.expanduser("~/.bitcoin"))
    ap.add_argument("--cookie")
    ap.add_argument("--rpc-url", default="http://127.0.0.1:8332")
    ap.add_argument("--build-log",
                    default=os.path.expanduser("~/monetary-node/results/build.log"))
    ap.add_argument("--log-dir",
                    default=os.path.expanduser("~/monetary-node/results"))
    ap.add_argument("--electrum", metavar="HOST:PORT",
                    help="Electrum-protocol indexer to monitor "
                         "(Fulcrum, electrs, ElectrumX)")
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
    a._selected_log = None
    a._indexer = None

    if a.host not in ("127.0.0.1", "localhost", "::1") and not a.exposed:
        sys.exit(
            f"refusing to bind {a.host}: this page shows your node's height,\n"
            "peers, tip, store layout, wallet activity and log output.\n"
            "Bind 127.0.0.1 and use an SSH tunnel:\n"
            f"    ssh -N -L {a.port}:127.0.0.1:{a.port} user@host\n"
            "Pass --i-understand-this-exposes-node-state to override.")

    feed = Feed()
    poller = Poller(a, feed)
    poller.start()

    Handler.cfg = a
    Handler.feed = feed
    Handler.poller = poller
    with Server((a.host, a.port), Handler) as srv:
        print(f"monetary node UI on http://{a.host}:{a.port}   (read only, Ctrl-C to stop)")
        print(f"  store      {a.store}")
        print(f"  node RPC   {a.rpc_url}")
        print(f"  logs       {a.log_dir}")
        print(f"  polling    every {POLL_SECONDS}s")
        if a.electrum:
            print(f"  indexer    {a.electrum}" + (" (TLS)" if a.electrum_ssl else ""))
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            print("\nstopping")
            poller.stop.set()
    return 0


if __name__ == "__main__":
    sys.exit(main())
