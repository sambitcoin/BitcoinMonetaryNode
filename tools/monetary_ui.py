#!/usr/bin/env python3
"""
monetary_ui.py — a local dashboard for a monetary node.

Serves one page on 127.0.0.1 showing what the node and the store are doing:
sync state, store position, how far the daemon is behind the tip, the
commitment and the height it belongs to, and what stripping has saved.

READ ONLY, deliberately. There are no buttons. Nothing here starts, stops,
converts or prunes anything. Pruning is irreversible and a web page is the
worst possible place to trigger it from -- a stray click, a prefetching
browser, or anything that can reach the port would be enough. Every
destructive operation stays on the command line where it belongs.

Binds to 127.0.0.1 by default and refuses other addresses unless you pass
--i-understand-this-exposes-node-state, because the page reveals your node's
height, peers and store layout.

Standard library only. No dependencies.

    python3 monetary_ui.py
    python3 monetary_ui.py --store ~/mstore --port 8080
    python3 monetary_ui.py --selftest

then open http://127.0.0.1:8080

BSD-2-Clause.
"""

import argparse
import base64
import html
import http.server
import json
import os
import re
import socketserver
import sys
import time
import urllib.error
import urllib.request

REFRESH_SECONDS = 10


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
        headers = {"Content-Type": "application/json", "Authorization": self.auth}
        req = urllib.request.Request(self.url, data=body, headers=headers)
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            out = json.loads(r.read().decode())
        if out.get("error"):
            raise RuntimeError(out["error"])
        return out["result"]


# ---------------------------------------------------------------- gathering
#
# Everything below must be CHEAP. The page refreshes every few seconds, so
# nothing here may walk the store, recompute a commitment, or du a directory
# of 666 GB. Where a figure can only come from an expensive job, it is read
# from that job's log instead of recomputed.


def read_state(store):
    try:
        with open(os.path.join(store, "state.json")) as fh:
            return json.load(fh), None
    except FileNotFoundError:
        return None, "no state.json — store not adopted by the daemon"
    except Exception as e:
        return None, f"unreadable: {e}"


def store_size(store):
    """Sum mblk*.dat sizes. Stat only, never reads content."""
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
    """Look for a live monetary_daemon.py without shelling out."""
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
    """Pull headline figures out of a finished build log, if there is one."""
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


def gather(cfg):
    now = time.time()
    d = {"generated": time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime(now)),
         "store_path": cfg.store, "errors": []}

    state, err = read_state(cfg.store)
    if err:
        d["errors"].append(err)
    d["state"] = state

    size, files = store_size(cfg.store)
    d["store_bytes"], d["store_files"] = size, files

    pid, cmd = daemon_running()
    d["daemon_pid"], d["daemon_cmd"] = pid, cmd

    try:
        rpc = RPC(cfg.rpc_url, cfg.cookie)
        info = rpc.call("getblockchaininfo")
        net = rpc.call("getnetworkinfo")
        d["node"] = {
            "chain": info.get("chain"),
            "blocks": info.get("blocks"),
            "headers": info.get("headers"),
            "progress": info.get("verificationprogress"),
            "ibd": info.get("initialblockdownload"),
            "pruned": info.get("pruned"),
            "bestblockhash": info.get("bestblockhash"),
            "connections": net.get("connections"),
            "subversion": net.get("subversion"),
        }
    except Exception as e:
        d["node"] = None
        d["errors"].append(f"node RPC: {e}")

    if state and d["node"]:
        d["lag"] = d["node"]["blocks"] - state.get("height", 0)
    else:
        d["lag"] = None

    d["build"] = read_build_log(cfg.build_log)
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
"""


def render(d):
    n, s, b = d["node"], d["state"], d["build"]
    p = []
    A = p.append

    A(f"<!doctype html><meta charset=utf-8>"
      f"<meta http-equiv=refresh content={REFRESH_SECONDS}>"
      f"<title>monetary node</title><style>{CSS}</style>"
      f"<div class=wrap><h1>MONETARY NODE</h1>"
      f"<div class=sub>{esc(d['generated'])} · refreshes every {REFRESH_SECONDS}s · read only</div>")

    for e in d["errors"]:
        A(f"<div class='card err'><h2>PROBLEM</h2><div class=bad>{esc(e)}</div></div>")

    # ---- node
    A("<div class=card><h2>NODE</h2><table>")
    if n:
        ibd = n["ibd"]
        sync = ("<span class=warn>syncing</span>" if ibd
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
            A("<tr><td class=k>pruned</td><td class=v><span class=warn>yes</span>"
              " — indexers that require a complete node will refuse</td></tr>")
    else:
        A("<tr><td class=v class=bad>unreachable</td></tr>")
    A("</table></div>")

    # ---- store
    A("<div class=card><h2>STORE</h2><table>")
    A(f"<tr><td class=k>path</td><td class=v>{esc(d['store_path'])}</td></tr>")
    if s:
        A(f"<tr><td class=k>height</td><td class=v><span class=big>{commas(s.get('height'))}</span></td></tr>")
        A(f"<tr><td class=k>records</td><td class=v>{commas(s.get('records'))}</td></tr>")
        A(f"<tr><td class=k>on disk</td><td class=v>{human(d['store_bytes'])}"
          f" <span class=dim>in {commas(d['store_files'])} files</span></td></tr>")
        c = s.get("commitment", "")
        zero = set(c) <= {"0"}
        A(f"<tr><td class=k>commitment C</td><td class='v hash'>"
          f"{'<span class=warn>not set — recompute with monetary_commit.py</span>' if zero else esc(c)}"
          f"</td></tr>")
        A("<tr><td class=k></td><td class=v class=dim>"
          f"C is only meaningful paired with a height: this one is at "
          f"{commas(s.get('height'))}</td></tr>")
    else:
        A("<tr><td class=v class=bad>no state</td></tr>")
    A("</table></div>")

    # ---- daemon
    A("<div class=card><h2>DAEMON</h2><table>")
    if d["daemon_pid"]:
        A(f"<tr><td class=k>status</td><td class=v><span class=ok>running</span>"
          f" <span class=dim>pid {d['daemon_pid']}</span></td></tr>")
    else:
        A("<tr><td class=k>status</td><td class=v><span class=warn>not running</span>"
          " — the store will fall behind the chain</td></tr>")
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
    A("<tr><td class=k></td><td class=v class=dim>Some lag is by design: blocks are"
      " stripped only after the configured confirmation depth, so a shallow reorg"
      " never touches stored data.</td></tr>")
    A("</table></div>")

    # ---- what stripping saved
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
                cls = "ok" if (k == "failed" and v.strip("0,") == "") else ""
                A(f"<tr><td class=k>{label}</td><td class='v {cls}'>{esc(v)}</td></tr>")
        A("</table><div class=note>Read from the build log, not recomputed."
          " Re-run the build or verify to refresh these.</div></div>")

    A("<div class=card><h2>NOT AVAILABLE HERE</h2><div class=note>"
      "This page cannot start, stop, convert or prune anything, by design."
      " Pruning a node is irreversible and a web page is the wrong place for it:"
      " a stray click or anything that can reach this port would be enough."
      " Those operations live on the command line."
      "</div></div>")

    A("</div>")
    return "".join(p)


# ---------------------------------------------------------------- server


class Handler(http.server.BaseHTTPRequestHandler):
    cfg = None
    server_version = "monetary-ui"

    def _send(self, code, body, ctype):
        raw = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/":
            self._send(200, render(gather(self.cfg)), "text/html; charset=utf-8")
        elif path == "/status.json":
            self._send(200, json.dumps(gather(self.cfg), indent=1, default=str),
                       "application/json")
        else:
            self._send(404, "not found", "text/plain")

    # Any other verb could only be an attempt to change something.
    def do_POST(self):
        self._send(405, "this interface is read only", "text/plain")

    do_PUT = do_DELETE = do_PATCH = do_POST

    def log_message(self, *a):
        pass


# ---------------------------------------------------------------- self-test


def selftest():
    ok = []

    def ck(name, cond, detail=""):
        ok.append(cond)
        print(f"  [{'ok  ' if cond else 'FAIL'}] {name}" + (f"  — {detail}" if detail else ""))

    ck("human(0)", human(0) == "0.0 B", human(0))
    ck("human bytes", human(1536) == "1.5 KB", human(1536))
    ck("human large", human(717_400_000_000).endswith("GB"), human(717_400_000_000))
    ck("human None", human(None) == "—")
    ck("commas", commas(1234567) == "1,234,567")

    log = """
original blocks       717.4 GB
monetary store        666.3 GB   (92.88%)
saved                 51.1 GB   (7.12%)
  total               37.5 GB
  blocks verified     967,985
  blocks failed       0
  filter entries      1,104,820
"""
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as fh:
        fh.write(log)
        p = fh.name
    b = read_build_log(p)
    os.unlink(p)
    ck("parses original", b.get("original") == "717.4 GB", b.get("original"))
    ck("parses saved with pct", b.get("saved", "").startswith("51.1 GB"), b.get("saved"))
    ck("parses verified count", b.get("verified") == "967,985", b.get("verified"))
    ck("parses zero failures", b.get("failed") == "0", b.get("failed"))
    ck("missing log yields nothing", read_build_log("/nonexistent") == {})

    with tempfile.TemporaryDirectory() as d:
        st, err = read_state(d)
        ck("absent state reports an error rather than crashing",
           st is None and "no state.json" in err)
        with open(os.path.join(d, "state.json"), "w") as fh:
            json.dump({"height": 967984, "records": 967985,
                       "commitment": "0" * 64}, fh)
        st, err = read_state(d)
        ck("state parses", st["height"] == 967984 and err is None)

        class C:
            store = d
            rpc_url = "http://127.0.0.1:1"   # nothing listening
            cookie = None
            build_log = "/nonexistent"
        g = gather(C)
        ck("gather survives an unreachable node", g["node"] is None)
        ck("unreachable node is reported, not hidden",
           any("RPC" in e for e in g["errors"]))
        page = render(g)
        ck("page renders without a node", "MONETARY NODE" in page)
        ck("zero commitment is flagged, not shown as a value",
           "not set" in page)
        ck("page says it cannot prune", "cannot start, stop, convert or prune" in page)

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
    ap.add_argument("--build-log", default=os.path.expanduser("~/build.log"))
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

    if a.host not in ("127.0.0.1", "localhost", "::1") and not a.exposed:
        sys.exit(
            f"refusing to bind {a.host}: this page shows your node's height,\n"
            "peers, tip and store layout. Bind 127.0.0.1 and use an SSH tunnel:\n"
            f"    ssh -N -L {a.port}:127.0.0.1:{a.port} user@host\n"
            "Pass --i-understand-this-exposes-node-state to override.")

    Handler.cfg = a
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer((a.host, a.port), Handler) as srv:
        print(f"monetary node UI on http://{a.host}:{a.port}   (read only, Ctrl-C to stop)")
        print(f"  store      {a.store}")
        print(f"  node RPC   {a.rpc_url}")
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            print("\nstopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
