#!/usr/bin/env python3
"""
monetary_ui.py — a local dashboard for a monetary node.

Node sync state, store position, daemon lag, the commitment and the height it
belongs to, what stripping saved, and a live tail of the log files so you can
see what the tools are doing.

READ ONLY, deliberately.

There are no buttons and no shell. A terminal over HTTP is remote code
execution on your node behind a page with no authentication -- a stray
request from anything that can reach the port would be enough. The log view
is a view of a file and nothing more: it cannot run a command, and it can
only open files this process already listed in one directory.

Nothing here starts, stops, converts or prunes. Pruning is irreversible and
lives on the command line.

Binds 127.0.0.1 and refuses other addresses unless overridden, because the
page reveals your node's height, peers, tip and store layout.

Standard library only.

    python3 monetary_ui.py --build-log results/build.log
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
import urllib.parse
import urllib.request

REFRESH_SECONDS = 10
LOG_LINES = 40
LOG_WINDOW = 32768


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


# ---------------------------------------------------------------- gathering
#
# Everything here must be CHEAP. The page refreshes every few seconds, so
# nothing may walk the store, recompute a commitment, or du a 666 GB tree.
# Figures that only come from an expensive job are read from that job's log.


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
    """Log files available to view. Names only — never a path from a client."""
    try:
        return sorted(e.name for e in os.scandir(log_dir)
                      if e.is_file() and e.name.endswith(".log"))
    except OSError:
        return []


def tail_log(log_dir, name, lines=LOG_LINES, window=LOG_WINDOW):
    """Last `lines` of a log, by seeking rather than reading the whole file.

    Build logs reach tens of MB and this runs on every refresh, so it reads a
    fixed window off the end regardless of size.

    `name` is matched against the directory listing rather than joined onto a
    path. A client-supplied '../../.bitcoin/bitcoin.conf', an absolute path,
    or a symlink must not be able to select the file — only a name this
    process already listed can be opened.
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
            text = text.split("\n", 1)[-1]       # drop the partial first line
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

    d["lag"] = (d["node"]["blocks"] - state.get("height", 0)
                if state and d["node"] else None)
    d["build"] = read_build_log(cfg.build_log)

    d["log_dir"] = cfg.log_dir
    d["logs"] = list_logs(cfg.log_dir)
    want = getattr(cfg, "_selected_log", None)
    if want is None:
        # default to whichever log changed most recently — almost always the
        # job you are actually waiting on
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
"""


def render(d):
    n, s, b = d["node"], d["state"], d["build"]
    p = []
    A = p.append

    A(f"<!doctype html><meta charset=utf-8>"
      f"<meta http-equiv=refresh content={REFRESH_SECONDS}>"
      f"<title>monetary node</title><style>{CSS}</style>"
      f"<div class=wrap><h1>MONETARY NODE</h1>"
      f"<div class=sub>{esc(d['generated'])} · refreshes every "
      f"{REFRESH_SECONDS}s · read only</div>")

    for e in d["errors"]:
        A(f"<div class='card err'><h2>PROBLEM</h2><div class=bad>{esc(e)}</div></div>")

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
            A("<tr><td class=k>pruned</td><td class=v><span class=warn>yes</span>"
              " — indexers requiring a complete node will refuse</td></tr>")
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
    A("<tr><td class=k></td><td class='v dim'>Some lag is by design: blocks are"
      " stripped only after the confirmation depth, so a shallow reorg never"
      " touches stored data.</td></tr>")
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

    if d.get("logs"):
        A("<div class=card><h2>LOG</h2><div class=tabs>")
        for nm in d["logs"]:
            cls = "tab on" if nm == d["log_name"] else "tab"
            q = urllib.parse.quote(nm, safe="")
            A(f"<a class='{cls}' href='/?log={q}'>{esc(nm)}</a>")
        A("</div>")
        if d.get("log_err"):
            A(f"<div class=bad>{esc(d['log_err'])}</div>")
        else:
            rows = d.get("log_rows") or []
            A("<pre class=term>" + ("\n".join(esc(r) for r in rows) or "(empty)")
              + "</pre>")
        A(f"<div class=note>Last {LOG_LINES} lines of {esc(d['log_name'])},"
          " refreshed with the page. This is a view of a file, not a shell:"
          " it cannot run anything, and only files in"
          f" {esc(d['log_dir'])} can be opened.</div></div>")

    A("<div class=card><h2>NOT AVAILABLE HERE</h2><div class=note>"
      "No shell, and no controls. This page cannot start, stop, convert or"
      " prune anything. A terminal over HTTP would be remote code execution"
      " on your node behind a page with no authentication; pruning is"
      " irreversible. Both live on the command line."
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
        parts = urllib.parse.urlparse(self.path)
        if parts.path == "/":
            want = urllib.parse.parse_qs(parts.query).get("log", [None])[0]
            self.cfg._selected_log = want
            self._send(200, render(gather(self.cfg)), "text/html; charset=utf-8")
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


# ---------------------------------------------------------------- self-test


def selftest():
    import tempfile
    ok = []

    def ck(name, cond, detail=""):
        ok.append(cond)
        print(f"  [{'ok  ' if cond else 'FAIL'}] {name}" + (f"  — {detail}" if detail else ""))

    ck("human(0)", human(0) == "0.0 B", human(0))
    ck("human bytes", human(1536) == "1.5 KB", human(1536))
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
    with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as fh:
        fh.write(log)
        bp = fh.name
    b = read_build_log(bp)
    ck("parses original", b.get("original") == "717.4 GB", b.get("original"))
    ck("parses saved with pct", b.get("saved", "").startswith("51.1 GB"))
    ck("parses verified", b.get("verified") == "967,985")
    ck("missing log yields nothing", read_build_log("/nonexistent") == {})
    os.unlink(bp)

    with tempfile.TemporaryDirectory() as d:
        logs = os.path.join(d, "results")
        os.makedirs(logs)
        with open(os.path.join(logs, "daemon.log"), "w") as fh:
            for i in range(200):
                fh.write(f"line {i}\n")
        with open(os.path.join(logs, "build.log"), "w") as fh:
            fh.write(log)
        open(os.path.join(logs, "notes.txt"), "w").write("not a log")

        names = list_logs(logs)
        ck("lists .log files only", names == ["build.log", "daemon.log"], str(names))

        rows, err = tail_log(logs, "daemon.log")
        ck("tail returns the last lines", err is None and rows[-1] == "line 199")
        ck("tail is bounded", len(rows) == LOG_LINES, str(len(rows)))

        # path traversal in every shape it usually arrives
        for bad in ("../../etc/passwd", "/etc/passwd", "notes.txt",
                    "..%2f..%2fetc%2fpasswd", "daemon.log/../../../etc/passwd"):
            r, e = tail_log(logs, bad)
            ck(f"rejects {bad!r}", r is None and e is not None)

        st, err = read_state(d)
        ck("absent state reports an error", st is None and "no state.json" in err)
        with open(os.path.join(d, "state.json"), "w") as fh:
            json.dump({"height": 967984, "records": 967985,
                       "commitment": "0" * 64}, fh)
        st, err = read_state(d)
        ck("state parses", st["height"] == 967984 and err is None)

        class C:
            store = d
            rpc_url = "http://127.0.0.1:1"
            cookie = None
            build_log = os.path.join(logs, "build.log")
            log_dir = logs
        g = gather(C)
        ck("survives an unreachable node", g["node"] is None)
        ck("unreachable node is reported", any("RPC" in e for e in g["errors"]))
        ck("defaults to the most recent log", g["log_name"] in ("build.log", "daemon.log"))

        page = render(g)
        ck("page renders", "MONETARY NODE" in page)
        ck("zero commitment flagged not shown", "not set" in page)
        ck("log card present", "LOG" in page and "term" in page)
        ck("page states it is not a shell", "not a shell" in page)
        ck("log content escaped", "<script>" not in page)

        with open(os.path.join(logs, "evil.log"), "w") as fh:
            fh.write("<script>alert(1)</script>\n")
        C._selected_log = "evil.log"
        page = render(gather(C))
        ck("log lines are HTML-escaped", "&lt;script&gt;" in page
           and "<script>alert" not in page)

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
                    default=os.path.expanduser("~/monetary-node/results"),
                    help="directory of .log files offered in the LOG card")
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

    if a.host not in ("127.0.0.1", "localhost", "::1") and not a.exposed:
        sys.exit(
            f"refusing to bind {a.host}: this page shows your node's height,\n"
            "peers, tip, store layout and log output. Bind 127.0.0.1 and use\n"
            "an SSH tunnel:\n"
            f"    ssh -N -L {a.port}:127.0.0.1:{a.port} user@host\n"
            "Pass --i-understand-this-exposes-node-state to override.")

    Handler.cfg = a
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer((a.host, a.port), Handler) as srv:
        print(f"monetary node UI on http://{a.host}:{a.port}   (read only, Ctrl-C to stop)")
        print(f"  store      {a.store}")
        print(f"  node RPC   {a.rpc_url}")
        print(f"  logs       {a.log_dir}")
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            print("\nstopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
