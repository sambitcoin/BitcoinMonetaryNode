#!/usr/bin/env python3
"""
status_page.py — the public, read-only face of a monetary node.

Serves one page: the commitment, the ruleset it was computed under, the
policy id, and the heights. Nothing else. It exists so somebody can check
the published claims without connecting to the node, and without the
operator becoming anyone's infrastructure.

This is NOT monetary_ui.py. The dashboard shows peers, wallet activity, log
tails and store paths, and binds localhost because all of that is nobody
else's business. This page is what is safe to hand to strangers, so it is a
separate program with a separate, much smaller surface:

  - No path routing. Every request gets the same page. There is no input to
    validate because there is no input.
  - No peer list, no wallet, no mempool, no file paths, no onion address, no
    log tail, no uptime.
  - Data is refreshed on a timer, not per request, so requests cannot drive
    RPC load. A flood costs a string copy.
  - Responses are capped and connections are short.

WHAT IT STILL LEAKS, because everything does:
  - That this node exists and is reachable, and roughly when it is up.
  - Its height, which with enough sampling is a liveness timeline.
That is the price of publishing anything at all, and it is much smaller
than the price of publishing the P2P or Electrum port.

    python3 status_page.py --store ~/mstore
    python3 status_page.py --selftest

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
import subprocess
import sys
import threading
import time
import urllib.parse

REFRESH_SECONDS = 60
MAX_BODY = 64 * 1024
REPO = "https://github.com/sambitcoin/BitcoinMonetaryNode"

# ---------------------------------------------------------------- the query
#
# The page above takes no input, which is most of why it is safe. /q breaks
# that deliberately, so it is fenced rather than trusted:
#
#   - Exactly two parameters. Both must match an exact regex before anything
#     touches the store. Anything else in the query string is ignored, not
#     parsed. There is no path routing and no filename ever reaches disk.
#   - A global token bucket. One query reads one block record off a laptop
#     disk over Tor; without a cap, a flood is a cheap way to make the node
#     unresponsive.
#   - Errors are chosen from a fixed list. Exception text is never echoed,
#     because exception text on this project contains store paths.
TXID_RE = re.compile(r"^[0-9a-f]{64}$")
HEIGHT_RE = re.compile(r"^[0-9]{1,7}$")
QUERY_MAX_BODY = 256 * 1024
BODY_HEX_CAP = 120000              # 60 KB of transaction, plenty over Tor
#   - Conservative rates. One query is a random-access read of up to a few MB
#     on a laptop already running bitcoind, electrs and the store daemon. This
#     is meant to run for days with nobody watching it, so the cap is set for
#     curiosity traffic, not for throughput.
RATE_PER_SEC = 2.0
RATE_BURST = 10
#     A connection cap alone is not enough: clients that connect and send
#     nothing fill every slot and the cap becomes the outage. The read timeout
#     is what actually frees them, so it is short. A real client — even one
#     six Tor hops away — sends its request line immediately after the local
#     handshake; only a stalled or hostile one sits there.
#
#     This is a denial-of-service ceiling, not a security boundary. Someone
#     determined can still make the page unreachable. Nothing leaks when they
#     do, and nothing else on the node is affected: the page is unreachable,
#     which is the correct worst case for a laptop publishing over Tor.
MAX_ACTIVE_CONNECTIONS = 48
CONNECTION_TIMEOUT = 5

# The published ruleset. These are the lines that make C meaningful; a
# commitment without them is an unverifiable number.
RULES = [
    ("OP_RETURN limit", "83"),
    ("scriptSig limit", "1650"),
    ("envelopes", "false push before OP_IF, true push before OP_NOTIF, "
                  "in taproot script-path and P2WSH witness scripts"),
    ("data keys", "not on secp256k1 (y^2 = x^3 + 7 mod p)"),
]


def esc(x):
    return html.escape(str(x), quote=True)


# ------------------------------------------------------------------ collect


def run(cmd, timeout=15):
    """Run a command, return stdout or None. Never raises."""
    try:
        out = subprocess.run(cmd, capture_output=True, timeout=timeout,
                             text=True)
        return out.stdout if out.returncode == 0 else None
    except Exception:
        return None


def collect(cfg):
    """Everything the page shows. Only these fields ever reach the network."""
    d = {"generated": int(time.time()), "node_height": None,
         "store_height": None, "store_records": None, "commitment": None,
         "policy_id": None, "chain": None}

    info = run(["bitcoin-cli", "-datadir=" + cfg.datadir,
                "getblockchaininfo"])
    if info:
        try:
            j = json.loads(info)
            d["node_height"] = j.get("blocks")
            d["chain"] = j.get("chain")
        except ValueError:
            pass

    st = run([sys.executable, os.path.join(cfg.tools, "monetary_daemon.py"),
              "--store", cfg.store, "--rpc-cookie", cfg.cookie, "--status"])
    if st:
        # Parse only the three fields we publish. Anything else in that
        # output — paths, file counts — stays local.
        m = re.search(r"state height\s+([\d,]+)", st)
        if m:
            d["store_height"] = m.group(1)
        m = re.search(r"state records\s+([\d,]+)", st)
        if m:
            d["store_records"] = m.group(1)
        m = re.search(r"\bC\s+([0-9a-f]{64})", st)
        if m:
            d["commitment"] = m.group(1)

    try:
        sys.path.insert(0, cfg.tools)
        from carrier_policy import Policy
        d["policy_id"] = Policy().policy_id()
    except Exception:
        pass

    return d


# --------------------------------------------------------------------- page


CSS = """
body{background:#0a0d0a;color:#c8c6c0;font:13px/1.6 ui-monospace,
SFMono-Regular,Menlo,monospace;margin:0;padding:40px 20px}
main{max-width:720px;margin:0 auto}
h1{color:#2fbf4f;font-size:16px;letter-spacing:2px;margin:0 0 4px}
.sub{color:#5c6b5c;font-size:11px;margin-bottom:28px}
section{border:1px solid #1e2a1e;padding:16px 18px;margin-bottom:18px}
h2{color:#8b8880;font-size:10px;letter-spacing:2px;margin:0 0 12px;
font-weight:normal}
table{width:100%;border-collapse:collapse}
td{padding:3px 0;vertical-align:top}
td.k{color:#5c6b5c;width:190px;white-space:nowrap}
td.v{color:#e8e6e1;word-break:break-all}
.hash{color:#2fbf4f}
.note{color:#5c6b5c;font-size:11px;margin-top:12px;line-height:1.55}
a{color:#2fbf4f}
code{color:#8b8880}
.in{background:#060806;border:1px solid #1e2a1e;color:#e8e6e1;font:12px/1.4
ui-monospace,Menlo,monospace;padding:7px 8px;width:100%;box-sizing:border-box;
margin:4px 0 2px}
.go{background:#132013;border:1px solid #2fbf4f;color:#2fbf4f;font:11px/1
ui-monospace,Menlo,monospace;letter-spacing:2px;padding:9px 20px;margin-top:10px;
cursor:pointer}
.big{color:#2fbf4f;font-size:15px;letter-spacing:1px}
.warn{color:#c9a227}
.branch{color:#8b8880;font-size:11px;line-height:1.7;word-break:break-all}
"""


def render(d):
    p = ['<!doctype html><meta charset=utf-8>',
         '<meta name=viewport content="width=device-width,initial-scale=1">',
         '<title>monetary node</title><style>', CSS, '</style><main>',
         '<h1>MONETARY NODE</h1>',
         '<div class=sub>a Bitcoin node that validates every consensus rule, '
         'then stores the blocks without the data carriers</div>']

    p.append('<section><h2>COMMITMENT</h2>')
    if d["commitment"] and d["store_height"]:
        p.append('<table>')
        p.append('<tr><td class=k>C</td><td class="v hash">%s</td></tr>'
                 % esc(d["commitment"]))
        p.append('<tr><td class=k>at height</td><td class=v>%s</td></tr>'
                 % esc(d["store_height"]))
        p.append('<tr><td class=k>records</td><td class=v>%s</td></tr>'
                 % esc(d["store_records"] or "-"))
        p.append('</table>')
        p.append('<div class=note>C_h = SHA256d(C_h-1 &#8214; blockhash_h '
                 '&#8214; K_h). Apply the same rules to the same range and '
                 'you get the same value, or one of us has a bug. '
                 '<b>A commitment quoted without its height is '
                 'unverifiable</b> — always take the pair.</div>')
    else:
        p.append('<div class=note>Not available right now.</div>')
    p.append('</section>')

    p.append('<section><h2>RULES IT WAS COMPUTED UNDER</h2><table>')
    for k, v in RULES:
        p.append('<tr><td class=k>%s</td><td class=v>%s</td></tr>'
                 % (esc(k), esc(v)))
    p.append('<tr><td class=k>carrier policy</td><td class="v hash">%s</td></tr>'
             % esc(d["policy_id"] or "-"))
    p.append('</table><div class=note>The carrier policy decides which '
             'OP_RETURN payloads are kept as payments rather than stripped as '
             'data. Two nodes with different policies derive different '
             'stores, so this hash belongs beside C.</div></section>')

    p.append('<section><h2>HEIGHTS</h2><table>')
    p.append('<tr><td class=k>chain</td><td class=v>%s</td></tr>'
             % esc(d["chain"] or "-"))
    p.append('<tr><td class=k>node</td><td class=v>%s</td></tr>'
             % esc(d["node_height"] if d["node_height"] is not None else "-"))
    p.append('<tr><td class=k>store</td><td class=v>%s</td></tr>'
             % esc(d["store_height"] or "-"))
    p.append('</table></section>')

    p.append('<section><h2>CHECK IT YOURSELF</h2>'
             '<div class=note>Every figure here is reproducible from the '
             'source. Do not take this page as evidence of anything; take it '
             'as a claim to go and test.<br><br>'
             '<a href="%s">%s</a></div></section>' % (REPO, REPO))

    state = d.get("query", "ready")
    p.append('<section><h2>ASK IT ABOUT A TRANSACTION</h2>')
    if state == "building":
        p.append('<div class=note><span class=warn>The query index is still '
                 'building.</span> It takes a few minutes after a restart. '
                 'Ask again shortly.</div>')
    elif state == "failed":
        p.append('<div class=note><span class=warn>Queries are unavailable '
                 'right now.</span> Nothing you did. The node is still '
                 'running; this part of it is not.</div>')
    elif d.get("query_range"):
        p.append('<div class=note>answering for heights %s</div>'
                 % esc(d["query_range"]))
    p.append('<form method=get action="/q">'
             '<div class=note>txid</div>'
             '<input class=in name=txid maxlength=64 spellcheck=false '
             'placeholder="64 hex characters">'
             '<div class=note>height it confirmed in</div>'
             '<input class=in name=height maxlength=7 placeholder="780000">'
             '<div><button class=go type=submit>ASK</button></div>'
             '</form>'
             '<div class=note>You get back what this node kept, and a merkle '
             'branch. Fold the branch over the txid and you get the block\'s '
             'merkle root — compare it against the header your own node '
             'already holds. If this node is lying, it will not match.<br><br>'
             'The height is required on purpose. There is no txid index here '
             'and there will not be one; your node has the height:<br>'
             '<code>bitcoin-cli getrawtransaction &lt;txid&gt; 1 | grep '
             'blockhash</code></div></section>')

    p.append('<section><h2>WHAT THIS IS NOT</h2><div class=note>'
             'This is a status page, not a service. It is one laptop run by '
             'one person, it is alpha software reviewed by nobody, and it is '
             'not somewhere to point a wallet. Run your own.'
             '</div></section>')

    p.append('<div class=sub>generated %s UTC</div></main>'
             % time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(d["generated"])))
    return "".join(p)


# ------------------------------------------------------------- query engine


class Bucket:
    """Token bucket. Shared by every caller — Tor gives no IP to key on, and
    wanting one would be the wrong instinct anyway."""

    def __init__(self, rate, burst):
        self.rate, self.burst = rate, burst
        self.tokens, self.t = float(burst), time.monotonic()
        self.lock = threading.Lock()

    def take(self):
        with self.lock:
            now = time.monotonic()
            self.tokens = min(self.burst,
                              self.tokens + (now - self.t) * self.rate)
            self.t = now
            if self.tokens < 1.0:
                return False
            self.tokens -= 1.0
            return True


class QueryEngine:
    """Wraps tx_query so no failure inside it can reach the network as text.

    tx_query is a command-line tool: it calls sys.exit with messages that name
    the store path. Every one of those becomes a fixed string here."""

    def __init__(self, cfg):
        self.cfg = cfg
        self.lock = threading.Lock()
        self.index = None
        self.base = None
        self.mod = None
        # "building" until the first walk finishes, "failed" if it did not.
        # Reporting both as "still building" would leave a permanently broken
        # service looking like a slow one, which is the worst way to find out
        # on Monday.
        self.state = "building"
        self.bucket = Bucket(RATE_PER_SEC, RATE_BURST)

    def load(self):
        """Build or extend the record index. Slow once, then trivial.

        Called again on every refresh, so a failure here is not terminal: the
        store daemon may have been mid-append, and the next cycle retries."""
        try:
            if self.mod is None:
                sys.path.insert(0, self.cfg.tools)
                import tx_query
                self.mod = tx_query
            index = self.mod.build_index(self.cfg.store, quiet=True)
            base = self.mod.base_height(self.cfg.store, index)
        except BaseException:
            with self.lock:
                if self.index is None:
                    self.state = "failed"
            return False
        with self.lock:
            self.index, self.base, self.state = index, base, "ready"
        return True

    def range(self):
        with self.lock:
            if self.index is None:
                return None
            return self.base, self.base + len(self.index) - 1

    def status(self):
        with self.lock:
            if self.index is None:
                return self.state, None, None
            return "ready", self.base, self.base + len(self.index) - 1

    def answer(self, txid_hex, height):
        """-> (dict, None) or (None, fixed error string)."""
        if not self.bucket.take():
            return None, "Too many queries at once. Wait a moment."
        state, _, _ = self.status()
        if state == "failed":
            return None, ("The query index is not available on this node "
                          "right now. Not your fault. Try later.")
        rng = self.range()
        if rng is None:
            return None, ("The store index is still building. This takes a "
                          "few minutes after a restart. Try again shortly.")
        lo, hi = rng
        if not lo <= height <= hi:
            return None, ("This store covers heights %s to %s. %s is outside "
                          "it." % (f"{lo:,}", f"{hi:,}", f"{height:,}"))
        with self.lock:
            mod, index, base = self.mod, self.index, self.base
        try:
            path, off = index[height - base]
            rec = mod.read_record_at(path, off)
            if mod.dsha(rec["header"]) != rec["block_hash"]:
                return None, "That record is corrupt on this disk."
            if mod.merkle_root(rec["txids"]) != rec["merkle_root"]:
                return None, "That record is corrupt on this disk."
            txid = bytes.fromhex(txid_hex)[::-1]
            try:
                pos = rec["txids"].index(txid)
            except ValueError:
                return {"found": False, "height": height,
                        "txid": txid_hex,
                        "block_hash": rec["block_hash"][::-1].hex(),
                        "n_tx": len(rec["txids"])}, None
            tx = rec["txs"][pos]
            branch = mod.merkle_branch(rec["txids"], pos)
            if mod.fold_branch(txid, pos, branch) != rec["merkle_root"]:
                return None, "That record is corrupt on this disk."
            body = tx["body"].hex() if tx["body"] is not None else None
            clipped = False
            if body and len(body) > BODY_HEX_CAP:
                body, clipped = body[:BODY_HEX_CAP], True
            return {"found": True, "txid": txid_hex, "height": height,
                    "block_hash": rec["block_hash"][::-1].hex(),
                    "merkle_root": rec["merkle_root"][::-1].hex(),
                    "position": pos, "n_tx": len(rec["txids"]),
                    "class": mod.CLASS_NAME[tx["flag"]],
                    "kept_bytes": len(tx["body"]) if tx["body"] else 0,
                    "body": body, "body_truncated": clipped,
                    "body_merkle_covered": tx["flag"] == mod.FLAG_WHOLE,
                    "branch": [h.hex() for h in branch]}, None
        except BaseException:
            # Includes SystemExit from tx_query. Never echo the reason.
            return None, "Could not read that block."


# ------------------------------------------------------------- query result


def render_query(r, err, txid="", height=""):
    p = ['<!doctype html><meta charset=utf-8>',
         '<meta name=viewport content="width=device-width,initial-scale=1">',
         '<title>monetary node</title><style>', CSS, '</style><main>',
         '<h1>MONETARY NODE</h1>',
         '<div class=sub><a href="/">&larr; back</a></div>']

    if err:
        p.append('<section><h2>NO ANSWER</h2><div class=note>%s</div>'
                 '</section></main>' % esc(err))
        return "".join(p)

    if not r["found"]:
        p.append('<section><h2>NOT IN THAT BLOCK</h2><table>')
        p.append('<tr><td class=k>txid</td><td class=v>%s</td></tr>'
                 % esc(r["txid"]))
        p.append('<tr><td class=k>height</td><td class=v>%s</td></tr>'
                 % f"{r['height']:,}")
        p.append('<tr><td class=k>that block holds</td><td class=v>%s '
                 'transactions, none with that txid</td></tr>'
                 % f"{r['n_tx']:,}")
        p.append('</table><div class=note>Check the height against your own '
                 'node:<br><code>bitcoin-cli getrawtransaction &lt;txid&gt; 1 '
                 '| grep blockhash</code></div></section></main>')
        return "".join(p)

    p.append('<section><h2>WHAT THIS NODE HOLDS</h2><table>')
    p.append('<tr><td class=k>txid</td><td class=v>%s</td></tr>'
             % esc(r["txid"]))
    p.append('<tr><td class=k>height</td><td class=v>%s</td></tr>'
             % f"{r['height']:,}")
    p.append('<tr><td class=k>block</td><td class=v>%s</td></tr>'
             % esc(r["block_hash"]))
    p.append('<tr><td class=k>position</td><td class=v>%s of %s</td></tr>'
             % (f"{r['position']:,}", f"{r['n_tx']:,}"))
    p.append('<tr><td class=k>class</td><td class="v big">%s</td></tr>'
             % esc(r["class"]))
    if r["class"] == "STRIPPED":
        p.append('<tr><td class=k>kept</td><td class=v>nothing — the txid '
                 'only</td></tr>')
    else:
        p.append('<tr><td class=k>kept</td><td class=v>%s bytes</td></tr>'
                 % f"{r['kept_bytes']:,}")
    p.append('</table>')

    if r["class"] == "STRIPPED":
        p.append('<div class=note>Every output of this transaction was a data '
                 'carrier, so all of it went. It moved no value. The txid '
                 'stays because the merkle root is computed over txids and '
                 'the block must still verify.</div>')
    p.append('</section>')

    p.append('<section><h2>MERKLE BRANCH — %d HASHES</h2><div class=branch>'
             % len(r["branch"]))
    for h in r["branch"]:
        p.append('%s<br>' % esc(h))
    p.append('</div><div class=note>Fold that over the txid and you get:<br>'
             '<span class=hash>%s</span><br><br>Now compare it to the header '
             'your own node holds:<br><code>bitcoin-cli getblockheader %s '
             '| grep merkleroot</code></div></section>'
             % (esc(r["merkle_root"]), esc(r["block_hash"])))

    p.append('<section><h2>HOW FAR THAT GOES</h2><div class=note>')
    if r["class"] == "RETAINED WHOLE":
        p.append('This transaction is stored untouched, and its txid is '
                 '<b>derived</b> from the bytes below rather than stored '
                 'beside them. So the branch proves the bytes, not just the '
                 'identifier. Nothing here has to be taken on trust.')
    elif r["class"] == "MODIFIED":
        p.append('<span class=warn>Careful.</span> The branch proves this '
                 '<b>txid</b> is in this block. It does <b>not</b> prove the '
                 'kept bytes match it, and it cannot — a modified body no '
                 'longer hashes to its own txid. That is the format working '
                 'as designed, not a gap in it.<br><br>So do not believe the '
                 'bytes. Diff them against your node:<br>'
                 '<code>bitcoin-cli getrawtransaction &lt;txid&gt;</code>'
                 '<br><br>What is missing from this copy is exactly what this '
                 'node declined to keep. If anything <i>else</i> differs, say '
                 'so loudly and publicly.')
    else:
        p.append('There are no bytes to check here, only the identifier.')
    p.append('<br><br>This node cannot show you what it dropped. Those bytes '
             'are gone, which is the point of the project rather than a '
             'limitation of it.</div></section>')

    if r["body"]:
        p.append('<section><h2>KEPT BYTES</h2><div class=branch>%s</div>'
                 % esc(r["body"]))
        if r["body_truncated"]:
            p.append('<div class=note>Truncated for transport. Run the tool '
                     'yourself for all of it — it is in the repo.</div>')
        p.append('</section>')

    p.append('</main>')
    return "".join(p)


# ------------------------------------------------------------------ serving


class Cache:
    def __init__(self, cfg, engine=None):
        self.cfg = cfg
        self.engine = engine
        self._lock = threading.Lock()
        self._html = b"<h1>starting</h1>"
        self._json = b"{}"

    def refresh(self):
        d = collect(self.cfg)
        if self.engine is not None:
            state, lo, hi = self.engine.status()
            d["query"] = state
            d["query_range"] = (f"{lo:,} to {hi:,}"
                                if lo is not None else None)
        h = render(d).encode()[:MAX_BODY]
        j = json.dumps(d, sort_keys=True).encode()[:MAX_BODY]
        with self._lock:
            self._html, self._json = h, j

    def get(self, as_json):
        with self._lock:
            return self._json if as_json else self._html


def parse_query(qs, engine):
    """Validate first, touch the store second. -> (result, error)."""
    if len(qs) > 200:
        return None, "Malformed request."
    try:
        q = urllib.parse.parse_qs(qs, keep_blank_values=False,
                                  strict_parsing=False, max_num_fields=8)
    except ValueError:
        return None, "Malformed request."

    txid = (q.get("txid") or [""])[0].strip().lower()
    height = (q.get("height") or [""])[0].strip()

    if not TXID_RE.match(txid):
        return None, ("A txid is 64 hex characters. Bitcoin displays them "
                      "that way, so paste it exactly as your node prints it.")
    if not HEIGHT_RE.match(height):
        return None, ("The height must be a plain number. Your own node has "
                      "it: bitcoin-cli getrawtransaction <txid> 1, then "
                      "getblockheader on the blockhash it prints.")

    return engine.answer(txid, int(height))


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "monetary"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    cache = None
    engine = None
    # socketserver applies this to the connection, so a client that opens a
    # socket and sends nothing is dropped instead of holding a thread.
    timeout = CONNECTION_TIMEOUT

    def log_message(self, *a):
        # No request logging. A log of who asked for what, on a machine
        # reached over Tor, is a record nobody benefits from keeping.
        pass

    def _send(self, body, ctype):
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        # No external resources are loaded, so forbid them outright.
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; style-src 'unsafe-inline'")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        # The path is split once, on "?", and the left side is compared
        # against two literals. It is never joined to anything, never opened,
        # and never reflected. Everything else is the status page.
        path, _, qs = self.path.partition("?")
        path = path.rstrip("/") or "/"

        if path in ("/q", "/q.json"):
            if self.engine is None:
                self._send(b"query not enabled\n", "text/plain")
                return
            r, err = parse_query(qs, self.engine)
            if path == "/q.json":
                body = json.dumps({"error": err} if err else r,
                                  sort_keys=True).encode()[:QUERY_MAX_BODY]
                self._send(body, "application/json")
            else:
                body = render_query(r, err).encode()[:QUERY_MAX_BODY]
                self._send(body, "text/html; charset=utf-8")
            return

        if path.endswith(".json"):
            self._send(self.cache.get(True), "application/json")
        else:
            self._send(self.cache.get(False), "text/html; charset=utf-8")

    def do_POST(self):
        self.send_error(405)

    do_PUT = do_DELETE = do_PATCH = do_POST


class Server(socketserver.ThreadingTCPServer):
    """Bounded on purpose.

    This runs for days with nobody watching. A thread per connection and no
    ceiling means one slow client opening sockets and never sending a request
    takes the laptop down — over Tor, from anywhere, for free. So: a hard cap
    on concurrent connections, and a socket timeout so a stalled one cannot
    hold its slot."""

    daemon_threads = True
    allow_reuse_address = True
    timeout = 10
    request_queue_size = 32

    def __init__(self, *a, **kw):
        self._active = 0
        self._active_lock = threading.Lock()
        super().__init__(*a, **kw)

    def process_request(self, request, client_address):
        with self._active_lock:
            if self._active >= MAX_ACTIVE_CONNECTIONS:
                try:
                    request.close()
                except OSError:
                    pass
                return
            self._active += 1
        super().process_request(request, client_address)

    def shutdown_request(self, request):
        try:
            super().shutdown_request(request)
        finally:
            with self._active_lock:
                self._active -= 1


# ---------------------------------------------------------------- selftest


def selftest():
    ok = []

    def ck(label, cond, extra=""):
        ok.append(bool(cond))
        print("  [%s] %s%s" % ("ok  " if cond else "FAIL", label,
                               "" if cond else "  <- " + str(extra)))

    d = {"generated": 1700000000, "node_height": 968558,
         "store_height": "968,554", "store_records": "968,555",
         "commitment": "a" * 64, "policy_id": "b" * 64, "chain": "main"}
    page = render(d)

    ck("shows the commitment", "a" * 64 in page)
    ck("shows the height beside it", "968,554" in page)
    ck("shows the policy id", "b" * 64 in page)
    ck("says a commitment without its height is unverifiable",
       "unverifiable" in page)

    # The whole point of a separate program: none of this may appear.
    #
    # Word matching alone is wrong — the page legitimately says "not
    # somewhere to point a wallet", and a test that fails on prose teaches
    # you to weaken the test. Check for leaked VALUES and for the words that
    # could only appear as data.
    for leak in ("onion", "/home/", "/Users/", "cookie", "192.168", "10.0.",
                 "electrum", "50011", "8332", "8080", "9050"):
        ck("does not leak %r" % leak, leak.lower() not in page.lower())

    body = render(dict(d, chain="main"))
    ck("no bitcoin addresses", not re.search(
        r"\b(bc1[a-z0-9]{20,}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b", body))
    ck("no txids or block hashes beyond the commitment",
       len(re.findall(r"\b[0-9a-f]{64}\b", body)) == 2,
       "expected exactly C and policy_id")
    ck("no dotted-quad addresses",
       not re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", body))
    ck("no filesystem paths",
       not re.search(r"(^|[\s\">])/[a-z]+/[a-z]", body))

    ck("no external resources",
       "http://" not in page.replace(REPO, "") and "//cdn" not in page)
    ck("escapes a hostile value",
       "<script>" not in render(dict(d, chain="<script>x</script>")))
    ck("survives every field being missing",
       "MONETARY NODE" in render({"generated": 0, "node_height": None,
                                  "store_height": None, "store_records": None,
                                  "commitment": None, "policy_id": None,
                                  "chain": None}))
    ck("body fits the cap", len(page.encode()) < MAX_BODY)

    class C:
        pass
    ck("refresh interval is not per-request", REFRESH_SECONDS >= 30)

    # ------------------------------------------------------------- the query
    #
    # /q is the one place this program accepts input, so the tests are about
    # what it refuses, not what it returns.

    class FakeEngine:
        def __init__(self):
            self.calls = []
            self.bucket = Bucket(RATE_PER_SEC, RATE_BURST)

        def answer(self, txid, height):
            self.calls.append((txid, height))
            return {"found": False, "txid": txid, "height": height,
                    "block_hash": "0" * 64, "n_tx": 1}, None

    e = FakeEngine()
    bad = [
        ("nothing at all", ""),
        ("no height", "txid=" + "a" * 64),
        ("no txid", "height=780000"),
        ("63 hex", "txid=" + "a" * 63 + "&height=1"),
        ("65 hex", "txid=" + "a" * 65 + "&height=1"),
        ("uppercase is fine but non-hex is not", "txid=" + "g" * 64 + "&height=1"),
        ("height not a number", "txid=" + "a" * 64 + "&height=abc"),
        ("negative height", "txid=" + "a" * 64 + "&height=-5"),
        ("height too long", "txid=" + "a" * 64 + "&height=99999999"),
        ("sql-ish", "txid=" + "a" * 64 + "&height=1%20OR%201=1"),
        ("path traversal in txid", "txid=../../etc/passwd&height=1"),
        ("null byte", "txid=" + "a" * 63 + "%00&height=1"),
        ("oversized query string", "txid=" + "a" * 400),
    ]
    refused = all(parse_query(qs, e)[0] is None for _, qs in bad)
    ck("every malformed query is refused before the store is touched",
       refused and not e.calls)
    for label, qs in bad:
        if parse_query(qs, e)[0] is not None:
            ck("  refused: %s" % label, False)

    r, err = parse_query("txid=%s&height=780000" % ("A" * 64), e)
    ck("uppercase hex is accepted and lowercased",
       err is None and e.calls and e.calls[-1][0] == "a" * 64)
    r, err = parse_query("txid=%s&height=780000&junk=../&junk2=x"
                         % ("b" * 64), e)
    ck("unknown parameters are ignored, not parsed", err is None)

    b = Bucket(1000.0, 3)
    ck("token bucket allows the burst",
       b.take() and b.take() and b.take())
    b2 = Bucket(0.0001, 2)
    b2.take(); b2.take()
    ck("token bucket then refuses", not b2.take())

    # The engine must convert every internal failure into a fixed string.
    # tx_query calls sys.exit with messages containing the store path.
    class Cfg:
        store = "/home/someone/mstore"
        tools = "/home/someone/monetary-node/tools"
    qe = QueryEngine(Cfg())
    _, err = qe.answer("a" * 64, 780000)
    ck("query before the index is built says so, with no path",
       err and "/home/" not in err and "mstore" not in err)
    qe.index, qe.base = [("x", 0)], 100
    _, err = qe.answer("a" * 64, 999999)
    ck("out-of-range height names the range, not the store",
       err and "/home/" not in err and "100" in err)
    _, err = qe.answer("a" * 64, 100)
    ck("an unreadable record gives a fixed string, not an exception",
       err == "Could not read that block.")

    # Result pages.
    hostile = {"found": True, "txid": "<script>alert(1)</script>",
               "height": 1, "block_hash": "<img src=x>", "merkle_root": "c" * 64,
               "position": 0, "n_tx": 1, "class": "<b>MODIFIED</b>",
               "kept_bytes": 10, "body": "<script>", "body_truncated": False,
               "body_merkle_covered": False, "branch": ["<script>"]}
    hp = render_query(hostile, None)
    ck("query page escapes every field", "<script>" not in hp
       and "<img src=x>" not in hp)

    modified = {"found": True, "txid": "a" * 64, "height": 780000,
                "block_hash": "b" * 64, "merkle_root": "c" * 64,
                "position": 3, "n_tx": 2000, "class": "MODIFIED",
                "kept_bytes": 240, "body": "de" * 50, "body_truncated": False,
                "body_merkle_covered": False, "branch": ["d" * 64] * 11}
    mp = render_query(modified, None)
    # This is the load-bearing one. A page that implies the branch proves a
    # modified body would be a false claim made in public over Tor.
    ck("MODIFIED page says the branch does not prove the bytes",
       "does <b>not</b> prove the kept bytes" in mp)
    ck("MODIFIED page tells them to diff against their own node",
       "getrawtransaction" in mp)
    ck("MODIFIED page says the dropped bytes are gone", "are gone" in mp)
    ck("MODIFIED page shows the branch", mp.count("d" * 64) >= 11)

    whole = dict(modified, **{"class": "RETAINED WHOLE",
                              "body_merkle_covered": True})
    wp = render_query(whole, None)
    ck("WHOLE page claims the stronger proof",
       "branch proves the bytes" in wp)
    ck("WHOLE page does not carry the MODIFIED warning",
       "does <b>not</b> prove the kept bytes" not in wp)

    ck("error page shows only the fixed string",
       "wait a moment" in render_query(None, "Wait a moment.").lower())
    ck("error page leaks no store path",
       "/home/" not in render_query(None, "Could not read that block."))

    nf = render_query({"found": False, "txid": "a" * 64, "height": 1,
                       "block_hash": "b" * 64, "n_tx": 9}, None)
    ck("not-found page tells them how to get the right height",
       "getrawtransaction" in nf)

    ck("status page offers the query form", 'action="/q"' in page)

    # Unattended behaviour. This runs for days with nobody looking at it, so
    # the failure modes have to announce themselves rather than look healthy.
    ck("page says so while the index builds",
       "still building" in render(dict(d, query="building")))
    ck("page says so if the index failed, and does not blame the visitor",
       "unavailable" in render(dict(d, query="failed")).lower())
    ck("page shows the answerable range when ready",
       "780,000 to 968,554" in render(dict(d, query="ready",
                                           query_range="780,000 to 968,554")))
    ck("a failed index is not reported as still building",
       "still building" not in render(dict(d, query="failed")))

    qe2 = QueryEngine(Cfg())
    ck("engine starts in the building state", qe2.status()[0] == "building")
    qe2.load()          # Cfg points at a path that does not exist
    ck("a failed first build is recorded as failed, not ready",
       qe2.status()[0] == "failed")
    _, err = qe2.answer("a" * 64, 1)
    ck("a failed index tells the visitor it is not their fault",
       err and "not your fault" in err.lower())
    ck("a failed index leaks no path", err and "/home/" not in err)

    ck("concurrent connections are capped", MAX_ACTIVE_CONNECTIONS <= 64)
    ck("connections have a timeout so a stalled one frees its slot",
       Handler.timeout and Handler.timeout <= 30)
    ck("the rate cap suits a laptop, not a server", RATE_PER_SEC <= 5)
    ck("query result pages stay under the transport cap",
       len(mp.encode()) < QUERY_MAX_BODY)

    print("\n%d/%d passed" % (sum(ok), len(ok)))
    return 0 if all(ok) else 1


# -------------------------------------------------------------------- main


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    home = os.path.expanduser("~")
    ap.add_argument("--store", default=os.path.join(home, "mstore"))
    ap.add_argument("--datadir", default=os.path.join(home, ".bitcoin"))
    ap.add_argument("--cookie",
                    default=os.path.join(home, ".bitcoin", ".cookie"))
    ap.add_argument("--tools", default=os.path.dirname(os.path.abspath(__file__)))
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8081)
    ap.add_argument("--no-query", action="store_true",
                    help="serve the status page only; disable /q entirely")
    ap.add_argument("--selftest", action="store_true")
    cfg = ap.parse_args()

    if cfg.selftest:
        return selftest()

    if cfg.host not in ("127.0.0.1", "::1", "localhost"):
        print("refusing to bind %s. Tor publishes this page; the process "
              "itself must stay on loopback." % cfg.host)
        return 1

    cache = Cache(cfg)
    cache.refresh()

    engine = None
    if not cfg.no_query:
        engine = QueryEngine(cfg)
        cache.engine = engine
        # The first index build walks every record prefix in the store, which
        # is minutes cold. Do it off the serving thread so the page is up
        # immediately; /q says "still building" until it finishes.
        threading.Thread(target=engine.load, daemon=True).start()

    def loop():
        while True:
            time.sleep(REFRESH_SECONDS)
            try:
                cache.refresh()
                if engine is not None:
                    engine.load()       # cheap once cached; extends the tail
            except Exception:
                pass
    threading.Thread(target=loop, daemon=True).start()

    Handler.cache = cache
    Handler.engine = engine
    with Server((cfg.host, cfg.port), Handler) as srv:
        print("status page on http://%s:%d — publish the ONION address for "
              "this, never this port" % (cfg.host, cfg.port))
        srv.serve_forever()


if __name__ == "__main__":
    sys.exit(main())
