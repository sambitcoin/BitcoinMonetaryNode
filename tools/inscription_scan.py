#!/usr/bin/env python3
"""
inscription_scan.py — measure inscription envelope payload bytes in Bitcoin blocks.

Counts, per block: total bytes, witness bytes, envelope payload bytes (data
pushed inside unexecutable OP_IF branches in taproot script-path witnesses),
and the subset carrying the "ord" protocol marker.

Reads raw blocks over Bitcoin Core / Knots RPC. Standard library only.

Built for long unattended runs against a rate-limited node (e.g. Umbrel):
waits out HTTP 403 throttling indefinitely rather than dying, paces requests,
resumes from a partial CSV, prints progress with an ETA.

Usage:
    python3 inscription_scan.py --start 767430 --end 962292 \
        --csv ~/Downloads/results.csv --resume

Config via environment:
    BTC_RPC_USER, BTC_RPC_PASS, BTC_RPC_HOST, BTC_RPC_PORT
"""

import argparse
import base64
import json
import os
import sys
import time
import urllib.error
import urllib.request

CONFIG = {
    "user": os.environ.get("BTC_RPC_USER", "umbrel"),
    "password": os.environ.get("BTC_RPC_PASS", ""),
    "host": os.environ.get("BTC_RPC_HOST", "umbrel.local"),
    "port": os.environ.get("BTC_RPC_PORT", "8332"),
}

CSV_HEADER = (
    "height,block_bytes,tx_count,witness_bytes,envelope_count,"
    "envelope_payload_bytes,ord_envelope_count,ord_payload_bytes,"
    "malformed_scripts\n"
)

FIELDS = ("block_bytes", "tx_count", "witness_bytes", "envelope_count",
          "envelope_payload_bytes", "ord_envelope_count", "ord_payload_bytes",
          "malformed_scripts")

# ---------------------------------------------------------------- rpc

_throttle_events = 0


def rpc(method, params=None, max_wait_total=3600):
    """
    JSON-RPC call returning the 'result' field.

    Transient failures retry with backoff. HTTP 403 (rate limiting) is treated
    as temporary and waited out with long pauses for up to max_wait_total
    seconds, since throttles are time-windowed and clear on their own.
    """
    global _throttle_events

    payload = json.dumps(
        {"jsonrpc": "1.0", "id": "scan", "method": method, "params": params or []}
    ).encode()
    url = f"http://{CONFIG['host']}:{CONFIG['port']}/"
    auth = base64.b64encode(
        f"{CONFIG['user']}:{CONFIG['password']}".encode()).decode()

    waited = 0.0
    attempt = 0
    while True:
        try:
            req = urllib.request.Request(url, data=payload)
            req.add_header("Authorization", f"Basic {auth}")
            req.add_header("Content-Type", "text/plain")
            with urllib.request.urlopen(req, timeout=180) as resp:
                body = json.loads(resp.read().decode())
            if body.get("error"):
                raise RuntimeError(f"node error: {body['error']}")
            return body["result"]

        except urllib.error.HTTPError as e:
            if e.code == 403:
                if waited == 0:
                    _throttle_events += 1
                    print(f"    throttled (403) at {method}; waiting it out",
                          file=sys.stderr, flush=True)
                wait = 30 if waited < 300 else 60
                if waited + wait > max_wait_total:
                    raise RuntimeError(
                        f"still throttled after {waited/60:.0f} minutes; "
                        f"stop and rerun with --resume later") from e
                time.sleep(wait)
                waited += wait
                continue
            if e.code in (401, 404):
                raise  # auth or endpoint problem: don't spin
            attempt += 1
            if attempt >= 6:
                raise
            time.sleep(min(2 ** attempt, 30))

        except Exception as e:  # noqa: BLE001
            attempt += 1
            if attempt >= 6:
                raise RuntimeError(f"{method} failed: {e}") from e
            wait = min(2 ** attempt, 30)
            print(f"    {method} failed ({e}); retry {attempt} in {wait}s",
                  file=sys.stderr, flush=True)
            time.sleep(wait)


# ---------------------------------------------------------------- byte reader


class Reader:
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def read(self, n):
        if self.pos + n > len(self.data):
            raise ValueError(f"read past end: want {n} at {self.pos}")
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def peek(self, n=1):
        return self.data[self.pos:self.pos + n]

    def u8(self):
        return self.read(1)[0]

    def u16(self):
        return int.from_bytes(self.read(2), "little")

    def u32(self):
        return int.from_bytes(self.read(4), "little")

    def u64(self):
        return int.from_bytes(self.read(8), "little")

    def varint(self):
        n = self.u8()
        if n < 0xFD:
            return n
        if n == 0xFD:
            return self.u16()
        if n == 0xFE:
            return self.u32()
        return self.u64()


# ---------------------------------------------------------------- script

OP_0, OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4 = 0x00, 0x4C, 0x4D, 0x4E
OP_IF, OP_NOTIF, OP_ENDIF = 0x63, 0x64, 0x68
ORD_MARKER = b"ord"


def iter_script(script):
    i, n = 0, len(script)
    while i < n:
        start = i
        op = script[i]
        i += 1
        data = None
        if 0x01 <= op <= 0x4B:
            if i + op > n:
                raise ValueError("truncated push")
            data = script[i:i + op]; i += op
        elif op == OP_PUSHDATA1:
            if i + 1 > n:
                raise ValueError("truncated len")
            ln = script[i]; i += 1
            if i + ln > n:
                raise ValueError("truncated data")
            data = script[i:i + ln]; i += ln
        elif op == OP_PUSHDATA2:
            if i + 2 > n:
                raise ValueError("truncated len")
            ln = int.from_bytes(script[i:i + 2], "little"); i += 2
            if i + ln > n:
                raise ValueError("truncated data")
            data = script[i:i + ln]; i += ln
        elif op == OP_PUSHDATA4:
            if i + 4 > n:
                raise ValueError("truncated len")
            ln = int.from_bytes(script[i:i + 4], "little"); i += 4
            if i + ln > n:
                raise ValueError("truncated data")
            data = script[i:i + ln]; i += ln
        yield op, data, i - start


def find_envelopes(script):
    """Unexecutable OP_IF branches. Falsity by script semantics, not literals."""
    out = []
    try:
        ops = list(iter_script(script))
    except ValueError:
        return out

    i = 0
    while i < len(ops) - 1:
        op, data, _ = ops[i]
        pushes_false = (op == OP_0 or
                        (data is not None and (len(data) == 0 or data == b"\x00")))
        if pushes_false and ops[i + 1][0] == OP_IF:
            depth, payload, has_ord = 1, 0, False
            j = i + 2
            while j < len(ops):
                op_j, data_j, _ = ops[j]
                if op_j in (OP_IF, OP_NOTIF):
                    depth += 1
                elif op_j == OP_ENDIF:
                    depth -= 1
                    if depth == 0:
                        break
                elif data_j is not None:
                    payload += len(data_j)
                    if data_j == ORD_MARKER:
                        has_ord = True
                j += 1
            if depth == 0:
                out.append({"payload_bytes": payload, "has_ord_marker": has_ord})
            i = j + 1
            continue
        i += 1
    return out


# ---------------------------------------------------------------- block


def is_taproot_script_path(items):
    if len(items) < 2:
        return False
    c = items[-1]
    if len(c) < 33 or (len(c) - 33) % 32 != 0:
        return False
    return (c[0] & 0xFE) == 0xC0


def parse_transaction(r):
    r.u32()
    segwit = r.peek(2) == b"\x00\x01"
    if segwit:
        r.read(2)

    n_in = r.varint()
    for _ in range(n_in):
        r.read(32); r.u32(); r.read(r.varint()); r.u32()

    for _ in range(r.varint()):
        r.u64(); r.read(r.varint())

    envelopes, malformed, wbytes = [], 0, 0
    if segwit:
        w0 = r.pos
        for _ in range(n_in):
            items = [r.read(r.varint()) for _ in range(r.varint())]
            if is_taproot_script_path(items):
                ts = items[-2]
                found = find_envelopes(ts)
                if not found and b"\x00\x63" in ts:
                    malformed += 1
                envelopes.extend(found)
        wbytes = (r.pos - w0) + 2

    r.u32()
    return envelopes, malformed, wbytes


def scan_block(raw_hex):
    data = bytes.fromhex(raw_hex)
    r = Reader(data)
    r.read(80)
    n_tx = r.varint()
    s = dict.fromkeys(FIELDS, 0)
    s["block_bytes"] = len(data)
    s["tx_count"] = n_tx
    for _ in range(n_tx):
        envs, malformed, wbytes = parse_transaction(r)
        s["witness_bytes"] += wbytes
        s["malformed_scripts"] += malformed
        for e in envs:
            s["envelope_count"] += 1
            s["envelope_payload_bytes"] += e["payload_bytes"]
            if e["has_ord_marker"]:
                s["ord_envelope_count"] += 1
                s["ord_payload_bytes"] += e["payload_bytes"]
    return s


# ---------------------------------------------------------------- helpers


def human(n):
    for u in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:,.1f} {u}"
        n /= 1024
    return f"{n:,.1f} PB"


def hms(sec):
    sec = int(sec)
    h, rem = divmod(sec, 3600)
    m, s = divmod(rem, 60)
    return f"{h}h{m:02d}m" if h else f"{m}m{s:02d}s"


def read_existing(path):
    totals = dict.fromkeys(FIELDS, 0)
    last = None
    if not path or not os.path.exists(path):
        return last, totals
    with open(path) as f:
        next(f, None)
        for line in f:
            p = line.strip().split(",")
            if len(p) != 9:
                continue
            try:
                v = [int(x) for x in p]
            except ValueError:
                continue
            last = v[0]
            for k, val in zip(FIELDS, v[1:]):
                totals[k] += val
    return last, totals


def summarise(totals, first, last, elapsed):
    bb, wb = totals["block_bytes"], totals["witness_bytes"]
    ep, op = totals["envelope_payload_bytes"], totals["ord_payload_bytes"]
    print()
    print(f"blocks {first:,} .. {last:,}")
    print(f"elapsed              {hms(elapsed)}")
    print(f"throttle events      {_throttle_events}")
    print(f"transactions         {totals['tx_count']:,}")
    print(f"block bytes          {human(bb)}")
    print(f"witness bytes        {human(wb)}   ({wb/bb*100 if bb else 0:.2f}% of blocks)")
    print(f"envelopes            {totals['envelope_count']:,}")
    print(f"envelope payload     {human(ep)}   "
          f"({ep/wb*100 if wb else 0:.2f}% of witness, "
          f"{ep/bb*100 if bb else 0:.2f}% of blocks)")
    print(f"  with 'ord' marker  {totals['ord_envelope_count']:,}, {human(op)}")
    print(f"  without marker     {totals['envelope_count']-totals['ord_envelope_count']:,}, "
          f"{human(ep-op)}")
    print(f"malformed scripts    {totals['malformed_scripts']:,}")


# ---------------------------------------------------------------- main


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--start", type=int, required=True)
    ap.add_argument("--end", type=int, required=True)
    ap.add_argument("--csv", type=str)
    ap.add_argument("--resume", action="store_true")
    ap.add_argument("--progress", type=int, default=500)
    ap.add_argument("--delay", type=float, default=0.03,
                    help="pause between blocks, seconds (default 0.03; raise "
                         "to 0.1 if the node keeps throttling)")
    args = ap.parse_args()

    if not CONFIG["password"]:
        sys.exit("Set BTC_RPC_PASS (and BTC_RPC_USER / HOST / PORT if not default).")

    info = rpc("getblockchaininfo")
    print(f"node at height {info['blocks']:,}  pruned={info['pruned']}")
    if args.end > info["blocks"]:
        sys.exit(f"--end {args.end} is beyond the node's tip")

    start = args.start
    totals = dict.fromkeys(FIELDS, 0)

    if args.resume and args.csv:
        last, totals = read_existing(args.csv)
        if last is not None:
            start = last + 1
            print(f"resuming from {start:,} (CSV has through {last:,})")
            if start > args.end:
                summarise(totals, args.start, args.end, 0)
                return

    csv_file = None
    if args.csv:
        fresh = not (args.resume and os.path.exists(args.csv))
        csv_file = open(args.csv, "w" if fresh else "a")
        if fresh:
            csv_file.write(CSV_HEADER)
            csv_file.flush()

    n_total = args.end - start + 1
    t0 = time.time()
    done = 0
    last_h = start - 1

    try:
        for height in range(start, args.end + 1):
            if args.delay:
                time.sleep(args.delay)
            s = scan_block(rpc("getblock", [rpc("getblockhash", [height]), 0]))
            for k in FIELDS:
                totals[k] += s[k]
            done += 1
            last_h = height

            if csv_file:
                csv_file.write(",".join(str(x) for x in
                               [height] + [s[k] for k in FIELDS]) + "\n")
                if done % 50 == 0:
                    csv_file.flush()

            if done % args.progress == 0:
                el = time.time() - t0
                rate = done / el
                pct = done / n_total * 100
                ep, bb = totals["envelope_payload_bytes"], totals["block_bytes"]
                print(f"  {height:,}  {pct:5.1f}%  {rate:.2f} blk/s  "
                      f"eta {hms((n_total-done)/rate if rate else 0)}  "
                      f"payload {human(ep)} ({ep/bb*100 if bb else 0:.1f}% of blocks)",
                      flush=True)

    except KeyboardInterrupt:
        print("\ninterrupted — CSV intact, rerun with --resume", file=sys.stderr)
    except Exception as e:  # noqa: BLE001
        print(f"\nstopped: {e}\nCSV intact, rerun with --resume", file=sys.stderr)
    finally:
        if csv_file:
            csv_file.flush()
            csv_file.close()

    summarise(totals, args.start, last_h, time.time() - t0)


if __name__ == "__main__":
    main()
