#!/usr/bin/env python3
"""
prune_behind.py — delete block files only after the daemon has stripped them.

Lets a node sync from genesis and build a complete monetary store on a disk
that could not hold both. The node keeps blocks until the daemon has read
them; then, and only then, they are deleted.

    node syncs  ────────────────────────────────────►  tip
    daemon strips  ──────────────►
    pruned  ────────►
                    ^ never crosses the daemon's position

HOW IT DECIDES WHAT TO DELETE

It reads the daemon's own `state.json` — the height the daemon has actually
written to the store — and prunes to that height minus a safety margin. It
never asks the node about the daemon's progress, and it never assumes: if the
state file is missing or unreadable, it prunes nothing.

This requires `prune=1` in the node's config, which is Bitcoin Core's manual
pruning mode: the node keeps everything until told otherwise. `prune=<size>`
would have the node deleting on its own schedule, which could remove blocks the
daemon has not reached.

WHY A MARGIN

`pruneblockchain` prunes up to the last full block *file*, not the exact height,
and a reorg near the daemon's position would need blocks it has just passed. The
default margin of 10,000 blocks costs a few gigabytes and removes the class of
mistake that ends in a re-sync.

Usage:
    python3 prune_behind.py --store ~/mstore --rpc-port 8332 \\
        --rpc-cookie /path/.cookie

    python3 prune_behind.py --store ~/mstore --rpc-port 8332 \\
        --rpc-cookie /path/.cookie --once --dry-run

Standard library only, plus monetary_daemon.py beside it. BSD-2-Clause.
"""

import argparse
import json
import os
import shutil
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from monetary_daemon import RPC, load_state
except ImportError:
    sys.exit("monetary_daemon.py must be in the same directory")

MIN_KEEP = 288          # Core refuses to prune within ~2 days of the tip


def human(n):
    for u in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:,.1f} {u}"
        n /= 1024
    return f"{n:,.1f} PB"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--store", required=True)
    ap.add_argument("--rpc-host", default="127.0.0.1")
    ap.add_argument("--rpc-port", type=int, default=8332)
    ap.add_argument("--rpc-user")
    ap.add_argument("--rpc-password")
    ap.add_argument("--rpc-cookie")
    ap.add_argument("--margin", type=int, default=10000,
                    help="blocks to keep behind the daemon")
    ap.add_argument("--interval", type=int, default=600)
    ap.add_argument("--min-free-gb", type=int, default=50,
                    help="warn loudly below this")
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    rpc = RPC(args.rpc_host, args.rpc_port, args.rpc_user, args.rpc_password,
              args.rpc_cookie)

    info = rpc.call("getblockchaininfo")
    if not info.get("pruned"):
        sys.exit(
            "The node is not in pruning mode.\n"
            "Set prune=1 (manual pruning) and restart it. With prune=1 the\n"
            "node keeps every block until this script says otherwise, which\n"
            "is the whole point — anything else risks deleting blocks the\n"
            "daemon has not stripped yet.")

    print(f"node      {args.rpc_host}:{args.rpc_port}, height "
          f"{info['blocks']:,}")
    print(f"store     {args.store}")
    print(f"margin    {args.margin:,} blocks behind the daemon")
    print(f"interval  {args.interval}s")
    if args.dry_run:
        print("DRY RUN — nothing will be pruned")
    print()

    last_pruned = None
    while True:
        st = load_state(args.store)
        if st is None or st.get("height") is None:
            print(f"{time.strftime('%H:%M:%S')}  no daemon state yet, "
                  f"pruning nothing", flush=True)
        else:
            daemon_h = st["height"]
            tip = rpc.call("getblockcount")
            target = daemon_h - args.margin

            # Never prune past the daemon, and never inside Core's own floor.
            target = min(target, tip - MIN_KEEP)

            free = shutil.disk_usage(args.store).free
            behind = tip - daemon_h

            if target <= 0:
                print(f"{time.strftime('%H:%M:%S')}  daemon at "
                      f"{daemon_h:,}, nothing safe to prune yet "
                      f"(need > {args.margin:,})", flush=True)
            elif last_pruned is not None and target <= last_pruned:
                print(f"{time.strftime('%H:%M:%S')}  daemon {daemon_h:,}, "
                      f"tip {tip:,}, behind {behind:,}, "
                      f"free {human(free)} — nothing new", flush=True)
            else:
                if args.dry_run:
                    print(f"{time.strftime('%H:%M:%S')}  would prune to "
                          f"{target:,} (daemon {daemon_h:,}, tip {tip:,})",
                          flush=True)
                else:
                    before = free
                    try:
                        actual = rpc.call("pruneblockchain", target)
                    except Exception as e:
                        print(f"{time.strftime('%H:%M:%S')}  prune failed: {e}",
                              flush=True)
                        actual = None
                    if actual is not None:
                        time.sleep(2)
                        after = shutil.disk_usage(args.store).free
                        print(f"{time.strftime('%H:%M:%S')}  pruned to "
                              f"{actual:,}  daemon {daemon_h:,}  tip {tip:,}  "
                              f"behind {behind:,}  freed "
                              f"{human(max(0, after - before))}  "
                              f"free {human(after)}", flush=True)
                        last_pruned = target

            if free < args.min_free_gb * (1 << 30):
                print(f"  WARNING: only {human(free)} free. If the daemon is "
                      f"far behind the node, pause the node and let it catch "
                      f"up.", flush=True)

        if args.once:
            return
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
