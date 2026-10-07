#!/usr/bin/env python3
"""
monetary_convert.py — turn a full node into a monetary node.

Runs the whole conversion: index, strip, verify, commit, adopt, follow, and
finally prune. Resumable, so a dropped connection or a reboot costs you the
current stage rather than the whole thing.

THE ONE THING THIS SCRIPT IS REALLY FOR

Pruning is irreversible. Once your node deletes its block files, the only way
back is a full re-sync — days, on the sort of hardware most people run.

So the pruning stage is structurally unreachable until the store has been
written AND independently verified AND the daemon has adopted it. Not "please
check first" in a comment: the script refuses, and it refuses by reading its
own state file rather than trusting that the earlier stages were run.

It also requires --yes-prune, typed deliberately, every time.

STAGES

  1 check    node synced, disk space, tools present, nothing already broken
  2 index    build the block index (~10 min, one-time, cached)
  3 strip    write the monetary store (hours)
  4 verify   re-read the store with no block file open (hours)
  5 commit   compute C over the store
  6 adopt    hand the store to the daemon and start following the chain
  7 prune    reconfigure the node to stop keeping block files  [DESTRUCTIVE]

Stages 1-6 are safe and reversible: delete the store and nothing has changed.
Stage 7 is not.

Usage:
    python3 monetary_convert.py --check
    python3 monetary_convert.py --run
    python3 monetary_convert.py --run --start 767430 --end 962292
    python3 monetary_convert.py --prune --yes-prune
    python3 monetary_convert.py --status

Standard library only. Calls the other tools rather than reimplementing them,
so there is one copy of the stripping logic and it is the one that was tested.
BSD-2-Clause.
"""

import argparse
import glob
import json
import os
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
STATE_VERSION = 1

TOOLS = ["mindex.py", "monetary_store.py", "monetary_commit.py",
         "monetary_daemon.py"]

STAGES = ["check", "index", "strip", "verify", "commit", "adopt", "prune"]


def say(msg=""):
    print(msg, flush=True)


def head(title):
    say()
    say("=" * 68)
    say(title)
    say("=" * 68)


def human(n):
    for u in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:,.1f} {u}"
        n /= 1024
    return f"{n:,.1f} PB"


def run(cmd, **kw):
    say(f"  $ {' '.join(str(c) for c in cmd)}")
    return subprocess.run(cmd, **kw)


# ---------------------------------------------------------------- state


class State:
    """
    Records which stages have completed. The prune stage consults this rather
    than assuming, because "I think I verified it" is exactly the thought that
    precedes an unrecoverable mistake.
    """

    def __init__(self, path):
        self.path = path
        self.d = {"version": STATE_VERSION, "done": {}, "config": {}}
        if os.path.exists(path):
            with open(path) as f:
                loaded = json.load(f)
            if loaded.get("version") != STATE_VERSION:
                sys.exit(f"{path}: unrecognised version")
            self.d = loaded

    def save(self):
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.d, f, indent=1)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path)

    def mark(self, stage, **info):
        self.d["done"][stage] = {"at": time.strftime("%Y-%m-%d %H:%M:%S"),
                                 **info}
        self.save()

    def is_done(self, stage):
        return stage in self.d["done"]

    def get(self, key, default=None):
        return self.d["config"].get(key, default)

    def set(self, key, value):
        self.d["config"][key] = value
        self.save()


# ---------------------------------------------------------------- node


class Node:
    """Talks to bitcoind, via docker exec if it is containerised."""

    def __init__(self, cli=None, container=None, rpcport=None, cookie=None,
                 datadir=None):
        self.container = container
        self.rpcport = rpcport
        self.cookie = cookie
        self.datadir = datadir
        self.cli = cli or "bitcoin-cli"

    def _cmd(self, *args):
        base = []
        if self.container:
            base = ["sudo", "docker", "exec", self.container]
        base.append(self.cli)
        if self.rpcport:
            base.append(f"-rpcport={self.rpcport}")
        return base + list(args)

    def call(self, *args, quiet=True):
        r = subprocess.run(self._cmd(*args), capture_output=True, text=True)
        if r.returncode != 0:
            raise IOError(r.stderr.strip() or r.stdout.strip())
        return r.stdout.strip()

    def info(self):
        return json.loads(self.call("getblockchaininfo"))


def detect_node():
    """
    Work out how to reach bitcoind and where its data lives.

    Handles a plain local node and the containerised layouts used by node
    appliances. Returns (Node, layout_name) or (None, reason).
    """
    # Containerised?
    try:
        r = subprocess.run(["sudo", "docker", "ps", "--format", "{{.Names}}"],
                           capture_output=True, text=True, timeout=20)
        names = r.stdout.split()
    except Exception:
        names = []

    for name in names:
        if not any(k in name.lower() for k in ("bitcoin", "knots", "bitcoind")):
            continue
        for port in (None, 8332, 9332):
            n = Node(container=name, rpcport=port)
            try:
                n.info()
                return n, f"container {name}" + (f" port {port}" if port else "")
            except Exception:
                continue

    if shutil.which("bitcoin-cli"):
        for port in (None, 8332, 9332):
            n = Node(rpcport=port)
            try:
                n.info()
                return n, "local bitcoin-cli" + (f" port {port}" if port else "")
            except Exception:
                continue

    return None, ("could not reach bitcoind. Pass --container and --rpcport, "
                  "or make bitcoin-cli work from this shell first.")


def find_blocks_dir():
    candidates = []
    for root in (os.path.expanduser("~"), "/", "/mnt", "/media"):
        try:
            for path in glob.glob(os.path.join(root, "**", "blk00000.dat"),
                                  recursive=True):
                candidates.append(os.path.dirname(path))
        except Exception:
            pass
        if candidates:
            break
    return candidates


# ---------------------------------------------------------------- stages


def stage_check(st, args):
    head("STAGE 1 — CHECK")
    problems = []

    say("tools")
    for t in TOOLS:
        p = os.path.join(HERE, t)
        ok = os.path.exists(p)
        say(f"  [{'ok  ' if ok else 'MISSING'}] {t}")
        if not ok:
            problems.append(f"{t} not found beside this script")

    say()
    say("python")
    v = sys.version_info
    ok = v >= (3, 8)
    say(f"  [{'ok  ' if ok else 'FAIL'}] {v.major}.{v.minor}.{v.micro}")
    if not ok:
        problems.append("Python 3.8 or later required")

    say()
    say("node")
    node, how = detect_node()
    if node is None:
        say(f"  [FAIL] {how}")
        problems.append(how)
        info = None
    else:
        say(f"  [ok  ] reachable via {how}")
        info = node.info()
        say(f"         chain {info['chain']}, height {info['blocks']:,}")
        if info.get("initialblockdownload"):
            say("  [FAIL] still in initial block download")
            problems.append("node has not finished syncing")
        else:
            say("  [ok  ] synced")
        if info.get("pruned"):
            say("  [FAIL] node is ALREADY pruned")
            problems.append(
                "already pruned: historical blocks are gone, so a store "
                "cannot be built from them. Nothing to convert.")
        else:
            say("  [ok  ] not pruned, block files present")
        st.set("container", node.container)
        st.set("rpcport", node.rpcport)
        st.set("tip", info["blocks"])

    say()
    say("block files")
    blocks = args.blocks or st.get("blocks")
    if not blocks:
        found = find_blocks_dir()
        if len(found) == 1:
            blocks = found[0]
            say(f"  [ok  ] found {blocks}")
        elif found:
            say("  [FAIL] several candidates, pass --blocks:")
            for f in found:
                say(f"           {f}")
            problems.append("ambiguous blocks directory")
        else:
            say("  [FAIL] no blk00000.dat found, pass --blocks")
            problems.append("blocks directory not found")
    else:
        ok = os.path.exists(os.path.join(blocks, "blk00000.dat"))
        say(f"  [{'ok  ' if ok else 'FAIL'}] {blocks}")
        if not ok:
            problems.append(f"no blk00000.dat in {blocks}")
    if blocks:
        st.set("blocks", blocks)
        xor = os.path.exists(os.path.join(blocks, "xor.dat"))
        say(f"         blocksdir is {'XOR-obfuscated (handled)' if xor else 'plain'}")

    say()
    say("disk")
    out = args.out or st.get("out") or os.path.expanduser("~/mstore")
    st.set("out", out)
    parent = os.path.dirname(os.path.abspath(out)) or "/"
    free = shutil.disk_usage(parent).free
    start = args.start or 767430
    end = args.end or (info["blocks"] - 6 if info else 0)
    est = max(0, (end - start)) * 1_300_000        # ~1.3 MB stored per block
    say(f"  free            {human(free)}")
    say(f"  estimated store {human(est)}  for blocks {start:,}-{end:,}")
    if free < est * 1.1:
        say("  [FAIL] not enough space")
        problems.append(f"need about {human(est * 1.1)} free, have {human(free)}")
    else:
        say("  [ok  ] sufficient")
    st.set("start", start)
    st.set("end", end)

    say()
    if problems:
        say("NOT READY")
        for p in problems:
            say(f"  - {p}")
        return False
    say("READY")
    say()
    say("Nothing so far is destructive. Stages 2-6 write a new store and")
    say("leave your node untouched; delete the store and nothing has changed.")
    st.mark("check")
    return True


def stage_index(st, args):
    head("STAGE 2 — INDEX")
    say("Block files record no heights, so the chain has to be walked from")
    say("genesis once. Cached afterwards.")
    say()
    r = run([sys.executable, "-u", os.path.join(HERE, "mindex.py"),
             "--blocks", st.get("blocks")])
    if r.returncode != 0:
        return False
    st.mark("index")
    return True


def stage_strip(st, args):
    head("STAGE 3 — STRIP")
    out = st.get("out")
    start, end = st.get("start"), st.get("end")
    say(f"blocks {start:,} to {end:,} into {out}")
    say("This is the long one. Several hours on slow storage.")
    say()
    r = run([sys.executable, "-u", os.path.join(HERE, "monetary_store.py"),
             "--blocks", st.get("blocks"), "--start", str(start),
             "--end", str(end), "--out", out])
    if r.returncode != 0:
        return False
    st.mark("strip")
    return True


def stage_verify(st, args):
    head("STAGE 4 — VERIFY")
    say("Re-reads the store with no block file open. Every block must")
    say("reconstruct to a merkle root matching its own header.")
    say()
    say("This gate is why pruning later is safe. If it fails, stop.")
    say()
    r = run([sys.executable, "-u", os.path.join(HERE, "monetary_store.py"),
             "--verify", st.get("out")])
    if r.returncode != 0:
        say()
        say("VERIFICATION FAILED. Do not prune. The store is not sound.")
        return False
    st.mark("verify", verified=True)
    return True


def stage_commit(st, args):
    head("STAGE 5 — COMMIT")
    csv = os.path.join(os.path.dirname(st.get("out")), "commitments.csv")
    r = run([sys.executable, "-u", os.path.join(HERE, "monetary_commit.py"),
             st.get("out"), "--csv", csv], capture_output=True, text=True)
    say(r.stdout)
    if r.returncode != 0:
        say(r.stderr)
        return False
    c = None
    for line in r.stdout.splitlines():
        if line.strip().startswith("C "):
            c = line.split()[-1]
    if c:
        st.set("commitment", c)
        say(f"C = {c}")
        say()
        say("Publish that. Anyone stripping the same range with the same")
        say("rules should get the same value, and the per-block CSV locates")
        say("the first block where two runs disagree.")
    st.mark("commit", commitment=c)
    return True


def stage_adopt(st, args):
    head("STAGE 6 — ADOPT AND FOLLOW")
    out = st.get("out")
    daemon = os.path.join(HERE, "monetary_daemon.py")

    r = run([sys.executable, daemon, "--adopt", "--store", out,
             "--start-height", str(st.get("start"))],
            capture_output=True, text=True)
    say(r.stdout.strip())
    if r.returncode != 0 and "nothing to adopt" not in r.stdout:
        say(r.stderr)
        return False

    c = st.get("commitment")
    if c:
        p = os.path.join(out, "state.json")
        s = json.load(open(p))
        s["commitment"] = c
        json.dump(s, open(p, "w"), indent=1)
        say(f"  restored C into state.json")

    say()
    say("Start the daemon yourself so you control how it runs:")
    say()
    cookie = st.get("cookie") or "<path to .cookie>"
    port = st.get("rpcport") or 8332
    say(f"  setsid nohup python3 -u {daemon} --store {out} \\")
    say(f"    --rpc-port {port} --rpc-cookie {cookie} \\")
    say(f"    > ~/daemon.log 2>&1 < /dev/null &")
    st.mark("adopt")
    return True


def stage_prune(st, args):
    head("STAGE 7 — PRUNE  [IRREVERSIBLE]")

    if not st.is_done("verify"):
        say("REFUSED: the store has not been verified.")
        say()
        say("Pruning deletes your node's block files. If the store turns out")
        say("to be unsound afterwards, the only way back is a full re-sync.")
        say("Run stage 4 first.")
        return False

    if not st.is_done("adopt"):
        say("REFUSED: the daemon has not adopted the store.")
        say("Without it, the store stops at the height you stripped and")
        say("nothing keeps it current.")
        return False

    if not args.yes_prune:
        say("REFUSED: pass --yes-prune to confirm.")
        say()
        say("What this does, permanently:")
        say("  - your node deletes its block files")
        say("  - blocks before the stripped range are gone for good")
        say("  - anything needing full blocks (txindex, electrs) stops working")
        say("  - the only way back is a full re-sync")
        return False

    say("Verified store, daemon adopted, confirmation given.")
    say()

    settings = st.get("appliance_settings")
    if settings and os.path.exists(settings):
        say(f"appliance settings: {settings}")
        shutil.copy(settings, settings + ".before-monetary")
        s = json.load(open(settings))
        s["prune"] = args.prune_gb
        s["txindex"] = False
        json.dump(s, open(settings, "w"), indent=2)
        say(f"  prune -> {args.prune_gb} GB, txindex -> off")
        say(f"  backup at {settings}.before-monetary")
        say()
        say("Now restart the node from your appliance's dashboard, then:")
    else:
        say("No appliance settings file found. Add these to bitcoin.conf:")
        say()
        say(f"  prune={args.prune_gb * 1024}")
        say("  txindex=0")
        say()
        say("then restart bitcoind, then:")

    say()
    say("  df -h .")
    say("  python3 monetary_daemon.py --status --store " + st.get("out"))
    say()
    say("The daemon should keep tracking the tip throughout. It reads blocks")
    say("six confirmations deep, far inside any sensible prune horizon.")
    st.mark("prune", prune_gb=args.prune_gb)
    return True


# ---------------------------------------------------------------- main


def show_status(st):
    head("CONVERSION STATUS")
    for i, s in enumerate(STAGES, 1):
        done = st.is_done(s)
        when = st.d["done"].get(s, {}).get("at", "")
        say(f"  {i}. {s:<8} {'done' if done else '-':<6} {when}")
    say()
    for k in ("blocks", "out", "start", "end", "commitment"):
        v = st.get(k)
        if v is not None:
            say(f"  {k:<12} {v}")
    say()
    if st.is_done("verify") and st.is_done("adopt") and not st.is_done("prune"):
        say("Ready to prune. Requires --prune --yes-prune.")
    elif not st.is_done("verify"):
        say("Not ready to prune: store unverified.")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--state", default=os.path.expanduser("~/.monetary_convert.json"))
    ap.add_argument("--blocks")
    ap.add_argument("--out")
    ap.add_argument("--start", type=int)
    ap.add_argument("--end", type=int)
    ap.add_argument("--container")
    ap.add_argument("--rpcport", type=int)
    ap.add_argument("--cookie")
    ap.add_argument("--appliance-settings",
                    help="path to an appliance's bitcoin settings JSON")
    ap.add_argument("--prune-gb", type=int, default=10)
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--run", action="store_true", help="stages 1-6")
    ap.add_argument("--prune", action="store_true", help="stage 7 only")
    ap.add_argument("--yes-prune", action="store_true")
    ap.add_argument("--status", action="store_true")
    ap.add_argument("--redo", help="rerun a completed stage by name")
    args = ap.parse_args()

    st = State(args.state)
    for k in ("cookie", "appliance_settings"):
        v = getattr(args, k if k != "appliance_settings" else "appliance_settings")
        if v:
            st.set(k, v)

    if args.status:
        show_status(st)
        return

    if args.redo:
        st.d["done"].pop(args.redo, None)
        st.save()
        say(f"cleared stage {args.redo}")
        return

    if args.check:
        sys.exit(0 if stage_check(st, args) else 1)

    if args.prune:
        sys.exit(0 if stage_prune(st, args) else 1)

    if not args.run:
        ap.print_help()
        say()
        say("Start with --check. It changes nothing.")
        return

    order = [("check", stage_check), ("index", stage_index),
             ("strip", stage_strip), ("verify", stage_verify),
             ("commit", stage_commit), ("adopt", stage_adopt)]
    for name, fn in order:
        if st.is_done(name):
            say(f"[skip] {name} already done ({st.d['done'][name]['at']})")
            continue
        if not fn(st, args):
            say()
            say(f"stopped at stage: {name}")
            say("Fix the problem and run again — completed stages are skipped.")
            sys.exit(1)

    head("DONE — STAGES 1 TO 6")
    say("Your node is untouched. The store exists, is verified, and the")
    say("daemon can keep it current.")
    say()
    say("Nothing has been saved yet: the store is additional storage until")
    say("the node stops keeping its own block files.")
    say()
    say("When you are ready, and only then:")
    say()
    say(f"  python3 {os.path.basename(__file__)} --prune --yes-prune")


if __name__ == "__main__":
    main()
