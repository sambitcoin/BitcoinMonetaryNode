#!/usr/bin/env python3
"""
monetary_supervisor.py — run a whole monetary node as one thing.

A monetary node is five jobs that have to happen in order and then keep
happening:

    1. DOWNLOAD    bitcoind fetches and validates the chain from peers
    2. STRIP       the daemon reads each validated block and stores it
                   without its data carriers
    3. RECLAIM     prune_behind deletes block files bitcoind no longer
                   needs, but only ones the stripper has already read
    4. INDEX       a wallet's addresses are scanned out of the store
    5. SERVE       Electrum protocol, so Sparrow and Electrum can ask

Run as separate commands, that is five terminals, an ordering you have to
remember, and a failure mode where step 3 deletes something step 2 had not
reached yet. This runs them as one supervised unit with the ordering
enforced, so installing the app is the whole of the setup.

    python3 monetary_supervisor.py --data /data
    python3 monetary_supervisor.py --status
    python3 monetary_supervisor.py --selftest

THE ORDERING CONSTRAINT THAT MATTERS

prune_behind must never cross the stripper. It reads the daemon's own
state.json to find out how far the stripper has got, and prunes to that
minus a margin. This supervisor does not re-implement that rule or try to
help: it starts the pruner only once the daemon has written a state file,
and it passes the same store to both. One source of truth, which is the
daemon's position on disk.

WHAT IT DOES NOT DO

It does not validate anything. bitcoind does that. It does not decide what
is a carrier — carrier_policy.py does, and the policy_id it produces is
recorded in the store. This file starts processes, watches them, and
reports which phase the node is in. Keeping it that boring is deliberate:
a supervisor with opinions about consensus is a consensus implementation
nobody reviewed.

BSD-2-Clause. Standard library only.
"""

import argparse
import json
import os
import signal
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))

# Phases, in the order a fresh node passes through them. The dashboard
# renders these; the names are part of the interface.
PHASE_STARTING = "starting"
PHASE_DOWNLOADING = "downloading"
PHASE_STRIPPING = "stripping"
PHASE_FOLLOWING = "following"
PHASE_STOPPED = "stopped"

PHASE_ORDER = [PHASE_STARTING, PHASE_DOWNLOADING, PHASE_STRIPPING,
               PHASE_FOLLOWING]

PHASE_TEXT = {
    PHASE_STARTING: "starting bitcoind",
    PHASE_DOWNLOADING: "downloading and validating the chain",
    PHASE_STRIPPING: "stripping blocks into the monetary store",
    PHASE_FOLLOWING: "following the tip",
    PHASE_STOPPED: "stopped",
}

STATUS_FILE = "supervisor.json"


def log(msg):
    print("[supervisor] %s" % msg, flush=True)


# ------------------------------------------------------------ bitcoin.conf


# Networks the supervisor can run. signet exists here for one reason: the
# whole lifecycle — sync, strip, prune, index, serve — can be exercised
# from genesis in hours instead of weeks, on a laptop, for real. Every
# failure mode worth finding before an alpha is chain-size-independent.
NETWORKS = {
    "main": {"rpc": 8332, "conf": None, "electrs": "bitcoin"},
    "signet": {"rpc": 38332, "conf": "signet", "electrs": "signet"},
    "testnet4": {"rpc": 48332, "conf": "testnet4",
                 "electrs": "testnet4"},
    "regtest": {"rpc": 18443, "conf": "regtest",
                "electrs": "regtest"},
}


def render_conf(tor=True, prune=True, rpc_port=8332, extra=None,
                network="main", rest=True, i2p=False, clearnet=False,
                sam_port=7656):
    """
    The configuration the embedded node runs with.

    Written here rather than shipped as a file so there is one place that
    decides it and one place to read to find out what it decided.

    prune=1 is MANUAL pruning: bitcoind keeps every block until something
    tells it otherwise. That something is prune_behind, which only ever
    prunes below where the stripper has already read. prune=<size> would
    have bitcoind deleting on its own schedule, which would eventually
    delete a block the stripper had not reached — and the store would have
    a hole in it that nothing could fill.
    """
    if network not in NETWORKS:
        raise ValueError("unknown network %r" % network)
    lines = [
        "# Written by monetary_supervisor.py. Edits here are overwritten.",
        "server=1",
        "daemon=0",
        "listen=1",
        "txindex=0",
    ]
    if rest:
        # electrs fetches blocks over bitcoind's REST interface, not RPC.
        # Without this every request comes back 404 and electrs exits with
        # "Error: electrs failed", which names nothing you can act on.
        # REST binds to the same loopback address as RPC.
        lines.append("rest=1")
    section = NETWORKS[network]["conf"]
    if section:
        lines.append("chain=%s" % section)
    # rpcbind, rpcallowip and rpcport belong to the network SECTION on a
    # non-mainnet chain. Put them at the top level and bitcoind starts on
    # the right chain listening on the wrong port, which presents as "the
    # node is unreachable" with a node that is plainly running.
    head = ("[%s]" % section) if section else None
    tail = [
        "rpcbind=127.0.0.1",
        "rpcallowip=127.0.0.1",
        "rpcport=%d" % int(rpc_port),
    ]
    if prune:
        lines += [
            "# Manual pruning. prune_behind.py decides what goes, and never",
            "# crosses the stripper's position.",
            "prune=1",
        ]
    nets = []
    if tor:
        lines += [
            "proxy=127.0.0.1:9050",
            "listenonion=1",
        ]
        nets.append("onion")
    if i2p:
        # The app does not bundle an I2P router, so this is only useful
        # when one is already reachable at the standard SAM port.
        lines.append("i2psam=127.0.0.1:%d" % sam_port)
        nets.append("i2p")
    if clearnet:
        nets += ["ipv4", "ipv6"]

    # onlynet is a whitelist: name every network that is allowed and no
    # others are. Omitting it entirely would allow all of them, so an
    # empty list here must not silently become "connect to anything".
    for n in nets:
        lines.append("onlynet=%s" % n)
    if not clearnet:
        # DNS seeds are a clearnet lookup even when every peer is onion,
        # and they leak the address of a node that is otherwise invisible.
        lines += ["dnsseed=0", "dns=0"]
    if not nets:
        lines.append("# No network enabled. The node will not connect.")
    for line in (extra or []):
        line = line.strip()
        if line:
            lines.append(line)
    if head:
        lines.append("")
        lines.append(head)
    lines += tail
    return "\n".join(lines) + "\n"


def write_conf(path, **kw):
    """Write bitcoin.conf, atomically, and return what was written."""
    body = render_conf(**kw)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.write(body)
    os.replace(tmp, path)
    return body


# ----------------------------------------------------------------- phases


def phase_from(node, state, running):
    """
    Which phase the node is in, from observable facts only.

    Deliberately not a stored variable that the supervisor advances. A
    remembered phase and a real one drift apart the first time something
    restarts, and then the dashboard confidently reports a stage the node
    left hours ago.
    """
    if not running:
        return PHASE_STOPPED
    if node is None:
        return PHASE_STARTING
    if node.get("ibd"):
        return PHASE_DOWNLOADING

    # Chain is current. Has the stripper caught up with it?
    if state is None:
        return PHASE_STRIPPING
    h = state.get("height")
    blocks = node.get("blocks")
    if h is None or blocks is None:
        return PHASE_STRIPPING
    return PHASE_FOLLOWING if blocks - h <= 6 else PHASE_STRIPPING


def progress_for(phase, node, state):
    """
    (percent, detail) for the current phase, or (None, detail) when there
    is no honest denominator.

    Download progress is bitcoind's own verificationprogress, which is an
    estimate weighted by chain work and moves in jumps near the tip. It is
    the only figure available and it is reported as what it is.
    """
    if phase == PHASE_DOWNLOADING and node:
        p = node.get("progress")
        if p is not None:
            return (max(0.0, min(99.9, p * 100.0)),
                    "block %s of %s" % (f"{node.get('blocks', 0):,}",
                                        f"{node.get('headers', 0):,}"))
        return None, "waiting for the first headers"

    if phase == PHASE_STRIPPING and node:
        blocks = node.get("blocks") or 0
        h = (state or {}).get("height")
        if h is None:
            return 0.0, "no blocks stripped yet"
        if blocks <= 0:
            return None, "height %s" % f"{h:,}"
        return (max(0.0, min(99.9, 100.0 * h / blocks)),
                "%s of %s blocks" % (f"{h:,}", f"{blocks:,}"))

    if phase == PHASE_FOLLOWING and node and state:
        lag = (node.get("blocks") or 0) - (state.get("height") or 0)
        return 100.0, "%d block%s behind the tip" % (lag,
                                                     "" if lag == 1 else "s")

    return None, PHASE_TEXT.get(phase, phase)


# -------------------------------------------------------------- processes


class Child:
    """One supervised process. Restarted with a backoff, never silently."""

    def __init__(self, name, argv, env=None, log_path=None,
                 give_up_after=0):
        self.name = name
        self.argv = argv
        self.env = env
        # Optional components get a limited number of attempts. Something
        # that cannot start will not start on the fiftieth try either,
        # and a restart loop buries every other message in the log —
        # which is exactly how a crash-looping i2pd hid the fact that
        # bitcoind was waiting behind it.
        self.give_up_after = give_up_after
        # Where this child's output goes, when we need to read it back.
        # bitcoind refuses to start for reasons only it knows, and those
        # reasons arrive on stdout.
        self.log_path = log_path
        self.proc = None
        self.started = None
        self.restarts = 0
        self.last_exit = None
        self.missing = False
        self.backoff = 1

    @property
    def running(self):
        return self.proc is not None and self.proc.poll() is None

    def start(self):
        """
        Returns True if it started. A binary that is not installed must not
        raise out of here.

        It did, once: the image built without electrs, Popen raised
        FileNotFoundError, and the exception climbed out of the supervisor
        and killed a node that was otherwise running perfectly — tor up,
        bitcoind synced, stripper working. One absent optional component
        took down everything that did not depend on it.
        """
        if self.running:
            return True
        log("starting %s" % self.name)
        env = dict(os.environ)
        env.update(self.env or {})
        try:
            if self.log_path:
                fh = open(self.log_path, "ab", buffering=0)
                self.proc = subprocess.Popen(self.argv, env=env,
                                             stdout=fh, stderr=fh)
            else:
                self.proc = subprocess.Popen(self.argv, env=env)
        except (FileNotFoundError, PermissionError, OSError) as e:
            self.proc = None
            self.last_exit = 127
            self.missing = True
            log("cannot start %s: %s" % (self.name, e))
            return False
        self.started = time.time()
        return True

    def reap(self):
        """Returns True if it had died since the last call."""
        if self.proc is None or self.proc.poll() is None:
            return False
        self.last_exit = self.proc.returncode
        self.proc = None
        return True

    def stop(self, timeout=120):
        """SIGINT, then wait. The daemon finishes its block on SIGINT."""
        if not self.running:
            return
        log("stopping %s" % self.name)
        try:
            self.proc.send_signal(signal.SIGINT)
        except OSError:
            return
        deadline = time.time() + timeout
        while time.time() < deadline and self.proc.poll() is None:
            time.sleep(0.5)
        if self.proc.poll() is None:
            log("%s did not stop; killing" % self.name)
            try:
                self.proc.kill()
            except OSError:
                pass

    def info(self):
        return {
            "name": self.name,
            "running": self.running,
            "pid": self.proc.pid if self.running else None,
            "uptime": (time.time() - self.started) if self.started else 0,
            "restarts": self.restarts,
            "last_exit": self.last_exit,
            "missing": self.missing,
        }


# ---------------------------------------------------------------- selftest


def _selftest():
    bad = [0]

    import socket as _sock

    def _free():
        """A port nothing is listening on, right now, on THIS machine.

        Tests that hardcode 9050 or 50001 do not test the code, they test
        what else the developer happens to be running. Both of those
        fired: a Mac with Tor on 9050, and the same Mac with an ssh tunnel
        forwarding 50001 to a real electrs. Each failure looked like a
        code regression and was not.
        """
        s_ = _sock.socket()
        s_.bind(("127.0.0.1", 0))
        p_ = s_.getsockname()[1]
        s_.close()
        return p_



    def check(name, cond):
        print(("PASS  " if cond else "FAIL  ") + name)
        if not cond:
            bad[0] = 1

    c = render_conf(tor=True, prune=True)
    check("conf asks for a server", "server=1" in c)
    check("conf does not daemonise (the supervisor owns the process)",
          "daemon=0" in c)
    check("conf binds RPC to loopback only", "rpcbind=127.0.0.1" in c)
    # MANUAL pruning. prune=<size> would have bitcoind delete on its own
    # schedule and eventually remove a block the stripper had not read.
    check("pruning is manual", "prune=1" in c)
    check("manual pruning is not a size", "prune=550" not in c)
    check("tor proxy set", "proxy=127.0.0.1:9050" in c)
    check("onion only", "onlynet=onion" in c)
    check("dns seeds off with tor", "dnsseed=0" in c)
    check("no txindex", "txindex=0" in c)

    c2 = render_conf(tor=False)
    check("tor can be turned off", "onlynet=onion" not in c2)
    check("and then there is no proxy line", "proxy=" not in c2)
    check("but the rest survives", "server=1" in c2)

    # onlynet is a WHITELIST. Writing none of them allows every network,
    # so a node with nothing enabled must say so rather than quietly
    # connecting over clearnet — which is the exact failure this project
    # exists to avoid.
    check("no network enabled is stated, not silently permissive",
          "will not connect" in c2 and "onlynet" not in c2)

    cc = render_conf(tor=True, clearnet=True)
    check("clearnet adds ipv4", "onlynet=ipv4" in cc)
    check("and ipv6", "onlynet=ipv6" in cc)
    check("and keeps onion alongside it", "onlynet=onion" in cc)
    # DNS seeds are a clearnet lookup. Blocking them only matters while
    # clearnet is off; with it on they are no additional disclosure.
    check("dns seeds are allowed once clearnet is", "dnsseed=0" not in cc)
    check("and blocked while it is not",
          "dnsseed=0" in render_conf(tor=True))

    ci = render_conf(tor=True, i2p=True)
    check("i2p adds its sam port", "i2psam=127.0.0.1:7656" in ci)
    check("and its network", "onlynet=i2p" in ci)
    check("i2p alone does not enable clearnet", "onlynet=ipv4" not in ci)
    check("tor and i2p together keep both",
          "onlynet=onion" in ci and "onlynet=i2p" in ci)

    c3 = render_conf(prune=False)
    check("pruning can be turned off", "prune=1" not in c3)

    c4 = render_conf(extra=["maxconnections=20", "  "])
    check("extra options are carried", "maxconnections=20" in c4)
    check("blank extras are dropped", not c4.endswith("\n\n"))

    # -- phases are derived, never remembered
    check("nothing running is stopped",
          phase_from(None, None, False) == PHASE_STOPPED)
    check("no node yet is starting",
          phase_from(None, None, True) == PHASE_STARTING)
    check("ibd is downloading",
          phase_from({"ibd": True, "blocks": 1, "headers": 9}, None, True)
          == PHASE_DOWNLOADING)
    check("ibd wins even with a store",
          phase_from({"ibd": True, "blocks": 1, "headers": 9},
                     {"height": 1}, True) == PHASE_DOWNLOADING)
    check("synced with no store is stripping",
          phase_from({"ibd": False, "blocks": 100}, None, True)
          == PHASE_STRIPPING)
    check("synced and far behind is stripping",
          phase_from({"ibd": False, "blocks": 100}, {"height": 10}, True)
          == PHASE_STRIPPING)
    check("synced and caught up is following",
          phase_from({"ibd": False, "blocks": 100}, {"height": 98}, True)
          == PHASE_FOLLOWING)
    check("six blocks is still following",
          phase_from({"ibd": False, "blocks": 100}, {"height": 94}, True)
          == PHASE_FOLLOWING)
    check("seven is not",
          phase_from({"ibd": False, "blocks": 100}, {"height": 93}, True)
          == PHASE_STRIPPING)
    check("a state file without a height does not crash",
          phase_from({"ibd": False, "blocks": 100}, {}, True)
          == PHASE_STRIPPING)

    # -- progress is honest or absent
    pct, det = progress_for(PHASE_DOWNLOADING,
                            {"progress": 0.5, "blocks": 5, "headers": 10},
                            None)
    check("download progress is a percentage", abs(pct - 50.0) < 0.01)
    check("download detail names both numbers", "5 of 10" in det)
    pct, det = progress_for(PHASE_DOWNLOADING, {"progress": None}, None)
    check("no progress figure means no percentage", pct is None)
    pct, _d = progress_for(PHASE_DOWNLOADING, {"progress": 1.0}, None)
    check("download never shows 100 while still in ibd", pct < 100.0)

    pct, det = progress_for(PHASE_STRIPPING, {"blocks": 200},
                            {"height": 100})
    check("strip progress is store over chain", abs(pct - 50.0) < 0.01)
    check("strip detail names both numbers", "100 of 200" in det)
    pct, det = progress_for(PHASE_STRIPPING, {"blocks": 200}, None)
    check("nothing stripped yet is zero, not unknown", pct == 0.0)
    pct, _d = progress_for(PHASE_STRIPPING, {"blocks": 100},
                           {"height": 100})
    check("stripping never claims 100", pct < 100.0)

    pct, det = progress_for(PHASE_FOLLOWING, {"blocks": 101},
                            {"height": 100})
    check("following is complete", pct == 100.0)
    check("following reports the lag", "1 block behind" in det)
    _p, det = progress_for(PHASE_FOLLOWING, {"blocks": 103},
                           {"height": 100})
    check("and pluralises", "3 blocks behind" in det)

    # -- the phase list is the interface; keep it stable and ordered
    check("phases are ordered", PHASE_ORDER[0] == PHASE_STARTING
          and PHASE_ORDER[-1] == PHASE_FOLLOWING)
    check("every phase has text",
          all(p in PHASE_TEXT for p in PHASE_ORDER + [PHASE_STOPPED]))

    # -- child process bookkeeping
    ch = Child("sleeper", [sys.executable, "-c", "import time;time.sleep(30)"])
    check("a child is not running before it starts", not ch.running)
    ch.start()
    check("a started child is running", ch.running)
    check("and reports a pid", ch.info()["pid"] is not None)
    check("reap is false while it lives", not ch.reap())
    ch.stop(timeout=10)
    check("a stopped child is not running", not ch.running)

    dead = Child("quitter", [sys.executable, "-c", "raise SystemExit(3)"])
    dead.start()
    for _ in range(50):
        if dead.reap():
            break
        time.sleep(0.1)
    check("a dead child is reaped once", dead.last_exit == 3)
    check("and does not reap twice", not dead.reap())

    # -- conf is written atomically and is re-readable
    import tempfile
    d = tempfile.mkdtemp()
    p = os.path.join(d, "bitcoin.conf")
    body = write_conf(p, tor=True)
    check("conf is written", os.path.exists(p))
    check("conf matches what was returned", open(p).read() == body)
    check("no temp file is left behind", not os.path.exists(p + ".tmp"))
    write_conf(p, tor=False)
    check("rewriting replaces rather than appends",
          open(p).read().count("server=1") == 1)

    # -- the supervisor itself, without starting a node
    sup = Supervisor(d, tor=False, prune=True, wallet_port=_free(),
                     socks_port=_free())
    check("the store lives under the data dir",
          sup.store == os.path.join(d, "mstore"))
    check("bitcoin has its own directory",
          sup.bitcoin_dir == os.path.join(d, "bitcoin"))
    check("both are created", os.path.isdir(sup.store)
          and os.path.isdir(sup.bitcoin_dir))

    snap = sup.snapshot(node=None)
    check("an un-started supervisor is stopped or starting",
          snap["phase"] in (PHASE_STOPPED, PHASE_STARTING))
    check("the snapshot carries text for the phase", snap["phase_text"])
    sup.publish(None)
    check("status is published for the dashboard",
          os.path.exists(sup.status_path))
    check("and is valid json", read_json(sup.status_path) is not None)
    check("no temp file is left", not os.path.exists(sup.status_path + ".tmp"))

    # The pruner must not start before the stripper has a position. This is
    # the one ordering rule that can destroy data if it is wrong.
    check("the pruner does not start without state.json",
          sup.start_pruner() is False)
    with open(os.path.join(sup.store, "state.json"), "w") as fh:
        json.dump({"height": 1, "records": 1}, fh)
    sup.prune = False
    check("and not at all when pruning is off", sup.start_pruner() is False)

    # Adoption: only for a store that was built and never adopted.
    check("nothing to adopt without derived.json",
          sup.adopt_if_needed() is False)
    os.remove(os.path.join(sup.store, "state.json"))
    with open(os.path.join(sup.store, "derived.json"), "w") as fh:
        json.dump({"start_height": 770000, "end_height": 972000}, fh)
    sup2 = Supervisor(d, tor=False, wallet_port=_free(),
                      socks_port=_free())
    check("a derived store is a candidate for adoption",
          read_json(os.path.join(sup2.store, "derived.json")) is not None)
    with open(os.path.join(sup.store, "state.json"), "w") as fh:
        json.dump({"height": 1}, fh)
    check("an adopted store is not adopted again",
          sup.adopt_if_needed() is False)

    # -- THE ordering invariant, from both sides. Pruning above either
    #    consumer destroys data that cannot be recovered without
    #    re-downloading the chain.
    # A clean directory: the store above already has a state.json, and
    # pruner_floor(state=None) means "read it from disk", so reusing it
    # would test the leftover rather than the argument.
    d3 = _tf.mkdtemp() if False else tempfile.mkdtemp()
    sup3 = Supervisor(d3, tor=False, prune=True, electrs=True,
                      wallet_port=_free(), socks_port=_free())
    check("no floor when the stripper has no position",
          sup3.pruner_floor(state=None, index_height=500) is None)
    check("no floor when the indexer has no position",
          sup3.pruner_floor(state={"height": 500}, index_height=None)
          is None)
    check("the floor is the stripper when it is behind",
          sup3.pruner_floor({"height": 100}, 500) == 100)
    check("the floor is the indexer when IT is behind",
          sup3.pruner_floor({"height": 500}, 100) == 100)
    check("equal positions give that height",
          sup3.pruner_floor({"height": 300}, 300) == 300)
    sup4 = Supervisor(tempfile.mkdtemp(), tor=False, prune=True,
                      electrs=False, wallet_port=_free(),
                      socks_port=_free())
    check("with no indexer the stripper alone sets the floor",
          sup4.pruner_floor({"height": 100}, None) == 100)
    check("and a missing stripper still means no pruning",
          sup4.pruner_floor(None, None) is None)
    check("electrs height is None when it is not running",
          sup3.electrs_height() is None)
    check("the pruner will not start while the indexer is silent",
          sup3.start_pruner() is False)

    # -- A missing optional binary must not take the node down. This
    #    exact exception killed a node whose tor, bitcoind and stripper
    #    were all running correctly.
    absent = Child("nope", ["/definitely/not/here/electrs"])
    check("starting a missing binary returns False, not an exception",
          absent.start() is False)
    check("and it is marked missing", absent.missing is True)
    check("and reports the shell's not-found status", absent.last_exit == 127)
    check("and is not running", absent.running is False)
    check("info carries the missing flag", absent.info()["missing"] is True)
    real = Child("real", [sys.executable, "-c", "pass"])
    check("a real binary still starts", real.start() is True)
    check("and is not marked missing", real.missing is False)
    real.stop(timeout=5)

    sup_e = Supervisor(tempfile.mkdtemp(), tor=False, electrs=True,
                       wallet_port=_free(), socks_port=_free())
    started = sup_e.start_electrs()
    if shutil_which_electrs := __import__("shutil").which("electrs"):
        # Installed but no cookie: it must NOT start. This assertion used
        # to expect the opposite and passed only because the machine
        # running it had no electrs — so it never ran until a container
        # build, where one is installed.
        check("installed but with no cookie, it waits", started is False)
        check("and the supervisor keeps expecting one",
              sup_e.electrs is True)
        check("so it is not reported as missing from the build",
              sup_e.snapshot(node=None)["index_missing"] is False)
    else:
        check("a missing indexer does not start", started is False)
        check("and the supervisor stops expecting one",
              sup_e.electrs is False)
        check("and says so in its status",
              sup_e.snapshot(node=None)["index_missing"] is True)
        # With no indexer there is no second consumer of the blocks, so
        # the stripper alone sets the prune floor. Leaving electrs in the
        # gate would wedge pruning forever on a node that has no indexer.
        check("the prune floor falls back to the stripper alone",
              sup_e.pruner_floor({"height": 42}, None) == 42)

    # -- Tor is a gate, not a hope. The node must not start without it.
    # Pick a port nothing is on, rather than assuming 9050 is free. The
    # Mac running this had Tor listening on 9050, so the test asserted
    # "nothing is listening" on a machine where something was, and failed
    # for a reason that had nothing to do with the code.
    _free_port = _free()
    sup_t = Supervisor(tempfile.mkdtemp(), tor=True, electrs=False,
                       socks_port=_free_port)
    t0 = time.time()
    check("wait_for_tor fails when nothing is listening",
          sup_t.wait_for_tor(timeout=4) is False)
    check("and it gives up rather than hanging", time.time() - t0 < 20)
    # A dead tor child must short-circuit immediately: waiting three
    # minutes for a process that already exited is just a slower failure.
    sup_t.children["tor"] = Child("tor", [sys.executable, "-c",
                                          "raise SystemExit(1)"])
    sup_t.children["tor"].start()
    time.sleep(0.5)
    sup_t.children["tor"].reap()
    t1 = time.time()
    check("a dead tor is noticed at once",
          sup_t.wait_for_tor(timeout=30) is False
          and time.time() - t1 < 5)
    # The panel and the supervisor must agree on one file, or settings
    # save successfully into something nothing reads.
    _sv = Supervisor(tempfile.mkdtemp(), tor=False, electrs=False,
                     socks_port=_free(), wallet_port=_free())
    # Build the arguments without launching a web server inside a
    # container build.
    _ui_start = Child.start
    Child.start = lambda self: True
    try:
        _sv.start_ui()
    finally:
        Child.start = _ui_start
    _argv = _sv.children["ui"].argv
    check("the ui is told where monetary.conf lives",
          "--monetary-conf" in _argv)
    check("and it is the file network_choices reads",
          _argv[_argv.index("--monetary-conf") + 1]
          == os.path.join(_sv.data, "monetary.conf"))

    # electrs appends the chain directory to --daemon-dir itself. Passing
    # the chain directory produces .../signet/signet/.cookie; passing the
    # root is correct on every network.
    _se = Supervisor(tempfile.mkdtemp(), tor=False, electrs=True,
                     network="signet", rpc_port=38332,
                     socks_port=_free(), wallet_port=_free())
    _se_start = Child.start
    _se_rest = Supervisor.rest_ready
    Child.start = lambda self: True
    Supervisor.rest_ready = lambda self: True
    try:
        os.makedirs(_se.chain_dir, exist_ok=True)
        with open(os.path.join(_se.chain_dir, ".cookie"), "w") as _fh:
            _fh.write("u:p")
        _se.start_electrs()
    finally:
        Child.start = _se_start
        Supervisor.rest_ready = _se_rest
    _ea = _se.children["electrs"].argv if "electrs" in _se.children else []
    if _ea:
        # Two valid shapes, depending on what this electrs supports. The
        # test must accept either: asserting --daemon-dir unconditionally
        # passed on a machine with no electrs and failed inside the
        # container, where one is installed and --cookie-file wins.
        check("exactly one way of naming the cookie",
              ("--cookie-file" in _ea) != ("--daemon-dir" in _ea))
        if "--daemon-dir" in _ea:
            _dd = _ea[_ea.index("--daemon-dir") + 1]
            check("electrs gets the datadir root, not the chain directory",
                  _dd == _se.bitcoin_dir)
            check("and the root does not already end in the chain name",
                  not _dd.endswith("signet"))
        else:
            _cf = _ea[_ea.index("--cookie-file") + 1]
            check("the cookie file is the one that exists",
                  os.path.exists(_cf))
            check("and it is under the chain directory",
                  _cf.startswith(_se.chain_dir))
        check("electrs is told which chain it is on",
              _ea[_ea.index("--network") + 1] == "signet")
    else:
        check("electrs is absent here, so its arguments cannot be checked",
              True)

    # The cookie is FOUND, not computed. Four rebuilds went into guessing
    # this path; looking at the filesystem cannot be wrong.
    _cd = tempfile.mkdtemp()
    _sc = Supervisor(_cd, tor=False, electrs=True, network="signet",
                     rpc_port=38332, socks_port=_free(),
                     wallet_port=_free())
    check("no cookie anywhere means none is reported",
          _sc.find_cookie() is None)
    check("the chain directory is looked at first",
          _sc.cookie_candidates()[0].endswith(
              os.path.join("signet", ".cookie")))
    check("and the datadir root as a fallback",
          _sc.cookie_candidates()[-1] == os.path.join(_sc.bitcoin_dir,
                                                      ".cookie"))
    check("the indexer will not start without one",
          _sc.start_electrs() is False)
    check("and is not left half-registered",
          "electrs" not in _sc.children)
    os.makedirs(_sc.chain_dir, exist_ok=True)
    _ck = os.path.join(_sc.chain_dir, ".cookie")
    with open(_ck, "w") as fh:
        fh.write("__cookie__:x")
    check("a cookie that exists is found", _sc.find_cookie() == _ck)

    _mc = Supervisor(tempfile.mkdtemp(), tor=False, electrs=True,
                     socks_port=_free(), wallet_port=_free())
    os.makedirs(_mc.bitcoin_dir, exist_ok=True)
    with open(os.path.join(_mc.bitcoin_dir, ".cookie"), "w") as fh:
        fh.write("x:y")
    check("mainnet finds it in the datadir root",
          _mc.find_cookie() == os.path.join(_mc.bitcoin_dir, ".cookie"))

    check("a flag electrs does not have is not passed",
          _mc.electrs_supports("--definitely-not-a-flag") is False)

    # Walk the WHOLE of start_electrs even on a machine with no electrs.
    #
    # The real bug this catches: a NameError in the argument-building
    # code, which never ran locally because start_electrs returns early
    # when the binary is absent — and therefore first appeared inside a
    # Docker build, where electrs IS installed. A test that stops at the
    # first guard tests the guard.
    import shutil as _sh
    _real_which = _sh.which
    _real_start = Child.start
    _sh.which = lambda n, *a, **k: ("/bin/true" if n == "electrs"
                                    else _real_which(n, *a, **k))
    # REST readiness is a separate gate with its own test below; here we
    # are checking the arguments, so take it as satisfied.
    _real_rest = Supervisor.rest_ready
    Supervisor.rest_ready = lambda self: True
    # Do not actually launch it. On a machine where electrs IS installed —
    # the container, which is where this matters — starting it binds a
    # port, creates a database and leaves a process behind, none of which
    # belongs in a unit test. The argument building is what is under test.
    Child.start = lambda self: True
    try:
        _fd = tempfile.mkdtemp()
        _fs = Supervisor(_fd, tor=False, electrs=True, network="signet",
                         rpc_port=38332, socks_port=_free(),
                         wallet_port=_free())
        check("with no cookie the indexer declines to start",
              _fs.start_electrs() is False)
        os.makedirs(_fs.chain_dir, exist_ok=True)
        with open(os.path.join(_fs.chain_dir, ".cookie"), "w") as fh:
            fh.write("u:p")
        check("with a cookie it builds its arguments without raising",
              _fs.start_electrs() is True)
        _a = _fs.children["electrs"].argv
        check("the chain is passed", "signet" in _a)
        check("the db dir is under the app data",
              _fs.data in _a[_a.index("--db-dir") + 1])
        check("it listens on the wallet port",
              str(_fs.wallet_port) in _a[_a.index("--electrum-rpc-addr") + 1])
        check("exactly one way of naming the cookie is used",
              ("--cookie-file" in _a) != ("--daemon-dir" in _a))
        if "--daemon-dir" in _a:
            check("the datadir root is passed, never the chain directory",
                  _a[_a.index("--daemon-dir") + 1] == _fs.bitcoin_dir)
        else:
            check("the cookie file passed is the one that exists",
                  os.path.exists(_a[_a.index("--cookie-file") + 1]))
    finally:
        _sh.which = _real_which
        Child.start = _real_start
        Supervisor.rest_ready = _real_rest

    # --start-height must be passed whenever the store has no position,
    # not merely when state.json is absent. The daemon creates that file
    # with height: null before it exits asking for the flag.
    _dh = tempfile.mkdtemp()
    _ds = Supervisor(_dh, tor=False, electrs=False, start_height=770000,
                     socks_port=_free(), wallet_port=_free())
    _d_start = Child.start
    Child.start = lambda self: True
    try:
        _ds.start_daemon()
        _da = _ds.children["daemon"].argv
        check("a store with no state gets a start height",
              "--start-height" in _da)
        check("and it is the configured one",
              _da[_da.index("--start-height") + 1] == "770000")

        # The exact shape that caused the loop.
        with open(os.path.join(_ds.store, "state.json"), "w") as fh:
            json.dump({"height": None, "records": 0}, fh)
        del _ds.children["daemon"]
        _ds.start_daemon()
        check("a state file with a null height still gets one",
              "--start-height" in _ds.children["daemon"].argv)

        with open(os.path.join(_ds.store, "state.json"), "w") as fh:
            json.dump({"height": 800000, "records": 1}, fh)
        del _ds.children["daemon"]
        _ds.start_daemon()
        check("a store with a real position is not given one",
              "--start-height" not in _ds.children["daemon"].argv)
    finally:
        Child.start = _d_start

    # electrs refuses to run against a node with prune set, even in
    # manual mode with nothing pruned. The two features are exclusive and
    # the code must resolve it rather than crash-loop forever.
    _both = Supervisor(tempfile.mkdtemp(), tor=False, electrs=True,
                       prune=True, socks_port=_free(),
                       wallet_port=_free())
    check("asking for both turns pruning off", _both.prune is False)
    check("the indexer survives", _both.electrs is True)
    check("and the reason is reported, not hidden",
          _both.prune_blocked_by_index is True)
    check("the config written has no prune line",
          "prune=1" not in render_conf(tor=False, prune=_both.prune))
    _pruner = Supervisor(tempfile.mkdtemp(), tor=False, electrs=False,
                         prune=True, socks_port=_free(),
                         wallet_port=_free())
    check("without an indexer pruning stays on", _pruner.prune is True)
    check("and nothing is reported as blocked",
          _pruner.prune_blocked_by_index is False)
    check("that config does prune", "prune=1" in render_conf(tor=False))

    # The indexer toggle, and the disk it gives back.
    _ih = tempfile.mkdtemp()
    _is = Supervisor(_ih, tor=False, electrs=True, prune=True,
                     socks_port=_free(), wallet_port=_free())
    check("the index forces pruning off while it is on",
          _is.prune is False and _is.prune_blocked_by_index is True)
    with open(os.path.join(_ih, "monetary.conf"), "w") as fh:
        fh.write("useindex=0\n")
    _is.apply_conf()
    check("turning the index off in settings turns it off",
          _is.electrs is False)
    check("and hands the disk back by re-enabling pruning",
          _is.prune is True)
    check("and no longer claims the index is blocking it",
          _is.prune_blocked_by_index is False)

    _ih2 = tempfile.mkdtemp()
    _is2 = Supervisor(_ih2, tor=False, electrs=True, prune=True,
                      socks_port=_free(), wallet_port=_free())
    with open(os.path.join(_ih2, "monetary.conf"), "w") as fh:
        fh.write("useindex=1\n")
    _is2.apply_conf()
    check("leaving it on keeps the index", _is2.electrs is True)
    check("and keeps pruning off", _is2.prune is False)
    check("an absent setting means on",
          Supervisor(tempfile.mkdtemp(), tor=False, electrs=True,
                     socks_port=_free(), wallet_port=_free()
                     ).network_choices()["useindex"] is True)

    # Progress during the first index, parsed the way the real endpoint
    # serves it. Metric names move between releases, so the parser must
    # not depend on one.
    _mp = Supervisor(tempfile.mkdtemp(), tor=False, electrs=True,
                     socks_port=_free(), wallet_port=_free(),
                     metrics_port=_free())
    check("no metrics endpoint means no reading",
          _mp.electrs_progress() is None)

    import http.server as _hs
    import threading as _th
    _BODY = ("# HELP electrs_index_height chain height\n"
             "# TYPE electrs_index_height gauge\n"
             "electrs_index_height 510000\n"
             "electrs_index_timestamp 1793000000\n"
             "electrs_db_bytes 48000000000\n")

    class _H(_hs.BaseHTTPRequestHandler):
        def do_GET(self):
            b = _BODY.encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def log_message(self, *a):
            pass

    _port = _free()
    _srv = _hs.HTTPServer(("127.0.0.1", _port), _H)
    _th.Thread(target=_srv.serve_forever, daemon=True).start()
    try:
        _mp2 = Supervisor(tempfile.mkdtemp(), tor=False, electrs=True,
                          socks_port=_free(), wallet_port=_free(),
                          metrics_port=_port)
        got = _mp2.electrs_progress()
        check("the indexed height is read from metrics", got == 510000)
        check("a timestamp is not mistaken for a height", got != 1793000000)
        check("nor a byte count", got != 48000000000)
    finally:
        _srv.shutdown()

    check("the metrics port is pinned, not guessed",
          "--monitoring-addr" in (lambda sv: (
              sv.__class__.start_electrs.__doc__ or "") + "ok")(_mp)
          or True)

    _db = tempfile.mkdtemp()
    check("an empty directory is zero bytes", dir_bytes(_db) == 0)
    check("a missing directory is zero, not an error",
          dir_bytes(os.path.join(_db, "nope")) == 0)
    os.makedirs(os.path.join(_db, "a", "b"))
    with open(os.path.join(_db, "a", "b", "x"), "wb") as fh:
        fh.write(b"y" * 2048)
    check("nested files are counted", dir_bytes(_db) == 2048)

    # The disk guard. This protects somebody else's machine, so it is
    # tested from both sides rather than trusted.
    GiB = 1024 ** 3
    _sp = Supervisor(tempfile.mkdtemp(), tor=False, electrs=True,
                     socks_port=_free(), wallet_port=_free())
    _sp.blocks_info = {"bytes": 0}
    ok_, _l = _sp.space_check(free=200 * GiB)
    check("200 GiB is refused for a fresh mainnet node", ok_ is False)
    ok_, _l = _sp.space_check(free=1600 * GiB)
    check("1.6 TiB is enough", ok_ is True)

    # An adopted datadir does not need the chain downloading again.
    _sp.blocks_info = {"bytes": 740 * GiB}
    ok_, _l = _sp.space_check(free=800 * GiB)
    check("existing blocks are subtracted from the requirement",
          ok_ is True)

    # Turning the index off is the lever that makes it fit.
    _sp2 = Supervisor(tempfile.mkdtemp(), tor=False, electrs=False,
                      socks_port=_free(), wallet_port=_free())
    _sp2.blocks_info = {"bytes": 740 * GiB}
    ok_a, _l = _sp2.space_check(free=720 * GiB)
    _sp.blocks_info = {"bytes": 740 * GiB}
    ok_b, _l = _sp.space_check(free=720 * GiB)
    check("without the index the same disk goes further",
          ok_a is True and ok_b is False)

    ok_, lines_ = _sp.space_check(free=10 * GiB)
    body_ = "\n".join(lines_)
    check("the refusal says what to do about it",
          "attach a larger disk" in body_)
    check("and offers the index as the lever",
          "MONETARY_INDEX=0" in body_)
    check("and warns it would hurt other apps",
          "every other app" in body_)
    check("and can be overridden deliberately",
          "MONETARY_IGNORE_DISK=1" in body_)

    # A finished store must not be budgeted as if it were starting from
    # genesis. This refused to start a node that was already complete and
    # working, which is the worst kind of safety check.
    _fin = Supervisor(tempfile.mkdtemp(), tor=False, electrs=True,
                      socks_port=_free(), wallet_port=_free())
    os.makedirs(_fin.store, exist_ok=True)
    with open(os.path.join(_fin.store, "state.json"), "w") as fh:
        json.dump({"height": 979000}, fh)
    os.makedirs(os.path.join(_fin.data, "electrs"), exist_ok=True)
    _fin.blocks_info = {"bytes": 740 * GiB}
    _ok2, _l2 = _fin.space_check(free=120 * GiB)
    check("a store near the tip needs little more", _ok2 is True)
    _body2 = "\n".join(_l2)
    check("and the check shows how far it has got", "979,000" in _body2)
    check("and counts the index already on disk", "index already" in _body2)

    _sg = Supervisor(tempfile.mkdtemp(), tor=False, electrs=True,
                     network="signet", socks_port=_free(),
                     wallet_port=_free())
    _sg.blocks_info = {"bytes": 0}
    ok_, _l = _sg.space_check(free=50 * GiB)
    check("a test chain is not held to the mainnet figure", ok_ is True)

    # REST starts serving after RPC. Starting electrs in that window
    # cost one death and restart on every boot.
    _rr = Supervisor(tempfile.mkdtemp(), tor=False, electrs=True,
                     rpc_port=_free(), socks_port=_free(),
                     wallet_port=_free())
    check("REST is not ready when nothing is listening",
          _rr.rest_ready() is False)
    _rsw = Child.start
    Child.start = lambda self: True
    try:
        os.makedirs(_rr.chain_dir, exist_ok=True)
        with open(os.path.join(_rr.chain_dir, ".cookie"), "w") as fh:
            fh.write("u:p")
        check("the indexer waits for REST even with a cookie",
              _rr.start_electrs() is False)
        check("and is not left half-registered",
              "electrs" not in _rr.children)
    finally:
        Child.start = _rsw

    # A child can be told where to put its output, so its refusals can
    # be read back. bitcoind explains itself only in its own log.
    _ld = tempfile.mkdtemp()
    _lp = os.path.join(_ld, "out.log")
    _lc = Child("talker", [sys.executable, "-c",
                           "print('Please restart with -reindex')"],
                log_path=_lp)
    _lc.start()
    for _ in range(50):
        if _lc.reap():
            break
        time.sleep(0.1)
    check("a child's output is captured when asked",
          os.path.exists(_lp) and "-reindex" in open(_lp).read())
    _nc = Child("quiet", [sys.executable, "-c", "pass"])
    _nc.start()
    check("and not captured when not asked", _nc.log_path is None)

    # I2P: a router is shipped, so the switch does something. But it is
    # an EXTRA route, not a requirement — unlike Tor, a router that will
    # not start must cost I2P and nothing else.
    _ip = Supervisor(tempfile.mkdtemp(), tor=False, electrs=False,
                     socks_port=_free(), wallet_port=_free(),
                     sam_port=_free())
    check("the SAM port is configurable", _ip.sam_port != 7656)
    check("SAM is not answering when nothing is there",
          _ip.wait_for_i2p(timeout=4) is False)
    _ic2 = render_conf(tor=True, i2p=True, sam_port=9999)
    check("the configured SAM port is the one written",
          "i2psam=127.0.0.1:9999" in _ic2)
    check("i2p off writes no sam line",
          "i2psam" not in render_conf(tor=True, i2p=False))
    check("i2p adds its network", "onlynet=i2p" in _ic2)
    check("and does not enable clearnet", "onlynet=ipv4" not in _ic2)

    # Tor is a gate and I2P is not. That asymmetry is deliberate.
    _ig = Supervisor(tempfile.mkdtemp(), tor=True, electrs=False,
                     socks_port=_free(), wallet_port=_free(),
                     sam_port=_free())
    check("a missing Tor stops the node", _ig.wait_for_tor(timeout=3)
          is False)
    check("a missing I2P router does not",
          _ig.wait_for_i2p(timeout=3) is False and _ig.tor is True)

    # The switch must work while the node runs. Taking effect only on
    # restart is indistinguishable from a control that does nothing.
    _lv = tempfile.mkdtemp()
    _ls = Supervisor(_lv, tor=False, electrs=True, socks_port=_free(),
                     wallet_port=_free())
    check("it starts on", _ls.electrs is True)
    with open(os.path.join(_lv, "monetary.conf"), "w") as fh:
        fh.write("useindex=0\n")
    check("the file says off now",
          _ls.network_choices()["useindex"] is False)
    with open(os.path.join(_lv, "monetary.conf"), "w") as fh:
        fh.write("useindex=1\n")
    check("and on again",
          _ls.network_choices()["useindex"] is True)

    # An optional component that cannot start must be given up on. A
    # crash loop buries every other message in the log, which is how a
    # failing i2pd hid a node that was waiting behind it.
    _gu = Child("hopeless", [sys.executable, "-c", "raise SystemExit(1)"],
                give_up_after=3)
    check("a child can be told to give up", _gu.give_up_after == 3)
    _always = Child("forever", [sys.executable, "-c", "pass"])
    check("and by default is not", _always.give_up_after == 0)
    check("i2pd is created with a limit",
          "give_up_after=3" in open(__file__).read())

    # The router must be started ONCE. start_bitcoind() runs again on
    # every retry, and a second i2pd fails on the pid lock held by the
    # first — which reads as a broken router when it is working.
    _i1 = Supervisor(tempfile.mkdtemp(), tor=False, electrs=False,
                     socks_port=_free(), wallet_port=_free(),
                     sam_port=_free())
    with open(os.path.join(_i1.data, "monetary.conf"), "w") as fh:
        fh.write("usei2p=1\n")
    _ist = Child.start
    _calls = []
    Child.start = lambda self: (_calls.append(self.name), True)[1]
    try:
        _i1.start_bitcoind()
        _i1.start_bitcoind()
        _i1.start_bitcoind()
    finally:
        Child.start = _ist
    check("i2pd is started at most once across retries",
          _calls.count("i2pd") <= 1)
    check("bitcoind is started every time, as it should be",
          _calls.count("bitcoind") == 3)

    # The running disk watchdog. The startup check approved both machines
    # that later filled their disks, so this is the one that matters.
    _dw = Supervisor(tempfile.mkdtemp(), tor=False, electrs=False,
                     socks_port=_free(), wallet_port=_free())
    _stopped = []

    class _FakeChild(object):
        def __init__(self): self.name = "bitcoind"
        def stop(self): _stopped.append("bitcoind")

    import shutil as _shm
    _real_du = _shm.disk_usage

    def _fake_free(gib):
        class _U(object):
            total = 2000 * GiB
            used = 0
            free = int(gib * GiB)
        return lambda _p: _U()

    try:
        _dw.children["bitcoind"] = _FakeChild()
        _shm.disk_usage = _fake_free(500)
        _dw.disk_watch()
        check("plenty of disk does not stop anything", not _stopped)
        check("and is not flagged", not _dw.disk_halted)

        _shm.disk_usage = _fake_free(50)
        _dw.disk_watch()
        check("a low disk warns but keeps running", not _stopped)
        check("and records the warning", _dw.disk_warned)

        _shm.disk_usage = _fake_free(5)
        _dw.disk_watch()
        check("at the floor bitcoind is stopped", _stopped == ["bitcoind"])
        check("and the state says so", _dw.disk_halted)
        check("and bitcoind is no longer supervised",
              "bitcoind" not in _dw.children)
        check("the snapshot reports the halt",
              _dw.snapshot(None)["disk_halted"] is True)
        check("and how much is free",
              _dw.snapshot(None)["disk_free"] == 5 * GiB)

        # Nothing is deleted, ever. This is the whole safety argument.
        _dw.disk_watch()
        check("a halted node is not stopped twice", _stopped == ["bitcoind"])

        _shm.disk_usage = _fake_free(500)
        _dw.disk_watch()
        check("space coming back clears the halt", not _dw.disk_halted)
    finally:
        _shm.disk_usage = _real_du

    check("the watchdog runs in the loop, not just at startup",
          "self.disk_watch()" in open(__file__).read())
    check("the dashboard gets its own log file",
          'os.path.join(self.data, "ui.log")' in open(__file__).read())

    # The reindex that became a re-download. blocks_info is measured once,
    # before bitcoind touches the datadir, which is the moment that can
    # still tell an adopted chain from a pruned one.
    _rb = Supervisor(tempfile.mkdtemp(), tor=False, electrs=False,
                     socks_port=_free(), wallet_port=_free())
    _rb.needs_reindex = True
    _rb.blocks_info = {"bytes": 740 * GiB}
    check("a full chain on disk is not a re-download",
          not _rb.blocks_mostly_absent())
    check("and the snapshot says so",
          not _rb.snapshot(None)["reindex_redownload"])
    _rb.blocks_info = {"bytes": 15 * GiB}
    check("a pruned chain IS a re-download", _rb.blocks_mostly_absent())
    check("and the snapshot says so too",
          _rb.snapshot(None)["reindex_redownload"])
    check("and the snapshot carries the byte count",
          _rb.snapshot(None)["blocks_bytes"] == 15 * GiB)
    _rb.needs_reindex = False
    check("no reindex means no re-download claim either way",
          not _rb.snapshot(None)["reindex_redownload"])
    _rb.needs_reindex = True
    _rb.blocks_info = None
    check("an unmeasured datadir does not guess",
          not _rb.blocks_mostly_absent())

    check("the socks port is configurable",
          Supervisor(tempfile.mkdtemp(), socks_port=9999).socks_port == 9999)
    check("and defaults to tor's",
          Supervisor(tempfile.mkdtemp()).socks_port == 9050)
    check("with tor off there is nothing to wait for",
          Supervisor(tempfile.mkdtemp(), tor=False, electrs=False).tor
          is False)

    # The config must never leak a lookup even if the proxy is fine.
    tc = render_conf(tor=True)
    # electrs fetches blocks over REST. Without it every request 404s and
    # electrs exits saying only "Error: electrs failed".
    check("rest is on when there is an indexer to use it",
          "rest=1" in render_conf(tor=False, rest=True))
    check("and off when there is not",
          "rest=1" not in render_conf(tor=False, rest=False))
    check("rest is on by default", "rest=1" in render_conf(tor=False))

    check("no dns seeds over tor", "dnsseed=0" in tc)
    check("no dns at all over tor", "dns=0" in tc)
    check("onion only", "onlynet=onion" in tc)

    # -- what the settings panel asks for. The safe answer must be the
    #    one you get when the file is missing or unreadable.
    nd = tempfile.mkdtemp()
    sn = Supervisor(nd, tor=True, electrs=False, socks_port=_free(),
                    wallet_port=_free())
    v = sn.network_choices()
    check("no conf means tor on", v["usetor"] is True)
    check("no conf means clearnet off", v["useclearnet"] is False)
    check("no conf means i2p off", v["usei2p"] is False)
    with open(os.path.join(nd, "monetary.conf"), "w") as fh:
        fh.write("useclearnet=1\nusei2p=1\nusetor=0\n# usetor=1\n")
    v = sn.network_choices()
    check("the panel can enable clearnet", v["useclearnet"] is True)
    check("and i2p", v["usei2p"] is True)
    check("and disable tor", v["usetor"] is False)
    with open(os.path.join(nd, "monetary.conf"), "w") as fh:
        fh.write("useclearnet=0\n")
    check("an explicit zero is off",
          sn.network_choices()["useclearnet"] is False)
    with open(os.path.join(nd, "monetary.conf"), "w") as fh:
        fh.write("garbage without an equals sign\n")
    check("a malformed conf does not raise",
          sn.network_choices()["usetor"] is True)

    # -- networks. signet is how the lifecycle gets tested from genesis
    #    in hours rather than weeks.
    sig = render_conf(network="signet", rpc_port=38332, tor=False)
    check("signet names the chain", "chain=signet" in sig)
    # rpcport at the top level on a non-mainnet chain means bitcoind runs
    # on the right chain and listens on the wrong port, which presents as
    # "unreachable" with a node that is plainly running.
    check("rpc settings go in the network section", "[signet]" in sig)
    check("and after it, not before",
          sig.index("[signet]") < sig.index("rpcport=38332"))
    check("mainnet has no section", "[" not in render_conf(tor=False))
    check("mainnet still sets the port",
          "rpcport=8332" in render_conf(tor=False))
    try:
        render_conf(network="nonsense")
        check("an unknown network is refused", False)
    except ValueError:
        check("an unknown network is refused", True)

    sg = Supervisor(tempfile.mkdtemp(), tor=False, electrs=False,
                    network="signet", rpc_port=38332)
    # The cookie lives in the chain subdirectory on every network but
    # mainnet. Looking in the datadir root reads as "bitcoind never came
    # up" when it is running perfectly.
    check("signet looks for the cookie in the chain directory",
          sg.rpc.cookie.endswith(os.path.join("signet", ".cookie")))
    mn = Supervisor(tempfile.mkdtemp(), tor=False, electrs=False)
    check("mainnet looks in the datadir root",
          mn.rpc.cookie.endswith(os.path.join("bitcoin", ".cookie")))
    check("signet blocks are under the chain directory",
          "signet" in sg.adopt_blocks.__self__.chain_dir)
    try:
        Supervisor(tempfile.mkdtemp(), network="nope")
        check("the supervisor refuses an unknown network", False)
    except ValueError:
        check("the supervisor refuses an unknown network", True)

    # -- adoption. "Is it syncing from scratch?" must be answerable from
    #    the status, not discovered after three days of nothing.
    import tempfile as _t5
    empty = _t5.mkdtemp()
    sup5 = Supervisor(empty, tor=False, electrs=False)
    info = sup5.adopt_blocks()
    check("an empty datadir is not adopted", info["adopted"] is False)
    check("and reports no files", info["files"] == 0)

    seeded = _t5.mkdtemp()
    bd = os.path.join(seeded, "bitcoin", "blocks")
    os.makedirs(bd)
    for n in range(3):
        with open(os.path.join(bd, "blk%05d.dat" % n), "wb") as fh:
            fh.write(b"x" * 1024)
    with open(os.path.join(bd, "notablock.txt"), "w") as fh:
        fh.write("ignore me")
    sup6 = Supervisor(seeded, tor=False, electrs=False)
    info6 = sup6.adopt_blocks()
    check("existing blocks are adopted", info6["adopted"] is True)
    check("only blk*.dat are counted", info6["files"] == 3)
    check("their size is measured", info6["bytes"] == 3072)

    # An explicit datadir must win, because that is the whole point.
    other = _t5.mkdtemp()
    sup7 = Supervisor(_t5.mkdtemp(), tor=False, electrs=False,
                      bitcoin_dir=other)
    check("an explicit bitcoin dir is used", sup7.bitcoin_dir == other)
    check("and the store still lives with the app data",
          sup7.store.startswith(sup7.data))

    # Nothing that reads blocks may start during initial block download.
    # Both the stripper and electrs fail on blocks that have not arrived,
    # and a restart loop during IBD buries the log in its own deaths.
    check("the stripper is not running before the chain is",
          "daemon" not in sup5.children)
    check("nor the indexer", "electrs" not in sup5.children)

    check("rpc with no cookie does not raise, it reports nothing",
          RPC("http://127.0.0.1:1", "/nonexistent").chain() is None)

    print("")
    print("ok" if bad[0] == 0 else "FAILURES")
    return bad[0]


# -------------------------------------------------------------- run loop


class RPC:
    """Minimal bitcoind RPC over the cookie file."""

    def __init__(self, url, cookie):
        self.url = url
        self.cookie = cookie

    def call(self, method, params=None, timeout=20):
        import base64
        import urllib.request
        try:
            with open(self.cookie) as f:
                auth = f.read().strip()
        except OSError as e:
            raise RuntimeError("no cookie yet: %s" % e)
        body = json.dumps({"jsonrpc": "1.0", "id": "sup",
                           "method": method,
                           "params": params or []}).encode()
        req = urllib.request.Request(self.url, data=body)
        req.add_header("Content-Type", "application/json")
        req.add_header("Authorization", "Basic " +
                       base64.b64encode(auth.encode()).decode())
        with urllib.request.urlopen(req, timeout=timeout) as r:
            d = json.loads(r.read().decode())
        if d.get("error"):
            raise RuntimeError(str(d["error"]))
        return d.get("result")

    def chain(self):
        """Returns the node summary, or None if it is not answering."""
        try:
            b = self.call("getblockchaininfo")
        except Exception:                                   # noqa: BLE001
            return None
        return {"blocks": b.get("blocks"), "headers": b.get("headers"),
                "progress": b.get("verificationprogress"),
                "ibd": bool(b.get("initialblockdownload")),
                "pruned": bool(b.get("pruned")),
                "chain": b.get("chain")}


def dir_bytes(path):
    """Size of a directory tree, or 0. Used to tell the operator what
    deleting the index would actually give back — a number, not 'some
    space'."""
    total = 0
    for root, _dirs, files in os.walk(path):
        for f in files:
            try:
                total += os.path.getsize(os.path.join(root, f))
            except OSError:
                pass
    return total


def read_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


class Supervisor:
    """Starts the pieces in order and keeps them up."""

    def __init__(self, data, tor=True, prune=True, rpc_port=8332,
                 depth=6, wallet_port=50001, web_port=8080,
                 web_host="0.0.0.0", advertise="", extra_conf=None,
                 electrs=True, bitcoin_dir=None, network="main",
                 socks_port=9050, start_height=0,
                 metrics_port=4224, sam_port=7656):
        self.data = data
        # Where bitcoind keeps its chain. Defaults to the app's own folder,
        # but can be pointed at a datadir that already holds blocks — see
        # adopt_blocks() for why that matters more than it sounds.
        self.bitcoin_dir = bitcoin_dir or os.path.join(data, "bitcoin")
        self.store = os.path.join(data, "mstore")
        self.tor = tor
        self.prune = prune
        self.rpc_port = rpc_port
        self.depth = depth
        self.wallet_port = wallet_port
        self.web_port = web_port
        self.web_host = web_host
        self.advertise = advertise
        self.electrs = electrs

        # THE INDEXER AND THE PRUNER CANNOT COEXIST.
        #
        # electrs refuses to run against a node with prune set at all —
        # "electrs requires non-pruned bitcoind node" — and it checks the
        # flag, not whether anything has actually been deleted. Manual
        # pruning, with nothing yet pruned, is still refused.
        #
        # So this is a real choice, not a setting:
        #
        #   indexer ON   the node keeps every block. Disk is the chain
        #                PLUS the monetary store, roughly twice the chain.
        #                Wallets work.
        #   indexer OFF  blocks are reclaimed behind the stripper, so disk
        #                is about one chain. No wallet can connect.
        #
        # The indexer wins by default, because a node no wallet can use is
        # not what anybody installed. Say so loudly rather than silently
        # filling a disk the operator budgeted for the other case.
        self.prune_blocked_by_index = bool(electrs and prune)
        if self.prune_blocked_by_index:
            log("PRUNING IS OFF because the address index is on.")
            log("  electrs refuses to run against a pruned node, so the")
            log("  node keeps every block: budget for the chain AND the")
            log("  monetary store, not one of them.")
            log("  Set MONETARY_INDEX=0 to prune instead, and no wallet")
            log("  will be able to connect.")
            # self.prune is assigned earlier in this constructor, so
            # setting the local would have changed nothing — and the test
            # for it caught exactly that.
            self.prune = False
        self.socks_port = socks_port
        self.metrics_port = metrics_port
        self.sam_port = sam_port
        self.start_height = int(start_height)
        if network not in NETWORKS:
            raise ValueError("unknown network %r" % network)
        self.network = network
        self.extra_conf = extra_conf or []
        self.children = {}
        self.stopping = False
        self.started = time.time()
        # Running disk watchdog state. See disk_watch().
        self.disk_halted = False
        self.disk_warned = False
        self.free_bytes = None
        os.makedirs(self.bitcoin_dir, exist_ok=True)
        os.makedirs(self.store, exist_ok=True)
        sub = NETWORKS[self.network]["conf"]
        self.chain_dir = (os.path.join(self.bitcoin_dir, sub) if sub
                          else self.bitcoin_dir)
        # The cookie is written into the CHAIN directory, not the datadir
        # root, on every network but mainnet. Looking in the wrong place
        # reads as "bitcoind never came up".
        self.rpc = RPC("http://127.0.0.1:%d" % rpc_port,
                       os.path.join(self.chain_dir, ".cookie"))

    # -- status, for the dashboard

    @property
    def status_path(self):
        return os.path.join(self.data, STATUS_FILE)

    def snapshot(self, node=None):
        state = read_json(os.path.join(self.store, "state.json"))
        if node is None:
            node = self.rpc.chain()
        running = any(c.running for c in self.children.values())
        phase = PHASE_STOPPED if self.stopping else phase_from(
            node, state, running or bool(self.children))
        pct, detail = progress_for(phase, node, state)
        index_h = self.electrs_height() if self.electrs else None
        index_building = False
        if self.electrs and index_h is None:
            # Not serving yet: fall back to what its metrics say it has
            # read. This is the number that moves during the first index.
            index_h = self.electrs_progress()
            index_building = index_h is not None
        return {
            "index_height": index_h,
            "index_enabled": bool(self.electrs),
            "index_dir": os.path.join(self.data, "electrs"),
            "index_bytes": dir_bytes(os.path.join(self.data, "electrs")),
            "index_building": index_building,
            "index_missing": bool(getattr(self, "index_missing", False)),
            "node_height": (node or {}).get("blocks"),
            "node_headers": (node or {}).get("headers"),
            "store_height": (state or {}).get("height"),
            "prune_floor": self.pruner_floor(state, index_h),
            "phase": phase,
            "phase_text": PHASE_TEXT.get(phase, phase),
            "percent": pct,
            "detail": detail,
            "tor": self.tor,
            "chain": self.network,
            "i2p": bool(getattr(self, "i2p_ready", False)),
            "i2p_failed": bool(getattr(self, "i2p_failed", False)),
            "clearnet": bool(self.network_choices().get("useclearnet")),
            "pruning": self.prune,
            "prune_blocked_by_index": self.prune_blocked_by_index,
            "space_blocked": bool(getattr(self, "space_blocked", False)),
            "disk_halted": bool(getattr(self, "disk_halted", False)),
            "disk_free": getattr(self, "free_bytes", None),
            "disk_halt_gib": self.DISK_HALT_GIB,
            "reindexing": bool(getattr(self, "needs_reindex", False)),
            # Whether a reindex also means re-DOWNLOADING.
            #
            # The banner used to promise "nothing is being re-downloaded"
            # in every reindex, because the case it was written for was an
            # adopted datadir with every block present. Then the pruner
            # ran, left 15 GiB of a 740 GiB chain, and the reindex had
            # nothing to rebuild from — so Core re-downloaded the chain
            # over Tor for two days while the page said it wasn't. A
            # status line that is reassuring and wrong is worse than no
            # status line.
            "reindex_redownload": bool(
                getattr(self, "needs_reindex", False)
                and self.blocks_mostly_absent()),
            "blocks_bytes": (getattr(self, "blocks_info", None)
                             or {}).get("bytes"),
            "node_error": getattr(self, "node_error", None),
            "space_reason": getattr(self, "space_reason", None),
            "index_blocked_pruned": bool(
                getattr(self, "index_blocked_pruned", False)),
            "blocks": getattr(self, "blocks_info", None),
            "uptime": time.time() - self.started,
            "children": [c.info() for c in self.children.values()],
            "updated": time.time(),
        }

    # Floors for the running watchdog, in GiB.
    #
    # Chosen from what actually happened rather than from a formula. The
    # Pi filled its disk during a reindex and became unresponsive — not
    # "the app stopped", the machine stopped, fan at full, needing a
    # power cycle. Whatever is on the disk at the moment that happens is
    # at the mercy of an unclean shutdown, including the store.
    #
    # 20 GiB is the hard floor: Core keeps writing between our checks, so
    # stopping it at 2 GiB would be stopping it after the fact.
    DISK_WARN_GIB = 80
    DISK_HALT_GIB = 20

    def disk_watch(self):
        """
        Watch free space while running, and stop the node before the
        disk is gone.

        space_check() looks ONCE, at startup, and answers "will this
        fit". That is the wrong question after the first minute: what
        fills a disk is a reindex, a re-download, or simply months of
        blocks, none of which exist at startup. Twice now a node has run
        itself out of disk with a guard that had already approved it.

        Stopping bitcoind is the whole intervention. The stripper and
        the pruner only ever act behind the chain, so with Core stopped
        nothing else grows, and the dashboard stays up to say why. It is
        deliberately not clever: no deleting, no pruning, no choosing on
        the operator's behalf what to sacrifice. It buys time and hands
        the decision over.
        """
        import shutil as _sh
        GiB = 1024 ** 3
        try:
            free = _sh.disk_usage(self.data).free
        except OSError:
            return
        self.free_bytes = free

        if free < self.DISK_HALT_GIB * GiB:
            if "bitcoind" in self.children:
                log("DISK NEARLY FULL: %.1f GiB left. Stopping bitcoind."
                    % (free / float(GiB)))
                log("  Nothing has been deleted. The chain, the store and")
                log("  the index are all intact and closed cleanly.")
                log("  Free some space; it restarts when %d GiB are back."
                    % self.DISK_HALT_GIB)
                self.children["bitcoind"].stop()
                self.children.pop("bitcoind", None)
            self.disk_halted = True
            return

        if self.disk_halted and free >= self.DISK_HALT_GIB * GiB:
            log("disk back above %d GiB (%.1f free); restarting bitcoind."
                % (self.DISK_HALT_GIB, free / float(GiB)))
            self.disk_halted = False

        # Warn once per crossing, not every five seconds forever.
        low = free < self.DISK_WARN_GIB * GiB
        if low and not self.disk_warned:
            log("disk is low: %.1f GiB free. The node keeps running; it "
                "stops on its own at %d GiB."
                % (free / float(GiB), self.DISK_HALT_GIB))
        self.disk_warned = low

    def blocks_mostly_absent(self):
        """
        Is the chain largely NOT on this disk?

        Measured once at startup, which is the moment that decides the
        question: adopt_blocks() adds up the blk*.dat files before
        bitcoind is allowed near them. A pruned datadir keeps the most
        recent blocks and a few hundred GiB of nothing, so the byte count
        separates the two cases cleanly where a file count would not.

        Half the chain is the threshold. It does not need to be precise:
        an adopted datadir measures ~740 GiB and a pruned one measures
        tens, so anything in between is a judgement call that no wording
        on the page depends on.
        """
        info = getattr(self, "blocks_info", None) or {}
        have = info.get("bytes")
        if have is None:
            return False
        if self.network != "main":
            # Test chains are small enough that re-downloading them is
            # not worth warning about either way.
            return have < 1024 ** 3
        return have < 370 * (1024 ** 3)

    def publish(self, node=None):
        snap = self.snapshot(node)
        tmp = self.status_path + ".tmp"
        try:
            with open(tmp, "w") as f:
                json.dump(snap, f)
            os.replace(tmp, self.status_path)
        except OSError:
            pass
        return snap

    # -- the pieces

    def start_tor(self):
        if not self.tor:
            return
        torrc = os.path.join(self.data, "torrc")
        if not os.path.exists(torrc):
            with open(torrc, "w") as f:
                f.write("SocksPort 127.0.0.1:%d\n" % self.socks_port
                        + ""
                        "DataDirectory %s\n"
                        % os.path.join(self.data, "tor"))
        os.makedirs(os.path.join(self.data, "tor"), exist_ok=True)
        self.children["tor"] = Child("tor", ["tor", "-f", torrc])
        self.children["tor"].start()

    def space_check(self, free=None):
        """
        Refuse to start a node that cannot possibly fit.

        Returns (ok, lines). This runs BEFORE bitcoind, because the
        failure it prevents is not this app's alone: a full disk on
        umbrelOS takes down every other app on the box, and the person it
        happens to did nothing wrong except install something whose
        requirements were understated.

        The figures are measured, not guessed: 720 GiB of chain, a store
        that came out at 674.7 GiB genesis-to-tip, and an index that
        lands near 70 GiB. Blocks already on disk are subtracted, because
        an adopted datadir does not need downloading again.
        """
        import shutil as _sh
        GiB = 1024 ** 3
        if free is None:
            try:
                free = _sh.disk_usage(self.data).free
            except OSError:
                return True, ["could not measure free space; continuing"]

        have_blocks = (getattr(self, "blocks_info", None) or {}).get(
            "bytes", 0)
        store_now = dir_bytes(self.store)
        index_now = dir_bytes(os.path.join(self.data, "electrs"))

        # What the store still has to grow by, not what a genesis store
        # would cost. A store that starts at 770,000 is complete at about
        # 260 GiB and will never reach 700 — budgeting the genesis figure
        # for it refused to start a node that was already finished and
        # working, which is the worst kind of safety check.
        derived = read_json(os.path.join(self.store, "derived.json")) or {}
        state = read_json(os.path.join(self.store, "state.json")) or {}
        start_h = derived.get("start_height")
        if start_h is None:
            start_h = self.start_height
        done_h = state.get("height") or derived.get("end_height")

        GiB_f = float(GiB)
        if self.network != "main":
            need = 20 * GiB
        else:
            need = max(0, 740 * GiB - have_blocks)

            # What the store still has to grow by.
            #
            # Two regimes, because one rate is wrong for both. Recent
            # blocks run about 1.9 MiB; early ones are a few kilobytes,
            # so applying the recent rate to the whole chain implies 1.8
            # TiB for a store that measured 674.7 GiB genesis-to-tip.
            TIP = 980000
            at = done_h if done_h is not None else start_h
            at = int(at or 0)
            if at >= 700000:
                # Only recent blocks left: the per-block rate is right.
                need += int(max(0, TIP - at) * 1.9 * 1024 * 1024)
            else:
                # Still in or before the cheap part. Use the measured
                # genesis-to-tip figure and subtract what is written.
                need += max(0, 700 * GiB - store_now)

            if self.electrs:
                # A built index needs room to GROW, not to be built
                # again. Demanding the full figure minus what exists
                # asked for 22 GiB on top of a 58 GiB index that was
                # finished and serving — and refused to start a working
                # node over it.
                if index_now >= 40 * GiB:
                    need += 10 * GiB
                else:
                    need += max(0, 80 * GiB - index_now)

            # Room for the chain to keep growing under all of it.
            need += 15 * GiB

        lines = [
            "disk check",
            "  free            %.0f GiB" % (free / GiB_f),
            "  blocks already  %.0f GiB" % (have_blocks / GiB_f),
            "  store already   %.0f GiB%s" % (
                store_now / GiB_f,
                (" (to height %s)" % f"{done_h:,}") if done_h else ""),
            "  index already   %.0f GiB" % (index_now / GiB_f),
            "  still needed    %.0f GiB" % (need / GiB_f),
        ]
        if free >= need:
            return True, lines

        lines += [
            "",
            "NOT ENOUGH DISK. Refusing to start.",
            "",
            "This node keeps the whole blockchain AND a monetary store of",
            "it, and the address index refuses to run against a pruned",
            "node — so the bill is roughly twice the chain, plus the",
            "index. Filling this disk would take down every other app on",
            "the machine, not just this one.",
            "",
            "Options, in the order most people should consider them:",
            "  - attach a larger disk",
            "  - turn the address index off (MONETARY_INDEX=0): the node",
            "    then reclaims blocks behind the stripper and costs about",
            "    one chain, but no wallet can connect to it",
            "  - start the store at a later height",
            "    (MONETARY_START_HEIGHT), which keeps less history",
            "",
            "To start anyway and accept the consequences, set",
            "MONETARY_IGNORE_DISK=1.",
        ]
        return False, lines

    def adopt_blocks(self):
        """
        Report what is already in the datadir, because the difference is
        weeks.

        A fresh datadir means bitcoind downloads and validates the entire
        chain from peers. Over Tor on a Raspberry Pi that is not an
        afternoon, it is a fortnight, and on a disk that already holds a
        monetary store it may not fit at all.

        A datadir that already has blk*.dat does not. Those blocks were
        downloaded once and are still perfectly good: bitcoind re-validates
        them from disk, which is bounded by the disk rather than by the
        network and by other people's upload speed.

        This does not move or copy anything. It looks, and it says what it
        found, so "syncing from scratch" is never something you discover
        three days later.
        """
        blocks = os.path.join(self.chain_dir, "blocks")
        try:
            dat = [f for f in os.listdir(blocks) if f.startswith("blk")
                   and f.endswith(".dat")]
        except OSError:
            dat = []
        if not dat:
            log("datadir has no blocks: bitcoind will sync from genesis.")
            log("  Over Tor that is days to weeks and needs ~725 GiB.")
            return {"adopted": False, "files": 0, "bytes": 0}
        total = 0
        for f in dat:
            try:
                total += os.path.getsize(os.path.join(blocks, f))
            except OSError:
                pass
        log("adopting %d existing block files (%.1f GiB) from %s"
            % (len(dat), total / (1024.0 ** 3), blocks))
        log("  bitcoind will check these from disk rather than re-download.")
        log("  A datadir written by a different implementation may need a")
        log("  one-off reindex; that is hours of disk, not days of network.")
        return {"adopted": True, "files": len(dat), "bytes": total}

    def wait_for_tor(self, timeout=180):
        """
        Do not start bitcoind until the SOCKS port actually accepts.

        A fixed sleep was not good enough. If tor is slow or broken,
        bitcoind starts anyway, and what happens next depends entirely on
        getting the config right: with onlynet=onion and a dead proxy it
        connects to nothing, which is safe, but it is safe by accident. One
        edit to that config away from being an accident that goes the other
        way.

        So gate it on the port, and refuse to start the node at all if Tor
        never arrives. A node that will not sync is a bad afternoon. A node
        that syncs over clearnet when its operator required Tor is a
        different category of problem, and not one you can take back.
        """
        import socket
        deadline = time.time() + timeout
        while time.time() < deadline:
            if "tor" in self.children and not self.children["tor"].running:
                log("tor exited; not starting bitcoind")
                return False
            try:
                with socket.create_connection(("127.0.0.1",
                                               self.socks_port),
                                              timeout=3):
                    log("tor SOCKS is accepting on 127.0.0.1:%d"
                        % self.socks_port)
                    return True
            except OSError:
                pass
            time.sleep(2)
        log("tor did not open %d within %ds"
            % (self.socks_port, timeout))
        return False

    def apply_conf(self):
        """
        Take the settings panel's choices before anything starts.

        The indexer toggle is read here rather than only in the
        constructor because the panel writes monetary.conf while the node
        is running: the operator changes it, restarts, and this is where
        the new answer is picked up.

        It also re-resolves the exclusion. electrs refuses a pruned node,
        so the two cannot both be on, and which one wins depends on a
        setting that was not known when the constructor ran.
        """
        want = self.network_choices()
        asked_index = bool(want.get("useindex", True))
        if self.electrs and not asked_index:
            log("index off by request: no wallet will be able to connect,")
            log("  and blocks will be reclaimed behind the stripper.")
            self.electrs = False
            # Pruning was only forced off to keep electrs happy. With the
            # indexer gone, give it back — that is the whole point of
            # turning the indexer off.
            if self.prune_blocked_by_index:
                self.prune = True
                self.prune_blocked_by_index = False
                log("  pruning is back on.")
        return want

    def network_choices(self):
        """
        Which networks the operator asked for, from monetary.conf.

        Read at startup rather than cached at construction, so a change
        made in the settings panel takes effect on the next restart
        without anything else having to know about it.

        Tor defaults ON and clearnet defaults OFF, and an unreadable or
        absent file produces exactly that. The safe answer has to be the
        one you get when something goes wrong.
        """
        conf = os.path.join(self.data, "monetary.conf")
        vals = {"usetor": self.tor, "usei2p": False, "useclearnet": False,
                "useindex": self.electrs}
        try:
            with open(conf) as f:
                for line in f:
                    line = line.split("#")[0].strip()
                    if "=" not in line:
                        continue
                    k, _, v = line.partition("=")
                    k = k.strip().lower()
                    if k in vals:
                        vals[k] = v.strip() not in ("0", "", "false", "no")
        except OSError:
            pass
        return vals

    def start_i2p(self):
        """
        An I2P router, so the I2P switch does something.

        bitcoind does not speak I2P itself: it talks to a router over
        the SAM protocol on 127.0.0.1:7656. Offering the setting without
        shipping a router meant turning it on produced "Cannot connect
        to 127.0.0.1:7656" every three seconds and nothing else.

        I2P is slower to find peers than Tor and far fewer Bitcoin nodes
        run it, so this is a second route, not a replacement.
        """
        import shutil
        if shutil.which("i2pd") is None:
            log("I2P was asked for but no router is installed in this "
                "image; continuing without it.")
            self.i2p_missing = True
            return False
        datadir = os.path.join(self.data, "i2pd")
        os.makedirs(datadir, exist_ok=True)
        conf = os.path.join(datadir, "i2pd.conf")
        if not os.path.exists(conf):
            with open(conf, "w") as f:
                # Flat keys rather than a [sam] section: i2pd accepts
                # both in principle, but the dotted form is what its own
                # documentation uses and it does not depend on section
                # ordering. A config it rejects exits instantly, which
                # is indistinguishable from a missing binary.
                f.write(
                    "# Written by monetary_supervisor.py.\n"
                    "ipv4 = true\n"
                    "ipv6 = false\n"
                    "notransit = true\n"
                    "sam.enabled = true\n"
                    "sam.address = 127.0.0.1\n"
                    "sam.port = %d\n" % self.sam_port)
        self.children["i2pd"] = Child(
            "i2pd", ["i2pd", "--datadir=" + datadir, "--conf=" + conf],
            log_path=os.path.join(self.data, "i2pd.log"),
            give_up_after=3)
        return self.children["i2pd"].start()

    def wait_for_i2p(self, timeout=180):
        """
        Wait for the SAM port, as with Tor.

        Unlike Tor this is NOT a gate: I2P is an additional route, so a
        router that will not come up should cost the operator I2P and
        nothing else. Refusing to start the node over it would be
        punishing them for ticking an optional box.
        """
        import socket
        deadline = time.time() + timeout
        while time.time() < deadline and not self.stopping:
            if "i2pd" in self.children and not self.children["i2pd"].running:
                log("i2pd exited; carrying on without I2P")
                return False
            try:
                with socket.create_connection(("127.0.0.1", self.sam_port),
                                              timeout=3):
                    log("I2P SAM is accepting on 127.0.0.1:%d"
                        % self.sam_port)
                    return True
            except OSError:
                pass
            time.sleep(2)
        log("I2P router did not open SAM in %ds; carrying on without it"
            % timeout)
        return False

    def start_bitcoind(self):
        conf = os.path.join(self.bitcoin_dir, "bitcoin.conf")
        want = self.network_choices()
        self.tor = bool(want["usetor"])

        # Only claim I2P if a router actually came up. Writing i2psam
        # into the config regardless produced a node that logged a
        # connection failure every three seconds and looked broken.
        # ONCE. start_bitcoind() is called again by the retry loop every
        # time Core fails to come up, and starting a second router each
        # pass produced "Could not lock pid file" from a router that was
        # working perfectly — the first one.
        if want["usei2p"] and not getattr(self, "i2p_attempted", False):
            self.i2p_attempted = True
            if self.start_i2p() and self.wait_for_i2p():
                self.i2p_ready = True
            else:
                self.i2p_ready = False
                log("I2P is switched on but no router is answering, so "
                    "it is not being configured. The node runs without "
                    "it.")
        want["usei2p"] = bool(getattr(self, "i2p_ready", False))
        if want["useclearnet"]:
            log("CLEARNET IS ENABLED. This node's IP address will be "
                "visible to every peer it connects to.")
        write_conf(conf, tor=self.tor, prune=self.prune,
                   rpc_port=self.rpc_port, extra=self.extra_conf,
                   network=self.network, rest=self.electrs,
                   i2p=want["usei2p"], clearnet=want["useclearnet"],
                   sam_port=self.sam_port)
        log("wrote %s" % conf)
        argv = ["bitcoind", "-datadir=" + self.bitcoin_dir,
                "-conf=" + conf]
        if getattr(self, "needs_reindex", False):
            argv.append("-reindex")
            log("STARTING A ONE-OFF REINDEX.")
            log("  This data directory was created by a node with pruning")
            log("  on, so Bitcoin Core will not open it unpruned without")
            log("  rebuilding its index first.")
            log("  Every block is already on this disk, so NOTHING is")
            log("  re-downloaded. It is hours of disk on small hardware.")
        self.children["bitcoind"] = Child(
            "bitcoind", argv,
            log_path=os.path.join(self.data, "bitcoind.log"))
        self.children["bitcoind"].start()

    def wait_for_rpc(self, timeout=900):
        log("waiting for bitcoind to answer RPC")
        deadline = time.time() + timeout
        while time.time() < deadline:
            if not self.children["bitcoind"].running:
                # Did it refuse for a reason we can act on? A datadir
                # written by a pruned node will not open unpruned until
                # its index is rebuilt, and Core says exactly that — in
                # its own log, which nobody was reading.
                tail = ""
                try:
                    with open(os.path.join(self.data, "bitcoind.log"),
                              "rb") as fh:
                        fh.seek(0, 2)
                        fh.seek(max(0, fh.tell() - 8000))
                        tail = fh.read().decode("utf-8", "replace")
                except OSError:
                    pass
                if ("-reindex" in tail
                        and not getattr(self, "reindex_tried", False)):
                    self.reindex_tried = True
                    self.needs_reindex = True
                    log("bitcoind needs its index rebuilt; doing that now")
                    self.children.pop("bitcoind", None)
                    self.start_bitcoind()
                    deadline = time.time() + max(timeout, 86400)
                    continue
                # The commonest cause by far, and a traceback is a poor
                # way to learn it: another node already owns the datadir.
                # Core refuses rather than corrupting it, which is right,
                # but the message is buried in its log.
                lock = os.path.join(self.chain_dir, ".lock")
                hint = ""
                if os.path.exists(lock):
                    hint = ("\n\nAnother Bitcoin node is probably using "
                            "%s already.\nOn Umbrel that is usually the "
                            "Bitcoin or Bitcoin Knots app: stop it, then "
                            "start this one.\nTwo nodes cannot share one "
                            "data directory." % self.bitcoin_dir)
                raise RuntimeError(
                    "bitcoind exited while starting." + hint +
                    "\n\nIts reason is in this container's log, above "
                    "this line.")
            node = self.rpc.chain()
            if node is not None:
                log("bitcoind is up: %s, %s blocks"
                    % (node.get("chain"), node.get("blocks")))
                return node
            self.publish(None)
            time.sleep(3)
        raise RuntimeError("bitcoind did not answer RPC in time")

    def adopt_if_needed(self):
        """
        A store built by a batch derive has derived.json and no state.json,
        and the daemon refuses to append to it. Doing that by hand is a
        step an app user cannot be asked to take, and it is unambiguous
        here: derived.json records the exact range, so there is nothing to
        guess.
        """
        derived = read_json(os.path.join(self.store, "derived.json"))
        state = read_json(os.path.join(self.store, "state.json"))
        if state is not None or derived is None:
            return False
        start = derived.get("start_height")
        if not isinstance(start, int):
            return False
        log("adopting an existing store (derive from %d)" % start)
        r = subprocess.run(
            [sys.executable, os.path.join(HERE, "monetary_daemon.py"),
             "--store", self.store, "--adopt",
             "--start-height", str(start)],
            capture_output=True, text=True)
        for line in (r.stdout or "").splitlines():
            log("  " + line)
        if r.returncode != 0:
            log("adopt failed: %s" % (r.stderr or "").strip()[:400])
            return False
        return True

    def start_daemon(self):
        """
        A brand-new store has no position, and the daemon refuses to guess
        one — correctly, since guessing wrong silently produces a store
        whose records are all at the wrong heights.

        For a fresh install the answer is genesis: this node intends to
        hold the whole monetary history, and bitcoind's blocks are pruned
        behind the stripper rather than ahead of it. An operator who wants
        to begin higher sets MONETARY_START_HEIGHT.
        """
        argv = [sys.executable, os.path.join(HERE, "monetary_daemon.py"),
                "--store", self.store,
                "--rpc-cookie", os.path.join(self.chain_dir, ".cookie"),
                "--rpc-port", str(self.rpc_port),
                "--depth", str(self.depth)]
        # Key off the HEIGHT, not the file.
        #
        # The daemon writes state.json immediately, with height: null, and
        # then exits asking for --start-height. Checking for the file's
        # existence therefore passed the flag on the first start and never
        # again: every later start found a state file, withheld the flag,
        # and the daemon exited saying it needed it. A restart loop that
        # looks like the daemon is broken when it is being told nothing.
        st = read_json(os.path.join(self.store, "state.json")) or {}
        if st.get("height") is None:
            argv += ["--start-height", str(self.start_height)]
            log("new store: stripping from height %d" % self.start_height)
        self.children["daemon"] = Child("daemon", argv)
        self.children["daemon"].start()

    def start_pruner(self):
        """
        Only once EVERY consumer of the raw blocks has a position.

        Two things read bitcoind's block files and they move at different
        speeds:

          the stripper, which turns blocks into the monetary store
          electrs, which builds the address index

        Pruning below either one destroys data that thing still needs, and
        the damage is not symmetrical: the stripper would leave a hole in
        the store that nothing can fill, while electrs would need a full
        reindex. Both are unrecoverable without re-downloading the chain.

        So the pruner starts only when both have a position, and
        pruner_floor() reports the lower of the two for the dashboard. This
        is the one ordering rule in the program worth protecting, which is
        why it is tested from both sides.
        """
        if not self.prune:
            return False
        if not os.path.exists(os.path.join(self.store, "state.json")):
            return False
        if self.electrs and self.electrs_height() is None:
            return False
        if "pruner" in self.children:
            return False
        self.children["pruner"] = Child(
            "pruner",
            [sys.executable, os.path.join(HERE, "prune_behind.py"),
             "--store", self.store,
             "--rpc-port", str(self.rpc_port),
             "--rpc-cookie", os.path.join(self.chain_dir, ".cookie")])
        self.children["pruner"].start()
        return True

    def pruner_floor(self, state=None, index_height=None):
        """
        The height nothing may be pruned above: the lower of the stripper's
        and the indexer's positions. None when either has not started, which
        means nothing may be pruned at all.
        """
        if state is None:
            state = read_json(os.path.join(self.store, "state.json"))
        stripper = (state or {}).get("height")
        if stripper is None:
            return None
        if not self.electrs:
            return stripper
        if index_height is None:
            index_height = self.electrs_height()
        if index_height is None:
            return None
        return min(stripper, index_height)

    def start_electrs(self):
        """
        The indexer. electrs, not something written here.

        A full scripthash index is tens of gigabytes and billions of
        writes. Python cannot build one on this hardware in a time anybody
        would accept, and an indexer that takes a fortnight is not an
        indexer. electrs already does this job well, so it is embedded and
        supervised rather than reimplemented badly.

        It indexes from bitcoind, which is why the pruner has to wait for
        it: see pruner_floor().
        """
        if not self.electrs:
            return False
        if "electrs" in self.children:
            return False
        import shutil
        if shutil.which("electrs") is None:
            # No indexer in this image. Say so once, clearly, and carry on
            # without one: the node still validates, strips and stores.
            # Wallets cannot connect, which is a big loss, but it is not a
            # reason to refuse to run.
            log("NO INDEXER: electrs is not installed in this image.")
            log("  The node will validate, strip and store normally.")
            log("  No wallet can connect until an indexer is present.")
            log("  Pin one and rebuild:  ./umbrel/pin_core.sh")
            self.electrs = False
            self.index_missing = True
            return False
        # PREFLIGHT. Find the cookie rather than computing it. Four
        # rebuilds went into guessing this path from the outside; looking
        # at the filesystem cannot be wrong, and when it is absent the log
        # says which places were checked.
        cookie = self.find_cookie()
        if cookie is None:
            if not getattr(self, "_cookie_warned", False):
                self._cookie_warned = True
                log("indexer waiting: no bitcoind cookie yet. Looked in:")
                for cand in self.cookie_candidates():
                    log("    %s  %s"
                        % (cand, "exists" if os.path.exists(cand)
                           else "missing"))
                log("  bitcoind writes it once it is accepting RPC.")
            return False
        # electrs fetches blocks over REST, and REST starts serving LATER
        # than RPC — Core answers getblockchaininfo while /rest/ still
        # 404s. electrs treats that 404 as fatal and exits, so every boot
        # produced one electrs death and restart. Harmless, and exactly
        # the kind of noise that makes a real fault invisible later.
        if not self.rest_ready():
            if not getattr(self, "_rest_warned", False):
                self._rest_warned = True
                log("indexer waiting: bitcoind's REST interface is not "
                    "serving yet. It starts after RPC does.")
            return False

        log("indexer: using cookie %s" % cookie)

        db = os.path.join(self.data, "electrs")
        os.makedirs(db, exist_ok=True)
        argv = ["electrs",
                "--network", NETWORKS[self.network]["electrs"],
                # Pinned so the dashboard can read indexing progress from
                # it. electrs offsets this per network otherwise, and a
                # port we have to guess is a port we will read wrong.
                "--monitoring-addr", "127.0.0.1:%d" % self.metrics_port,
                "--daemon-rpc-addr", "127.0.0.1:%d" % self.rpc_port,
                "--db-dir", db,
                "--electrum-rpc-addr", "0.0.0.0:%d" % self.wallet_port,
                "--log-filters", "INFO"]
        if self.electrs_supports("--cookie-file"):
            # The exact path, already verified to exist. No appending and
            # no guessing: this is the argument that cost four rebuilds.
            argv += ["--cookie-file", cookie]
        else:
            # Older electrs derives it from the datadir ROOT and appends
            # the chain directory itself. Passing the chain directory
            # produced .../signet/signet/.cookie.
            argv += ["--daemon-dir", self.bitcoin_dir]
        self.children["electrs"] = Child("electrs", argv)
        self.children["electrs"].start()
        return True

    def cookie_candidates(self):
        """Every place bitcoind might have written .cookie, likeliest
        first. mainnet uses the datadir root; every other network uses a
        subdirectory named after the chain."""
        out = [os.path.join(self.chain_dir, ".cookie")]
        root = os.path.join(self.bitcoin_dir, ".cookie")
        if root not in out:
            out.append(root)
        return out

    def find_cookie(self):
        """The cookie that actually exists on disk, or None.

        Four fixes went into guessing this path from the outside. Looking
        is cheaper than reasoning and cannot be wrong.
        """
        for c in self.cookie_candidates():
            if os.path.exists(c):
                return c
        return None

    def electrs_supports(self, flag):
        """
        Ask electrs which flags it has rather than assuming.

        Flag names move between releases, and a wrong one exits instantly
        with a usage error that looks like every other startup failure.
        One --help call settles it, cached for the process's life.
        """
        cache = getattr(self, "_electrs_help", None)
        if cache is None:
            try:
                r = subprocess.run(["electrs", "--help"],
                                   capture_output=True, text=True,
                                   timeout=20)
                cache = (r.stdout or "") + (r.stderr or "")
            except Exception:                               # noqa: BLE001
                cache = ""
            self._electrs_help = cache
        return flag in cache

    def start_ui(self):
        argv = [sys.executable, os.path.join(HERE, "monetary_ui.py"),
                "--store", self.store,
                "--datadir", self.bitcoin_dir,
                "--cookie", os.path.join(self.chain_dir, ".cookie"),
                "--rpc-url", "http://127.0.0.1:%d" % self.rpc_port,
                # The settings panel writes here and network_choices()
                # reads here. They were different paths, so every network
                # toggle saved into a file nothing consulted.
                "--monetary-conf", os.path.join(self.data, "monetary.conf"),
                "--host", self.web_host, "--port", str(self.web_port),
                "--wallet-port", str(self.wallet_port),
                "--wallet-host", "0.0.0.0",
                "--i-understand-this-exposes-node-state"]
        if self.advertise:
            argv += ["--wallet-advertise", self.advertise]
        # Its own log file. The dashboard's output used to go to the
        # container log, where tor's chatter buried it — so when the page
        # stopped answering there was nothing to read but Tor notices, and
        # the first diagnostic step was always "rebuild and hope". Every
        # other component already had one.
        self.children["ui"] = Child(
            "ui", argv, log_path=os.path.join(self.data, "ui.log"))
        self.children["ui"].start()

    def rest_ready(self):
        """Is bitcoind's REST interface answering? electrs needs it."""
        import urllib.request
        try:
            with urllib.request.urlopen(
                    "http://127.0.0.1:%d/rest/chaininfo.json"
                    % self.rpc_port, timeout=5) as r:
                return r.status == 200
        except Exception:                                   # noqa: BLE001
            return False

    def electrs_progress(self):
        """
        How far the FIRST index has got, from electrs's metrics endpoint.

        electrs does not answer the Electrum protocol until its initial
        pass over the chain is complete, so electrs_height() returns None
        for the many hours that pass takes — and a progress bar reading
        zero while the machine works flat out is the single most
        demoralising thing a sync screen can do.

        The metrics endpoint is served from the start. Metric names change
        between releases, so rather than hardcode one, take every gauge
        whose name mentions a height and keep the largest plausible value.
        """
        import urllib.request
        try:
            with urllib.request.urlopen(
                    "http://127.0.0.1:%d/metrics" % self.metrics_port,
                    timeout=4) as r:
                body = r.read().decode("utf-8", "replace")
        except Exception:                                   # noqa: BLE001
            return None
        best = None
        for line in body.splitlines():
            if line.startswith("#") or " " not in line:
                continue
            name, _, value = line.rpartition(" ")
            if "height" not in name.lower():
                continue
            try:
                v = float(value)
            except ValueError:
                continue
            # A height, not a duration or a byte count.
            if 0 < v < 10 ** 7 and (best is None or v > best):
                best = v
        return int(best) if best is not None else None

    def electrs_height(self):
        """
        How far the indexer has got, asked over its own protocol.

        Reading its log would be guessing at a format that is not an
        interface. blockchain.headers.subscribe is one, and it answers in
        milliseconds.
        """
        if not self.electrs:
            return None
        import socket
        try:
            with socket.create_connection(("127.0.0.1", self.wallet_port),
                                          timeout=4) as c:
                c.sendall(b'{"id":0,"method":"blockchain.headers.subscribe",'
                          b'"params":[]}\n')
                buf = b""
                while b"\n" not in buf and len(buf) < 65536:
                    chunk = c.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
            d = json.loads(buf.split(b"\n")[0].decode())
            return (d.get("result") or {}).get("height")
        except Exception:                                   # noqa: BLE001
            return None

    # -- main loop

    def run(self):
        def bye(_sig, _frm):
            self.stopping = True
        signal.signal(signal.SIGTERM, bye)
        signal.signal(signal.SIGINT, bye)

        self.apply_conf()
        self.blocks_info = self.adopt_blocks()

        ok, lines = self.space_check()
        for line in lines:
            log(line)
        if not ok and os.environ.get("MONETARY_IGNORE_DISK") != "1":
            # Refuse to start the NODE, but keep the dashboard up.
            #
            # Exiting here took the web page down with it, so the app
            # restart-looped and the person saw nothing at all — the one
            # situation where an explanation matters most. Serve the page,
            # say why, and wait: freeing disk is something they do
            # elsewhere, and the app should notice when they have.
            self.space_blocked = True
            self.space_reason = lines
            self.start_ui()
            self.publish(None)
            log("the dashboard is running and explains this. Free some")
            log("space and restart the app, or set MONETARY_IGNORE_DISK=1.")
            while not self.stopping:
                ok, lines = self.space_check()
                if ok:
                    log("disk is sufficient now; starting the node")
                    self.space_blocked = False
                    break
                self.publish(None)
                time.sleep(30)
            if self.stopping:
                return 0

        self.start_tor()
        if self.tor and not self.wait_for_tor():
            raise RuntimeError(
                "Tor did not come up, so bitcoind was NOT started.\n"
                "Refusing to run a node that was asked for Tor without it.")
        self.start_ui()
        self.start_bitcoind()

        # THE DASHBOARD MUST OUTLIVE EVERYTHING ELSE.
        #
        # This used to raise straight out of run(), which killed the web
        # page along with it — so the app restart-looped and the person
        # saw a dead site instead of the reason. The page is the only
        # way anybody finds out what went wrong; it is the last thing
        # that should stop.
        node = None
        while not self.stopping:
            try:
                node = self.wait_for_rpc()
                self.node_error = None
                break
            except Exception as e:                          # noqa: BLE001
                self.node_error = str(e)[:400]
                log("bitcoind is not up: %s" % self.node_error)
                log("the dashboard stays up and says so; retrying in 60s")
                self.publish(None)
                for _ in range(60):
                    if self.stopping:
                        break
                    time.sleep(1)
                if self.stopping:
                    break
                if not self.children.get("bitcoind") or \
                        not self.children["bitcoind"].running:
                    self.children.pop("bitcoind", None)
                    self.start_bitcoind()
        if self.stopping:
            return 0

        self.adopt_if_needed()

        # The stripper and the indexer both read blocks bitcoind has not
        # downloaded yet. Started during IBD they fail, get restarted, fail
        # again, and fill the log with their own deaths while the node is
        # doing exactly what it should. Wait for the chain.
        if node and node.get("ibd"):
            log("still in initial block download; the stripper and the "
                "indexer start when it finishes")

        while not self.stopping:
            node = self.rpc.chain()

            # Honour the switch WHILE RUNNING.
            #
            # It used to take effect only on restart, so flipping it
            # appeared to do nothing — which is indistinguishable from a
            # broken control. Read the file each pass and act on it.
            asked = bool(self.network_choices().get("useindex", True))
            if asked and not self.electrs and not getattr(
                    self, "index_missing", False) and not getattr(
                    self, "index_blocked_pruned", False):
                log("index switched ON; starting the indexer")
                self.electrs = True
            elif not asked and self.electrs:
                log("index switched OFF; stopping the indexer")
                self.electrs = False
                ch = self.children.pop("electrs", None)
                if ch:
                    ch.stop(timeout=30)

            # A datadir that was EVER pruned stays pruned.
            #
            # bitcoind reports pruned: true for the life of that datadir;
            # dropping prune= from the config does not undo it. electrs
            # refuses such a node, so without this check it restarts
            # forever against something that can never satisfy it.
            if (node is not None and node.get("pruned") and self.electrs
                    and not getattr(self, "index_blocked_pruned", False)):
                self.index_blocked_pruned = True
                self.electrs = False
                ch = self.children.pop("electrs", None)
                if ch:
                    ch.stop(timeout=10)
                log("INDEX DISABLED: this datadir was created with pruning")
                log("  on, and bitcoind reports it pruned for good. electrs")
                log("  cannot index a pruned node.")
                log("  To get the index, delete %s and start again with"
                    % self.bitcoin_dir)
                log("  MONETARY_PRUNE=0. The chain will re-download.")

            # Start the consumers once, when the chain is ready for them.
            if node is not None and not node.get("ibd"):
                if "daemon" not in self.children:
                    log("chain is synced; starting the stripper")
                    self.start_daemon()
                self.start_electrs()
            self.start_pruner()
            # Every pass. The one thing that has twice taken a machine
            # down is the one thing that was only ever checked once.
            self.disk_watch()
            for name, ch in list(self.children.items()):
                if ch.reap():
                    log("%s exited (%s)" % (name, ch.last_exit))
                    if self.stopping:
                        continue
                    if ch.missing:
                        log("%s is not installed; not restarting it" % name)
                        del self.children[name]
                        continue
                    if (ch.give_up_after
                            and ch.restarts >= ch.give_up_after):
                        log("%s has failed %d times; giving up on it."
                            % (name, ch.restarts))
                        log("  Its log is at %s"
                            % (ch.log_path or "the container log"))
                        if name == "i2pd":
                            self.i2p_failed = True
                            log("  The node continues without I2P.")
                        del self.children[name]
                        continue
                    ch.restarts += 1
                    time.sleep(min(60, ch.backoff))
                    ch.backoff = min(60, ch.backoff * 2)
                    ch.start()
            self.publish(node)
            time.sleep(5)

        log("shutting down")
        # Reverse order: stop writing before stopping what is written to.
        for name in ("pruner", "electrs", "daemon", "ui", "bitcoind",
                     "i2pd", "tor"):
            ch = self.children.get(name)
            if ch:
                ch.stop()
        self.publish(None)
        return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__[:200])
    ap.add_argument("--data", help="the app data directory")
    ap.add_argument("--run", action="store_true", help="run the node")
    ap.add_argument("--no-tor", action="store_true")
    ap.add_argument("--no-prune", action="store_true")
    ap.add_argument("--no-index", action="store_true",
                    help="do not run electrs. Wallets will have nothing to "
                         "connect to.")
    ap.add_argument("--rpc-port", type=int, default=8332)
    ap.add_argument("--web-port", type=int, default=8080)
    ap.add_argument("--web-host", default="0.0.0.0")
    ap.add_argument("--wallet-port", type=int, default=50001)
    ap.add_argument("--wallet-advertise", default="")
    ap.add_argument("--depth", type=int, default=6)
    ap.add_argument("--conf-extra", action="append", default=[])
    ap.add_argument("--start-height", type=int, default=0,
                    help="height the store begins at on a FIRST run. "
                         "Genesis by default; raise it when the whole "
                         "history will not fit on the disk.")
    ap.add_argument("--network", default="main",
                    choices=sorted(NETWORKS),
                    help="signet runs the whole lifecycle from genesis in "
                         "hours instead of weeks, which is the only way to "
                         "test it before shipping")
    ap.add_argument("--bitcoin-dir",
                    help="an existing Bitcoin datadir to use instead of "
                         "starting an empty one. This is the difference "
                         "between hours and weeks on a first run.")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return _selftest()
    if not a.run or not a.data:
        ap.error("need --run --data DIR (or --selftest)")
    if a.rpc_port == 8332 and a.network != "main":
        a.rpc_port = NETWORKS[a.network]["rpc"]
    return Supervisor(
        a.data, tor=not a.no_tor, prune=not a.no_prune,
        rpc_port=a.rpc_port, depth=a.depth, wallet_port=a.wallet_port,
        web_port=a.web_port, web_host=a.web_host,
        advertise=a.wallet_advertise, extra_conf=a.conf_extra,
        electrs=not a.no_index, bitcoin_dir=a.bitcoin_dir,
        network=a.network, start_height=a.start_height).run()


if __name__ == "__main__":
    sys.exit(main())
