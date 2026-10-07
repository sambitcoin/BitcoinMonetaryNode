#!/usr/bin/env python3
"""
node_settings.py — the Knots-style advanced settings panel, as data.

One catalogue of every setting the UI offers: its group, type, default, units
and the plain-English explanation of what it costs you. monetary_ui.py renders
this; node_config.sh could read it; nothing has to be kept in sync by hand.

    python3 node_settings.py --conf ~/.bitcoin/bitcoin.conf --show
    python3 node_settings.py --conf ~/.bitcoin/bitcoin.conf --set dbcache=2048
    python3 node_settings.py --conf ~/.bitcoin/bitcoin.conf --defaults
    python3 node_settings.py --selftest

THREE RULES THIS MODULE ENFORCES, BECAUSE THE UI CANNOT BE TRUSTED TO.

1. A key is written only if `bitcoind -help` lists it. Bitcoin Knots has about
   twenty policy knobs Core does not, and this project's own patched build
   adds more. Which of those exist depends on the binary in front of you, not
   on what a settings page thinks. Unsupported keys are shown, greyed, and
   never written.

2. Every value is validated against its declared type and range before it
   goes anywhere near the file. A web form is an untrusted input even when it
   is bound to loopback, and a malformed bitcoin.conf is discovered at the
   next restart — which on a headless box is the worst possible time.

3. The file is backed up before every write, and the write is atomic. Keys
   this catalogue does not know about are preserved untouched: the operator's
   own lines are theirs, not ours to tidy.

WHAT THIS MODULE DELIBERATELY WILL NOT DO. It does not restart the node.
Bitcoin Core reads its configuration once at startup, so nothing here takes
effect until a restart, and that restart is a decision with consequences —
mempool loss, a slow reindex if something is wrong, and on this project's
node, a Tor lockdown to re-verify afterwards. The UI says "restart required"
and stops there. Pulling the node out from under itself from a web form is
not a feature.

BSD-2-Clause.
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

# group | key | type | default | unit | label | help | scope | re
#
# type: bool, int, str
# re:   which shape a str setting accepts. Every string setting names one.
#
# EVERY SETTING HERE WORKS ON STOCK BITCOIN CORE. Options that exist only in
# Knots, or only in this project's patched build, are deliberately absent
# rather than shown greyed out: a row you cannot touch reads as a broken
# panel, not as a missing feature in Core. Settings that only affect a node
# building block templates are absent too — this node is for people
# verifying their own payments and perhaps running Lightning, and a knob with
# no effect on that is an invitation to misunderstand what the node does.

BOOL, INT, STR = "bool", "int", "str"

# Scope decides which file a setting lands in and whether bitcoind has to
# admit it exists.
#
#   bitcoind — a bitcoin.conf key. Written only if `bitcoind -help` lists it.
#   monetary — a monetary-node option, written to ~/.monetary/monetary.conf.
#              bitcoind has never heard of these and never will, so the
#              support check is skipped. They must NEVER be written into
#              bitcoin.conf: Core warns on unknown keys and the operator ends
#              up chasing a warning about a setting Core was never meant to
#              see.
SCOPE_BITCOIND, SCOPE_MONETARY = "bitcoind", "monetary"

SETTINGS = [
    # ---------------------------------------------------------------- access
    dict(group="Access", key="rest", type=BOOL, default=0,
         label="Public REST API",
         help="Lets certain wallets and apps talk to your node over HTTP. "
              "Access is unauthenticated, so it can mean unauthorised use, "
              "privacy loss and denial of service. electrs 0.12 needs it and "
              "fails with a bare 404 without it. Binds to the RPC address, "
              "so on this node that is loopback only."),
    dict(group="Access", key="rpcworkqueue", type=INT, default=128,
         unit="requests", min=8, max=8192,
         label="RPC Work Queue Size",
         help="How many RPC requests can queue up before your node starts "
              "refusing them. Higher values absorb bursts from connected "
              "wallets and apps at the cost of memory."),
    dict(group="Access", key="rpcthreads", type=INT, default=4,
         unit="threads", min=1, max=64,
         label="RPC Threads",
         help="How many requests your node answers at once. The queue above "
              "is how many wait; this is how many are served. Raise both "
              "together if a wallet and an indexer are competing."),

    # Deliberately absent: rpcbind and rpcallowip. They are what you would
    # reach for to let a Lightning node on another machine connect, and they
    # are also the single commonest way a node ends up with its RPC port open
    # to the internet. Offering them in a web form with no authentication is
    # not a trade worth making. Use an SSH tunnel:
    #
    #   ssh -N -L 8332:127.0.0.1:8332 you@thisnode
    #
    # Also absent: proxy, onlynet, listenonion and bind. tor_setup.sh owns
    # those, tor_lockdown.sh verifies them, and the Tor guarantee is the one
    # thing on this node that must not be editable from a browser.

    # ----------------------------------------------------------- performance
    dict(group="Performance", key="dbcache", type=INT, default=450,
         unit="MiB", min=4, max=65536,
         label="Cache Size",
         help="How much of the UTXO set to hold in RAM. A large cache speeds "
              "up initial sync considerably. Once synced it makes very little "
              "difference and simply holds memory you could use elsewhere."),
    dict(group="Performance", key="par", type=INT, default=0,
         unit="threads", min=-16, max=16,
         label="Script Verification Threads",
         help="How many cores to use checking signatures. 0 means use them "
              "all, which is right while syncing and antisocial afterwards "
              "on a laptop you also use. A negative number leaves that many "
              "cores free: -2 keeps the machine usable during a reindex."),
    dict(group="Performance", key="txindex", type=BOOL, default=1,
         label="Enable Transaction Indexing",
         help="Indexes every transaction so lookups by txid are instant. Many "
              "connected apps need it. Incompatible with pruning — Core "
              "disables it automatically if you prune."),
    dict(group="Performance", key="coinstatsindex", type=BOOL, default=0,
         label="Coin Stats Index",
         help="Makes gettxoutsetinfo fast instead of glacial, at the cost of "
              "extra disk. Worth it if you audit the UTXO set; pointless "
              "otherwise."),
    dict(group="Performance", key="blockreconstructionextratxn", type=INT,
         default=32768, unit="txs", min=0, max=1000000,
         label="Transactions kept for reconstruction",
         help="Extra transactions held in memory to rebuild compact blocks "
              "without asking a peer for the missing pieces."),
    dict(group="Performance", key="blockreconstructionextratxnsize", type=INT,
         default=10, unit="MB", min=0, max=4096,
         label="Max memory for reconstruction",
         help="Ceiling on the memory used for those extra transactions."),

    # --------------------------------------------------------------- mempool
    dict(group="Mempool", key="maxmempool", type=INT, default=300,
         unit="MB", min=5, max=32768,
         label="Maximum Mempool Size",
         help="RAM set aside for unconfirmed transactions. Larger means more "
              "accurate fee estimates and better data for explorer apps; it "
              "also means holding more of other people's traffic in memory."),
    dict(group="Mempool", key="mempoolexpiry", type=INT, default=336,
         unit="hours", min=1, max=8760,
         label="Memory Expiration",
         help="How long an unconfirmed transaction may sit in your mempool "
              "before being dropped. Shorter keeps memory tidy; longer keeps "
              "transactions alive through congestion."),
    dict(group="Mempool", key="persistmempool", type=BOOL, default=1,
         label="Persist Mempool",
         help="Save the mempool on shutdown and reload it on start. Off means "
              "a faster start and a mempool rebuilt from scratch."),
    dict(group="Mempool", key="maxorphantx", type=INT, default=100,
         unit="txs", min=0, max=100000,
         label="Max Orphan Transactions",
         help="Transactions whose inputs you have not seen yet, held in case "
              "the parent shows up. More costs memory; fewer means evicting "
              "some that would have resolved."),

    # ---------------------------------------------------------------- policy
    dict(group="Spam policy", key="datacarrier", type=BOOL, default=1,
         label="Relay Transactions Containing Arbitrary Data",
         help="Relay transactions with OP_RETURN outputs at all. The size "
              "limit below is what actually does the work."),
    dict(group="Spam policy", key="datacarriersize", type=INT, default=83,
         unit="bytes", min=0, max=100000,
         label="Max Allowed Size of Arbitrary Data",
         help="The pre-v30 limit. Core v30 raised its default to 100000, "
              "which is effectively uncapped. 83 restores the old bound and "
              "matches the rule the published commitment C was computed "
              "under. Needs datacarrier enabled to have any effect."),
    dict(group="Spam policy", key="permitbaremultisig", type=BOOL, default=0,
         label="Relay Bare Multisig Transactions",
         help="Bare multisig is where off-curve keys get stuffed. Core relays "
              "it by default; Knots does not. 102.2 MB of what this node "
              "strips arrived this way."),
    # The seven Knots-only policy knobs that used to sit here are gone.
    # Stock Core has no -rejectparasites, -rejecttokens, -permitbarepubkey,
    # -permitbaredatacarrier, -datacarriercost, -acceptnonstddatacarrier or
    # -maxscriptsize, and a row you cannot touch is worse than no row: it
    # suggests the panel is broken rather than that Core is missing a feature.
    # What this node does instead is strip those carriers at the storage
    # layer, which is the project.
    #
    # The block-construction group is gone for a different reason: this node
    # is for people verifying their own payments and perhaps running
    # Lightning. blockmaxweight and blockmintxfee only shape templates a
    # miner would build, and -datum exists for DATUM mining. None of them
    # does anything on a node that does not mine, so offering them would be
    # inviting someone to tune a setting with no effect.

    # ------------------------------------------------------------------ fees
    dict(group="Fees", key="minrelaytxfee", type=STR, default="0.00001",
         unit="BTC/kvB",
         label="Minimum Fee to Relay Transactions",
         warn="Change incrementalrelayfee to match, or replacement behaviour "
              "becomes inconsistent with relay.",
         help="Lowest fee rate this node will relay, mine, or admit to its "
              "mempool. 0.00001 BTC/kvB is 1 sat/vB."),
    dict(group="Fees", key="incrementalrelayfee", type=STR, default="0.00001",
         unit="BTC/kvB",
         warn="Change minrelaytxfee to match.",
         label="Additional Fee for Replacing Transactions",
         help="How much more a replacement must pay to evict the transaction "
              "already in the mempool."),

    # --------------------------------------------------------------- network
    dict(group="Network", key="maxconnections", type=INT, default=125,
         unit="peers", min=4, max=1000,
         label="Maximum Connections",
         help="Tor connections are slower and costlier than clearnet ones. "
              "125 slots over Tor on a laptop buys congestion, not "
              "resilience."),
    dict(group="Network", key="maxuploadtarget", type=INT, default=0,
         unit="MB/24h", min=0, max=1000000,
         label="Upload Limit",
         help="Caps what this node serves per day. 0 is unlimited. A full "
              "chain is roughly 720 GB, so a 5000 MB cap means you cannot "
              "become anyone's sync source even if they try."),
    dict(group="Network", key="peerblockfilters", type=BOOL, default=0,
         label="Serve Compact Block Filters",
         help="Serve BIP157 filters to light clients. This is how a wallet "
              "finds its own history without an address indexer, and without "
              "telling anyone which addresses it cares about."),
    dict(group="Network", key="blockfilterindex", type=BOOL, default=0,
         label="Build Block Filter Index",
         warn="Must be built before pruning. Prune first and the node will "
              "not start with this enabled.",
         help="The index that makes the setting above possible. Roughly "
              "4-5 GB, and it survives pruning once built."),
    dict(group="Network", key="peerbloomfilters", type=BOOL, default=0,
         label="Serve Bloom Filters",
         help="BIP37. Carries privacy and denial-of-service problems and is "
              "superseded by compact filters. Leave it off."),
    dict(group="Network", key="uacomment", type=STR, default="",
         label="User Agent Comment",
         help="Appended to the version string every peer sees, so other "
              "operators can tell what they have connected to. Broadcast to "
              "everyone: over Tor it is not tied to an IP, but it does "
              "announce that this node runs unreviewed alpha software."),

    # ------------------------------------------------------------- lightning
    #
    # LND and Core Lightning do not poll; they subscribe. Without these a
    # Lightning node either refuses to start or silently fails to notice
    # channel closes, which is the failure that costs money. This is the most
    # important group on the page for anyone who said "and maybe Lightning".
    #
    # Every address is restricted to loopback by the validator. ZMQ has no
    # authentication of any kind: a publisher bound to 0.0.0.0 hands your
    # whole transaction stream to the network, and on this node that would
    # also defeat the Tor lockdown. If your Lightning node is on another
    # machine, reach it over an SSH tunnel, not by binding wider.
    dict(group="Lightning", key="zmqpubrawblock", type=STR, default="",
         re="zmq", label="Publish Raw Blocks (ZMQ)",
         help="LND requires this. It is how a Lightning node hears about a "
              "new block the instant you do, instead of polling and being "
              "late. Usual value: tcp://127.0.0.1:28332"),
    dict(group="Lightning", key="zmqpubrawtx", type=STR, default="",
         re="zmq", label="Publish Raw Transactions (ZMQ)",
         help="LND requires this too. It is how your node learns that a "
              "channel counterparty has broadcast a commitment transaction, "
              "in time to respond. Usual value: tcp://127.0.0.1:28333"),
    dict(group="Lightning", key="zmqpubhashblock", type=STR, default="",
         re="zmq", label="Publish Block Hashes (ZMQ)",
         help="Hashes rather than whole blocks. Core Lightning and some "
              "other software prefer this. Usual value: "
              "tcp://127.0.0.1:28334"),
    dict(group="Lightning", key="zmqpubhashtx", type=STR, default="",
         re="zmq", label="Publish Transaction Hashes (ZMQ)",
         help="The transaction equivalent. Usual value: "
              "tcp://127.0.0.1:28335"),
    dict(group="Lightning", key="disablewallet", type=BOOL, default=0,
         label="Disable Core's Own Wallet",
         warn="If you hold coins in Bitcoin Core's wallet, turning this on "
              "makes them invisible to this node until you turn it back off. "
              "The coins are not gone, but do not do this without knowing "
              "where your keys are.",
         help="Lightning keeps its own wallet, so Core's is dead weight "
              "alongside it — and a wallet you do not use is a wallet you do "
              "not have to back up. Leave it on if you use Core's wallet to "
              "receive payments."),
    dict(group="Lightning", key="blocksonly", type=BOOL, default=0,
         label="Blocks Only",
         warn="Turn this ON and Lightning breaks: no mempool means no "
              "unconfirmed transactions, so your node cannot see a "
              "counterparty's commitment broadcast, and fee estimation stops "
              "working. Do not combine it with the Lightning settings above.",
         help="Stop relaying unconfirmed transactions, which cuts bandwidth "
              "sharply. Reasonable for a node that only verifies its own "
              "confirmed history; wrong for anything else."),

    # --------------------------------------------------------------- router
    #
    # Here so they can be seen to be off. Both ask your router to open a port
    # from the internet to this machine, which is the opposite of what a
    # Tor-only node wants, and the kind of thing that gets switched on once
    # and forgotten for a year.
    dict(group="Router", key="upnp", type=BOOL, default=0,
         label="UPnP Port Mapping",
         warn="Leave this off. It asks your router to forward a port from the "
              "public internet to this machine, which pairs your home IP "
              "with this node for anyone scanning — exactly what running "
              "over Tor is meant to prevent.",
         help="Automatic port forwarding via UPnP. Off by default in Core, "
              "and it should stay off here."),
    dict(group="Router", key="natpmp", type=BOOL, default=0,
         label="NAT-PMP Port Mapping",
         warn="Same as above, different protocol. Leave it off.",
         help="Automatic port forwarding via NAT-PMP."),

    # ------------------------------------------------------ monetary node
    #
    # Not bitcoin.conf keys. These configure this project's own tools, and
    # they are in the same panel because an operator does not care which
    # process reads a setting, only what it does.
    dict(group="Monetary node", key="raceobserve", type=BOOL, default=1,
         scope=SCOPE_MONETARY,
         label="Watch for competing blocks",
         help="Notice when two blocks arrive at the same height, measure how "
              "much data each one carries, and record which one the network "
              "went on to keep. Observation only — it reads the chain and "
              "writes a log. Nothing about this node's chain selection "
              "changes, and nothing about it can."),
    dict(group="Monetary node", key="racewindow", type=INT, default=30,
         unit="seconds", min=5, max=600, scope=SCOPE_MONETARY,
         label="Competing block observation window",
         warn="This is a stopwatch, not a tiebreak. Bitcoin picks the tip by "
              "most work, with first-seen breaking ties, and this node obeys "
              "that without exception. A node that preferred a cleaner block "
              "of equal work would be choosing a different chain from the "
              "network and would fork off the moment its choice lost.",
         help="How long to keep watching a race before writing down the "
              "result. Most are settled in seconds; 30 is long enough to see "
              "which side the network took."),
    dict(group="Monetary node", key="racedepth", type=INT, default=10,
         unit="blocks", min=1, max=100, scope=SCOPE_MONETARY,
         label="Keep watching forks this deep",
         help="How far back to keep examining stale tips reported by "
              "getchaintips. Deeper costs a little more RPC per poll and "
              "finds races this node was slow to hear about."),
]

for _s in SETTINGS:
    _s.setdefault("scope", SCOPE_BITCOIND)

BY_KEY = {s["key"]: s for s in SETTINGS}
GROUPS = []
for _s in SETTINGS:
    if _s["group"] not in GROUPS:
        GROUPS.append(_s["group"])

# Keys this module manages. Anything else in the file is the operator's and is
# copied through untouched.
MANAGED = set(BY_KEY)

KEY_RE = re.compile(r"^[a-z][a-z0-9]*$")
# Core takes fee rates as decimal BTC. Anything else is a typo we can catch
# before the node refuses to start over it.
DECIMAL_RE = re.compile(r"^\d+(\.\d{1,8})?$")
# uacomment lands in a version string peers parse. Parentheses and slashes
# would break the BIP14 structure, so they are not allowed through.
COMMENT_RE = re.compile(r"^[A-Za-z0-9 ._:-]{0,32}$")
# ZMQ publishers have no authentication whatsoever. Anything that can reach
# the socket gets your full block and transaction stream, so the address is
# constrained to loopback here rather than warned about. A Lightning node on
# another machine should come over an SSH tunnel.
ZMQ_RE = re.compile(r"^tcp://(127\.0\.0\.1|\[::1\]):([1-9][0-9]{2,4})$")


# ------------------------------------------------------------------ support


def help_text(bitcoind="bitcoind", timeout=30):
    """`bitcoind -help` output, or "" if it cannot be run.

    The timeout is a parameter because a web request waiting on this is a very
    different budget from a command line invocation: the dashboard passes
    something short, since a slow answer there costs a held request thread."""
    try:
        out = subprocess.run([bitcoind, "-help"], capture_output=True,
                             text=True, timeout=timeout)
        return (out.stdout or "") + (out.stderr or "")
    except Exception:
        return ""


def supported(key, help_blob):
    """Is this option in this build?

    Core lists value options as "-key=<n>" but booleans as a plain "-key", so
    matching on "-key=" silently misses every flag. The trailing group also
    stops -datacarrier matching -datacarriersize."""
    if not help_blob:
        return None                       # unknown, not unsupported
    return bool(re.search(r"^[ \t]*-%s(=|[ \t]|$)" % re.escape(key),
                          help_blob, re.M))


# -------------------------------------------------------------------- read


def read_conf(path):
    """-> (values, raw_lines). Last occurrence of a key wins, as Core does."""
    values, lines = {}, []
    if not os.path.exists(path):
        return values, lines
    with open(path, "r", errors="replace") as f:
        for line in f:
            lines.append(line.rstrip("\n"))
            s = line.strip()
            if not s or s.startswith("#") or s.startswith("["):
                continue
            if "=" not in s:
                continue
            k, v = s.split("=", 1)
            values[k.strip()] = v.strip()
    return values, lines


def is_supported(s, help_blob):
    """Can this setting be written? Monetary-scope options always can."""
    if s.get("scope", SCOPE_BITCOIND) == SCOPE_MONETARY:
        return True
    return supported(s["key"], help_blob) if help_blob else None


def effective(path, help_blob=None, mpath=None):
    """Every managed setting with its current value, default and support.

    `path` is bitcoin.conf; `mpath` is monetary.conf. mpath may be omitted,
    in which case monetary-scope settings report their defaults."""
    values, _ = read_conf(path)
    mvalues, _ = read_conf(mpath) if mpath else ({}, [])
    out = []
    for s in SETTINGS:
        scope = s.get("scope", SCOPE_BITCOIND)
        src = mvalues if scope == SCOPE_MONETARY else values
        raw = src.get(s["key"])
        out.append({
            "key": s["key"], "group": s["group"], "label": s["label"],
            "type": s["type"], "default": s["default"], "scope": scope,
            "unit": s.get("unit", ""), "help": s["help"],
            "warn": s.get("warn", ""),
            "value": raw if raw is not None else s["default"],
            "set": raw is not None,
            "supported": is_supported(s, help_blob),
            "at_default": (raw is None
                           or str(raw) == str(s["default"])),
        })
    return out


# ---------------------------------------------------------------- validate


def validate(key, value):
    """-> (normalised_string, None) or (None, reason).

    Runs before anything touches the file. A web form is untrusted input even
    on loopback, and a bad bitcoin.conf surfaces at the next restart."""
    if key not in BY_KEY:
        return None, "unknown setting"
    s = BY_KEY[key]
    v = str(value).strip()

    if s["type"] == BOOL:
        if v in ("1", "true", "True", "on", "yes"):
            return "1", None
        if v in ("0", "false", "False", "off", "no", ""):
            return "0", None
        return None, "must be on or off"

    if s["type"] == INT:
        if not re.fullmatch(r"-?\d{1,12}", v):
            return None, "must be a whole number"
        n = int(v)
        lo, hi = s.get("min"), s.get("max")
        if lo is not None and n < lo:
            return None, f"must be at least {lo:,}"
        if hi is not None and n > hi:
            return None, f"must be at most {hi:,}"
        return str(n), None

    # STR. Every string setting names which shape it accepts; none falls
    # through to "anything goes", because bitcoin.conf is newline-separated
    # key=value and an unconstrained string is a config injection.
    shape = s.get("re")
    if shape == "zmq":
        if v == "":
            return "", None                 # empty means "do not publish"
        if not ZMQ_RE.fullmatch(v):
            return None, ("must be tcp://127.0.0.1:PORT — ZMQ has no "
                          "authentication, so only loopback is accepted. For "
                          "a Lightning node elsewhere, use an SSH tunnel.")
        return v, None
    if s["key"] == "uacomment":
        if not COMMENT_RE.fullmatch(v):
            return None, ("letters, digits, spaces and . _ : - only, "
                          "32 characters max")
        return v, None
    if not DECIMAL_RE.fullmatch(v):
        return None, "must be a decimal amount in BTC, such as 0.00001"
    return v, None


def validate_all(pairs, help_blob=None):
    """-> (clean_dict, errors_dict). Never partially applies."""
    clean, errors = {}, {}
    for k, v in pairs.items():
        if k not in BY_KEY:
            errors[k] = "unknown setting"
            continue
        if is_supported(BY_KEY[k], help_blob) is False:
            errors[k] = "not available in this build"
            continue
        norm, why = validate(k, v)
        if why:
            errors[k] = why
        else:
            clean[k] = norm
    return clean, errors


# ------------------------------------------------------------------- write


def write_conf(path, changes, help_blob=None, backup=True):
    """Apply changes to bitcoin.conf. -> (written_dict, backup_path).

    Rewrites managed keys in place, appends ones that are absent, and copies
    every unmanaged line through untouched. Atomic: the replacement is built
    beside the file and renamed over it, so an interrupted write cannot leave
    a half-written config that stops the node booting."""
    clean, errors = validate_all(changes, help_blob)
    if errors:
        raise ValueError("; ".join(f"{k}: {v}" for k, v in errors.items()))
    if not clean:
        return {}, None

    _, lines = read_conf(path)
    seen = set()
    out = []
    for line in lines:
        s = line.strip()
        if s and not s.startswith("#") and not s.startswith("[") and "=" in s:
            k = s.split("=", 1)[0].strip()
            if k in clean:
                if k in seen:
                    continue              # drop duplicate earlier definitions
                out.append(f"{k}={clean[k]}")
                seen.add(k)
                continue
        out.append(line)

    missing = [k for k in clean if k not in seen]
    if missing:
        if out and out[-1].strip():
            out.append("")
        out.append("# written by node_settings.py %s"
                   % time.strftime("%Y-%m-%d %H:%M:%S"))
        for k in missing:
            out.append(f"{k}={clean[k]}")

    bak = None
    if backup and os.path.exists(path):
        # Second granularity alone silently overwrites the previous backup
        # when two saves land in the same second — which a settings page makes
        # easy. The whole point of the backup is the state before THIS write.
        stamp = time.strftime("%Y%m%d%H%M%S")
        bak = "%s.bak.%s" % (path, stamp)
        n = 1
        while os.path.exists(bak):
            bak = "%s.bak.%s-%d" % (path, stamp, n)
            n += 1
        shutil.copy2(path, bak)

    # ~/.monetary/ may not exist yet, and an atomic replace needs the temp
    # file in the same directory as the target.
    d = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d,
                               prefix="." + os.path.basename(path) + ".")
    try:
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(out).rstrip("\n") + "\n")
            f.flush()
            os.fsync(f.fileno())
        if os.path.exists(path):
            shutil.copymode(path, tmp)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return clean, bak


def write_settings(paths, changes, help_blob=None):
    """Apply changes across both config files. -> (written, {scope: backup}).

    Routes each key to the file its scope names, then uses write_conf — the
    tested single-file primitive — for each. Validation happens first, across
    everything, so a bad value in one file cannot leave the other half
    applied.

    `paths` is {"bitcoind": path, "monetary": path}. A scope with no path is
    an error rather than a silent skip: quietly dropping a setting the
    operator just saved is worse than refusing."""
    clean, errors = validate_all(changes, help_blob)
    if errors:
        raise ValueError("; ".join(f"{k}: {v}" for k, v in errors.items()))

    by_scope = {}
    for k, v in clean.items():
        by_scope.setdefault(BY_KEY[k].get("scope", SCOPE_BITCOIND), {})[k] = v

    for scope in by_scope:
        if not paths.get(scope):
            raise ValueError("no %s config path configured" % scope)

    written, backups = {}, {}
    for scope, subset in by_scope.items():
        w, bak = write_conf(paths[scope], subset, help_blob)
        written.update(w)
        if bak:
            backups[scope] = bak
    return written, backups


def restore_defaults(path, help_blob=None, keys=None):
    """Put every managed setting back to its catalogue default.

    Unmanaged lines survive. This is a reset of the panel, not of the file —
    an operator's own additions are not ours to delete."""
    want = keys if keys is not None else list(BY_KEY)
    changes = {}
    for k in want:
        if k not in BY_KEY:
            continue
        if BY_KEY[k].get("scope", SCOPE_BITCOIND) != SCOPE_BITCOIND:
            continue
        if is_supported(BY_KEY[k], help_blob) is False:
            continue
        changes[k] = BY_KEY[k]["default"]
    # An empty uacomment is not a value Core accepts; absence is the default.
    changes = {k: v for k, v in changes.items() if not (v == "" )}
    return write_conf(path, changes, help_blob)


def restore_all_defaults(paths, help_blob=None):
    """Restore defaults in every scope. -> (written, {scope: backup})."""
    changes = {}
    for k, s in BY_KEY.items():
        if is_supported(s, help_blob) is False:
            continue
        if s["default"] == "":
            continue        # absence IS the default for these
        changes[k] = s["default"]
    return write_settings(paths, changes, help_blob)


# ----------------------------------------------------------------- selftest


def selftest():
    checks, passed = [], 0

    def ck(name, ok, extra=""):
        nonlocal passed
        checks.append(name)
        passed += bool(ok)
        print("  [%s] %s%s" % ("ok  " if ok else "FAIL", name,
                               "" if ok else "  <- " + str(extra)))

    print("catalogue")
    ck("every key is a plausible bitcoind option",
       all(KEY_RE.fullmatch(s["key"]) for s in SETTINGS))
    ck("no duplicate keys", len(BY_KEY) == len(SETTINGS))
    ck("every setting has a group, label and help",
       all(s.get("group") and s.get("label") and s.get("help")
           for s in SETTINGS))
    ck("every default validates against its own rules",
       all(validate(s["key"], s["default"])[1] is None
           for s in SETTINGS if s["default"] != ""),
       [s["key"] for s in SETTINGS
        if s["default"] != "" and validate(s["key"], s["default"])[1]])
    ck("every int setting declares a range",
       all("min" in s and "max" in s for s in SETTINGS if s["type"] == INT))
    ck("the spam knobs stock Core does have are offered",
       {"datacarrier", "datacarriersize", "permitbaremultisig"} <= MANAGED)

    # The catalogue's promise is that nothing in it is dead on arrival. These
    # keep it honest: an option Core lacks, a mining-only option, or pruning
    # creeping back in all fail here with the reason attached.
    knots_only = {"rejectparasites", "rejecttokens", "permitbarepubkey",
                  "permitbaredatacarrier", "datacarriercost",
                  "acceptnonstddatacarrier", "maxscriptsize", "blockmaxsize"}
    ck("no Knots-only option is offered", not (knots_only & MANAGED),
       sorted(knots_only & MANAGED))
    miner_only = {"blockmaxweight", "blockmintxfee", "datum", "blockmaxsize"}
    ck("no mining-template option is offered", not (miner_only & MANAGED),
       sorted(miner_only & MANAGED))
    ck("pruning is not offered at all", "prune" not in MANAGED)
    ck("no group is named for block construction",
       not any("block construction" in g.lower() for g in GROUPS))

    # rpcbind/rpcallowip are the commonest way a node's RPC ends up facing
    # the internet, and proxy/onlynet are the Tor guarantee. Neither belongs
    # behind an unauthenticated form.
    for dangerous in ("rpcbind", "rpcallowip", "proxy", "onlynet",
                      "listenonion", "bind"):
        ck("does not offer %s" % dangerous, dangerous not in MANAGED)

    ck("blockfilterindex warns about ordering",
       "prun" in BY_KEY["blockfilterindex"]["warn"].lower())

    print("\nlightning")
    ck("LND's two required publishers are offered",
       {"zmqpubrawblock", "zmqpubrawtx"} <= MANAGED)
    ck("the raw block publisher says LND requires it",
       "LND requires" in BY_KEY["zmqpubrawblock"]["help"])
    ck("blocksonly warns that it breaks Lightning",
       "Lightning breaks" in BY_KEY["blocksonly"]["warn"])
    ck("disablewallet warns about existing coins",
       "keys are" in BY_KEY["disablewallet"]["warn"])

    # ZMQ has no authentication. A publisher on 0.0.0.0 hands the whole
    # transaction stream to the network and defeats the Tor lockdown, so the
    # validator refuses it rather than warning about it.
    ck("a loopback zmq address is accepted",
       validate("zmqpubrawblock", "tcp://127.0.0.1:28332")[0]
       == "tcp://127.0.0.1:28332")
    ck("an IPv6 loopback address is accepted",
       validate("zmqpubrawtx", "tcp://[::1]:28333")[1] is None)
    ck("empty means do not publish",
       validate("zmqpubrawblock", "")[0] == "")
    for bad in ("tcp://0.0.0.0:28332", "tcp://192.168.86.34:28332",
                "tcp://example.com:28332", "tcp://127.0.0.1:28332\nprune=1",
                "ipc:///tmp/x", "28332", "tcp://127.0.0.1",
                "http://127.0.0.1:28332"):
        ck("refuses zmq address %r" % bad[:30],
           validate("zmqpubrawblock", bad)[1] is not None)
    ck("the refusal explains the loopback rule",
       "loopback" in validate("zmqpubrawblock", "tcp://0.0.0.0:28332")[1])
    ck("every string setting constrains its shape",
       all(s.get("re") or s["key"] in ("uacomment",)
           or DECIMAL_RE.fullmatch(str(s["default"]))
           for s in SETTINGS if s["type"] == STR))

    print("\nrouter")
    ck("port-mapping options default to off",
       BY_KEY["upnp"]["default"] == 0 and BY_KEY["natpmp"]["default"] == 0)
    ck("upnp explains that it pairs your IP with this node",
       "home IP" in BY_KEY["upnp"]["warn"])

    print("\nvalidation")
    ck("a boolean accepts on and off",
       validate("txindex", "on") == ("1", None)
       and validate("txindex", "off") == ("0", None))
    ck("a boolean rejects a number", validate("txindex", "7")[1])
    ck("an int below range is refused", validate("dbcache", "1")[1])
    ck("an int above range is refused", validate("dbcache", "999999")[1])
    ck("an int accepts a sane value", validate("dbcache", "2048")[0] == "2048")
    ck("a fee rate accepts decimal BTC",
       validate("minrelaytxfee", "0.00001")[0] == "0.00001")
    ck("a fee rate rejects sat/vB style input",
       validate("minrelaytxfee", "1 sat/vB")[1])
    ck("an unknown key is refused", validate("rm", "-rf")[1] == "unknown setting")

    # The injection cases. bitcoin.conf is newline-separated key=value, so a
    # newline in a value is a config injection, not a typo.
    for hostile in ("1\nrpcallowip=0.0.0.0/0", "1\n\nproxy=evil.onion:9050",
                    "1; rm -rf /", "$(whoami)", "`id`", "1\r\nprune=1"):
        ck("refuses injected value %r" % hostile[:24],
           validate("txindex", hostile)[1] is not None)
    for hostile in ("a\nb", "x(y)", "a/b", "/" * 40):
        ck("uacomment refuses %r" % hostile[:20],
           validate("uacomment", hostile)[1] is not None)
    ck("uacomment accepts a plain name",
       validate("uacomment", "monetarynode")[0] == "monetarynode")

    print("\nsupport detection")
    # Stands in for `bitcoind -help` on a stock build: the value options carry
    # "=<n>", the booleans do not, and none of the patched-only policy knobs
    # are present.
    help_core = ("  -datacarrier\n  -datacarriersize=<n>\n  -dbcache=<n>\n"
                 "  -txindex\n  -maxconnections=<n>\n  -maxmempool=<n>\n"
                 "  -onlynet=<net>\n  -proxy=<ip:port>\n  -uacomment=<cmt>\n"
                 "  -prune=<n>\n  -blockfilterindex\n  -peerblockfilters\n")
    ck("a boolean listed without = is detected",
       supported("datacarrier", help_core) is True)
    ck("a value option is detected",
       supported("datacarriersize", help_core) is True)
    ck("a prefix does not match a longer option",
       supported("datacarriercost", help_core) is False)
    ck("an absent option is absent",
       supported("rejectparasites", help_core) is False)
    ck("no help text means unknown, not unsupported",
       supported("rejectparasites", "") is None)

    print("\nreading and writing")
    d = tempfile.mkdtemp(prefix="nset")
    conf = os.path.join(d, "bitcoin.conf")
    with open(conf, "w") as f:
        f.write("# my node\n"
                "dbcache=900\n"
                "onlynet=onion\n"
                "proxy=127.0.0.1:9050\n"
                "[main]\n"
                "txindex=1\n")

    vals, _ = read_conf(conf)
    ck("reads existing values", vals.get("dbcache") == "900")
    ck("skips comments and sections", "[main]" not in vals)

    eff = {e["key"]: e for e in effective(conf, help_core)}
    ck("reports a set value as set", eff["dbcache"]["value"] == "900"
       and eff["dbcache"]["set"])
    ck("reports an unset value as its default",
       eff["maxmempool"]["value"] == 300 and not eff["maxmempool"]["set"])
    ck("flags a value that differs from default",
       not eff["dbcache"]["at_default"])
    # coinstatsindex is in the catalogue but absent from the fake help blob,
    # standing in for a Core older than this panel expects.
    ck("marks unsupported options", eff["coinstatsindex"]["supported"] is False)

    written, bak = write_conf(conf, {"dbcache": "2048", "maxmempool": "1000"},
                              help_core)
    vals, lines = read_conf(conf)
    ck("updates a key in place", vals["dbcache"] == "2048")
    ck("appends a key that was absent", vals["maxmempool"] == "1000")
    ck("a backup was taken", bak and os.path.exists(bak))

    # Two saves in the same second must not collapse into one backup: the
    # earlier state is exactly what you want back when the second save is the
    # mistake.
    write_conf(conf, {"dbcache": "1024"}, help_core)
    write_conf(conf, {"dbcache": "1025"}, help_core)
    baks = [f for f in os.listdir(d) if ".bak." in f]
    ck("rapid saves each keep their own backup", len(baks) >= 3, baks)
    ck("unmanaged lines survive",
       vals.get("onlynet") == "onion" and vals.get("proxy") == "127.0.0.1:9050")
    ck("comments survive", any(l.startswith("# my node") for l in lines))
    ck("the section header survives", any(l.strip() == "[main]" for l in lines))
    ck("no key is duplicated",
       len([l for l in lines if l.strip().startswith("dbcache=")]) == 1)

    # The load-bearing refusal. An option the build does not have must never
    # reach the file, however the caller asks for it.
    try:
        write_conf(conf, {"coinstatsindex": "1"}, help_core)
        ck("refuses to write an unsupported key", False)
    except ValueError as e:
        ck("refuses to write an unsupported key", "not available" in str(e))
    vals, _ = read_conf(conf)
    ck("the unsupported key is not in the file",
       "coinstatsindex" not in vals)

    try:
        write_conf(conf, {"dbcache": "2048", "maxmempool": "0"}, help_core)
        ck("one bad value rejects the whole batch", False)
    except ValueError:
        ck("one bad value rejects the whole batch", True)
    vals, _ = read_conf(conf)
    ck("nothing was partially applied", vals["maxmempool"] == "1000")

    try:
        write_conf(conf, {"txindex": "1\nrpcallowip=0.0.0.0/0"}, help_core)
        ck("an injected newline never reaches the file", False)
    except ValueError:
        ck("an injected newline never reaches the file", True)
    vals, _ = read_conf(conf)
    ck("no injected key appeared", "rpcallowip" not in vals)

    write_conf(conf, {"dbcache": "4096"}, help_core)
    restore_defaults(conf, help_core)
    vals, _ = read_conf(conf)
    ck("restore puts a managed key back to its default",
       vals["dbcache"] == "450")
    ck("restore leaves unmanaged lines alone",
       vals.get("onlynet") == "onion")
    ck("restore does not write unsupported keys",
       "coinstatsindex" not in vals)

    # A file that does not exist yet is a fresh install, not an error.
    conf2 = os.path.join(d, "new.conf")
    write_conf(conf2, {"dbcache": "512"}, help_core)
    v2, _ = read_conf(conf2)
    ck("creates a config that did not exist", v2.get("dbcache") == "512")

    # Duplicate keys: Core takes the last. Our rewrite must collapse to one.
    conf3 = os.path.join(d, "dup.conf")
    with open(conf3, "w") as f:
        f.write("dbcache=100\ndbcache=200\nonlynet=onion\n")
    write_conf(conf3, {"dbcache": "300"}, help_core)
    _, l3 = read_conf(conf3)
    ck("collapses duplicate keys to one line",
       len([l for l in l3 if l.strip().startswith("dbcache=")]) == 1)

    print("\nscopes")
    ck("every setting declares a scope",
       all(s.get("scope") in (SCOPE_BITCOIND, SCOPE_MONETARY)
           for s in SETTINGS))
    mon = [s for s in SETTINGS if s["scope"] == SCOPE_MONETARY]
    ck("the monetary-node options are monetary-scoped", len(mon) == 3)
    ck("monetary options skip the bitcoind support check",
       all(is_supported(s, help_core) is True for s in mon))
    ck("a bitcoind option absent from the build is still unsupported",
       is_supported(BY_KEY["coinstatsindex"], help_core) is False)

    # The warning is the point of the setting. A future edit that softened it
    # into a tiebreak would be a consensus change wearing a stopwatch's name.
    ck("the race window says plainly it is not a tiebreak",
       "not a tiebreak" in BY_KEY["racewindow"]["warn"])
    ck("the race observer says it cannot change chain selection",
       "nothing about it can" in BY_KEY["raceobserve"]["help"])

    mconf = os.path.join(d, "monetary", "monetary.conf")
    paths = {SCOPE_BITCOIND: conf, SCOPE_MONETARY: mconf}

    written, baks = write_settings(
        paths, {"dbcache": "600", "racewindow": "45"}, help_core)
    bv, _ = ns_read = read_conf(conf)
    mv, _ = read_conf(mconf)
    ck("a bitcoind key goes to bitcoin.conf", bv.get("dbcache") == "600")
    ck("a monetary key goes to monetary.conf", mv.get("racewindow") == "45")
    ck("a monetary key never lands in bitcoin.conf", "racewindow" not in bv)
    ck("a bitcoind key never lands in monetary.conf", "dbcache" not in mv)
    ck("the monetary directory is created on demand",
       os.path.isdir(os.path.dirname(mconf)))
    ck("both keys are reported as written", set(written) ==
       {"dbcache", "racewindow"})

    eff = {e["key"]: e for e in effective(conf, help_core, mconf)}
    ck("effective() reads the monetary file too",
       eff["racewindow"]["value"] == "45" and eff["racewindow"]["set"])
    ck("effective() tags each row with its scope",
       eff["racewindow"]["scope"] == SCOPE_MONETARY
       and eff["dbcache"]["scope"] == SCOPE_BITCOIND)
    eff_nom = {e["key"]: e for e in effective(conf, help_core)}
    ck("without a monetary path, monetary rows report defaults",
       eff_nom["racewindow"]["value"] == 30
       and not eff_nom["racewindow"]["set"])

    # One bad value must not leave the other file written. This is why
    # validation runs across everything before any file is touched.
    before_b, before_m = open(conf).read(), open(mconf).read()
    try:
        write_settings(paths, {"dbcache": "700", "racewindow": "1"},
                       help_core)
        ck("a bad value in one scope aborts both", False)
    except ValueError:
        ck("a bad value in one scope aborts both", True)
    ck("neither file was touched",
       open(conf).read() == before_b and open(mconf).read() == before_m)

    try:
        write_settings({SCOPE_BITCOIND: conf}, {"racewindow": "40"},
                       help_core)
        ck("a missing scope path is refused, not silently dropped", False)
    except ValueError as e:
        ck("a missing scope path is refused, not silently dropped",
           "monetary" in str(e))

    restore_all_defaults(paths, help_core)
    bv, _ = read_conf(conf)
    mv, _ = read_conf(mconf)
    ck("restore resets both scopes",
       bv.get("dbcache") == "450" and mv.get("racewindow") == "30")
    ck("restore still leaves unmanaged lines alone",
       bv.get("onlynet") == "onion")
    ck("restore writes no unsupported key anywhere",
       "coinstatsindex" not in bv and "coinstatsindex" not in mv)

    print("\n%d/%d passed" % (passed, len(checks)))
    return 0 if passed == len(checks) else 1


# --------------------------------------------------------------------- main


def main():
    ap = argparse.ArgumentParser(description="advanced node settings")
    ap.add_argument("--conf", default=os.path.expanduser(
        "~/.bitcoin/bitcoin.conf"))
    ap.add_argument("--bitcoind", default="bitcoind")
    ap.add_argument("--show", action="store_true")
    ap.add_argument("--set", action="append", default=[],
                    metavar="key=value")
    ap.add_argument("--defaults", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()

    if a.selftest:
        return selftest()

    blob = help_text(a.bitcoind)
    if not blob:
        print("warning: could not run `%s -help`; support is unknown and "
              "nothing will be written" % a.bitcoind, file=sys.stderr)

    if a.defaults:
        if not blob:
            return 1
        written, bak = restore_defaults(a.conf, blob)
        print("restored %d settings to defaults" % len(written))
        if bak:
            print("backup   %s" % bak)
        print("\nCore reads its config at startup — restart to apply.")
        return 0

    if a.set:
        if not blob:
            return 1
        pairs = {}
        for item in a.set:
            if "=" not in item:
                sys.exit("--set takes key=value")
            k, v = item.split("=", 1)
            pairs[k.strip()] = v.strip()
        try:
            written, bak = write_conf(a.conf, pairs, blob)
        except ValueError as e:
            sys.exit("refused: %s" % e)
        for k, v in written.items():
            print("  set %s=%s" % (k, v))
        if bak:
            print("backup %s" % bak)
        print("\nCore reads its config at startup — restart to apply.")
        return 0

    group = None
    for e in effective(a.conf, blob):
        if e["group"] != group:
            group = e["group"]
            print("\n%s" % group.upper())
        mark = " " if e["at_default"] else "*"
        avail = "" if e["supported"] is not False else "   (not in this build)"
        print("  %s %-34s %-12s (default %s)%s"
              % (mark, e["key"], e["value"], e["default"], avail))
    print("\n  * = differs from default")
    return 0


if __name__ == "__main__":
    sys.exit(main())
