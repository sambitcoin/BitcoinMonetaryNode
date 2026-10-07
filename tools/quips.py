#!/usr/bin/env python3
"""
quips.py — occasional editorial in the log.

One progress line in a hundred is followed by a remark. It has no effect on
anything: nothing is measured, decided or written differently, and the store
is byte-identical whether or not a quip appeared.

Paste `QUIPS`, `quip_prefix` and `maybe_quip` into whichever tool you want it
in — the tools are deliberately standalone with no imports between them, so
this is duplicated rather than shared. Call it wherever a progress line is
printed:

    print(f"  {height:,}  {human(written)} stored")
    q = maybe_quip()
    if q:
        print(q)

Every line is prefixed with "#" so log parsers can skip them, and the whole
thing is off when MONETARY_NO_QUIPS is set. Both matter: monetary_ui.py
greps build logs for figures, and a stray sentence in the wrong place is the
kind of thing that silently breaks a regex six months from now.

BSD-2-Clause.
"""

import os
import random

QUIP_CHANCE = 100          # one line in this many
QUIP_PREFIX = "  # "       # marks it as commentary, not output


QUIPS = (
    "Every byte of non-monetary junk you broadcast to my node is just a crying plea for validation from a blockchain that doesn't care about your jpeg.",
    "My node runs on pure monetary signal. If you want to dump megabytes of arbitrary garbage into block space, go buy a cloud server like a normal person.",
    "Pruned, filtered, and hardened: my node is a monetary fortress, not your personal digital landfill.",
    "You burn real energy just to store arbitrary bloat on thousands of hard drives forever. That's not innovation, that's just digital vandalism.",
    "I run a full node to validate financial truth, not to act as a free web host for your un-censorable graffiti.",
    "Block space is the most valuable real estate on Earth. Using it for monetary settlement is engineering.",
    "My node's block filter is a zero-tolerance policy against state bloat and protocol spam. Keep the ledger pure or get dropped at the peer level.",
    "A clean node is a quiet node. No junk scripts, no data dumps, no free storage for scammers - just cold, un-diluted monetary settlement.",
    "If your transaction requires a 2MB payload of arbitrary data to function, it's not a transaction. It's an attack on low-cost node operations.",
    "We built a censorship-resistant central bank killer, and you turned it into a low-resolution image board. I filter your traffic without hesitation.",
    "Every megabyte of bloat you push onto the network makes it harder for someone on modest hardware to run a node. Clean the chain, save decentralization.",
    "My mempool, my rules. If it doesn't look like an exchange of value, my node drops it before it even reaches the disk.",
    "Proof-of-Work was designed to secure absolute monetary scarcity, not to host your high-latency database experiments.",
    "Pruning isn't just a storage strategy; it's a moral stance against bloat.",
    "I don't host your internet garbage for free. Pay the settlement fee for real transactions or go back to Web2.",
    "A bloated blockchain is a centralized blockchain. Every filter I apply keeps the hardware requirements low enough for the rest of us.",
    "Your transaction spent 10,000 sats in fees just to embed text nobody will ever read. My node dropped it for 0 sats because I don't care.",
    "Keep the ledger lean. Keep the node light. Keep the central bankers terrified.",
    "If I wanted to run a node that downloads gigabytes of arbitrary web data every hour, I'd open a Web browser. Keep the blockchain monetary.",
    "We are building peer-to-peer electronic cash, not an un-curated image gallery for tech VCs with too much money.",
    "Filter the mempool, drop the bloat, enforce the protocol, stay sovereign.",
    "Every non-monetary script pushed to the ledger is an interest payment made to hardware manufacturers. Strip the data, keep the money.",
    "My node isn't a museum for your experimental tokens. It's a settlement engine for cold, hard, cryptographic truth.",
    "Running a clean node is the ultimate act of network hygiene. Vacuum the mempool, trash the bloat.",
    "You want infinite data storage on a distributed ledger? It's called the internet. Leave Bitcoin to the money.",
    "Block space is for economic freedom, not for cluttering disk space on home servers.",
    "I filter garbage at the peer layer because decentralization dies when node costs exceed a Raspberry Pi.",
    "If your protocol idea relies on tricking nodes into storing useless bytes forever, your protocol idea is garbage.",
    "Monetary purity is non-negotiable. If it doesn't settle value, it doesn't touch my mempool.",
    "Clean block, clean mind, sovereign node.",
    "They tried to spam the chain to price out home nodes. We updated our filters and kept running smoothly.",
    "A node that accepts all garbage without filtering isn't open; it's just a digital trash can.",
    "You call it 'on-chain data richness.' I call it disk pollution. Filter dropped.",
    "We don't yield block space to spam. Validate the signal, purge the noise.",
    "The beauty of Bitcoin is its minimalism. Anything that adds useless weight to the ledger is a threat to node sovereignty.",
    "My peer connections are reserved for nodes that respect the protocol's original intent: pure, un-censorable money.",
    "Don't bloat the chain, don't trust custodians, run a clean node, stay sovereign.",
    "A 1MB block of pure financial transactions is worth more than a 4MB block filled with arbitrary script bloat.",
    "If you want a decentralized database, go build one. Stop piggybacking on the hardest money ever created.",
    "I run my own node so I can reject your protocol's junk transactions in real time.",
    "The mempool is a high-security vault, not a public bulletin board.",
    "Purge the non-monetary bloat before it purges home node runners from the network.",
    "Your experimental protocol isn't 'expanding Bitcoin's utility'; it's just inflating disk requirements for validation.",
    "I don't store your arbitrary bytes, I don't relay your spam, and I don't validate your bloat.",
    "Keeping a clean chain isn't toxicity - it's protocol defense.",
    "Every byte stripped from a block is a victory for decentralization.",
    "Real Bitcoiners keep their nodes light, their scripts simple, and their mempools clean.",
    "If it can't be justified as a monetary transfer, it doesn't belong in the block header.",
    "Clean validation, zero junk, absolute monetary focus.",
    "We run nodes to enforce scarcity, including the scarcity of our own hard drive space. Filter everything.",
)


def quip_prefix():
    return QUIP_PREFIX


def maybe_quip(rng=None, chance=QUIP_CHANCE):
    """Return a prefixed quip roughly once every `chance` calls, else None.

    `rng` takes a random.Random so tests are deterministic; production passes
    nothing and uses the module-level generator.
    """
    if os.environ.get("MONETARY_NO_QUIPS"):
        return None
    if chance <= 0:
        return None
    r = rng or random
    if r.randrange(chance) != 0:
        return None
    return QUIP_PREFIX + r.choice(QUIPS)


def selftest():
    ok = []

    def ck(name, cond, detail=""):
        ok.append(cond)
        print(f"  [{'ok  ' if cond else 'FAIL'}] {name}" + (f"  — {detail}" if detail else ""))

    ck("there are quips", len(QUIPS) >= 40, f"{len(QUIPS)}")
    ck("all are strings", all(isinstance(q, str) and q for q in QUIPS))
    ck("none contain newlines", not any("\n" in q for q in QUIPS))
    ck("no duplicates", len(set(QUIPS)) == len(QUIPS),
       f"{len(QUIPS) - len(set(QUIPS))} repeated")

    r = random.Random(1)
    hits = sum(1 for _ in range(100_000) if maybe_quip(r) is not None)
    ck("fires about 1 in 100", 800 < hits < 1200, f"{hits} in 100,000")

    a = [maybe_quip(random.Random(7), chance=1) for _ in range(3)]
    b = [maybe_quip(random.Random(7), chance=1) for _ in range(3)]
    ck("same seed gives the same line", a == b)

    ck("chance=1 always fires", maybe_quip(random.Random(3), chance=1) is not None)
    ck("chance=0 never fires", maybe_quip(random.Random(3), chance=0) is None)
    ck("prefixed for log parsers",
       maybe_quip(random.Random(3), chance=1).startswith(QUIP_PREFIX))

    os.environ["MONETARY_NO_QUIPS"] = "1"
    silent = all(maybe_quip(random.Random(i), chance=1) is None for i in range(20))
    del os.environ["MONETARY_NO_QUIPS"]
    ck("MONETARY_NO_QUIPS silences it", silent)
    ck("unset again and it returns", maybe_quip(random.Random(3), chance=1) is not None)

    # the reason the prefix exists: monetary_ui.py greps build logs
    import re
    fake = "saved                 51.1 GB   (7.12%)\n" + maybe_quip(random.Random(5), chance=1) + "\n"
    m = re.search(r"saved\s+([\d.]+\s*[KMGT]?B\s*\([\d.]+%\))", fake)
    ck("a quip does not break build-log parsing", m is not None)

    print(f"\n{sum(ok)}/{len(ok)} passed")
    return 0 if all(ok) else 1


if __name__ == "__main__":
    import sys
    if "--selftest" in sys.argv:
        sys.exit(selftest())
    for _ in range(5):
        print(maybe_quip(chance=1))
