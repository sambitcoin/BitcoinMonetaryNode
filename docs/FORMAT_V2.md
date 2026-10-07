# Monetary block store — format version 2

A single change to the v1 format, for a single reason: **v1 cannot bootstrap a
usable node.**

Not yet implemented. This is the specification to implement against.

An earlier draft of this document called the cost unmeasured and guessed at
"single-digit GB." It has since been measured genesis to tip. The real figure
is **about 117 KB**, and it changes the conclusion from "weigh the cost"
to "there is no cost worth weighing."

## The problem v1 has

`monetary_ibd.py` already serves blocks from one monetary node to another, and
the receiving node verifies every one against real proof-of-work. But a node
is not usable without an address index, and an index rebuilt from a v1 store
is **wrong** — silently.

A transaction stored with flag `2` keeps its txid and nothing else. That is
correct for its outputs, which were entirely spam. It is not correct for its
**inputs**, which spent outputs belonging to someone.

Concretely: Alice funds an inscription by creating a commit output at an
address she controls, then spends it with a reveal transaction whose outputs
are all spam. The reveal is stored as flag `2` — txid only. An index rebuilt
from that store never learns Alice's commit output was spent. Her wallet shows
a phantom unspent balance, permanently, with no error anywhere.

This only bites on the bootstrap path. A node that stripped its own blocks
built its index from complete data before stripping, so it never sees the
problem — which is exactly why it would have gone unnoticed until someone
bootstrapped from a peer and quietly got a broken wallet.

If bootstrapping requires falling back to a full node, nobody ever escapes the
full download and the store is a compression trick rather than a bootstrap
mechanism. So this gap has to close.

## The change

A new transaction flag. Flags `0` and `1` are unchanged.

| Flag | Meaning | Followed by |
|---|---|---|
| `0` | retained whole | varint length, then the transaction verbatim |
| `1` | modified | 32-byte txid, varint length, then the reduced body |
| `2` | stripped (**v1 only, deprecated**) | 32-byte txid only |
| `3` | stripped, inputs retained | 32-byte txid, varint input count, then one entry per input |

Each input entry:

| Field | Bytes |
|---|---|
| prevout txid | 32 |
| prevout vout | varint |

**Writers at version 2 never emit flag `2`.** Readers must still accept it, so
that v1 stores remain readable — and must treat any flag `2` record as an
explicit signal that the store cannot bootstrap an index.

A new flag rather than reinterpreting flag `2` under a version check, so a
record is self-describing: you can tell what a record contains without
consulting the version field.

## Cost — measured, genesis to tip

The first genesis-to-tip store was built over blocks 0–967,984 and verified
from disk alone: 967,985 blocks, 0 failed, 0 corrupt records.

| | |
|---|---|
| Transactions modified (flag `1`) | 122,419,745 |
| Transactions fully stripped (flag `2`) | **3,552** |
| Filter entries | 1,104,820 |

Only flag `2` records need prevout retention. At 33 bytes for a single-input
transaction — 32 for the prevout txid, one for the varint vout — that is
**roughly 117 KB across the entire chain.** Even at several inputs each it
stays comfortably under a megabyte.

The ratio is the surprising part. Across seventeen years, only 3,552
transactions had every output classified as a carrier — one in every 34,000
modified transactions. Almost everything that carries data also pays somebody,
so it keeps a monetary output and stays flag `1`, where inputs are already
retained in the reduced body.

**This is the cheapest possible fix for the most serious correctness gap in
the format**, and the earlier draft's guess was wrong by four orders of
magnitude. The lesson is the project's usual one: the figure was available for
the cost of counting, and estimating it was never justified.

## Why this is enough

An address index needs, for every output: scriptPubKey, amount, txid, vout,
height. For every input: which output it spent.

| Record type | Outputs | Inputs |
|---|---|---|
| Flag `0` whole | present | present |
| Flag `1` modified | retained ones present; dropped ones in filter entries | present in the reduced body |
| Flag `3` stripped | none existed worth keeping | **now present** |

With flag `3`, every output ever created and every output ever spent is
recoverable from the store alone.

## Effect on the commitment

The record body changes, so the body digest changes, so `C` changes.

`f0e4c825e753cc9469a2027425c9625801f2bf8662f2e6b3cdbc4647b8406b61` remains
correct for v1 rules over blocks 767,430–962,292. A v2 store over any range
produces a different value. Neither is wrong; they are commitments to
different rule sets and are not comparable.

## What verifies the prevout list — and what does not

This distinction matters and should not be glossed.

**The merkle root does not cover it.** The root is computed over txids. A
stored txid is self-verifying: fabricate one and the root stops matching the
header. The prevout list sits underneath a txid that keeps matching whatever
is written beneath it.

**The body digest covers it, locally.** Corruption on disk is detected. A peer
sending a consistent-but-false record is not.

**The chained commitment is the real defence.** `C_h = SHA256d(C_{h-1} ‖ block
hash_h ‖ K_h)` includes the body digest, so two nodes that stripped identically
produce identical `C`, and a peer that omitted or forged a prevout diverges
permanently and visibly.

**The failure mode if it were forged** is precisely the bug being fixed: an
omitted prevout leaves an output unspent forever in the resulting index. It is
not locally detectable — nothing looks wrong, an output simply never gets
marked spent. `C` comparison is what catches it.

## A limit that stays

`blockchain.transaction.get` returns raw transaction hex. A monetary node
**can** serve it — reconstruction from the stored body plus filter entries
reproduces a modified transaction byte for byte, and the result hashes to the
stored txid, which the merkle root protects. Tested.

What it cannot reproduce is **witness data**, which is gone permanently. That
does not affect the txid and no light client checks it, but anything that
verifies the witness commitment will fail.

So the honest statement is that a monetary node serves verifiable legacy
serialisations of every transaction, and cannot serve witnesses for the ones
it modified.

## Implementation checklist

1. `monetary_store.py` — emit flag `3` with prevouts; stop emitting flag `2`
2. Reader — accept flag `2` from v1 stores, and surface it as
   "cannot bootstrap an index" rather than failing silently
3. `test_monetary_store.py` — round-trip flag `3`; a negative test proving a
   v1 store is *detected* as unable to bootstrap
4. `monetary_commit.py` — no change; it digests whatever the body contains
5. `monetary_ibd.py` — no change; records are opaque to it
6. ~~Measure the flag 1 / flag 2 split~~ — done: 122,419,745 / 3,552
7. Index rebuild from a store — the consumer this exists for, still unwritten
