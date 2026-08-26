# Monetary Node

**A Bitcoin node that validates every consensus rule and stores no spam.**

Inscription witness data, oversized `OP_RETURN`, stamp-style bare multisig,
scriptSig payloads — all removed from block storage after validation. The blocks
still verify against their own headers, against real proof-of-work.

No fork. No confiscation. Nobody's permission required.

This repository holds the measurements, the tools, and the raw logs.

---

## The result

Blocks **767,430 – 962,292** (194,863 blocks) on a fully synced Bitcoin Knots
node. Stripped, written to disk in a defined format, then re-verified **reading
nothing but the stripped store** — no original block file opened.

> ### 194,863 blocks verified. 0 failures. 0 corrupt records.

| | |
|---|---|
| Spam removed | **37.2 GB** — 12.56% of block bytes |
| Original blocks | 296.2 GB |
| Monetary store | 247.4 GB |
| Storage saved | 48.7 GB (16.46%) — [not the same number, see why](docs/STRIP_RESULTS.md#read-the-two-storage-numbers-carefully) |

**By carrier**

| Carrier | Removed |
|---|---|
| Inscription envelopes (taproot witness) | 37.1 GB |
| Stamp-style bare multisig | 77.5 MB |
| `OP_RETURN` over 83 bytes | 12.3 MB |
| Oversized scriptSig | 13.8 KB |

**Transaction treatment**

| | |
|---|---|
| Retained whole | 507,173,533 (80.66%) |
| Modified | 121,599,086 (19.34%) |
| Reduced to a txid | 615 |
| Filter index entries | 806,626 |

---

## Why a block survives losing its data

A block's merkle root is computed over **txids**. The store keeps the 32-byte
txid of every transaction it modifies or discards. Nothing downstream needs to
re-derive those from transaction data — so the data can go, and the block still
verifies against its header.

The stored txids are **self-verifying**. A fabricated txid produces a merkle
root that does not match the header, and the block is rejected. The list cannot
be forged.

Transactions retained unmodified need no stored txid at all; the reader computes
those itself. Only modified or discarded transactions pay the 32 bytes.

This is what the usual objection misses. *"You can't remove `OP_RETURN`, it's
committed inside the txid"* is true only for designs that **recompute** txids.
It does not apply when the txid is stored.

---

## What this demonstrates

### Nothing is stranded

806,626 outputs were dropped from block storage. Each kept a filter entry —
outpoint, amount, scriptPubKey, height. Seven were ever spent, and **all seven
had their entry present**. Six had their **ECDSA signatures re-verified against
scriptPubKeys recovered from the index**, including a 2-of-2 requiring both keys.

That is cryptographic proof that deleting the output did not make it unspendable
and did not require asking a peer.

### Spam outputs are almost never spent

**7 of 806,626 — about one in 115,000.**

Monetary outputs get spent because someone wants the coins. Data carriers sit
forever because nobody ever wanted the coins, only the bytes. That is a measured
distinction between money and data rather than an opinion about it — and it
prices the anti-confiscation guarantee at about 66 MB of index, of which seven
entries were ever read.

### Wallets are unaffected

Balances and transaction history computed from the stripped store, compared
against an independent Electrum server reading complete block data:
**32 of 32 completed comparisons identical**, zero invented transactions.

### Stamps were measured for the first time

The bare multisig carrier had been reported as **0 bytes** by a detector that
checked whether public keys began with `02`, `03` or `04` — but Stamps
deliberately use those prefixes so their outputs pass standardness checks. It
caught nothing and returned a clean zero, which is the worst kind of wrong,
because a zero reads as a finding.

Corrected by testing whether each key is genuinely a point on secp256k1
(`y² = x³ + 7 mod p`, checked by Euler's criterion). Real figure: **77.5 MB**,
corroborated within an order of magnitude by an independent UTXO-set
measurement.

---

## What's here

### Tools

Standard library only. No dependencies.

| Tool | Purpose |
|---|---|
| [`tools/mindex.py`](tools/mindex.py) | Build the block index. Reads 1.8 GB of 696 GB — 0.26% — in ~10 minutes. Cached and incremental. |
| [`tools/monetary_store.py`](tools/monetary_store.py) | Strip, write the store, verify it from disk. |
| [`tools/test_monetary_store.py`](tools/test_monetary_store.py) | 42 format checks against synthetic blocks with real merkle roots. |
| [`tools/spend_check.py`](tools/spend_check.py) | Is the filter index sufficient? Includes pure-Python secp256k1 and legacy sighash. |
| [`tools/wallet_check.py`](tools/wallet_check.py) | Compare balances and history against any Electrum server. |
| [`tools/monetary_commit.py`](tools/monetary_commit.py) | The chained commitment C, derived from a store. |
| [`tools/chainstate_filter.py`](tools/chainstate_filter.py) | Dust at the UTXO layer, with honest accounting of what it saves. |
| [`tools/inscription_scan.py`](tools/inscription_scan.py) | Original block measurement. |
| [`tools/utxo_scan.py`](tools/utxo_scan.py) | Original chainstate measurement. |

### Documents

| Document | Contents |
|---|---|
| [`docs/STRIP_RESULTS.md`](docs/STRIP_RESULTS.md) | The main result, with every caveat. |
| [`docs/FORMAT.md`](docs/FORMAT.md) | Storage format specification. |
| [`docs/RESULTS.md`](docs/RESULTS.md) | Measurement results and method. |
| [`docs/monetary_ibd_design.md`](docs/monetary_ibd_design.md) | How monetary nodes sync from each other. |
| [`docs/Monetary_Nodes.md`](docs/Monetary_Nodes.md) | Specification draft. |
| [`GAMEPLAN.md`](GAMEPLAN.md) | Architecture, build sequence, and a table separating code from specification. |

### Results

[`results/`](results/) holds the unedited logs from every run above. They are
the evidence behind every number on this page. If a figure here disagrees with a
log, the log is right.

---

## Reproducing

Requires a non-pruned Bitcoin Core or Knots node and ~250 GB free.

```bash
python3 tools/mindex.py --blocks /path/to/bitcoin/blocks

python3 tools/monetary_store.py --blocks /path/to/bitcoin/blocks \
  --start 767430 --end 962292 --out /path/to/mstore

python3 tools/monetary_store.py --verify /path/to/mstore
```

On Umbrel-class hardware with a 12 MB/s disk: 10 minutes to index, 7.4 hours to
strip, 3.5 hours to verify. On an NVMe, a fraction of that.

**A warning for anyone reproducing this.** Bitcoin Core 28 and later
XOR-obfuscate `blk*.dat` against an 8-byte key stored in `blocks/xor.dat`. A
reader that ignores this finds zero blocks **and reports no error** — it simply
sees no magic bytes and stops. These tools handle it. The UTXO snapshot format
also mixes two integer encodings: CompactSize for counts and output indices,
Core's base-128 VARINT for coin fields. Mixing them desyncs the parser
immediately.

---

## Limitations

Stated plainly, because they are the first things a reviewer will look for.

**A stripped block cannot be served to a legacy node.** Conventional full nodes
require complete block data. Monetary nodes can serve each other; they cannot
serve everyone else. If monetary nodes ever became a large share of the network,
who serves the chain is an open question.

**19.34% of transactions lose signature re-verifiability.** `SIGHASH_ALL` commits
to a transaction's outputs, and the stripper removes some of them, so a modified
transaction's signed preimage cannot be reconstructed. The 80.66% retained whole
are unaffected. Every transaction was validated once, in full, by Knots, when its
block was connected. Demonstrated with a specific transaction in
[STRIP_RESULTS.md](docs/STRIP_RESULTS.md).

**Dust figures are a proxy.** They count sub-1000-sat P2TR outputs from the
inscription era, which includes ordinary small taproot payments and excludes
inscription outputs above the threshold. Not a direct measurement of inscription
activity.

**Chainstate removal is not deletion.** Dust is removed from the UTXO database
and retained in block storage, where the same output costs 43 bytes instead of
the 82 a standalone index entry would need. That is a real saving in the
structure that wants to live in RAM — but it is relocation, not deletion, and
the two layers must not be added together.

**The classifier is a policy decision.** Something has to decide what counts as
spam. That decision lives in storage and never in consensus — no classifier
touches validation. It can still be wrong; see Corrections.

**Single node, single run.** Independent reruns are the most useful contribution
anyone could make, particularly disagreements about where the classification
boundaries should sit.

---

## Corrections

Three published figures from this project were wrong. They are retracted here
with reasons, and the originals left visible in the documents.

| Claim | Reality |
|---|---|
| `OP_RETURN` spam is 2.9 GB | The tool classified *every* `OP_RETURN` as spam, including small policy-compliant ones. Data above the 83-byte limit is **12.3 MB**. |
| Stamps are 0 bytes | The detector checked key prefixes, which Stamps deliberately make look standard. Real figure **77.5 MB**. |
| Stripped transactions cannot be re-verified | Too loose. Precisely: transactions *modified or stripped* lose signature re-verifiability, 19.34%. The rest are unaffected. |

---

## Status and roadmap

| Step | State |
|---|---|
| Block measurement | done |
| Chainstate measurement | done |
| General stripper | done — 194,863 blocks |
| Storage format | done — 42 tests |
| Store written and re-verified from disk | done — 0 failures |
| Stamps detection | done — first measurement |
| Wallet compatibility | demonstrated on a sample |
| Spend validation from the filter index | done — 6 signatures verified |
| Chained commitment C | code and self-tests; not yet run on a real store |
| Chainstate filtering | code and self-tests; needs a snapshot |
| Monetary IBD | **design only, never adversarially reviewed** |
| The daemon | **not built** |
| Alpha | **not built** |

Please read [`GAMEPLAN.md`](GAMEPLAN.md) before assuming anything here is
finished.

---

## Prior and related work

This is not the only proposal in this space, and pretending otherwise would be
dishonest.

**[Utreexo](https://bitcoinops.org/en/topics/utreexo/)** replaces the UTXO set
with a hash accumulator. Lossless and content-neutral: nothing is deleted,
nothing is judged, and block storage is untouched. A different problem — but if
it ships, the chainstate half of the argument here weakens considerably, because
UTXO set size stops being expensive.

**[Dust expiry](https://delvingbitcoin.org/t/dust-expiry-clean-the-utxo-set-from-spam/1707/)**
(Robin Linus) proposes removing low-value outputs from the UTXO set after a
time. Close to the dust filtering here. The difference: that needs a soft fork,
this does not.

**[Witnessless sync](https://delvingbitcoin.org/t/witnessless-sync-for-pruned-nodes/1742/)**
(Jose SK) proposes pruned nodes skipping witness download for `assumevalid`
blocks. Ruben Somsen's objection there applies with more force here: if nobody
routinely validates that data exists, it can be lost. Worth reading before
engaging with this project.

---

## How to help

Most useful, in order:

1. **Rerun the measurements** on your own node and report disagreements.
2. **Attack the IBD design** in `docs/monetary_ibd_design.md`. It has never been
   adversarially reviewed and every earlier version of this project's designs
   failed on second inspection.
3. **Argue about the classification boundaries.** Where should the line sit for
   `OP_RETURN`? For dust? For Runes, which mostly fall under 83 bytes and so
   currently pass?
4. **Find an error.** Three have been found so far, all by continuing to check
   rather than by anyone objecting. There are likely more.

---

## Licence

BSD-2-Clause. See [LICENSE](LICENSE).
