# Monetary Node

A Bitcoin node that validates every consensus rule and stores no spam.

Every non-monetary carrier — inscription witness data, oversized `OP_RETURN`,
stamp-style bare multisig, scriptSig payloads — is removed from block storage
after validation. The blocks still verify against their own headers, against
real proof-of-work. No fork, no confiscation, nobody's permission required.

This repository contains the measurements, the tools, and the raw logs.

## Result

Blocks **767,430 – 962,292** (194,863 blocks) on a fully synced Bitcoin Knots
node. Stripped, written to disk in a defined format, then re-verified **reading
nothing but the stripped store**.

> **194,863 blocks verified. 0 failures. 0 corrupt records.**

| | |
|---|---|
| Spam removed | **37.2 GB** (12.56% of block bytes) |
| Original blocks | 296.2 GB |
| Monetary store | 247.4 GB |
| Storage saved | 48.7 GB (16.46%) — [see the accounting](docs/STRIP_RESULTS.md#read-the-two-storage-numbers-carefully) |

**By carrier:**

| Carrier | Removed |
|---|---|
| Inscription envelopes (taproot witness) | 37.1 GB |
| Stamp-style bare multisig | 77.5 MB |
| `OP_RETURN` over 83 bytes | 12.3 MB |
| Oversized scriptSig | 13.8 KB |

## How a block survives losing its data

A block's merkle root is computed over **txids**. The store keeps the 32-byte
txid of every transaction it modifies or discards. Nothing downstream needs to
re-derive those from transaction data — so the data can go and the block still
verifies against its header.

The stored txids are self-verifying. A fabricated txid produces a merkle root
that does not match the header, and the block is rejected. The list cannot be
forged.

Transactions retained unmodified need no stored txid; the reader computes those
itself. Only modified or discarded transactions pay the 32 bytes.

This is the point the usual objection misses. "You can't remove `OP_RETURN`,
it's committed inside the txid" is true only for designs that *recompute* txids.
It does not apply when the txid is stored.

## Three things this demonstrates

**Nothing is stranded.** 806,626 outputs were dropped from block storage; each
kept a filter entry with its amount and scriptPubKey. Seven were ever spent, and
all seven had their entry. Six had their **ECDSA signatures re-verified against
scriptPubKeys recovered from the index** — cryptographic proof that deleting the
output did not make it unspendable.

**Spam outputs are almost never spent.** Seven of 806,626 — about one in
115,000. Monetary outputs get spent because someone wants the coins; data
carriers sit forever because nobody ever wanted the coins, only the bytes. That
is a measured distinction between money and data, not an opinion about it.

**Wallets are unaffected.** Balances and transaction history computed from the
stripped store were compared against an independent Electrum server reading
complete block data. 32 of 32 completed comparisons were identical, with zero
invented transactions.

## What's here

**Tools** — standard library only, no dependencies.

| | |
|---|---|
| [`tools/mindex.py`](tools/mindex.py) | Build the block index. Reads 1.8 GB of 696 GB; ~10 minutes, cached and incremental. |
| [`tools/monetary_store.py`](tools/monetary_store.py) | Strip, write the store, verify from disk. |
| [`tools/test_monetary_store.py`](tools/test_monetary_store.py) | 42 format checks against synthetic blocks. |
| [`tools/spend_check.py`](tools/spend_check.py) | Is the filter index sufficient? Includes pure-Python secp256k1. |
| [`tools/wallet_check.py`](tools/wallet_check.py) | Compare balances and history against an Electrum server. |
| [`tools/monetary_commit.py`](tools/monetary_commit.py) | The chained commitment C, derived from a store. |
| [`tools/chainstate_filter.py`](tools/chainstate_filter.py) | Dust at the UTXO layer. |
| [`tools/inscription_scan.py`](tools/inscription_scan.py) | Original block measurement. |
| [`tools/utxo_scan.py`](tools/utxo_scan.py) | Original chainstate measurement. |

**Documents**

| | |
|---|---|
| [`docs/STRIP_RESULTS.md`](docs/STRIP_RESULTS.md) | The main result, with every caveat. |
| [`docs/FORMAT.md`](docs/FORMAT.md) | Storage format specification. |
| [`docs/RESULTS.md`](docs/RESULTS.md) | Measurement results and method. |
| [`docs/monetary_ibd_design.md`](docs/monetary_ibd_design.md) | How monetary nodes sync from each other. |
| [`docs/Monetary_Nodes.md`](docs/Monetary_Nodes.md) | Specification draft. |
| [`GAMEPLAN.md`](GAMEPLAN.md) | Architecture, build sequence, and what is and isn't built. |

**Results** — `results/` holds the raw logs from every run above. They are the
evidence behind every number on this page.

## Reproducing

Requires a non-pruned Bitcoin Core or Knots node and ~250 GB free.

```
python3 tools/mindex.py --blocks /path/to/bitcoin/blocks

python3 tools/monetary_store.py --blocks /path/to/bitcoin/blocks \
  --start 767430 --end 962292 --out /path/to/mstore

python3 tools/monetary_store.py --verify /path/to/mstore
```

On Umbrel-class hardware: 10 minutes to index, 7.4 hours to strip, 3.5 hours to
verify. On an NVMe, considerably less.

**Note for anyone reproducing this.** Bitcoin Core 28 and later XOR-obfuscate
`blk*.dat` against an 8-byte key in `blocks/xor.dat`. A reader that ignores this
finds zero blocks **and reports no error** — it simply sees no magic bytes and
stops. These tools handle it.

## Limitations

Stated plainly, because they are the first things a reviewer will look for.

**A stripped block cannot be served to a legacy node.** Conventional full nodes
require complete block data. Monetary nodes can serve each other; they cannot
serve everyone else.

**19.34% of transactions lose signature re-verifiability.** `SIGHASH_ALL` commits
to a transaction's outputs, and the stripper removes some of them, so a modified
transaction's signed preimage can no longer be reconstructed. The 80.66%
retained whole are unaffected. Every transaction was validated once, in full, by
Knots, when its block was connected. This is demonstrated with a specific
transaction in [STRIP_RESULTS.md](docs/STRIP_RESULTS.md).

**Dust is a proxy.** The dust figures count sub-1000-sat P2TR outputs from the
inscription era, which includes ordinary small taproot payments and excludes
inscription outputs above the threshold. It is not a direct measurement of
inscription activity.

**The classifier is a policy decision.** Something has to decide what counts as
spam. That decision lives in storage, never in consensus — no classifier touches
validation.

**Single node, single run.** Independent reruns are the most useful thing anyone
could contribute, particularly disagreements about where the classification
boundaries should sit.

## Corrections

Three published figures from this project were wrong and have been retracted
with the reasons stated:

- **`OP_RETURN` reported as 2.9 GB.** The tool classified *every* `OP_RETURN` as
  spam, including small policy-compliant ones. The real figure for data above
  the 83-byte limit is 12.3 MB.
- **Stamps reported as 0 bytes.** The detector checked whether public keys began
  with `02`, `03` or `04` — but Stamps deliberately use those prefixes so their
  outputs look standard. It caught nothing and returned a clean zero. Corrected
  by testing whether each key is genuinely a point on secp256k1. Real figure:
  77.5 MB.
- **"Stripped transactions cannot be re-verified."** Too loose. The correct
  statement is above, and it is narrower.

## Status

Measurement and storage are done and demonstrated. Monetary IBD, the daemon, and
the alpha are not built. [`GAMEPLAN.md`](GAMEPLAN.md) has a table separating what
is code from what is still specification — please read it before assuming
anything here is finished.

## Licence

BSD-2-Clause. See [LICENSE](LICENSE).
