# Removing all spam from Bitcoin block storage — a demonstration

Run 18 August 2026 against blocks **767,430 – 962,292** (194,863 blocks) on a
fully synced Bitcoin Knots node.

Every non-monetary carrier was stripped from stored block data, and every
block's merkle root was then rebuilt and checked against its header.

> **194,863 blocks. Zero merkle failures.**

Every block remains verifiable against its proof-of-work with all spam removed.

## The mechanism

A block's merkle root is computed over **txids**. The stripper stores the
32-byte txid of every transaction it modifies or discards. Nothing downstream
needs to re-derive those txids from transaction data, so the data can be
removed and the block still verifies against its header.

This is the point that makes full spam removal possible. The common objection —
that OP_RETURN or output data cannot be removed because it is committed inside
the txid — applies only to designs that recompute txids. It does not apply when
the txid is stored.

The stored txids are **self-verifying**: fabricated ones produce a merkle root
that does not match the header, and the block is rejected. They cannot be
forged.

Transactions retained unmodified need no stored txid at all — a receiving node
computes those itself. Only modified or fully stripped transactions pay the 32
bytes.

## Results

| | |
|---|---|
| Blocks | 194,863 |
| Transactions | 628,773,234 |
| — untouched | 507,670,355 (80.7%) |
| — modified | 121,102,269 |
| — fully stripped | 610 |
| Stored txids | 121,102,879 (3.6 GB) |
| Filter index entries | 32,432 (2.5 MB) |

**Spam removed by carrier**

| Carrier | Removed |
|---|---|
| Inscription envelopes (taproot witness) | 37.1 GB |
| OP_RETURN over 83 bytes | 12.3 MB |
| Stamp-style bare multisig | 0 B |
| Oversized scriptSig | 13.8 KB |
| **Total** | **37.1 GB** |

**Storage**

| | |
|---|---|
| Original | 296.2 GB |
| Retained | 262.7 GB |
| **Saved** | **33.5 GB (11.30%)** |

**Merkle verification: 194,863 verified, 0 failed.**

## What is stripped

**Inscription envelopes** — data pushed inside unexecutable branches of taproot
script-path witnesses. Falsity is evaluated by script semantics rather than by
matching an opcode literal, so `OP_0`, an empty push and a push of `0x00` all
qualify and re-encoded variants are not missed.

**OP_RETURN over the datacarrier limit** — only outputs exceeding 83 bytes.
Outputs within the limit are treated as monetary and left untouched: they are
policy-compliant, provably unspendable, and never enter the UTXO set.

**Stamp-style bare multisig** — outputs whose public keys are not valid curve
points, indicating data stuffed into key positions.

**Oversized scriptSig** — input scripts beyond the standard limit.

Every dropped output receives a filter index entry (outpoint, amount,
scriptPubKey, height) so that a future spend can still be validated in full,
locally, with no peer involvement.

## Two findings worth stating separately

**Oversized OP_RETURN is currently negligible: 12.3 MB.**

Bitcoin Core v30 raised the default datacarrier limit from 83 bytes to 100,000
in October 2025. Ten months later, across the entire inscription era, only
12.3 MB of OP_RETURN data exceeds the old limit. Almost all OP_RETURN usage
still respects 83 bytes.

An earlier version of this tool reported 2.9 GB because it classified *every*
OP_RETURN as spam, including small compliant ones. That figure was wrong and is
retracted here. The distinction matters: the argument that raising the limit
would flood the chain has not, so far, been borne out in the data.

**The Stamps figure of 0 bytes is not trustworthy.** A UTXO measurement of the
same chain found 2,646,140 unspent bare multisig outputs totalling 384 MB, so
Stamps data clearly exists. The detector used here flags only keys whose first
byte is not `02`, `03` or `04` — but Stamps deliberately use those prefixes so
their outputs pass standardness checks, and so they are not caught.

Correct detection requires testing whether each key is genuinely a point on the
secp256k1 curve (y² = x³ + 7 mod p, checked for quadratic residuosity). Real
public keys always are; data stuffed into key positions almost never is. Until
that is implemented, treat the Stamps row as unmeasured rather than zero.

Oversized scriptSig at 13.8 KB is measured and genuinely negligible.

## What this does not cover

**Dust outputs in chainstate.** This tool operates on block storage. Inscription
dust outputs are retained here as monetary outputs; removing them is a separate
mechanism at the chainstate layer, measured separately at 3.6 GB of an 11.8 GB
UTXO set (30.84%). The two should not be added together without care — they are
different layers with different mechanisms.

**Legacy node service.** A node storing stripped blocks cannot serve initial
block download to a conventional full node, which requires complete block data.

**Re-validation under future rules.** Stripped transactions cannot be
re-verified. They were validated once, in full, when the block was connected.

## Method and validation

Blocks are read directly from `blk*.dat`, handling the XOR-obfuscated blocksdir
introduced in Core 28. The block index is reconstructed from prev-hash links,
since block files do not record heights.

**The merkle check is the validation.** If the txid computation were wrong by a
single byte in any transaction, that block's root would not match its header.
194,863 consecutive matches is a complete check on the approach.

**Cross-tool agreement.** The inscription figure of 37.1 GB is identical to that
produced by `inscription_scan_local.py`, a separate tool with an independent
implementation. On a shared 101-block sample the two agreed on payload bytes
exactly and on transaction counts within 0.6%.

**False positives.** The envelope classifier was run over blocks 709,632–715,000
— after Taproot activation, before the first inscription, containing genuine
script-path spends. Result: zero envelopes across 9,847,964 transactions.

## Reproducing

```
python3 spam_strip.py \
  --blocks /path/to/bitcoin/blocks \
  --start 767430 --end 962292 \
  --csv results.csv
```

Requires a non-pruned node. Standard library only. 7h34m on Umbrel-class
hardware, plus indexing. Resumable with `--resume`.

Per-block output in `results.csv`: height, original and retained bytes,
transaction counts by treatment, stored txids, filter entries, bytes removed by
carrier, and the merkle result for every block.

## Licence

BSD-2-Clause. Independent reruns welcome, particularly disagreements about
where the classification boundaries should sit.
