# Removing all spam from Bitcoin block storage — a demonstration

Blocks **767,430 – 962,292** (194,863 blocks) on a fully synced Bitcoin Knots
node. Every non-monetary carrier stripped, the result written to disk in a
defined storage format, and every block's merkle root rebuilt and checked
against its header.

> **194,863 blocks. Zero merkle failures.**

Every block remains verifiable against its proof-of-work with all spam removed.

## The mechanism

A block's merkle root is computed over **txids**. The store keeps the 32-byte
txid of every transaction it modifies or discards. Nothing downstream needs to
re-derive those txids from transaction data, so the data can be removed and the
block still verifies against its header.

This is the point that makes full spam removal possible. The common objection —
that OP_RETURN or output data cannot be removed because it is committed inside
the txid — applies only to designs that recompute txids. It does not apply when
the txid is stored.

The stored txids are **self-verifying**: fabricated ones produce a merkle root
that does not match the header, and the block is rejected. They cannot be
forged.

Transactions retained unmodified need no stored txid — a receiving node computes
those itself. Only modified or fully stripped transactions pay the 32 bytes.

## Results

| | |
|---|---|
| Blocks | 194,863 |
| Transactions | 628,773,234 |
| — retained whole | 507,173,533 (80.66%) |
| — modified | 121,599,086 (19.34%) |
| — fully stripped | 615 |
| Stored txids | 121,599,701 (3.9 GB) |
| Filter index entries | 806,626 |
| Run time | 7h24m |

**Spam removed by carrier**

| Carrier | Removed |
|---|---|
| Inscription envelopes (taproot witness) | 37.1 GB |
| Stamp-style bare multisig | 77.5 MB |
| OP_RETURN over 83 bytes | 12.3 MB |
| Oversized scriptSig | 13.8 KB |
| **Total** | **37.2 GB** — 12.56% of block bytes |

**Storage**

| | |
|---|---|
| Original blocks | 296.2 GB |
| Monetary store | 247.4 GB (83.54%) |
| **Saved** | **48.7 GB (16.46%)** |

**Merkle verification: 194,863 verified, 0 failed.**

## Read the two storage numbers carefully

**37.2 GB is the spam figure. 48.7 GB is the storage figure. They are not the
same thing and should not be quoted interchangeably.**

The difference is a deliberate design decision, and here is the full
accounting:

| | |
|---|---|
| Spam carriers removed | +37.2 GB |
| Remaining witness of modified transactions | +15.4 GB |
| Stored txids added back | −3.9 GB |
| **Net saving** | **48.7 GB** |

When a transaction is modified, the store discards its **entire** witness, not
only the inscription envelope inside it. Signatures and control blocks go too.
Those are not spam — they are ordinary transaction machinery — and they are
dropped because that transaction has already been altered and can no longer be
re-verified regardless.

That is defensible, but it is a separate claim from spam removal, and it has a
cost: those transactions cannot be re-checked even under current rules.
Retaining signature witness on modified transactions would give back roughly
15 GB of the saving and preserve re-verifiability. The current code takes the
bytes.

**If you quote one number, quote 37.2 GB.** That is what spam costs.

## The Stamps figure was wrong, and is now fixed

An earlier run reported **0 bytes** for stamp-style bare multisig. That was a
detector failure, not a finding.

The old check flagged only keys whose first byte was not `02`, `03` or `04`.
Stamps deliberately use those prefixes so their outputs pass standardness
checks, so the check caught nothing and returned a clean zero — the worst kind
of wrong, because a zero reads as a result.

A UTXO measurement of the same chain had already found 2,646,140 unspent bare
multisig outputs totalling 384 MB, which is what made the zero obviously
suspect.

**The corrected test** asks whether each key is genuinely a point on secp256k1:
compute y² = x³ + 7 mod p and check quadratic residuosity by Euler's criterion.
A real public key always passes. Arbitrary data passes about half the time by
chance, so one key is weak evidence — but a bare multisig output carries
several, and the probability that all of them land on the curve by accident
halves with each one.

Result across the era: **77.5 MB**, and the filter index grew from 32,432
entries to 806,626 — almost entirely bare multisig outputs the old detector
could not see.

**Independently corroborated.** A 2,001-block sample from blocks 900,000–902,000
found ~23,900 such outputs, about 12 per block. Extrapolated across the era that
is roughly 2.3 million, against the 2,646,140 the UTXO scan found unspent. Two
tools, different data sources, same order of magnitude.

## Oversized OP_RETURN is still negligible

**12.3 MB across the entire era.**

Bitcoin Core v30 raised the default datacarrier limit from 83 bytes to 100,000
in October 2025. Ten months later, only 12.3 MB of OP_RETURN data exceeds the
old limit. Almost all OP_RETURN usage still respects 83 bytes.

A 2,001-block sample of recent blocks (900,000–902,000) found just 10.2 KB,
confirming the pattern holds at the tip rather than being an artifact of
averaging over the whole era.

An earlier version of this tool reported 2.9 GB because it classified *every*
OP_RETURN as spam, including small compliant ones. That figure was wrong and is
retracted. The argument that raising the limit would flood the chain has not,
so far, been borne out.

## The store, not just the measurement

This does not only measure what stripping would save. It writes the stripped
blocks to disk in a defined format and reads them back.

Blocks 900,000–902,000, written and re-verified **reading nothing but the
store** — no `blk*.dat` involved:

| | |
|---|---|
| Blocks verified from disk | 2,001 |
| Failed | 0 |
| Records corrupt | 0 |
| Retained whole | 4,395,514 (90.5%) |
| Fully stripped | 0 |
| Filter entries | 23,914 |

Every block was reconstructed from the store alone and matched its own header.
That is the difference between showing spam *could* be removed and showing a
node can hold the result and still prove it belongs to the chain.

Format specification in `FORMAT.md`; 42-check verification suite in
`test_monetary_store.py`.

## What is stripped

**Inscription envelopes** — data pushed inside unexecutable branches of taproot
script-path witnesses. Falsity is evaluated by script semantics rather than by
matching an opcode literal, so `OP_0`, an empty push and a push of `0x00` all
qualify and re-encoded variants are not missed.

**Stamp-style bare multisig** — outputs whose public keys are not valid
secp256k1 curve points, indicating data stuffed into key positions.

**OP_RETURN over the datacarrier limit** — only outputs exceeding 83 bytes.
Outputs within the limit are treated as monetary and left untouched: they are
policy-compliant, provably unspendable, and never enter the UTXO set.

**Oversized scriptSig** — input scripts beyond the standard limit.

Every dropped output receives a filter index entry (outpoint, amount,
scriptPubKey, height) so a future spend can still be validated in full, locally,
with no peer involvement.

## Dust: retained in blocks, removed from chainstate

127,021,924 dust outputs were identified. They are **kept** in block storage and
excluded at the chainstate layer instead, because the arithmetic runs opposite
ways in the two places.

Inside its transaction a P2TR dust output costs **43 bytes** — amount, script
length, script — because the block supplies the height and its position supplies
the outpoint. Extracting it into a standalone filter entry costs **~82 bytes**,
since all that context must become explicit. Removing it from blocks would
roughly double its cost.

Removing it from the random-access UTXO database is a clear win, and the data
remains in block storage if a spend ever needs it. So nothing is duplicated,
nothing is confiscated, and no peer is trusted — the node can still validate a
spend of a filtered output by itself.

**The two layers must not be added together.** Block storage removal deletes
data outright. Chainstate removal takes entries out of a database that wants to
live in RAM. Both are real; only the first is deletion.

**The dust figure is a proxy.** Any sub-1000-sat P2TR output from block 767,430
onward is counted, which includes ordinary small payments to taproot addresses
and excludes inscription outputs above the threshold. It is not a direct
measurement of inscription activity.

## What this does not cover

**Legacy node service.** A node storing stripped blocks cannot serve initial
block download to a conventional full node, which requires complete block data.

**Re-validation under future rules.** Modified and stripped transactions cannot
be re-verified. They were validated once, in full, when the block was connected.

**Wallet history for fully stripped transactions.** 615 transactions were reduced
to a txid alone, which loses their inputs and so breaks the link from a spent
output to its spending transaction. That is 615 of 628.8 million, but it is a
correctness gap rather than a rounding error, and it is not yet fixed.

## Method and validation

Blocks are read directly from `blk*.dat`, handling the XOR-obfuscated blocksdir
introduced in Core 28. The block index is reconstructed from prev-hash links,
since block files do not record heights.

**The merkle check is the validation.** If the txid computation were wrong by a
single byte in any transaction, that block's root would not match its header.
194,863 consecutive matches is a complete check on the approach.

**Cross-tool agreement.** The inscription figure of 37.1 GB is identical to that
produced by `inscription_scan_local.py`, a separate tool with an independent
implementation, and identical to that produced by the earlier `spam_strip.py`
run.

**False positives.** The envelope classifier was run over blocks 709,632–715,000
— after Taproot activation, before the first inscription, containing genuine
script-path spends. Result: zero envelopes across 9,847,964 transactions.

**Curve arithmetic.** The multisig detector is checked against the secp256k1
generator (passes), genuine uncompressed keys (pass), and `02`-prefixed
off-curve data (flagged), plus a statistical check that random data lands
on-curve about half the time.

## Reproducing

```
python3 build_index.py --blocks /path/to/bitcoin/blocks

python3 monetary_store.py --blocks /path/to/bitcoin/blocks \
  --start 767430 --end 962292 --out /path/to/mstore

python3 monetary_store.py --verify /path/to/mstore
```

Requires a non-pruned node and ~250 GB free. Standard library only. The index
build is a one-time cost — it reads 1.81 GB of 696 GB of block files, about ten
minutes — and is cached and updated incrementally thereafter.

## Licence

BSD-2-Clause. Independent reruns welcome, particularly disagreements about
where the classification boundaries should sit.
