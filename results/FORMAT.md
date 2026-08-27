# Monetary block store — storage format

The on-disk format a monetary node uses in place of `blk*.dat`. Reference
implementation: `monetary_store.py`. Verification suite:
`test_monetary_store.py`, 42 checks, all passing.

This is the specification an implementation would follow. Everything prior to
it measured what stripping saves; this defines what is actually stored.

## Why a block survives losing its data

A block's merkle root is computed over **txids**. The store keeps the 32-byte
txid of every transaction it modifies or discards. Nothing downstream needs to
re-derive those from transaction data — so the data can be removed and the
block still verifies against its header, against real proof-of-work.

The stored txids are self-verifying. A fabricated txid produces a merkle root
that does not match the header, and the block is rejected. The list cannot be
forged.

Transactions retained whole need no stored txid: the reader computes those
itself. Only modified or discarded transactions pay the 32 bytes.

## Record layout

Records are written sequentially into `mblk*.dat`, rolling at a configurable
size (128 MB by default).

| Field | Bytes | Notes |
|---|---|---|
| magic | 4 | `4D 42 4C 4B` (`MBLK`) |
| version | 2 | little-endian, currently `1` |
| record length | 4 | little-endian, counts everything after this field |
| body digest | 32 | `SHA256d` over everything after this field |
| block hash | 32 | index convenience; recomputed from the header, never trusted |
| header | 80 | verbatim, unmodified |
| transaction count | varint | |
| transactions | … | see below |
| filter count | varint | |
| filter entries | … | see below |

### Transaction entries

Each begins with a one-byte flag.

| Flag | Meaning | Followed by |
|---|---|---|
| `0` | retained whole | varint length, then the transaction verbatim |
| `1` | modified | 32-byte txid, varint length, then the reduced body |
| `2` | stripped | 32-byte txid only |

For flag `0` the reader computes the txid itself, stripping witness data first
if the transaction is SegWit-serialised. For flags `1` and `2` it uses the
stored txid.

A **modified** body is the transaction reserialised in legacy form with dropped
outputs removed and witness data discarded. A **stripped** transaction had no
monetary output left once its spam was removed, so only the txid remains.

### Filter entries

One per dropped output.

| Field | Bytes |
|---|---|
| txid | 32 |
| vout | varint |
| amount | 8, little-endian |
| height | 4, little-endian |
| scriptPubKey length | varint |
| scriptPubKey | n |

This is everything needed to validate a future spend of a dropped output
locally, with no peer involvement. Roughly 80 bytes each.

## Reading a record

1. Check magic and version.
2. Recompute the body digest and compare. Reject on mismatch.
3. Recompute the block hash from the header and compare.
4. Walk the transaction entries, building the txid list.
5. Compute the merkle root over that list and compare against bytes 36–68 of
   the header.
6. Verify the header's proof-of-work as normal.

A record passing all six is proven to be the block at that position in the
chain, with all spam absent.

## What each integrity mechanism covers

This distinction was found by testing, not by design, and matters.

**The merkle root covers retained whole transactions.** Corrupt one byte and
its computed txid changes, the root no longer matches, the block is rejected.

**The merkle root does not cover modified bodies or filter entries.** For those
the txid is stored rather than derived, so it keeps matching whatever happens to
the body beneath it. A corrupted filter entry — a wrong amount on a dropped
output — would pass a merkle check silently.

**The body digest covers everything.** It is what makes corruption in those
regions detectable at all.

**The body digest is local integrity only.** It detects damage; it does not
detect a peer that sends a consistent-but-false record. Agreement between nodes
is the job of the chained commitment

    C_h = SHA256d(C_{h-1} ‖ block hash_h ‖ L_h ‖ M_h)

which is compared across nodes and makes divergence visible. The digest and the
commitment answer different questions and neither substitutes for the other.

## Dust and the two layers

Dust outputs are **retained in block storage** and **excluded from chainstate**.

This is deliberate, and it is an arithmetic result rather than a preference.
Dropping a dust output from a block saves its ~42 bytes but costs an ~80-byte
filter entry — a net loss. The saving from dust is real at the chainstate
layer, where the UTXO entry is what you avoid carrying, and it is large: 30.84%
of the UTXO set by bytes.

So the two layers are handled by different mechanisms and their savings should
not be added together carelessly. `monetary_store.py` reports the dust outputs
it identifies so the chainstate figure can be tracked alongside the block one.

## Carriers removed

| Carrier | Test |
|---|---|
| Inscription envelopes | Data pushed inside unexecutable branches of taproot script-path witnesses. Falsity by script semantics, not opcode literal, so `OP_0`, an empty push and a push of `0x00` all qualify. |
| OP_RETURN over the datacarrier limit | Outputs above 83 bytes. Compliant ones are left alone. |
| Stamp-style bare multisig | Keys that are not points on secp256k1. |
| Oversized scriptSig | Input scripts beyond the standard limit. |
| Dust outputs | Sub-1000-sat P2TR from block 767,430 onward — chainstate layer. |

### On the multisig test

Stamps prefix their fake keys with `02` or `03` so the outputs look standard.
Checking the prefix therefore catches nothing, which is why an earlier version
of this work reported zero bytes for this carrier.

The reliable test is whether each key is genuinely a point on secp256k1:
compute `y² = x³ + 7 mod p` and check quadratic residuosity by Euler's
criterion. A real public key always passes. Arbitrary data passes about half
the time by chance, so a single key is weak evidence — but a bare multisig
output carries several, and the probability that all of them land on the curve
by accident halves with each one.

Verified in the test suite: the secp256k1 generator passes, random data passes
at 94/200, and 02-prefixed off-curve data is caught.

## Verification suite

`python3 test_monetary_store.py` builds synthetic blocks containing every
carrier, with real merkle roots computed the way Bitcoin computes them, and
checks 42 properties across seven groups:

- curve arithmetic, including that real keys are never flagged
- multisig detection, both compressed and uncompressed genuine keys
- envelope detection across all three falsity encodings
- output classification at each boundary
- end-to-end strip, persist, reload, verify
- multi-record files read sequentially
- tamper resistance: forged txids, corrupted bodies, corrupted filter entries

The tamper group includes a check that the merkle root alone would **not** have
caught filter-entry corruption — so the digest is demonstrably doing work
rather than duplicating an existing guarantee.

## Usage

```
python3 monetary_store.py --blocks /path/to/bitcoin/blocks \
    --start 800000 --end 810000 --out /path/to/mstore

python3 monetary_store.py --verify /path/to/mstore
```

Standard library only. Requires a non-pruned node. The reader handles the
XOR-obfuscated blocksdir introduced in Core 28.

## Known limits

- Modified and stripped transactions cannot be re-validated under future
  consensus rules. They were validated once, in full, when the block was
  connected.
- A store cannot serve initial block download to a legacy node, which requires
  complete blocks.
- Witness data is discarded for modified transactions, including signature
  material, so those transactions cannot be re-verified even under current
  rules.
- The format is version 1 and not yet stable.

## Licence

BSD-2-Clause.
