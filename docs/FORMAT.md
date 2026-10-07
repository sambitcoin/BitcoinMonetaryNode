# Monetary block store — storage format

The on-disk format a monetary node uses in place of `blk*.dat`. Reference
implementation: `monetary_store.py`. Verification suite:
`test_monetary_store.py`, **56 checks**, all passing.

This is the specification a second implementation would follow. It is written to
be sufficient on its own — if you build from this and get a different commitment
over the same range, one of us has a bug and the per-block chain will say which
block.

## Why a block survives losing its data

A block's merkle root is computed over **txids**. The store keeps the 32-byte
txid of every transaction it modifies or discards. Nothing downstream needs to
re-derive those from transaction data — so the data can be removed and the block
still verifies against its header, against real proof-of-work.

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
monetary output left once its carriers were removed, so only the txid remains.

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

Everything needed to validate a future spend of a dropped output locally, with
no peer involvement. Roughly 82 bytes each.

Measured across blocks 767,430–962,292: 806,626 entries written, **seven of
which were ever read** — seven dropped outputs were spent in four years. All
seven validated locally; six had their ECDSA signatures re-verified against
scriptPubKeys recovered from the index. The index is almost pure insurance, and
it costs about 66 MB.

## Reading a record

1. Check magic and version.
2. Recompute the body digest and compare. Reject on mismatch.
3. Recompute the block hash from the header and compare.
4. Walk the transaction entries, building the txid list.
5. Compute the merkle root over that list and compare against bytes 36–68 of
   the header.
6. Verify the header's proof-of-work against the target its own `nBits` encodes,
   and check that target against the network minimum.

A record passing all six is proven to be the block at that position in the
chain, with its carriers absent.

## What each integrity mechanism covers

This distinction was found by testing rather than designed in, and it matters.

**The merkle root covers retained whole transactions.** Corrupt one byte and its
computed txid changes, the root no longer matches, the block is rejected.

**The merkle root does not cover modified bodies or filter entries.** For those
the txid is stored rather than derived, so it keeps matching whatever happens to
the body beneath it. A corrupted filter entry — a wrong amount on a dropped
output — would pass a merkle check silently.

**The body digest covers everything.** It is what makes corruption in those
regions detectable at all. The test suite includes a check that the merkle root
alone would *not* have caught filter-entry corruption, so the digest is
demonstrably doing work rather than duplicating an existing guarantee.

**The body digest is local integrity only.** It detects damage; it does not
detect a peer sending a consistent-but-false record. Agreement between nodes is
the job of the commitment.

## The commitment

    C_h = SHA256d( C_{h-1} ‖ block hash_h ‖ K_h )

where **K is the record's body digest** — a hash over everything stored for that
block: retained transactions, stored txids, and every filter entry.

Two nodes that made identical stripping decisions produce identical C at every
height. One disagreement anywhere diverges permanently and visibly. So "do we
agree?" reduces to comparing 32 bytes.

C is **derived from the store**, computed by reading it back, not written during
stripping. A node therefore cannot assert a commitment its own data does not
support, and any reviewer can recompute it independently.

**A note on an earlier version of this document**, which specified
`C_h = SHA256d(C_{h-1} ‖ block hash ‖ L_h ‖ M_h)` with L and M as MuHash
accumulators over the full and filtered UTXO sets. That design is not
implemented — it requires a UTXO database — and the formula above is what the
code actually does. C as implemented commits to **stripping decisions**, not to
UTXO set state. It answers "did we strip identically", not "do we hold identical
UTXO sets". Those are different questions and only the first is answered.

C confers no security of its own. It anchors to proof-of-work by reference,
mixing in block hashes that real work committed to. It is not proof of that
work.

## Carriers removed

| Carrier | Test |
|---|---|
| Inscription envelopes | Data pushed inside an unexecutable branch: a **false** push before `OP_IF`, or a **true** push before `OP_NOTIF`. Falsity by script semantics rather than opcode literal, so `OP_0`, an empty push and a push of `0x00` all qualify. Detected in taproot script-path witnesses **and** in P2WSH witness scripts. |
| Stamp-style bare multisig | Keys that are not points on secp256k1. |
| Fake keys in bare P2PK | The same on-curve test applied to `<key> OP_CHECKSIG`. |
| OP_RETURN over the datacarrier limit | Outputs above 83 bytes. Compliant ones are left alone. |
| Oversized scriptSig | Input scripts beyond the standard limit. |
| Dust outputs | Sub-1000-sat P2TR from block 767,430 onward — **chainstate layer only**, retained in blocks. |

### On the branch test

Only two of the four combinations are carriers, and getting this wrong in either
direction is a bug:

| Construction | Branch | Carrier? |
|---|---|---|
| false push, `OP_IF` | skipped | **yes** |
| true push, `OP_NOTIF` | skipped | **yes** |
| false push, `OP_NOTIF` | executes | no |
| true push, `OP_IF` | executes | no |

Data inside an executing branch would be run as script and the spend would
fail, so those are not carriers. Flagging them would mean stripping data from
transactions that legitimately contain it. Both negative cases are tested.

### On the curve test

Stamps prefix their fake keys with `02` or `03` so the outputs look standard.
Checking the prefix therefore catches nothing, which is why an earlier version
of this work reported **zero bytes** for that carrier — a clean zero that read
like a finding.

The reliable test is whether each key is genuinely a point on secp256k1: compute
`y² = x³ + 7 mod p` and check quadratic residuosity by Euler's criterion. A real
public key always passes. Arbitrary data passes about half the time by chance,
so one key is weak evidence — but a bare multisig carries several, and the
probability that all of them land on the curve by accident halves with each one.

Verified in the suite: the generator passes, random data passes at 94/200,
`02`-prefixed off-curve data is caught, and genuine compressed and uncompressed
keys are not.

The same test also *reduced* a figure: an earlier UTXO scan counted 2,646,140
bare multisig outputs as Stamps; only 963,024 actually carry data. A detector
that only ever finds more spam is one nobody should trust.

## Dust and the two layers

Dust outputs are **retained in block storage** and **excluded from chainstate**.

Arithmetic, not preference. Inside its transaction a P2TR dust output costs
**43 bytes** — amount, script length, script — because the block supplies the
height and its position supplies the outpoint. Extracting it into a standalone
filter entry costs **~82 bytes**. Removing it from blocks would roughly double
its cost.

Removing it from the random-access UTXO database is a clear win: 5.09 GB,
31.97%, with **zero additional storage**, because the data is already in block
storage.

The two layers use different mechanisms and their savings must not be added
together.

## Classifier versioning

**Changing the classifier changes C.** Stores built under different rules
produce different commitments over the same blocks, and neither is wrong.

The published value

    f0e4c825e753cc9469a2027425c9625801f2bf8662f2e6b3cdbc4647b8406b61

is correct for blocks 767,430–962,292 under the rules *before* `OP_NOTIF`, P2WSH
and bare-P2PK detection were added. A store built with the current rules will
differ.

The record format is unchanged, so version 1 still describes the layout. Anyone
comparing commitments must state which rule set they used.

## Verification suite

`python3 test_monetary_store.py` builds synthetic blocks containing every
carrier, with real merkle roots computed the way Bitcoin computes them, and
checks **56 properties**:

- curve arithmetic, including that real keys are never flagged
- multisig and bare-P2PK detection, compressed and uncompressed
- envelope detection across all falsity encodings, in taproot and P2WSH, with
  negative cases for branches that execute
- output classification at each boundary
- end-to-end strip, persist, reload, verify
- multi-record files read sequentially
- tamper resistance: forged txids, corrupted bodies, corrupted filter entries,
  and proof that the merkle root alone would not have caught the last of these

## Usage

```
python3 monetary_store.py --blocks /path/to/bitcoin/blocks \
    --start 0 --end 962292 --out /path/to/mstore

python3 monetary_store.py --verify /path/to/mstore
```

Standard library only. Requires a non-pruned node. The reader handles the
XOR-obfuscated blocksdir introduced in Core 28 — a reader that ignores it finds
zero blocks **and reports no error**.

## Known limits

- **19.34% of transactions lose signature re-verifiability.** `SIGHASH_ALL`
  commits to a transaction's outputs, and the stripper removes some of them, so
  a modified transaction's signed preimage cannot be reconstructed. The 80.66%
  retained whole are unaffected. All were validated in full, once, when their
  block was connected.
- A store cannot serve initial block download to a legacy node, which requires
  complete blocks. Monetary nodes serve each other.
- Coverage is not complete and cannot be: data in a 20-byte hash160 or a 32-byte
  witness program is indistinguishable from a legitimate output. See
  `CARRIERS.md`.
- Commit outputs — 4.97 GB, measured, identifiable exactly — are **not yet
  removed**. They sit in earlier blocks than the reveals that identify them.
- The format is version 1 and not yet stable.

## Licence

BSD-2-Clause.
