# Monetary IBD — the design

How monetary nodes bootstrap each other without legacy nodes, while storing no
spam. Established 13 August 2026.

## The requirement

Monetary nodes must be able to serve initial block download to other monetary
nodes. If they cannot, the network stays permanently dependent on nodes that
store spam, and the endgame fails.

## The problem this solves

A block's identity is its header hash. The header commits to a **merkle root**,
and that merkle root is computed over **txids**.

If a node strips spam from a block and stores the reduced version, the stripped
transactions no longer hash to their original txids. A receiving node therefore
cannot rebuild the merkle root, cannot match it against the header, and cannot
confirm the block is real. The block becomes unverifiable — which is why every
earlier version of this design was non-archival.

## The construction

Store the **txid** of every stripped transaction.

A monetary node retains, per block:

| What | Size | Purpose |
|---|---|---|
| Block header | 80 bytes | Proof-of-work, merkle root |
| Monetary transactions, in full | as-is | The payment record |
| Txid of each stripped transaction | 32 bytes each | Rebuilds the merkle root |
| Filter index entry per spam output | ~80 bytes | outpoint, amount, scriptPubKey |
| L, M, C | 96 bytes | State commitments (C chained) |

A 400 KB inscription transaction is reduced to 32 bytes.

## Stripping: what happens to a block, step by step

This is the operation performed once, by a node that has the original block,
and never again thereafter.

**Input:** a block exactly as mined, containing monetary transactions,
inscription-bearing transactions, OP_RETURN payloads, bare multisig data
outputs, and whatever else.

**Step 1 — validate completely.** Every rule, every signature, every script,
identical to Bitcoin Core. Nothing is skipped or deferred. Chainstate is updated
normally at this moment, including for spam outputs, because they must be
tracked to validate the block. This is the only point at which the full block
is required, and it happens exactly once.

**Step 2 — classify.** Each transaction is sorted as monetary or non-monetary
by the deterministic rules: inscription envelopes in taproot script-path
witnesses, stamp-style bare multisig encodings, registered OP_RETURN token
markers, dust-creating outputs. Classification is syntactic and requires no
external index.

**Step 3 — record what will be lost.** Before anything is discarded:

- The **txid** of every transaction to be stripped is written down. This is the
  piece that preserves verifiability, and it is why the merkle root survives.
- For every spam **output**, a filter index entry is written: outpoint, amount,
  scriptPubKey, and creation height. Around 80 bytes. This is what allows a
  future spend of that output to be validated in full.
- Every discarded output is folded into the **L accumulator** before removal, so
  the full-state commitment remains correct without the data being retained.

**Step 4 — discard.** The bodies of non-monetary transactions are dropped:
inscription witness payloads, OP_RETURN data, bare multisig fake keys, scriptSig
data. Nothing of the payload survives in any carrier.

**Step 5 — commit.** L and M are updated, and C is computed and chained onto the
previous C.

**Output:** a stored record consisting of the block header, the monetary
transactions in full, a list of txids for what was removed, filter index
entries, and the three commitments.

## Reconstitution: how a receiving node becomes a full monetary node

A new node syncing from monetary peers receives that stored record. It does not
receive, and never sees, any spam data.

**Rebuild the merkle root.** It computes txids for every monetary transaction it
received, takes the stored txids for the stripped ones, orders them as they
appeared in the block, and builds the merkle tree. The result matches the merkle
root in the header. **The block is now proven authentic** — the receiving node
knows this exact set of transactions was mined into a block carrying real
proof-of-work.

**Verify proof-of-work.** Standard header validation, unchanged, back to genesis.

**Tie its own history to the chain.** Every monetary transaction it holds can be
independently hashed and located in the merkle tree. Every payment in the node's
record is cryptographically bound to a mined block. Nothing about the payment
history rests on trust.

**Construct chainstate.** Monetary outputs are applied to the UTXO set exactly
as a normal node would. Spam outputs are not added — they never enter the
working database.

**Load the filter index.** Entries for spam outputs are stored so that if one is
ever spent by a future transaction, the node has the amount and scriptPubKey
needed to validate that spend completely. Supply integrity is enforced locally
and never depends on a peer.

**Recompute L, M and C independently.** Not adopted from the peer — derived. The
node then compares its C against peers. Agreement across the chained values
attests that every derivation since activation matched; divergence anywhere is
permanent and immediately visible.

**Result:** a node that validates every new block under full consensus rules,
holds the complete monetary history of Bitcoin bound to proof-of-work, can
validate any spend including of long-discarded outputs, and can serve all of the
above to the next monetary node — having never stored or transmitted a byte of
spam.

## What a receiving node can verify

1. **Proof-of-work** — from the header, unchanged.
2. **Merkle root** — recompute the full txid list: derive txids from the
   monetary transactions it received, take the stored txids for the stripped
   ones, build the tree. **It matches the header.** The block is confirmed
   authentic.
3. **Monetary transactions** — independently recompute each txid and confirm it
   appears in the merkle tree at the expected position. Every payment in the
   node's history is cryptographically tied to a proof-of-work-secured block.
4. **UTXO set** — constructed from monetary outputs directly.
5. **Future spends of spam outputs** — validated from the filter index, which
   carries the amount and scriptPubKey. Supply integrity is enforced locally.

So the chain is verified against real proof-of-work without a single byte of
spam being transmitted or stored.

## What it cannot verify, stated plainly

**Validity of the stripped transactions themselves.** A syncing node accepts
them on accumulated proof-of-work rather than re-checking their scripts. This
is the same posture as Bitcoin Core's `assumevalid` default, which every Core
user already runs — it is not a new trust assumption, but it must be disclosed.

**Correctness of the serving node's filter index.** The receiving node takes
the amount and scriptPubKey of spam outputs on trust. Divergence between peers
is detectable by comparing the chained C values, so a dishonest or buggy node
is caught — but the guarantee is consistency across independent derivations,
not standalone proof.

**Service to legacy nodes.** A monetary node cannot serve IBD to a conventional
full node, which requires complete block data. The monetary network becomes
self-sufficient; it does not serve the old one.

## Why C matters here

C_h = SHA256d(C_{h-1} ‖ block hash_h ‖ L_h ‖ M_h), chained from the activation
height.

Because derivation is deterministic, two honest monetary nodes produce identical
C values at every height. A single comparison at the tip therefore attests
agreement across the entire derivation history, including every filter index
entry that fed into M. Any divergence — a stripping bug, a bad index entry, a
dishonest peer — propagates forward permanently and is visible immediately.

C is not proof-of-work and does not confer authority. It is anchored to a
proof-of-work-secured block hash, and it makes disagreement detectable.

## Storage consequence

Full spam removal, in every carrier: inscription witnesses, OP_RETURN payloads,
bare multisig data, scriptSig data. Nothing is retained but the 32-byte txid and
the filter index entry needed to validate a future spend.

Unlike prior versions of this design, block-level removal no longer costs
archival capability *within the monetary network*.

## Open questions

- Exact serialisation of the stored block format, and its versioning.
- Whether the filter index should be committed in a root of its own, so peers
  can compare it independently of M.
- Reorg handling for stripped blocks: undo data and the reorg window.
- Whether the merkle position of each monetary transaction should be stored, to
  allow inclusion proofs without rebuilding the whole tree.
- Storage engine: this is a non-canonical format and cannot flow through code
  paths expecting a valid `CBlock`.

## Status

Design, not implementation. Not yet reviewed adversarially — the earlier
versions each survived one round and failed the next, and this one has not been
tested at all. Next step is the same treatment: hand it to independent models
and to developers, and see what breaks.
