# BIP-XXXX: Monetary Nodes — Parallel State Commitments for a Spam-Free Bitcoin

```
BIP:     XXXX
Layer:   Peer Services
Title:   Monetary Nodes — Parallel State Commitments for a Spam-Free Bitcoin
Author:  Neal Sampat <sampat.neal@gmail.com>
Status:  Draft
Type:    Standards Track
Created: 2026-08-04
License: BSD-2-Clause
```

## Abstract

This document specifies a node policy class, referred to as a Monetary Node, which performs full consensus validation identical to that of a standard full node while excluding non-monetary data (inscription, stamp, and token-protocol outputs) from transaction relay and from its persistently stored unspent transaction output (UTXO) set. Non-monetary outputs are deleted from the node's working database immediately after each block is validated; they never persist in chainstate.

This deletion produces two views of UTXO state under a single, unmodified chain. Beginning at block height 680,000, a conforming node therefore computes two per-block commitments: a legacy state root, committing to the complete UTXO set, and a monetary state root, committing to the UTXO set as it stands after spam deletion. As a tamper-evidence measure, the two roots are bound together with the block hash into a single paired commitment, ensuring that neither view can be presented apart from — or mismatched with — the chain and the full state from which it was derived.

To permit rapid bootstrap of new Monetary Nodes from existing ones, this document further specifies a snapshot mechanism modeled on Bitcoin Core's `assumeutxo`: each software release commits to the hash of the monetary UTXO snapshot at a recent checkpoint height, incorporating the paired commitment so that a fabricated filtered view cannot masquerade as one derived from the real chain. A new node obtains the snapshot from any Monetary Node peer, verifies it against the release-committed hash, and becomes operational immediately — followed by mandatory background download and full validation of the historical chain, obtainable from Monetary Node peers or from any archival full node, which cross-verifies the snapshot and converges the node on fully self-validated state.

Block hashes, transaction validity rules, and chain selection are unmodified. This proposal requires no change to consensus rules and no fork of any kind.

In essence: **the spam is deleted; the hashes are saved.** A Monetary Node discards the content of non-monetary outputs from its working database the moment each block is validated, while permanently retaining every block hash, a compact index of what was removed, and dual commitments to both views of UTXO state. Full historical blocks remain available — locally or from the network — for the rare cases where discarded data must be re-examined. The result is a fully validating node at roughly half the chainstate, on the same chain, under the same rules, secured by the same proof-of-work.

## Motivation

The Bitcoin network exists to provide final settlement of value without a trusted third party. It is, first and last, money — and every property that makes it valuable, from its fixed supply to its permissionless validation, depends on ordinary participants being able to verify the ledger cheaply and completely. Data-embedding schemes that repurpose transaction outputs as storage — inscriptions, stamps, and token protocols — impose costs on all validating nodes while contributing nothing to this function. Whatever their merits as applications, they are tenants who do not pay rent: their data must be stored, indexed, and verified forever by parties who derive no benefit from it. These costs are material and compounding:

1. **UTXO set growth.** The UTXO set grew gradually to approximately 80–90 million entries between 2009 and early 2023. Following the emergence of inscription protocols, it exceeded 160 million entries within approximately one year and currently exceeds 173 million. Independent analyses estimate that 40–50% of current entries are data-embedding outputs that are unlikely ever to be spent. Each such entry must be retained in chainstate by every full node indefinitely.

2. **Fee market displacement.** Data-embedding transactions compete with monetary settlement for block space, raising the cost of value transfer.

3. **Validation cost.** UTXO set growth increases initial block download time, memory requirements, and the hardware cost of operating a fully validating node, with corresponding pressure on network decentralization.

4. **Long-term risk.** Because the storage burden of unspent data outputs is unbounded and borne by parties who receive no benefit from them, continued growth of non-monetary usage constitutes a structural risk to the network's ability to remain cheaply and widely validated.

### Relationship to prior work

This proposal is informed by the BIP draft known as "The Cat" (Ostrom, December 2025), which identified the same problem and proposed a consensus-level soft fork rendering identified data-embedding outputs permanently unspendable, permitting their removal from chainstate. That proposal demonstrated the scale of the problem but encountered substantive objections: it invalidates previously valid outputs, depends on external indexers for output classification, and requires network-wide coordination that significant constituencies have stated they would resist.

The present proposal pursues a comparable reduction in stored and relayed non-monetary data through node-local policy alone. No output is rendered unspendable. No transaction that is valid under current consensus rules becomes invalid. Classification is deterministic and syntactic, requiring no external index. Adoption is unilateral per node and reversible.

### Resource footprint

The practical advantage of a Monetary Node is measured in disk, memory, and time, and it begins at initial block download.

During IBD, a standard node accumulates every data-embedding output into chainstate as it validates, carrying tens of millions of spam entries forward from 2023 onward and holding them indefinitely. A Monetary Node discards these outputs continuously as each block is connected: spam enters chainstate only for the instant required to validate the block that created it, and never persists. The node's chainstate therefore never bloats in the first place — it is not cleaned after the fact, it is simply never dirtied.

The long-term difference is substantial. With 40–50% of current UTXO entries attributable to data embedding, a Monetary Node's chainstate is on the order of half the size of a standard node's — several gigabytes smaller today, with the gap widening every year spam persists. A smaller chainstate fits further into memory (`dbcache`), which accelerates block validation and IBD throughput; it shortens node startup, reduces I/O, and lowers the minimum hardware needed to run a fully validating node. Combined with block-file pruning, a Monetary Node offers full validation at a resource footprint materially below anything a spam-storing node can achieve.

This leanness is not a convenience; it is the adoption mechanism. Node software spreads when it is cheaper to run, and the cheapest fully validating node available will, over time, be a Monetary Node. Every operator who chooses it for the disk savings alone strengthens the monetary relay subgraph regardless of their views on spam.

### Intended long-term effect

Monetary Nodes carry a smaller chainstate, synchronize faster, and can bootstrap from one another without recourse to spam nodes (nodes that store and relay non-monetary data).

This friction is intended to be ever-increasing. The explicit goal of this proposal is the gradual expulsion of spam from the network: as the cost and unreliability of embedding data in Bitcoin rises with each operator who adopts monetary policy, the rational venue for such data moves elsewhere, and Bitcoin's block space returns to its purpose. Because Monetary Nodes preferentially peer with and bootstrap from one another, each new Monetary Node strengthens the monetary subgraph and further marginalizes the spam-relaying one — a natural ramp toward the eventual extinction of spam nodes, reached not by prohibition but by attrition.

This effect arises solely from the aggregate of individual node-operator policy choices. It involves no change to transaction or block validity and no coordination among operators. Bitcoin remains money because its node operators choose, one by one, to run it as money.

## Specification

The key words "MUST", "MUST NOT", "SHOULD", "SHOULD NOT", and "MAY" in this document are to be interpreted as described in RFC 2119.

### 1. Definitions

- **Non-monetary output:** an output classified under Section 2.
- **Non-monetary transaction:** a transaction containing one or more non-monetary outputs, or bearing an inscription envelope in any input witness.
- **Monetary UTXO set:** the UTXO set excluding all unspent non-monetary outputs.
- **Spam node:** a node that admits, stores, and relays non-monetary data without restriction.
- **Legacy state root:** a commitment to the complete UTXO set at a given height.
- **Monetary state root:** a commitment to the monetary UTXO set at a given height.
- **Monetary snapshot:** a serialization of the monetary UTXO set and filter index at a checkpoint height, identified by its hash.
- **Activation height:** block 680,000. Blocks below this height are processed identically to a standard full node, and the chainstate at the activation height is treated as entirely monetary.

### 2. Classification

Classification MUST be deterministic and computable from transaction data alone. External indexers MUST NOT be required. An output or transaction is non-monetary if it matches any of the following rules:

**Rule A — Inscription envelope.** A transaction containing, in any input witness, an unexecuted conditional branch initiated by a provably false condition — `OP_FALSE OP_IF` (equivalently `OP_0 OP_IF`), or any push evaluating to logical falsity followed by `OP_IF` — and terminated by `OP_ENDIF`. Such a branch is provably unexecutable and serves only to embed data. Implementations MUST evaluate falsity according to standard script semantics rather than by matching opcode literals, to prevent evasion via alternative encodings of false (e.g., a pushed zero byte or an empty push).

**Rule B — Bare multisig data encoding.** Outputs using bare multisig whose public keys match defined data-encoding patterns (e.g., stamp encodings) and are not valid points or are otherwise provably unspendable as constructed.

**Rule C — Token protocol markers.** `OP_RETURN` outputs bearing registered token-protocol identifiers (e.g., BRC-20 JSON envelopes, Runes markers), as enumerated in an appendix to be versioned with this document.

Rules A–C define the canonical classification used for the monetary state root. Implementations applying Rules A–C to identical block data MUST produce identical classifications.

**Rule D — Local extensions.** An operator MAY apply stricter relay filters (e.g., `OP_RETURN` size limits). Such extensions apply to relay policy only and MUST NOT affect the computation of the monetary state root.

### 3. Relay policy

A Monetary Node:

1. MUST NOT admit non-monetary transactions to its mempool;
2. MUST NOT announce or relay non-monetary transactions to peers;
3. MUST relay valid blocks in their entirety, including any non-monetary transactions contained therein;
4. MUST retain the standard `OP_RETURN` datacarrier limit of 83 bytes, consistent with Bitcoin Knots policy and BIP-110. Bounded `OP_RETURN` outputs within this limit are provably unspendable, are excluded from the UTXO set by existing behavior, and are not classified as non-monetary under Rules A–C;
5. SHOULD signal the service bit `NODE_MONETARY` (bit assignment to be requested) in its service field.

### 4. Consensus validation

A Monetary Node MUST enforce consensus rules identical to those of a standard full node. All transactions in a connected block, including non-monetary transactions, MUST be fully validated. Block structure, block hashes, proof-of-work requirements, and most-work chain selection are unmodified. A Monetary Node MUST NOT reject a block on the basis of its inclusion of non-monetary transactions.

### 5. Storage and state commitments

Upon connecting a block at or above the activation height, a Monetary Node:

1. MUST validate the block per Section 4;
2. MUST remove outputs classified under Rules A–C from its persistent chainstate. During initial block download this removal is applied continuously as each block is connected, so that non-monetary outputs never accumulate in chainstate at any point in the node's life;
3. MUST record, for each removed output, an entry in a local filter index comprising the outpoint, the output amount, a reference sufficient to locate the originating transaction (block height and transaction index), and a spent flag;
4. MUST compute and store the legacy state root and the monetary state root for the block;
5. SHOULD retain block files from the activation height onward, in order to serve historical blocks to bootstrapping peers and to support local reconstruction under Section 6.

Block files are stored unmodified: filtering applies exclusively to chainstate, and a block retained by a Monetary Node is byte-identical to that block as stored by any archival node. Block propagation is therefore never affected by filtering.

#### 5.0 Paired commitment

For each block at or above the activation height, a node MUST additionally compute the paired commitment:

```
C_h = SHA256d(block_hash_h || legacy_state_root_h || monetary_state_root_h)
```

`C_h` binds the filtered view to the full view at a specific block, preventing any presentation of a monetary root alongside a legacy root or chain to which it does not correspond. Consistency auditing between peers (Section 7.3) SHOULD compare `C_h` values; snapshot commitments (Section 7.2) MUST commit to `C_h` at the checkpoint height rather than to the monetary state root alone, so that a snapshot implicitly attests to the complete chain state from which the filtered view was derived.

**Voluntary miner attestation.** A miner MAY embed `C_h` (for the previous block) in a coinbase `OP_RETURN` output, following the structural precedent of the BIP 141 witness commitment. Such an embedding requires no consensus change: nodes MUST NOT reject blocks lacking it or containing a mismatched value, and it confers no consensus authority. Where present and matching a node's own computation, it provides a proof-of-work-timestamped, independently verifiable attestation that the embedding miner computed identical filtered state — a periodic hardened audit trail whose density grows with voluntary miner adoption. A mismatch between a miner-embedded `C_h` and local computation indicates a fault or divergence and SHOULD be logged and reported, but has no validity consequence.

#### 5.1 Storage summary

For clarity, a Monetary Node's storage is as follows.

**Always retained:**

- Block headers for every block, including every block hash, permanently — identical to any full node.
- The monetary UTXO set (all unspent monetary outputs).
- The filter index: for each discarded non-monetary output, its outpoint, amount, originating location, and spent flag (~48 bytes, versus hundreds of bytes to tens of kilobytes for the embedded data itself).
- Both state roots (legacy and monetary) for every block from the activation height (64 bytes per block).

**Discarded:**

- The full content of non-monetary outputs — the embedded data payload and scriptPubKey — is removed from chainstate as each block connects. This is the deletion this proposal effects: spam never persists in the node's working database.

**Retained by default, prunable by choice:**

- Full block files (which contain non-monetary transactions as mined). These are kept unmodified to serve bootstrapping peers and support Section 6 reconstruction; an operator MAY prune them under existing pruning rules, in which case reconstruction falls back to peer retrieval.

In summary: the spam data is deleted from the live database; the hashes — block hashes via headers, and both UTXO state roots — are always saved; and full historical blocks remain available locally or from the network for the rare cases where deleted data must be re-examined.

State roots are computed over the UTXO set using an incremental accumulator (e.g., MuHash, as implemented in Bitcoin Core's UTXO set hash); the accumulator construction MUST be uniform across implementations. The legacy state root is maintained incrementally without persisting non-monetary output data: each such output is hashed into the legacy accumulator at validation time, immediately before its removal from chainstate, and is removed from the accumulator upon being spent (using the output data reconstructed under Section 6). Maintenance of the legacy root therefore never depends on the existence of unfiltered nodes. State roots are node-local data and are not committed to in any consensus structure. Their functions are: (a) cross-implementation consistency auditing — two Monetary Nodes at the same height with the same chain MUST report identical roots, and a divergence indicates a classification or accumulator fault; and (b) identification and verification of monetary snapshots under Section 7. They do not alter chain selection and confer no consensus authority.

### 6. Validation of spends of filtered outputs

Filtered outputs are removed from the active monetary UTXO set but remain spendable under consensus rules. When a connected block contains a transaction spending a filtered output, the spend MUST be fully validated. The originating output is reconstructed by the first available of the following methods:

1. **Local reconstruction.** The node retrieves the originating transaction from its local block store using the location reference in the filter index, and extracts the referenced output in full (amount and scriptPubKey).

2. **Historical block retrieval (existing protocol).** A node that has pruned the relevant block files requests the originating block from any peer using the existing `getdata`/`block` messages. The received block MUST be verified against the block hash for that height already held in the node's validated header chain; the originating transaction is then extracted and the output reconstructed. This method requires no protocol extension and is serviceable by any archival peer, whether or not it implements this specification. Because spends of long-dormant data-embedding outputs are infrequent, the amortized bandwidth cost is negligible.

To bound block-connection latency, implementations SHOULD: (a) upon observing an unconfirmed transaction that spends a filtered output, pre-fetch and cache the originating output data in advance of block connection; and (b) limit concurrent historical-block retrievals to at most `N` outpoints per connecting block (default `N = 16`), queuing the remainder. A block spending more filtered outputs than available cache and fetch capacity delays only that node's local connection timing, never the block's validity.

Upon successful reconstruction, script validation, amount validation, and all other consensus checks MUST be performed exactly as for an unfiltered output. Upon confirmation of the spend, the corresponding filter index entry MUST be marked spent and MAY subsequently be pruned.

This construction preserves full validation: no consensus check is weakened or deferred by the filtering of an output from persistent chainstate, and neither method depends on infrastructure that does not already exist in the deployed network.

### 7. Bootstrap and synchronization

#### 7.1 Full-validation IBD (default)

A new Monetary Node:

1. synchronizes headers and full blocks below the activation height from any peer and constructs chainstate normally;
2. from the activation height, downloads full blocks, validates them per Section 4, applies filtering per Section 5, and computes both state roots and the paired commitment `C_h` (Section 5.0) at every height as synchronization proceeds. The node SHOULD prefer `NODE_MONETARY` peers for block download — Monetary Nodes retaining block files per Section 5 serve them identically to archival nodes — and MUST fall back to any available peer, including spam nodes, when no `NODE_MONETARY` peer is reachable;
3. MAY, at intervals during synchronization, request `C_h` values from `NODE_MONETARY` peers via `getstateroots` and compare them against its own computation. A divergence indicates an implementation fault or a dishonest peer, SHOULD be logged and reported, and MAY result in disconnection of the divergent peer. Peer-supplied commitments are advisory only and MUST NOT substitute for, or override, local computation;
4. upon completion, serves blocks, state roots, paired commitments, and snapshots to subsequently bootstrapping peers.

Because full blocks are the sole trust basis of this path, it is exactly as trustless as standard IBD regardless of which peers serve the data.

#### 7.2 Snapshot bootstrap (`assumemonetary`)

This mechanism is modeled on Bitcoin Core's `assumeutxo` and carries the same trust model: the snapshot hash is committed in the released source code, where it is reproducible and auditable by anyone who recomputes it independently.

1. Each software release MAY embed a constant `MONETARY_SNAPSHOT_HASH(H_s)`: the hash of the canonical serialization of the monetary UTXO set and filter index at checkpoint height `H_s`, together with the paired commitment `C_{H_s}` (Section 5.0).
2. A bootstrapping node obtains the snapshot from any `NODE_MONETARY` peer via `getmonetarysnapshot(H_s)` (chunked transfer). The node MUST verify the received snapshot against the release-committed hash and MUST discard it on mismatch.
3. Upon verification, the node synchronizes headers, validates full blocks from `H_s` to the tip per Sections 4–6, and begins normal operation.
4. **Background verification (mandatory).** The node MUST subsequently download and fully validate all blocks from genesis to `H_s` — from `NODE_MONETARY` peers or from any archival full node — recomputing chainstate and both state roots. If the recomputed monetary state root at `H_s` does not match the snapshot, the node MUST discard the snapshot-derived state and resynchronize via Section 7.1. Until background verification completes, the node SHOULD NOT serve snapshots to other peers.

Snapshot bootstrap therefore provides immediate operation sourced entirely from Monetary Node peers, while background verification — obtainable from any full node on the network, filtered or not — guarantees eventual convergence on fully self-validated state. At no point is a peer-asserted state root trusted: the only externally trusted artifact is the release binary the operator has already chosen to run, and even that commitment is verified against the chain in the background.

#### 7.3 Peer-to-peer messages

- `getstateroots(start_height, count)` → `stateroots`: for each requested height, the legacy state root, the monetary state root, and the paired commitment `C_h`. Used for consistency auditing between Monetary Nodes, including during IBD (Section 7.1); a peer whose values diverge from local computation SHOULD be reported and MAY be disconnected. Peer-supplied values MUST NOT substitute for local computation.
- `getmonetarysnapshot(height)`: chunked transfer of the monetary snapshot at a supported checkpoint height (Section 7.2).

The preference for `NODE_MONETARY` peers in Sections 7.1 and 7.2 makes the monetary subgraph self-reinforcing: as coverage grows, new nodes bootstrap without ever contacting a spam node, and the network's dependence on spam nodes declines accordingly, while archival full nodes of any kind remain usable for background cross-verification.

### 8. Reorganization

Upon disconnection of a block, a node MUST restore filter index entries and chainstate via standard undo data, and MUST recompute state roots for all affected heights upon connection of the replacement branch. Because classification is deterministic, conforming nodes converge on identical roots for identical chains.

## Rationale

**Absence of consensus changes.** Consensus-level removal of data outputs, as proposed in "The Cat", invalidates existing outputs and requires coordination that has proven contentious. Relay and storage policy are established node-operator prerogatives; this proposal extends them with the snapshot and auditing infrastructure necessary for filtering nodes to bootstrap one another, and nothing further.

**Parallel state roots rather than a filtered chain.** Removing transactions from blocks would alter transaction Merkle roots and block hashes, producing a divergent chain with attendant wallet, proof, and reorganization incompatibilities. Committing instead to two views of UTXO state under a single unmodified chain avoids divergence entirely, at a storage cost of 64 bytes per block. The roots are deliberately modest in role: they audit consistency and identify snapshots. They are not, and cannot be, a trust anchor — a limitation this proposal states plainly rather than obscures. Should the ecosystem later desire consensus-committed UTXO commitments, the structures specified here are a working prototype for that discussion; such a commitment is explicitly out of scope for this document.

**Snapshot trust model.** The `assumemonetary` mechanism introduces no trust assumption beyond those Bitcoin Core users already accept under `assumeutxo`: the operator trusts the reviewed, reproducible release they run, and mandatory background validation independently verifies the snapshot against the full chain after the fact. A dishonest snapshot cannot survive background verification.

**Choice of activation height.** Height 680,000 predates inscription protocols. Chainstate below it requires no filtering pass, and initial block download below it is identical to that of a standard node.

**Fixed canonical classification.** The monetary state root serves auditing and snapshot identification only if all conforming nodes compute the same root; the canonical rule set is therefore minimal, syntactic, and versioned. Operator discretion is confined to relay policy.

**Full validation of filtered spends.** Filtering an output from persistent chainstate is a storage decision, not a validity decision. Section 6 ensures that every spend is validated against the reconstructed originating output, so a Monetary Node's acceptance of any chain is identical to that of a standard full node.

## Backward compatibility

This proposal is fully backward compatible. Nodes not implementing it require no changes and interoperate with Monetary Nodes for block and header synchronization. No transaction or block valid under current rules is rendered invalid, and no existing output is frozen or confiscated. A Monetary Node may revert to standard behavior by restoring filtered outputs from block data or from peers per Section 7.

## Security considerations

- **Classification divergence.** An implementation fault producing divergent classification would partition the monetary bootstrap network but could not affect consensus, as chain acceptance is governed solely by Section 4. Shared test vectors and cross-implementation testing are prescribed as mitigation.
- **Snapshot integrity.** A malicious or faulty snapshot is bounded by two independent checks: the release-committed hash at download time, and mandatory full background validation thereafter. An operator's exposure between bootstrap and completed background verification is equivalent to that accepted by `assumeutxo` users today.
- **Dishonest peers.** Peer-supplied state roots are advisory and never substitute for local computation; snapshot data is verified against the release commitment; historical blocks are verified against the validated header chain. A node unable to locate honest `NODE_MONETARY` peers falls back to full-block synchronization from any peer, and its availability is therefore no worse than that of a standard node.
- **Relay filtering.** Filtering of unconfirmed transactions cannot prevent their confirmation, as any miner may include them and all blocks are relayed in full. The proposal accordingly introduces no censorship capability at the consensus layer.
- **Compact block relay.** Because a Monetary Node's mempool excludes non-monetary transactions, compact block reconstruction (BIP 152) for a block containing such transactions requires an additional `getblocktxn` round trip to fetch them. This adds modest latency to the propagation of spam-bearing blocks through monetary peers — a cost already borne by filtering nodes today — and has no effect on validity, chain selection, or the node's own security.
- **Long-term block-data availability.** Two functions permanently require full historical blocks: reconstruction of filtered outputs upon spending (Section 6) and full-validation IBD (Section 7.1). The legacy state root itself carries no such dependency — it is maintained incrementally by Monetary Nodes, which hash each non-monetary output into the accumulator at validation time before discarding it, and therefore remains correct without any legacy node in existence. However, in a network where unfiltered archival nodes have dwindled toward zero, Monetary Nodes retaining block files per Section 5 constitute the archival layer of last resort. Implementations SHOULD treat block-file retention from the activation height as the default configuration, SHOULD warn operators enabling pruning of the network-level consequences, and node distributors SHOULD monitor the population of block-serving `NODE_MONETARY` peers. Deleted from every working database, the historical data remains preserved in the block archives — consistent with this proposal's premise that filtering is a storage decision about the working set, never an erasure of the chain's history.

## Reference implementation

A patchset against Bitcoin Knots is to be provided. Knots currently ships the relay-policy foundations extended here (configurable `datacarrier` limits and inscription-envelope rejection), making it the natural base. The patchset comprises classification per Section 2, the filter index, incremental dual state roots, the snapshot mechanism and messages of Section 7, and associated configuration options. Classification and state root test vectors will be published concurrently. A port to Bitcoin Core is invited; the changes concern policy, indexing, and peer services only.

## Acknowledgments

Claire Ostrom, whose "The Cat" BIP draft (December 2025) established the scale of the UTXO growth problem and motivated this alternative; and participants in the ensuing bitcoindev mailing list discussion.

## References

- Nakamoto, S., *Bitcoin: A Peer-to-Peer Electronic Cash System* (2008)
- Ostrom, C., "The Cat", BIP draft discussion, bitcoindev mailing list (December 2025)
- BIP 141, Segregated Witness
- BIP 152, Compact Block Relay
- BIP-110, `OP_RETURN` datacarrier limit (83 bytes)
- Bitcoin Core `assumeutxo` design and implementation
- Bitcoin Core UTXO set hash (MuHash) implementation
- Ordinals protocol, inscription envelope specification
- RFC 2119, Key words for use in RFCs to Indicate Requirement Levels

## Copyright

This document is licensed under the BSD-2-Clause license.
