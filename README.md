Monetary Nodes

Parallel State Commitments for a Spam-Free Bitcoin. A BIP draft.

The spam is deleted; the hashes are saved.

A Monetary Node validates every consensus rule a full node does — and refuses to store or relay anything else. Non-monetary outputs (inscriptions, stamps, token dust) are deleted from the node's working database the moment each block is validated, while every block hash, a compact index of what was removed, and dual cryptographic commitments to both views of UTXO state are kept permanently. The result is a fully validating node at roughly half the chainstate — on the same chain, under the same rules, secured by the same proof-of-work.

No fork. No confiscation. No coordination. No censorship.

Website: https://monetarynode.org Full spec: BIP_DRAFT_Monetary_Nodes.md (this repository) Discussion: bitcoindev mailing list (link TBD)

The problem

The UTXO set grew gradually to roughly 90 million entries between 2009 and early 2023. Within about one year of inscription protocols appearing, it exceeded 160 million; it now exceeds 173 million, with an estimated 40–50% of entries being data-embedding spam that will likely never be spent.

Every unspent output — including spam — must be held in chainstate by every full node, forever. Inscriptions, stamps, and token protocols embed data in outputs that node operators must store, index, and verify while receiving nothing in return. The burden is permanent, compounding, and unbounded.

The design in five points
Full validation, filtered storage. Every block is validated under unchanged consensus rules; spam outputs are then deleted from chainstate as each block connects — continuously, including during IBD. Classification is deterministic and syntactic (inscription envelopes, stamp encodings, token markers). No external indexers.
No spam relay. Non-monetary transactions never enter the mempool or relay. Blocks always relay in full, byte-identical to any archival node. OP_RETURN stays capped at 83 bytes, per Bitcoin Knots policy.
Dual state roots, married. From block 680,000, each node computes a legacy state root (full UTXO set) and a monetary state root (spam removed), bound with the block hash into a single paired commitment — neither view can be presented apart from, or mismatched with, the other. Miners can voluntarily notarize it in the coinbase under proof-of-work. None of this requires a fork.
Fast bootstrap, verified in the background. New nodes can start from a snapshot verified against a release-committed hash (the assumeutxo trust model), then mandatorily download and fully validate the entire chain in the background — from monetary peers or any archival full node. Every node eventually checks everything itself.
Everything stays spendable. Spends of deleted outputs are fully validated by reconstructing the original output from local block files, or by fetching the historical block via the existing P2P protocol and verifying it against the already-validated header chain. Nothing is confiscated; nothing becomes unspendable.
Relationship to "The Cat"

This proposal is directly inspired by The Cat (Ostrom, December 2025), which correctly diagnosed the UTXO spam crisis but proposed a consensus-level soft fork rendering spam outputs permanently unspendable. This design pursues the same goal with none of that mechanism:

Mechanism: The Cat is a soft fork making outputs unspendable; Monetary Nodes are node policy — outputs are simply not stored or relayed.
Coordination: The Cat requires network-wide agreement; Monetary Nodes are adopted unilaterally, one operator at a time.
Confiscation: The Cat freezes outputs; under Monetary Nodes everything stays spendable.
Indexers: The Cat depends on external indexers (Ord, Stamps); Monetary Nodes use purely syntactic classification.
Reversibility: The Cat is permanent; a Monetary Node can revert by toggling a setting.
Fork risk: The Cat's is high; Monetary Nodes' is zero.

The Cat discussion thread: https://groups.google.com/g/bitcoindev/c/Q6ulQb13okg

Repository contents
BIP_DRAFT_Monetary_Nodes.md — the full draft specification (RFC 2119 form)
index.html — website: overview one-pager
technical.html — website: technical details in plain language
Status

Done:

Draft specification
Website

Next:

bitcoindev mailing list post
Classification and state root test vectors
Reference implementation (Bitcoin Knots patchset)
Formal BIP number assignment

The reference implementation targets Bitcoin Knots, which already ships the datacarrier limits and inscription-envelope filters this design extends. The changes touch policy, indexing, and peer services only — consensus code is untouched. A Bitcoin Core port is invited.

Contributing

Review, objections, and sharper knives welcome — open an issue or reply on the mailing list thread. Particularly valuable right now:

Review of the classification rules (Section 2), the paired-commitment construction (Section 5.0), and the snapshot bootstrap (Section 7.2)
Measurements of current UTXO spam share from live nodes
Knots developers interested in the patchset
License

BSD-2-Clause. Inspired by "The Cat" (Ostrom, 2025). Built for Bitcoin Knots.
