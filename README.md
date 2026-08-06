Monetary Nodes

A BIP draft: a Bitcoin node that validates all consensus rules but deletes non-monetary data (inscriptions, stamps, token dust) from its UTXO set and refuses to relay it. Roughly half the chainstate of a standard node. Same chain, same rules, no fork.

How it works

Every block is fully validated, then outputs matching deterministic classification rules are removed from chainstate as the block connects — continuously, including during initial block download. Spam never accumulates in the working database. Full block files are kept unmodified, so deleted outputs remain spendable: a spend is validated by reconstructing the original output from local blocks, or by fetching the historical block from any peer and checking it against the already-validated header chain.

From block 680,000 the node maintains two incremental UTXO set hashes (MuHash): a legacy hash over the full set and a monetary hash over the filtered set, bound with the block hash into a single paired commitment. Non-monetary outputs are folded into the legacy hash at validation time, just before deletion — so the full-state hash stays correct without the data being stored, and without depending on any unfiltered node. Filtering can be enabled on an existing node via a reindex, which replays the chain to rebuild the filtered chainstate and both hashes from local block files.

New nodes sync by full IBD, or from a monetary UTXO snapshot verified against a release-committed hash (the assumeutxo trust model), followed by mandatory background validation of the full chain.

Contents
Monetary_Nodes.md — the specification
index.html, technical.html — website (monetarynode.org)
