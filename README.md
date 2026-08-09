Monetary Nodes

A BIP draft: a Bitcoin node that validates all consensus rules but deletes non-monetary data (inscriptions, stamps, token dust) from its UTXO set and refuses to relay it. Roughly half the chainstate of a standard node. Same chain, same rules, no fork.

Every other approach to UTXO spam needs someone's permission — miners, a supermajority of nodes, a consensus process. This one needs none. Chainstate is not consensus, and what a node stores has always been its operator's decision.

How it works

Every block is fully validated, then outputs matching deterministic classification rules are removed from chainstate as the block connects — continuously, including during initial block download. Spam never accumulates in the working database. Full block files are kept unmodified, so deleted outputs remain spendable: a spend is validated by reconstructing the original output from local blocks, or by fetching the historical block from any peer and checking it against the already-validated header chain.

From block 680,000 the node maintains two incremental UTXO set hashes (MuHash): a legacy hash over the full set and a monetary hash over the filtered set, bound with the block hash into a single paired commitment. Non-monetary outputs are folded into the legacy hash at validation time, just before deletion — so the full-state hash stays correct without the data being stored, and without depending on any unfiltered node. Filtering can be enabled on an existing node via a reindex, which replays the chain to rebuild the filtered chainstate and both hashes from local block files.

New nodes sync by full IBD, or from a monetary UTXO snapshot verified against a release-committed hash (the assumeutxo trust model), followed by mandatory background validation of the full chain.

Why it matters

The mechanism is small; the implication is not. Validation is what makes a node sovereign, and validation is only as decentralized as it is affordable. Data embedding raises that cost permanently and without bound: dust outputs that will never be spent sit in every node's working set forever, and the burden compounds with every block.

Filtering inverts the incentive. A monetary node carries a smaller working set, which means less disk, better cache behaviour, and shorter initial sync — with the largest gains on exactly the constrained hardware that decentralization depends on. That advantage widens every year spam accumulates, so the cheapest fully validating node available should, over time, be one that refuses to store it.

Nothing here forces that outcome, and nothing here binds miners. Spam transactions remain valid, remain minable, and remain permanently in the block archives that monetary nodes keep. What changes is the cost each operator carries by choice, and the share of the network willing to relay data it considers worthless. It is attrition rather than prohibition, and it starts working on the first node that runs it.

Contents
BIP_DRAFT_Monetary_Nodes.md — the specification
index.html — website (monetarynode.org)
Status

Draft. Not yet posted to the bitcoindev mailing list. Reference implementation (Bitcoin Knots patchset) not yet started.

Feedback: open an issue, or reach the author on X: @marketanarchy21 (https://x.com/marketanarchy21).

License

BSD-2-Clause
