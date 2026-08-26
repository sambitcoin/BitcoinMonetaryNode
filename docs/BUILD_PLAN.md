# Build plan — from measurement to alpha

Status as of 17 August 2026. Each stage produces a shippable artifact. Stages 1
and 2 are done; stage 3 is buildable now; stages 4 onward need a collaborator,
and the earlier artifacts are what recruit one.

## Done

**1. Block-level measurement.** `inscription_scan_local.py`. Inscription
envelope payload across blocks 767,430–962,292: **37.1 GB**, 12.51% of block
bytes in that era, 22.71% of witness data. 130.5M envelopes, 628.8M
transactions parsed. Validated by cross-implementation agreement and a
zero-result false-positive test over post-Taproot pre-inscription blocks.

**2. Chainstate measurement.** `utxo_scan.py`. UTXO set at block
…5e02eb7: 165,858,242 outputs, 11.8 GB serialised. Dust below 1,000 sats is
46.69% of outputs and 49.12% of bytes. P2TR dust from the inscription era is
**28.70% of outputs, 30.84% of bytes**. Independently corroborated by
mempool.space's 29.6% figure derived by a different method. Total value matched
circulating supply, confirming the amount decompression is correct.

## Stage 3 — block file splitter (next, buildable now)

A standalone tool that reads `blk*.dat` and writes two files: transaction
bodies and witness data, separately. Reports sizes and verifies round-trip.

**What it must demonstrate:**

- Clean separation of witness bytes from transaction bodies at the storage layer
- **Byte-perfect round-trip**: split a block, recombine, confirm the block hash
  is unchanged, across all 195,000 blocks in the inscription era
- The exact disk saving a `wit*.dat` split would enable, measured

The round-trip proof is the point. It answers the central objection to
segregated storage — that separating witness data risks corrupting blocks —
with evidence, before any C++ is written.

**Deliverable:** tool, results, and a short note. Days of work, no Core changes,
nothing that can damage a node.

## Stage 4 — segregated witness storage in Core

Write transaction bodies to `blk*.dat` and witnesses to `wit*.dat`, with the
block index recording both offsets. Reassemble on read. Consensus, validation
and block hashes untouched — purely a disk layout change.

Witness pruning then becomes whole-file deletion, exactly as safe as existing
pruning, rather than the in-place rewriting that made every earlier design
unworkable.

**Target Bitcoin Core**, not Knots. The storage layer is effectively identical
between them, so the patch applies to either, but Core is where an upstream
proposal has to land and it carries no exposure to Knots' proof-of-work
situation.

**Proposed on general merits:** smaller nodes, faster IBD, prunable signatures.
Named dully. The spam consequence follows without needing to be argued.

**Touches:** block write path, block index schema, block read path, pruning
logic, reindex. Substantial C++ in code that has to be right. **Needs a
developer.**

## Stage 5 — dual IBD with txid retention

Monetary nodes serving initial block download to each other without transmitting
spam. Store the 32-byte txid of every stripped transaction so the receiving node
can rebuild the merkle root and verify it against the header — the block is
proven authentic without the spam data ever moving.

Detailed in `monetary_ibd_design.md`. **Not yet adversarially reviewed** — every
prior design survived one review round and failed the next, and this one has had
none. Review before building.

## Stage 6 — alpha

Segregated storage plus witness pruning plus chainstate filtering, running on
regtest, then a walletless mainnet soak alongside an unmodified node watching
for any block-level disagreement.

## Running alongside

**Publish stages 1 and 2.** Repo with both scanners, `RESULTS.md`, and the
per-block CSV. Then Delving Bitcoin — measurement only, no proposal attached.
Then X, linking to Delving rather than the site.

**Adversarial review of the IBD design.** Independent, can happen any time, and
should happen before stage 5 rather than after.

**Update the site and spec** with measured figures. They still carry the old
estimates. Replacing 40–50% guesses with 12.51% of blocks and 30.84% of
chainstate — measured, reproducible, with published code — is a straight
credibility upgrade.

**Whole-chain denominator.** Still outstanding: total `blk*.dat` bytes, so
inscription payload can be stated as a share of all Bitcoin block data rather
than of the inscription era alone.

**rbitcoin.** A from-scratch Rust node that already has no UTXO database and
already separates witness data by storage class. The closest existing
architecture to what stages 4 and 5 need. Worth approaching with the
measurement — not the proposal — once stages 1 and 2 are published.

## The through-line

Each artifact is independently useful and independently publishable. The
measurements stand alone as research. The splitter stands alone as a
demonstration. Nobody has to accept the proposal to find any of it valuable —
which is what makes it likely someone eventually will.
