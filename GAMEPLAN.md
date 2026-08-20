# GAMEPLAN — read this first

## THE PREMISE. DO NOT NARROW IT.

**ALL SPAM IS REMOVED FROM THE MONETARY NODE'S STORAGE.** Every carrier:
inscriptions in witness, OP_RETURN payloads, stamp-style bare multisig,
scriptSig data, dust outputs in chainstate. Not witness-only. Not
chainstate-only. All of it.

**This is possible because the node stores the txid of every transaction it
strips.** A block's merkle root is computed over txids. Once the txid is
stored, nothing downstream needs to re-derive it from transaction data — so
transaction data can be modified or discarded entirely and the block still
verifies against its header, against real proof-of-work.

**The stored txids are self-verifying.** Fabricated txids produce a merkle root
that does not match the header, and the block is rejected. The txid list cannot
be forged.

Anyone — including me — who says "OP_RETURN can't be removed because it's
inside the txid" has forgotten that the txid is stored rather than recomputed.
That objection applies only to designs without txid retention. It does not
apply here.

**If the scope narrows to witness-only, the project is a coding exercise.** The
goal is a node that carries no spam of any kind.

**ACCOUNT FOR EVERY CARRIER, EVERY TIME.** Any tool, measurement or write-up
must cover all of them: inscription envelopes, OP_RETURN, Runes, Stamps and
bare-multisig data, scriptSig data, dust outputs. If a carrier reports zero,
verify the detector before believing it. A detector that silently misses a
carrier is worse than no detector, because the result gets published.

**IF WALLETS DON'T WORK, IT ISN'T A NODE.** Spam removal that breaks Electrum,
balances, or transaction history is a storage experiment, not a node anyone can
run. Wallet compatibility is a first-class requirement and must be demonstrated,
not assumed.

**THE TARGET IS A WORKING ALPHA.** Not a spec, not a measurement, not a post.
Code that runs, that others can run, that survives being checked. Interest
follows working software.

---

## The architecture

**Do not reimplement consensus.** A monetary node runs alongside Bitcoin Knots.
Knots validates every block completely, exactly as it does today. The monetary
daemon strips, stores, commits and serves. We never write a script interpreter
and never need to be bit-identical with Core, because we never make a consensus
decision. This is the decision that keeps the project finishable.

**Validate completely.** Every block, every rule, identical to Core. Nothing
skipped, nothing deferred, no classifier touching consensus. Chainstate is
updated normally at validation time, including for spam outputs, because they
are needed to validate the block. This happens once.

**Then strip.** Per transaction:

- **Monetary** — retained in full.
- **Spam** — body discarded, 32-byte txid retained.
- **Mixed** — monetary parts retained, spam parts discarded, original txid
  retained.

**Record before discarding.** For every dropped output: outpoint, amount,
scriptPubKey, height — around 80 bytes. This is what allows a future spend to
be validated completely, locally, with no peer involvement.

**Commit.** `C_h = SHA256d(C_{h-1} ‖ block hash_h ‖ K_h)`, chained, where K is
the record's body digest. Two nodes that stripped identically produce identical
C forever; one disagreement diverges permanently. C is *derived from* the store,
so no node can assert a C its own data does not support.

C anchors to proof-of-work by reference — each step mixes in a block hash real
work committed to. It is **not** proof of that work. **No separate mining. No
signature-based attestation. No node counting.** Security is inherited from
Bitcoin's proof-of-work, never replaced.

## Two layers, two mechanisms

Do not conflate them and do not add their savings together carelessly.

**Block storage** — where inscription witness data lives. 37.1 GB measured,
12.51% of era block bytes. Removal is a clear win.

**Chainstate** — where dust lives. 30.84% of the UTXO set by bytes. Removal is
a clear win *here*, and only here.

**Dust is retained in block storage and excluded from chainstate.** Dropping a
42-byte dust output from a block to add an 80-byte filter entry is a net loss.
This is arithmetic, not a softening of the premise: the removal happens where it
actually saves space.

## Wallet compatibility — what must be proven

An Electrum server indexes scriptPubKeys and outpoints from block data. Against
a monetary store:

- **Retained transactions** — complete, no issue.
- **Modified transactions** — inputs and monetary outputs retained; dropped
  outputs recoverable from filter entries. Address indexing works.
- **Fully stripped transactions** — only the txid survives. Their outputs are in
  the filter index, but **their inputs are not**, so the link from a spent
  output to its spending transaction is lost. This was 610 transactions of
  628.8 million in the measured range, but it is a real correctness gap and must
  be either fixed (retain inputs for stripped transactions) or measured and
  disclosed.
- **Raw transaction retrieval** — a wallet asking for the original bytes of a
  spam transaction cannot be served. By design. Wallets asking for their own
  transactions are unaffected.

**This must be demonstrated with a real wallet against a real store**, not
argued from the format. Balances and history must match a reference node.

## Measured, not guessed

**Blocks 767,430–962,292:** inscription envelope payload **37.1 GB**, 12.51% of
block bytes in that era, 22.71% of witness data. 130.5M envelopes across 628.8M
transactions. Validated by cross-implementation agreement and a zero-result
false-positive test.

**Full strip run, same range:** 194,863 blocks, **zero merkle failures**.
80.7% of transactions untouched. 33.5 GB saved (11.30%).

**UTXO set at tip:** 165,858,242 outputs, 11.8 GB serialised. Dust below 1,000
sats is 46.69% of outputs and 49.12% of bytes. P2TR dust from the inscription
era is 28.70% of outputs and **30.84% of bytes** — corroborated within one point
by mempool.space's independently derived 29.6%.

**Also established:** 88% of all taproot outputs are inscription-era dust. Two
thirds of the entire UTXO set was created after December 2022. OP_RETURN over
the old 83-byte limit is only 12.3 MB across the whole era.

**Not yet measured:** Stamps. The original detector checked key prefixes, which
Stamps deliberately make look standard, so it reported zero. Fixed with a
secp256k1 on-curve test but not yet run against the chain. Treat as unmeasured.

**Unresolved:** small Runestones fall under 83 bytes and pass the OP_RETURN
rule, conflicting with the stated target list.

## Status — code versus spec

Be precise about this. Claiming unbuilt things is how credibility dies.

| Piece | State |
|---|---|
| Block measurement | code, run, published |
| Chainstate measurement | code, run, published |
| General stripper | code, run over 194,863 blocks |
| Storage format | code, 42 tests passing |
| Commitment C | code, 8 properties verified, not yet run on a real store |
| Spend validation from filter index | format supports it, no code |
| Chainstate filtering | identified only, no code |
| Wallet / Electrum compatibility | **unproven** |
| Monetary IBD | design only, never attacked |
| Full L/M UTXO accumulator | spec only, needs a UTXO database |

## Build sequence

1. ~~Block measurement~~ — `inscription_scan_local.py`
2. ~~Chainstate measurement~~ — `utxo_scan.py`
3. ~~General stripper~~ — `spam_strip.py`
4. ~~Storage format~~ — `monetary_store.py`, `test_monetary_store.py`
5. ~~Chained commitment~~ — `monetary_commit.py`
6. **Wallet compatibility** — index a monetary store, serve Electrum, match
   balances and history against a reference node. Blocks everything downstream.
7. **Spend validation** — prove a dropped output can still be spent using only
   the filter index.
8. **Chainstate filtering** — build a filtered UTXO set, measure the real saving.
9. **Monetary IBD** — server and client over the store; verify merkle from
   stored txids, verify PoW on headers, compare C on connect.
10. **The daemon** — follow the Knots tip, strip each block, extend C.
11. **Alpha** — packaged, documented, runnable by someone else.

Because monetary nodes cannot serve legacy nodes anyway, the IBD transport does
not have to be Bitcoin P2P. A clean protocol of our own is a few hundred lines
rather than a fork of Core's net layer.

## Standing technical constraints

These are real and no design escapes them:

- Block validity is atomic. Validation is always complete.
- Node counts confer no security. Only accumulated work does.
- Validating a spend needs the spent output's amount, scriptPubKey, height and
  coinbase flag — never the creating transaction's witness.
- A stripped block cannot be served to a legacy node.
- A stripped block cannot be re-validated under future consensus rules.
- The merkle root does not cover modified bodies or filter entries; only the
  body digest does, and that is local integrity, not peer trust.

## Prior art that must be cited

Presenting any of this as novel without acknowledging the following will lose
the room:

- **Utreexo** — replaces the UTXO set with an accumulator. Lossless and
  content-neutral; nothing is deleted and block storage is untouched. Different
  problem. But if it ships, the chainstate half of our argument weakens sharply,
  because UTXO set size stops being expensive.
- **Dust expiry** (Robin Linus, Delving Bitcoin 2025) — removing low-value
  outputs from the UTXO set after a time. Close to our dust filtering. Our
  differentiator is that it needs a soft fork and ours does not. Cite it.
- **Witnessless sync** (Jose SK, Delving Bitcoin 2025) — pruned nodes skipping
  witness download for assumevalid blocks, 40%+ bandwidth saving. Ruben Somsen's
  objection is the one aimed at us: if nobody routinely validates that data
  exists, it can be lost, as has happened to at least one altcoin. **Have an
  answer ready before posting.**

## Endgame

An independent implementation with storage designed for this from the start,
using `libbitcoinkernel` for validation so consensus is bit-identical to Core
and divergence is impossible. rbitcoin is the closest existing architecture — no
UTXO database, witness already separated by storage class.

## Working rules

- The repo is the source of truth. Session workspaces are disposable.
- Publish continuously. Working code attracts developers; specs do not.
- State what is built and what is not, every time.
- Adversarial review will come from strangers on Delving. Better to have found
  the holes first.
