# electrs integration — project plan

Goal: a wallet user can check balances and send and receive transactions
against a monetary node, with as little non-standard software as possible.

## A correction, first

I claimed earlier that unmodified electrs would work against a monetary node,
on the reasoning that the indexer runs ahead of the stripper and never needs
the deleted data afterwards. **That claim is wrong**, and the source says so.

`electrs 0.11.1`, `src/daemon.rs:169-176`:

```rust
fn rpc_poll(&self, skip_block_download_wait: bool) -> PollResult {
    match self.call::<GetBlockchainInfoResult>("getblockchaininfo", &[]) {
        Ok(info) => {
            if info.pruned {
                return PollResult::Done(Err(anyhow!(
                    "electrs requires non-pruned bitcoind node"
                )));
            }
```

electrs refuses to start against a pruned node. The check runs on every
connection attempt, before `skip_block_download_wait` is consulted, and no
config flag bypasses it. `--ignore-mempool` and
`--skip-block-download-wait` exist; nothing for this.

Since `monetary_convert.py` stage 7 prunes the node, electrs would index fine
right up until the first restart after conversion, then refuse to start —
with its index intact and useless.

I should also retract something I passed on from a web search: that "electrs
supports pruned nodes, unlike the others." The source contradicts it. I
repeated a summary without checking, which is the same mistake this project
has published retractions for before.

**Consequence: there is no zero-patch path.** The objection about a tougher
sell when users must run a patched electrs alongside a novel node stands, and
the plan below is about making that patch as small and as defensible as
possible — not about avoiding it.

## The critical unknown

**Does electrs ever re-read a block it has already indexed?**

Everything below assumes it does not — that indexing is forward-only and the
database is authoritative once written. If that assumption is wrong, the
entire approach fails and the only path is indexing from the monetary store
directly, which is a far larger change.

Nothing has been verified here. This is phase 1 and it gates everything else.

Specifically, what happens on: compaction, reorg deeper than cached state,
restart with a partially-written database, and `blockchain.transaction.get`
for an old transaction.

That last one is already known to be a problem — a monetary node cannot serve
raw transaction hex for the 19.34% of transactions that are modified or
stripped. Whether electrs serves that from its own database or re-fetches from
the daemon is exactly the kind of thing phase 1 must establish.

## Options considered

| Option | Verdict |
|---|---|
| Don't prune the node | Defeats the purpose entirely |
| RPC proxy that answers for missing blocks | **Rejected.** Stripped blocks cannot be reconstructed, so the proxy would have to serve blocks that do not hash correctly. Serving fabricated blocks to an indexer is not acceptable regardless of how convenient it is |
| Proxy that reports `pruned: false` | Rejected. Same dishonesty, smaller |
| Minimal electrs patch: opt-in flag to allow a pruned daemon | **Recommended** |
| electrs indexes from the monetary store directly | The right long-term answer, much larger change; needed anyway for bootstrap |

## Recommended path

A single flag, `--allow-pruned-daemon`, default off, that turns the hard
refusal into a warning.

It is small, it is honest about what it does, it has value to people who have
nothing to do with monetary nodes (running electrs on a pruned node after
indexing is a thing people have wanted), and it is plausibly upstreamable on
its own merits — which would collapse the trust ask back to one non-standard
component.

If upstream declines, it remains a patch small enough to read in one sitting,
which is a materially different proposition from a fork.

## Phases

### Phase 1 — establish the facts (blocking)

Nothing is built until these are answered, and they are answered by reading
source and running experiments, not by assuming.

1. Does electrs re-read indexed blocks? Under what conditions?
2. How does it fetch full block data — the code path was not located; only
   `getblock` with verbosity 1 (txids only) was found
3. How does it serve `blockchain.transaction.get` — own database, or daemon?
4. What does it expose as its indexed height?

**Deliverable:** a short findings document. If question 1 answers badly, the
plan changes shape entirely and that is worth knowing before any code.

### Phase 2 — regtest harness

Independent of electrs, needed for everything, and does not require the new
hardware.

- Mine blocks on demand, construct each carrier type deliberately
- Strip, then attempt to spend a dropped output and assert the node accepts it
- Runs in CI

**Deliverable:** a test file that fails when the spend path breaks.

### Phase 3 — the electrs patch

- `--allow-pruned-daemon`, default off
- A test against a pruned regtest node
- Opened as an *issue* upstream first, describing the use case, before any PR

**Deliverable:** a patch, and an upstream conversation.

### Phase 4 — prune_behind respects the indexer

`prune_behind.py` currently tracks only the daemon's recorded height. It needs
a second input:

```
prune_floor = min(daemon_height, electrs_height) − margin
```

electrs's height comes from `blockchain.headers.subscribe` over the Electrum
protocol — `wallet_check.py` already speaks it, so the client code exists.

**The fail-safe matters more than the check.** If electrs is stopped, crashed
or unreachable, pruning must refuse entirely rather than fall back to the
daemon height. A stalled prune fills a disk, which is visible and fixable.
Deleting blocks the indexer never saw produces missing wallet history
discovered weeks later.

**Deliverable:** the height source, the refusal path, and tests for both.

### Phase 5 — end to end on regtest

Electrum wallet → electrs → monetary node. Receive, confirm, spend, including
a spend of an output whose transaction was stripped.

**Deliverable:** the first evidence that any of this works for a wallet user.

### Phase 6 — index rebuild from a store (bootstrap)

The piece that makes monetary nodes able to seed each other with wallet
support intact. Depends on format v2 — see `FORMAT_V2.md`, where stripped
transactions must retain their prevout list or the rebuilt index is silently
wrong.

Largest phase, least specified, and the one that matters most for the
project's actual claim. Should not be attempted before phase 5 proves the
simpler path works.

## Risks

**The phase 1 assumption is wrong.** Mitigated only by doing phase 1 first.

**Upstream declines the patch.** Likely, on the evidence: of the last 2,000
electrs-adjacent commits in comparable projects the core team writes the large
majority, and Electrum's own history shows features arriving as maintainer
implementations of issues rather than merged outside PRs. Plan for the patch
to live in this repo and be readable, not for it to be merged.

**Scope.** Six phases across Rust and Python, with an unwritten index rebuilder
at the end. This is months for one person. The alpha does not depend on any of
it and should ship first.

## What this does not change

The v0.1.0 alpha stands on its own: node, tools, docs, measured results. It
runs against an unmodified node and does not require electrs at all. Shipping
it is not blocked by anything in this document.
