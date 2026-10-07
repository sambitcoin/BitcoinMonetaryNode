# Indexer integration — project plan

Goal: a wallet user can check balances and send and receive transactions
against a monetary node, running as little non-standard software as possible.

Supersedes an earlier draft of this document, which recommended patching
electrs. See "A rejection, retracted" below.

## The blocker

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
config flag bypasses it.

This is not an electrs quirk. Bitcoin Core makes `-prune` incompatible with
`-txindex`; Fulcrum requires `txindex=1` and a non-pruned node; ElectrumX the
same. **No Electrum-style indexer works against a pruned node**, because an
address index must read every transaction that ever existed and a pruned node
deleted them.

Since `monetary_convert.py` stage 7 prunes the node, electrs would index fine
right up to the first restart after conversion, then refuse to start — with
its index intact and useless.

Also worth noting for the local setup: Umbrel's Knots runs with
`prune=953674`, a target larger than the chain, so nothing is ever actually
deleted — but `getblockchaininfo` still reports `pruned: true`. That alone
would make electrs refuse, with every block physically present. It likely
explains the "Electrum is running but broken" symptom from weeks ago.

## The reframe that matters

Losing wallet-server capability is an **existing** cost of pruning that
everyone already accepts. This project does not introduce it — and a monetary
node is in a strictly better position than a pruned one:

| | Pruned node | Monetary node |
|---|---|---|
| Old block data | deleted | 87.44% retained |
| Dropped outputs | gone | filter entries: txid, vout, amount, scriptPubKey, height |
| Index rebuildable? | **never** | **yes** |

A pruned node can never rebuild an index. A monetary node keeps every monetary
transaction plus structured records of everything it dropped. The information
is present; what is missing is tooling that reads it.

"Monetary nodes restore wallet support that pruning takes away" is a stronger
claim than "we patched an indexer to tolerate pruning", and it is the one the
format actually supports.

## A rejection, retracted

The earlier draft rejected an RPC proxy on the grounds that stripped blocks
cannot be reconstructed, so a proxy would have to serve blocks that do not
hash correctly.

**That was wrong, and it has been tested.**

An indexer needs semantic content — txid, inputs, outputs — not original
bytes. Witness data is irrelevant to an address index. And `monetary_store.py`
retains enough to rebuild the rest.

Every dropped output receives a filter entry **unconditionally**. There is no
"skip provably unspendable" guard, so even OP_RETURN payloads keep their
scriptPubKey, vout and amount:

```python
for vout, amount, spk in dropped_outs:
    filter_entries.append((txid, vout, amount, height, spk))
```

Reconstructing a modified transaction — version, inputs and locktime from the
stored body, outputs merged from the retained ones plus filter entries placed
at their recorded vouts — reproduces the original **byte for byte**:

    classification: whole=0 modified=1 stripped=0
    filter entries: 2
    reconstruction == original bytes : True
    reconstructed txid == stored txid: True

And it is checkable rather than assumed. txid excludes witness data, so a
correct reconstruction hashes to the stored txid — which the merkle root
protects, which proof-of-work protects.

That is verified reconstruction, not fabrication. The distinction is the whole
argument, and the earlier draft missed it.

## Options

| Option | Verdict |
|---|---|
| Don't prune the node | Defeats the purpose entirely |
| Proxy reporting `pruned: false` while serving nothing | Rejected — dishonest, and serves no data |
| **RPC proxy serving verified reconstructions** | **Recommended** |
| electrs patch: opt-in flag to allow a pruned daemon | Fallback, or a bridge while the proxy is built |
| electrs indexes the monetary store natively | Larger change, unnecessary if the proxy works |

## Recommended path

A block server presenting a bitcoind-compatible RPC interface, answering from
the monetary store, serving reconstructions verified against stored txids
before returning them.

**The invariant that makes this legitimate:** every reconstructed transaction
must hash to its stored txid before being served. Any block containing a
transaction that fails must **error rather than serve partially**. Without
that assertion this becomes the thing the earlier draft rightly rejected.

**Why it beats patching electrs:** it requires no patch to anything. electrs,
Fulcrum and ElectrumX all speak the same RPC, so one tool serves all three
unmodified, and the trust ask collapses to this repository alone. That also
answers the objection that a novel node plus a patched indexer is a much
harder sell than either alone.

**What it cannot do.** Witness data is gone permanently, so reconstructed
blocks carry correct txids and no witnesses, and the witness commitment will
not match. Address indexers do not check it; anything that does will break.
The claim is therefore *sufficient for indexing* — never "identical to a
legacy node".

**Format v2 is a prerequisite, not an extra.** Stripped transactions keep
their outputs (tested — they do receive filter entries) but lose their inputs,
so they cannot be reconstructed at all under v1. See `FORMAT_V2.md`.

## Phases

### Phase 1 — establish the facts (blocking)

Answered by reading source and running experiments, not by assuming. The
earlier draft's central error came from assuming.

1. Does electrs re-read blocks it has already indexed? Under what conditions —
   compaction, deep reorg, restart with a partially-written database?
2. How does it fetch full block data? Only `getblock` with verbosity 1 (txids
   only) was located; the full-block path was not found.
3. Does it serve `blockchain.transaction.get` from its own database, or
   re-fetch from the daemon? A monetary node cannot serve raw hex for the
   19.34% of transactions that are modified or stripped.
4. What does it expose as its indexed height?

**Deliverable:** a findings document. Question 3 is the one most likely to
force a redesign.

### Phase 2 — regtest harness

Independent of everything else, needed regardless, and requires no new
hardware.

- Mine on demand, construct each carrier type deliberately
- Strip, then spend a dropped output and assert the node accepts it
- Runs in CI

**Deliverable:** a test file that fails when the spend path breaks.

### Phase 3 — format v2

Prevout retention for stripped transactions. Small, specified, and blocking
for phase 4. See `FORMAT_V2.md`.

**Measure the flag 1 / flag 2 split first.** Modified-plus-stripped is 19.34%
of transactions across the era; the split has never been counted, and the cost
of v2 depends entirely on it.

### Phase 4 — the reconstruction proxy

- bitcoind-compatible RPC surface, enough for an indexer
- Reconstruct from stored body plus filter entries
- **Verify every reconstruction against its stored txid before serving**
- Error, loudly, on any block that cannot be fully reconstructed

**Deliverable:** unmodified electrs indexing from a monetary node.

### Phase 5 — prune_behind respects the indexer

`prune_behind.py` currently tracks only the daemon's recorded height:

```
prune_floor = min(daemon_height, indexer_height) − margin
```

The indexer's height comes from `blockchain.headers.subscribe`, which
`wallet_check.py` already speaks.

**The fail-safe matters more than the check.** If the indexer is stopped or
unreachable, pruning must refuse entirely rather than fall back to the daemon
height. A stalled prune fills a disk — visible and fixable. Deleting blocks
the indexer never saw produces missing wallet history discovered weeks later.

### Phase 6 — end to end on regtest

Electrum wallet → electrs → proxy → monetary node. Receive, confirm, spend,
including a spend of an output whose transaction was stripped.

**Deliverable:** the first evidence any of this works for a wallet user.

## Risks

**Phase 1 assumptions are wrong.** Mitigated only by doing phase 1 first. The
earlier draft of this document is the cautionary example.

**`blockchain.transaction.get` turns out to be load-bearing.** If wallets
routinely fetch raw transactions the proxy cannot serve, the user-visible
failure rate is higher than the 19.34% figure suggests. Phase 1, question 3.

**Scope.** Six phases, with an untested proxy at the centre. Months for one
person. The alpha depends on none of it.

## What this does not change

The v0.1.0 alpha stands alone: node, tools, docs, measured results. It runs
against an unmodified node, requires no indexer, and is not blocked by
anything in this document.
