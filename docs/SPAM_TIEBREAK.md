# Spam-biased tiebreak — design note

**Goal:** when two valid blocks compete at the same height, prefer the one
carrying less spam. Follow most-work as normal the instant either chain is
extended. No fork, no consensus change, no block ever rejected.

Written against Bitcoin Core master, `src/node/blockstorage.cpp` and
`src/node/blockstorage.h`, so the names below are real. Not implemented.

## Why this is not a fork

Chain selection is most-work. At **equal** work, the choice between two valid
tips is arbitrary local policy — Core currently resolves it by order of
arrival, and nodes already disagree with each other based on network topology.

```cpp
bool CBlockIndexWorkComparator::operator()(const CBlockIndex* pa, const CBlockIndex* pb) const
{
    // First sort by most total work, ...
    if (pa->nChainWork > pb->nChainWork) return false;
    if (pa->nChainWork < pb->nChainWork) return true;

    // ... then by earliest activatable time, ...
    if (pa->nSequenceId < pb->nSequenceId) return false;
    if (pa->nSequenceId > pb->nSequenceId) return true;
    ...
```

`nSequenceId` is the first-seen rule, and its own comment describes it as
"sequential id assigned to distinguish order in which blocks are received."
Nothing in consensus depends on it.

Substituting a different equal-work preference is therefore a policy change,
not a rule change. Both blocks stay valid, neither is rejected, and as soon as
one chain gains a block the work comparison decides and this code never runs.

**The line to stay behind:** below majority hashpower this is a preference.
At majority it becomes a soft fork by adoption, because spam blocks would be
systematically orphaned. The code is identical either way; the difference is
who runs it.

## The change

Insert one comparison between work and `nSequenceId`:

```cpp
    if (pa->nChainWork < pb->nChainWork) return true;

    // ... then by spam content, when enabled, ...
    if (g_spam_tiebreak && pa->m_spam_score != pb->m_spam_score) {
        return pa->m_spam_score > pb->m_spam_score;   // lower score sorts "better"
    }

    // ... then by earliest activatable time, ...
    if (pa->nSequenceId < pb->nSequenceId) return false;
```

Note the comparator's convention is inverted — it returns `true` when `pa` is
**worse**, because `setBlockIndexCandidates` is a `std::set` read from the
back. Getting this backwards silently prefers spam.

## Four constraints that will break this if ignored

### 1. The score must never change while the index is in the set

`setBlockIndexCandidates` is `std::set<CBlockIndex*, CBlockIndexWorkComparator>`.
A `std::set` requires its ordering to be stable for as long as an element is
in it. Mutating `m_spam_score` on an index already inserted is undefined
behaviour, and the failure mode is a corrupted set rather than a crash.

So: compute once, during block validation, before the index can enter the
candidate set. Never recompute, never update.

### 2. It must be memoised, not computed in the comparator

The comparator runs constantly and must stay O(1). The score is a field on
`CBlockIndex` populated during `ConnectBlock`, not a call into the classifier.

### 3. Memory-only — do not serialise it

`CDiskBlockIndex::SERIALIZE_METHODS` is the downgrade hazard already
documented in `CORE_PATCH.md`. Adding a field there means an older binary
misreads the index.

It does not need to persist. Races are resolved within seconds; a score that
is lost on restart costs nothing, because by then the tie is long settled.
Blocks loaded from disk get the default and are never in a live race.

### 4. The comparator has a wider blast radius than races

It is not only used for tiebreaks. In `validation.cpp` it also appears in the
`ActivateBestChain` loop (3416), and in the invalidate/reconsider paths (3562,
3634). Changing the ordering changes behaviour in all of them.

This is the part that needs review by someone who knows that code, and the
reason this is a design note rather than a patch.

## Scoring

The score must be **deterministic** — two nodes computing different scores for
the same block will disagree about the tip, and the point is to be predictable.

Simplest defensible metric: **carrier bytes identified by the existing
classifier**, which is already the project's definition of spam and is already
computed per block. Reuse it; do not invent a second definition.

A coarser score is better than a precise one here. Ranking blocks by exact
byte counts makes the outcome sensitive to classifier edge cases; bucketing
(none / some / heavy) makes it robust to them.

**The classifier becomes chain-selection-adjacent.** Today a classifier bug
costs storage accuracy. Wired here, it costs which block the node builds on.
That is a real escalation in the consequences of a false positive, and it is
the strongest argument for keeping the metric coarse and the feature off by
default.

## Configuration

`-spamtiebreak=0` by default. Off must be byte-identical to today.

## What it actually does — stated honestly

**On a mining node it has an effect.** Choosing to build on the cleaner block
in a race means a spam-heavy block carries marginally more orphan risk. That
is an economic signal applied through a lever miners already control.

**On a non-mining node it has almost none.** Ordinary nodes do not decide
races; hashpower does. The second-order effect is that a node relays what it
considers best, so with wide adoption the cleaner block propagates marginally
faster. Weak, but not zero.

**The magnitude problem is real and should be measured first.** Races are
rare — with compact blocks and direct pool connectivity, stale blocks occur on
the order of one in several hundred to a thousand. A preference applied to
that, in only the subset of races where one block is notably cleaner, is a
small lever.

Stale blocks are not in the chain, so this cannot be measured from local data;
fork-monitoring services track them. **Get that number before writing code.**
If it is a handful a month, this is a statement of principle more than a
mechanism — which may still be worth shipping, but should be described as
what it is.

## What this does not do

It does not reject blocks. It does not fork. It does not favour any miner,
pool, or identity — the criterion is block content, not who produced it, and
nothing in the implementation can see or use a coinbase tag.

That last distinction is worth stating explicitly in any public description,
because "bias the tiebreak" invites the assumption that someone is picking
winners.
