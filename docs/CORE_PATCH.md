# Monetary block storage in Bitcoin Core

A design note, not a patch. Written against `src/node/blockstorage.h` and
`src/chain.h` at master, so the names and constants below are real rather than
remembered. I have not written this code and cannot compile it — what follows is
an attempt to be precise enough that someone who knows this area can say "yes,
that seam works" or "no, X breaks" without first reverse-engineering my
intentions.

Where I am unsure I say so. There are four such places and they are the reason
for the document.

---

## What already works, outside the node

A companion process reads blocks the node has validated, removes data carriers,
and maintains a separate store. On mainnet, blocks 767,430–962,292:

| | |
|---|---|
| Data carriers removed | 37.2 GB — 12.56% of era block bytes |
| Blocks re-verified from the store alone | 194,863, zero failures |
| Dropped outputs later spent | 7 of 806,626 — all validatable locally, 6 signature-verified |
| Wallet histories vs an independent Electrum server | 32 of 32 identical |
| Sync between two such nodes | 5,000 blocks, 0 rejected, 14 adversarial cases rejected |

**Its defect is duplication.** The node keeps `blk*.dat`; the store is
additional. The saving is only realised by pruning the node and letting the
store be the archive — which works, and is what I run, but is two storage
systems where there should be one.

---

## Mechanism

A block's merkle root is computed over txids. Retain the 32-byte txid of every
transaction modified or discarded, and nothing downstream needs to re-derive it
from transaction data — so the data can go and the block still reconstructs to a
root matching its header. Fabricated txids produce a mismatch, so the retained
list cannot be forged. Transactions kept whole need no stored txid.

Same property as whitepaper section 7, different selection criterion: section 7
prunes *spent* transactions; this removes data carriers regardless of spentness,
which is why it needs an index section 7 does not.

---

## Scope

**In scope:** what `BlockManager` writes to disk after `ConnectBlock` has
returned.

**Out of scope:** validation, consensus, relay policy, mempool, mining. No
classifier runs before or during validation. A bug in stripping must not be able
to affect which chain the node follows.

---

## Where it fits

### The prune-lock mechanism already does the hard part

`BlockManager` maintains `m_prune_locks`, a map from name to `PruneLockInfo{
height_first }` — "do not prune below this height." Indexes already use it.

A monetary stripper is structurally an index: it consumes blocks in order, lags
the tip, and must not have blocks deleted from under it. It registers a prune
lock and advances it as it goes. `FindFilesToPrune` already honours this.

This is the piece I expected to have to invent, and it is already there. It also
means the external tool I wrote to hold pruning back is redundant once this is
internal.

### Blockfiles are already segmented by type

```cpp
enum BlockfileType { NORMAL = 0, ASSUMED = 1, NUM_TYPES = 2 };
```

with `m_blockfile_cursors` indexed by type, and `BlockfileTypeForHeight()`
deciding which a block belongs to. The comment explains the motivation —
avoiding wildly different height ranges in one file, because it "would impair
our ability to prune effectively."

A `STRIPPED` type fits that existing structure rather than fighting it.

### The read path already has an error channel

```cpp
enum class ReadRawError { IO, BadPartRange };
using ReadRawBlockResult = util::Expected<std::vector<std::byte>, ReadRawError>;
ReadRawBlockResult ReadRawBlock(const FlatFilePos& pos, ...) const;
```

Adding `ReadRawError::Stripped` gives callers an explicit, typed answer rather
than a partial block. The two `ReadBlock` overloads return `bool` and would need
the same treatment — a caller that silently receives an incomplete `CBlock` is
how this becomes a consensus bug.

---

## The four things I am unsure about

### 1. Where the stripped position lives — and `nFile` is shared

`CBlockIndex` has one `nFile`, used for **both** `blk?????.dat` and
`rev?????.dat`:

```cpp
int nFile;               // which blk?????.dat AND which rev?????.dat
unsigned int nDataPos;   // offset in blk
unsigned int nUndoPos;   // offset in rev
```

So a stripped block cannot simply be repointed to a different file number
without dragging its undo data along. That kills the "parallel `mblk*.dat` with
its own numbering" idea unless new fields are added:

```cpp
int nStrippedFile;
unsigned int nStrippedPos;
```

serialized conditionally in `CDiskBlockIndex`, the way `nDataPos` and `nUndoPos`
already are:

```cpp
if (obj.nStatus & BLOCK_HAVE_DATA) READWRITE(VARINT(obj.nDataPos));
if (obj.nStatus & BLOCK_HAVE_UNDO) READWRITE(VARINT(obj.nUndoPos));
```

**The alternative is rewriting `blk*.dat` in place**, one file at a time into a
replacement and swapping, so positions change but the layout stays as it is.
Some of that machinery exists around `FlushBlockFile` and `PruneOneBlockFile`.

I do not know which is less invasive. **This is the question I would most like
answered**, because it determines almost everything else.

### 2. A new status bit, and what a downgrade does

The enum has room — occupied values run to 256, so 512 is free:

```cpp
BLOCK_OPT_WITNESS     = 128,
BLOCK_STATUS_RESERVED = 256,   // unused
BLOCK_STRIPPED        = 512,   // proposed
```

`nStatus` is serialized as `VARINT`, so an added bit is ignored by code that
does not know it. That is the problem, not the reassurance: **an older binary
reading this index would see `BLOCK_HAVE_DATA` set and believe it has complete
blocks.** It would then serve truncated data to peers or fail obscurely.

Options seem to be: clear `BLOCK_HAVE_DATA` and rely entirely on the new bit,
which is honest but touches every `GetBlockPos()` caller; or bump a database
version so old binaries refuse the directory outright. The second seems safer
and I would expect it to be required.

Note `GetBlockPos()` returns an empty `FlatFilePos` unless `BLOCK_HAVE_DATA` is
set, so whichever way this goes, that function is on the path.

### 3. `-reindex` cannot work, and I do not know if that is fatal

Reindex rebuilds the block index by re-reading `blk*.dat`. Stripped blocks
cannot reproduce complete ones, so a monetary node cannot reindex.

`m_blockfiles_indexed` and the reindex flag in `BlockTreeDB` are the relevant
machinery. The honest options are to refuse reindex outright, or to permit it
only in a mode that rebuilds from the stripped form and accepts the result is
not a normal node.

Pruned nodes already cannot return to unpruned without re-downloading, so there
is precedent for one-way doors — but reindex is a repair tool, and taking it
away removes a recovery path people rely on when something goes wrong. **I
suspect this is the objection that decides whether this belongs in Core at all.**

### 4. Which callers of the read path break

I can enumerate the obvious ones but not exhaustively, and the ones I have
missed are the dangerous ones.

| Caller | Needs | Under stripping |
|---|---|---|
| `net_processing`, serving `getdata` | complete block | must not serve; needs a service-bit story |
| Reorg / undo | `CBlockUndo` from `rev*.dat` | unaffected — separate file, separate path |
| `getblock` RPC | complete block | error naming the reason |
| Wallet rescan | complete block | fails below the strip horizon, as on a pruned node |
| `txindex`, filter indexes | complete block | must be built ahead of the stripper's prune lock, or disabled |
| `-reindex` | complete blocks | see above |

---

## Other pieces

**Config.** `-monetarystore=1` (default off, off must be byte-identical to
today) and `-monetarydepth=N` (default 6).

**Strip at depth, not at connect.** A reorg shallower than the depth never
touches stripped data, so there is no rollback path to get wrong; the commitment
only extends over blocks that will not change; and an inscription's commit
output — which sits in an earlier block than the reveal identifying it — becomes
removable, worth a further 4.97 GB measured.

**Filter index.** Each dropped output retains outpoint, amount, scriptPubKey and
height, about 82 bytes, so a later spend validates locally with no peer. Measured:
806,626 dropped outputs, seven ever spent, all seven validatable. It is almost
pure insurance and costs about 66 MB. Plausibly it belongs in the existing index
framework.

**Commitment.** `C_h = SHA256d(C_{h-1} ‖ block hash ‖ K_h)` where K digests
everything stored for that block. Two nodes that stripped identically produce
identical C; one disagreement diverges permanently and visibly. Exposed by RPC
so operators can compare. Reference for 767,430–962,292:

```
f0e4c825e753cc9469a2027425c9625801f2bf8662f2e6b3cdbc4647b8406b61
```

Two independent implementations agree on it.

**Obfuscation.** `m_obfuscation` is now a first-class `BlockManager` member.
Stripped files must go through it too, or the format becomes inconsistent with
the rest of the directory.

---

## What I am asking

1. **In-place rewrite, or new file type with new index fields?** `nFile` being
   shared between block and undo is the constraint I keep running into.
2. **Is refusing `-reindex` disqualifying?**
3. **What breaks that the table above misses?**
4. **Does this belong in Core, in Knots, or only in a `libbitcoinkernel`-based
   implementation designed for it?** I lean toward the last as the endgame, with
   a patch as the way to test the idea in something people already run.

"This is unworkable because X" is more useful than silence, and better heard now
than after someone writes the code.

---

## Reference implementation

Standard-library Python, no dependencies: storage format with 42 tests, verifier,
commitment, sync protocol with a 14-case attack harness, daemon, converter, and
the measurement tools behind every figure above. Every raw log published. Where a
write-up and a log disagree, the log is correct.
