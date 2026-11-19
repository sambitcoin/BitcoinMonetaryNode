# Monetary Node

**A Bitcoin node that enforces every consensus rule and stores the blocks
without the data carriers.**

Inscription witness data, oversized `OP_RETURN`, stamp-style bare multisig,
fake-key P2PK, oversized scriptSig — all removed from block storage after
validation. The blocks still verify against their own headers, against real
proof-of-work.

No fork. No confiscation. Nobody's permission required.

**Where the validation happens.** Bitcoin Core validates. It connects the
block, executes every script, checks every signature. These tools then run
over what Core has already accepted and rewrite how it is stored. The system
enforces every consensus rule; the store does not re-execute them, and no
claim here should be read as saying otherwise. That boundary is the whole
safety argument, and it is why nothing in this repository touches validation
code.

---

## The result

Heights **0 – 970,000** (970,001 blocks) from a fully synced Bitcoin Core
node. Stripped, written to disk in a defined format, then re-verified
**reading nothing but the stripped store** — no original block file opened.

> ### 970,001 blocks verified. 0 failures. 0 corrupt records.
> Each record was also shown to extend the one before it.

| | |
|---|---|
| Carriers removed | **36.6 GiB** |
| Original blocks | 720.3 GiB |
| Monetary store | 674.7 GiB |
| Storage saved | 45.6 GiB (6.33%) — [not the same number, see below](#read-the-two-storage-numbers-carefully) |
| Time | 8h 43m on an NVMe laptop |
| Carrier policy | `d4141831063597f35542c8327314be85b1a719439dbde33a283a75c4ecea2c3e` |

**By carrier**

| Carrier | Removed |
|---|---|
| Inscription envelopes (taproot and P2WSH witness) | 36.5 GiB |
| Stamp-style bare multisig | 102.2 MiB |
| `OP_RETURN` over the 83-byte script limit | 16.7 MiB |
| Oversized scriptSig | 152.7 KiB |
| Fake-key P2PK | 29.9 KiB |

**Transaction treatment**

| | |
|---|---|
| Retained whole | 1,333,831,731 (91.79%) |
| Modified | 119,294,164 (8.21%) |
| Reduced to a txid | 3,562 |
| Filter index entries | 1,100,767 |

### Read the two storage numbers carefully

**36.6 GiB of carriers** and **45.6 GiB saved** are different quantities, and
the 9 GiB gap is not an accounting error.

A transaction that loses a carrier output is *modified*, and a modified
transaction does not carry its witness into the store — the witness is either
the carrier itself, or signature material already verified by Core when the
block was connected. That witness is real disk saved and it is not a carrier,
so it appears in one figure and not the other.

Quote 36.6 GiB when you mean "data carriers found". Quote 45.6 GiB when you mean
"disk no longer used". They are not interchangeable.

---

## Why a block survives losing its data

A block's merkle root is computed over **txids**. The store keeps the 32-byte
txid of every transaction it modifies or discards. Nothing downstream needs to
re-derive those from transaction data — so the data can go, and the block still
verifies against its header.

The stored txids are **self-verifying**. A fabricated txid produces a merkle
root that does not match the header, and the block is rejected. The list cannot
be forged.

Transactions retained unmodified need no stored txid at all; the reader computes
those itself. Only modified or discarded transactions pay the 32 bytes.

This is what the usual objection misses. *"You can't remove `OP_RETURN`, it's
committed inside the txid"* is true only for designs that **recompute** txids.
It does not apply when the txid is stored.

**What the merkle root does not cover.** A modified transaction's stored body
no longer hashes to its own txid — that is the point. So the body is covered by
the record's own digest instead, which detects corruption on this disk and
nothing else. Cross-node agreement is the job of the chained commitment `C`.
`tools/tx_query.py` states this distinction on every answer it gives, because
conflating the two would be the easiest way to overclaim.

---

## The commitment

```
C_h = SHA256d( C_{h-1} ‖ blockhash_h ‖ K_h )
```

`blockhash_h` is **recomputed from the block's own header**, not read from the
record's block-hash field. `K_h` is the record's body digest.

A commitment is only comparable against one computed over the same range under
the same ruleset, so three things travel together or none of them do:

| | |
|---|---|
| `C` | `825e12bc7e00062e1f55c60eb94a31e1dd169753cabc3658693423915c8088b3` |
| height | 970,000 |
| `policy_id` | `d4141831063597f35542c8327314be85b1a719439dbde33a283a75c4ecea2c3e` |

Quoting `C` without its height and policy is publishing an unverifiable number.

---

## Trying it without a Bitcoin node

Every tool is standard library only and carries a `--selftest` that builds its
own fixtures. None of them needs a synced node, a chain, or a network. So a
reviewer can judge the logic in about a minute:

```sh
git clone https://github.com/sambitcoin/BitcoinMonetaryNode
cd BitcoinMonetaryNode
./release_check.sh
```

That runs every suite, checks every shell script parses, validates the Umbrel
package's own invariants, and prints a SHA-256 of every tracked file. It exits
non-zero if anything fails.

The tests worth reading first, because they are the ones the project's claims
rest on:

| What to doubt | Where it is tested |
|---|---|
| A stripped block still verifies against its own header | `test_monetary_store.py` |
| An ordinary contract is not mistaken for an inscription | `test_monetary_store.py`, the BOLT 3 cases |
| A modified transaction's bytes are *not* proven by its merkle branch | `tx_query.py --selftest` |
| The carrier policy cannot be loosened by a malformed payload | `carrier_policy.py --selftest` |
| `C` follows the header, not the record's claim about it | `monetary_commit.py --selftest` |
| The public status page leaks no address, path or port | `status_page.py --selftest` |
| The settings panel never writes an option your build lacks | `node_settings.py --selftest` |
| The race observer calls no RPC that could move the chain | `tip_race.py --selftest` |
| An adversarial IBD peer cannot make the node accept a lie | `monetary_ibd.py --attack-suite` |

A failing self-test on your machine is more useful to this project than a
passing one on mine. Open an issue with the output.

---

## What's here

### Tools

Standard library only. No dependencies.

| Tool | Purpose |
|---|---|
| [`tools/mindex.py`](tools/mindex.py) | Build the block index, reading only the 88 bytes per block that matter. |
| [`tools/monetary_store.py`](tools/monetary_store.py) | Strip, write the store, verify it from disk. |
| [`tools/test_monetary_store.py`](tools/test_monetary_store.py) | Format and classifier checks against synthetic blocks with real merkle roots. |
| [`tools/carrier_policy.py`](tools/carrier_policy.py) | The retention ruleset and its published identifier. |
| [`tools/monetary_daemon.py`](tools/monetary_daemon.py) | Follow the tip, stripping as blocks confirm. |
| [`tools/monetary_commit.py`](tools/monetary_commit.py) | The chained commitment `C`, derived from a store. |
| [`tools/tx_query.py`](tools/tx_query.py) | What this node kept of one transaction, with a merkle branch you check against your own node. |
| [`tools/spend_check.py`](tools/spend_check.py) | Is the filter index sufficient? Includes pure-Python secp256k1 and legacy sighash. |
| [`tools/wallet_check.py`](tools/wallet_check.py) | Compare balances and history against any Electrum server. |
| [`tools/chain_check.py`](tools/chain_check.py) | Are you on the SHA256 chain? Run this before anything irreversible. |
| [`tools/monetary_ui.py`](tools/monetary_ui.py) | Dashboard: network banner, live feed, store state, settings. |
| [`tools/status_page.py`](tools/status_page.py) | The public, read-only face. Commitment and ruleset, nothing else. |
| [`tools/tip_race.py`](tools/tip_race.py) | When two blocks arrive at one height, which was cleaner and which did the network keep? Observation only. |
| [`tools/monetary_ibd.py`](tools/monetary_ibd.py) | How monetary nodes sync from each other. **Design only.** |
| [`tools/chainstate_filter.py`](tools/chainstate_filter.py) | Dust at the UTXO layer, with honest accounting of what it saves. |
| [`tools/sbtc_scan.py`](tools/sbtc_scan.py) | Would a policy change move `C`? Measures it against the real chain. |

Superseded experiments are in [`archive/`](archive/) rather than deleted — they
are what the earliest measurements were taken with.

### Documents

| Document | Contents |
|---|---|
| [`GAMEPLAN.md`](GAMEPLAN.md) | Architecture, build sequence, and what is code versus specification. |
| [`docs/FORMAT_V2.md`](docs/FORMAT_V2.md) | Storage format specification. |
| [`docs/CARRIER_POLICY.md`](docs/CARRIER_POLICY.md) | What counts as a carrier, and why each rule exists. |
| [`docs/CARRIERS.md`](docs/CARRIERS.md) | Carrier audit. |
| [`docs/STRIP_RESULTS.md`](docs/STRIP_RESULTS.md) | Earlier results, with every caveat. |
| [`docs/monetary_ibd_design.md`](docs/monetary_ibd_design.md) | How monetary nodes sync from each other. |
| [`docs/Monetary_Nodes.md`](docs/Monetary_Nodes.md) | Specification draft. |
| [`docs/CORE_PATCH.md`](docs/CORE_PATCH.md) | The Knots-style relay policy patch for Core. |

### Results

[`results/`](results/) holds the unedited logs from every run. They are the
evidence behind every number on this page. If a figure here disagrees with a
log, the log is right. [`results/run-pre-audit/`](results/run-pre-audit/) holds
the state of the superseded store, kept so the retractions below have a
before.

---

## Running it

```sh
python3 tools/chain_check.py    # confirm the node is on Bitcoin
```

**Run `chain_check.py` before anything irreversible.** In August 2026 a chain
split at height 961,632 produced a fork that changed proof-of-work to
BLAKE2b. A node synced with the wrong release reaches a plausible height,
reports `chain: main`, shows no warnings, and is on a different chain. The
checker compares block hashes against known checkpoints, including the split
height, and exits non-zero on a mismatch. This is not hypothetical — it
happened during development of this project and cost several days.

Then, against a fully synced non-pruned node:

```sh
python3 tools/monetary_store.py --blocks ~/.bitcoin/blocks \
    --start 0 --end 970000 --out ~/mstore
python3 tools/monetary_commit.py ~/mstore
```

Pass `--start 0` explicitly. A wrong default here once cost the author blocks
0–767,429 permanently.

Then the daemon follows the tip, and a dashboard shows what is happening:

```sh
python3 tools/monetary_daemon.py --store ~/mstore --adopt --start-height 0
python3 tools/monetary_daemon.py --store ~/mstore \
    --rpc-cookie ~/.bitcoin/.cookie --depth 6 &
python3 tools/monetary_ui.py --store ~/mstore --conf ~/.bitcoin/bitcoin.conf
```

**A warning for anyone reproducing this.** Bitcoin Core 28 and later
XOR-obfuscate `blk*.dat` against an 8-byte key stored in `blocks/xor.dat`. A
reader that ignores this finds zero blocks **and reports no error** — it simply
sees no magic bytes and stops. These tools handle it. The UTXO snapshot format
also mixes two integer encodings: CompactSize for counts and output indices,
Core's base-128 VARINT for coin fields. Mixing them desyncs the parser
immediately.

**Disk.** The store sits on top of the blockchain, not instead of it. Genesis
to tip needs roughly 675 GiB in addition to your ~720 GiB of blocks. A store
that starts at a later height is far smaller, still verifies every block it
holds, and still follows the tip — it simply has nothing to say about history
below where it starts.

---

## Limitations

Stated plainly, because they are the first things a reviewer will look for.

**A stripped block cannot be served to a legacy node.** Conventional full nodes
require complete block data. Monetary nodes can serve each other; they cannot
serve everyone else. If monetary nodes ever became a large share of the network,
who serves the chain is an open question.

**8.21% of transactions lose signature re-verifiability.** `SIGHASH_ALL` commits
to a transaction's outputs, and the stripper removes some of them, so a modified
transaction's signed preimage cannot be reconstructed. The 91.79% retained whole
are unaffected. Every transaction was validated once, in full, by Core, when its
block was connected.

**Monetary IBD is design only and has never been adversarially reviewed.** It
verifies body digests, header hashes, prev-hash linkage, proof-of-work, the
retarget rule and the commitment, and it accepts stripped transactions on
accumulated work. That is an assumevalid-style sync, not full validation. A
node that syncs this way has not re-executed the scripts in the blocks below
its starting point. Three independent reviewers identified this as the
project's largest unexamined risk, and they are right.

**The filter-index evidence needs re-measuring.** The published "7 of 806,626
dropped outputs were ever spent, 6 signatures re-verified" result was computed
against a store built by the pre-audit stripper, which no longer exists.
`spend_check.py` and `wallet_check.py` have not yet been re-run against the
current store. Until they are, treat the anti-confiscation claim as
*previously demonstrated, not currently measured*.

**Signature verification coverage is narrow.** `spend_check.py` verifies
`SIGHASH_ALL` bare multisig only. It does not cover other sighash types or any
SegWit spend. It enforces low-S. The "nothing is stranded" argument rests on a
sample, not on the whole population.

**Value conservation needs the whole UTXO set in RAM.** Near the tip that is
roughly 100 million entries, tens of gigabytes. Use
`spend_check.py --completeness-only` on ordinary hardware; the central claim
and signature verification are unaffected.

**Dust figures are a proxy.** They count sub-1000-sat P2TR outputs from the
inscription era, which includes ordinary small taproot payments and excludes
inscription outputs above the threshold. Not a direct measurement of
inscription activity, and not consensus dust.

**Chainstate removal is not deletion.** Dust is removed from the UTXO database
and retained in block storage. That is a real saving in the structure that wants
to live in RAM — but it is relocation, not deletion, and the two layers must not
be added together.

**The classifier is a policy decision.** Something has to decide what counts as
a carrier. That decision lives in storage and never in consensus — no classifier
touches validation. It can still be wrong; see Corrections. Runes mostly fall
under the 83-byte limit and currently pass, which is a boundary worth arguing
about.

**Inscription detection requires a known protocol tag.** Only envelopes opening
with `ord` are detected. An envelope protocol not on that list is retained, not
stripped. That is the deliberate direction of the error: a missed carrier wastes
disk, a false match destroys signatures. See Corrections.

**Single node, single run.** Independent reruns are the most useful contribution
anyone could make, particularly disagreements about where the classification
boundaries should sit.

---

## Corrections

Published figures from this project that were wrong. They are retracted here
with reasons, and the originals left visible in the documents. Four independent
code reviews have been run against this repository and every one of them found
something real.

| Claim | Reality |
|---|---|
| Spam removed is 51.1 GiB (7.12%) | The inscription detector matched the *shape* of an envelope — a push, then `OP_IF`, then data pushes — which is also the shape of a Lightning HTLC and any hash-locked contract. Those transactions were marked modified and lost their **entire witness**. **14.5 GiB, about 28% of the figure, was contract signature data, not carriers.** Real figure **36.6 GiB**. Detection now requires the `ord` protocol tag, with regression tests built from real BOLT 3 scripts. |
| Oversized scriptSig removed: 13.8 KiB | Counted and then copied into the store verbatim. `rebuild_without` reserialised inputs unchanged, so the bytes never left the disk. A saving that never happened. Now actually removed: **152.7 KiB** over genesis to 970,000. |
| `policy_id` describes the store | `monetary_store.py` never imported `carrier_policy.py`. The stripper applied a bare length test while the status page published a `policy_id` for a ruleset that had never run. Now one source, and a store records the policy that built it. Wiring them together also exposed a three-byte disagreement: Core's limit is on the **script**, not the payload. |
| `C` commits to the block hash | It committed to the 32-byte field the record *claimed*, which the format specification itself describes as "not trusted, recomputed from header". Now recomputed from the header. |
| 19.34% of transactions modified | Inflated by the envelope bug, and measured over 194,863 inscription-era blocks rather than the whole chain. Genesis to 970,000: **8.21%**. |
| Stamps are 77.5 MiB | Reported under "bare multisig" together with fake-key P2PK, which is a different carrier. Separated: bare multisig **102.2 MiB**, fake-key P2PK **29.9 KiB**. |
| `OP_RETURN` spam is 2.9 GiB | The tool classified *every* `OP_RETURN` as spam, including small policy-compliant ones. Data above the limit is **16.7 MiB**. |
| Stamps are 0 bytes | The detector checked key prefixes, which Stamps deliberately make look standard. Corrected by testing whether each key is a point on secp256k1. |
| Stripped transactions cannot be re-verified | Too loose. Precisely: transactions *modified or stripped* lose signature re-verifiability. The rest are unaffected. |
| Storage figures in GB | They were measured in powers of 1024 and labelled with decimal units, so **every storage figure this project has published was GiB wearing a GB label**. Two tools in the repository disagreed — the same store read as 674.7 GB by one and 724.5 GB by the other — which is how it was found. The measurements were right; the labels were not. All figures above are now GiB, and a test compares the tools against each other. Percentages are unaffected, being ratios of same-base numbers. |

Tooling and robustness findings from the same reviews, which changed no
published figure: `spend_check.py` and `wallet_check.py` read store records
without verifying the body digest, so they could compute cryptographic results
over corrupt data; `verify_store` claimed sufficiency without checking that
records form one chain; `scan_file` truncated the block index silently on
mid-file corruption; `load_state` crashed on a corrupt `state.json` under a
restart loop; the IBD record parser enumerated exception types for input an
attacker chooses. All fixed, all with tests.

---

## Status

| Step | State |
|---|---|
| Block measurement | done |
| Chainstate measurement | done |
| General stripper | done — genesis to 970,000 |
| Storage format | done |
| Store written and re-verified from disk | done — 0 failures, chain linkage checked |
| Carrier policy with a published identifier | done |
| Chained commitment `C` | done — computed on a real store |
| Policy divergence scan against the real chain | done — 0 divergences in 970,386 blocks |
| The daemon | done — follows the tip |
| Dashboard, status page, transaction query | done |
| Tor-only enforcement | done — kernel-enforced, with a verifier |
| Electrum index alongside | done |
| Spend validation from the filter index | **needs re-running on the current store** |
| Wallet comparison | **needs re-running on the current store** |
| Knots-style relay policy patch for Core | **written, never compiled** |
| Monetary IBD | **design only, never adversarially reviewed** |
| Umbrel package | alpha, not yet published |
| Independent reproduction by anyone else | **not done** |

Please read [`GAMEPLAN.md`](GAMEPLAN.md) before assuming anything here is
finished.

---

## Prior and related work

This is not the only proposal in this space, and pretending otherwise would be
dishonest.

**[Utreexo](https://bitcoinops.org/en/topics/utreexo/)** replaces the UTXO set
with a hash accumulator. Lossless and content-neutral: nothing is deleted,
nothing is judged, and block storage is untouched. A different problem — but if
it ships, the chainstate half of the argument here weakens considerably, because
UTXO set size stops being expensive.

**[Dust expiry](https://delvingbitcoin.org/t/dust-expiry-clean-the-utxo-set-from-spam/1707/)**
(Robin Linus) proposes removing low-value outputs from the UTXO set after a
time. Close to the dust filtering here. The difference: that needs a soft fork,
this does not.

**[Witnessless sync](https://delvingbitcoin.org/t/witnessless-sync-for-pruned-nodes/1742/)**
(Jose SK) proposes pruned nodes skipping witness download for `assumevalid`
blocks. Ruben Somsen's objection there applies with more force here: if nobody
routinely validates that data exists, it can be lost. Worth reading before
engaging with this project.

---

## How to help

Most useful, in order:

1. **Attack the IBD design** in `docs/monetary_ibd_design.md` and
   `tools/monetary_ibd.py`. Three reviewers independently named it the largest
   unexamined risk. Every earlier design in this project failed on second
   inspection.
2. **Rerun the measurements** on your own node and report disagreements. One
   node and one run is the weakest part of every figure above.
3. **Argue about the classification boundaries.** Where should the line sit for
   `OP_RETURN`? For dust? For Runes, which mostly fall under the limit and so
   currently pass? Is `ord` the only envelope tag that matters?
4. **Find an error.** Every review so far has found one. There are likely more.

---

## Licence

BSD-2-Clause. See [LICENSE](LICENSE).
