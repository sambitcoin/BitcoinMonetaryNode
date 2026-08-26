# Inscription payload bytes in Bitcoin's blockchain — a measurement

Measured 13 August 2026, at chain tip **962,292**, by direct parsing of block
files on a fully synced Bitcoin Knots node.

To my knowledge this is the first published figure separating **inscription
envelope payload bytes** from ordinary witness data. Existing public figures
measure either total witness bytes or inscription-related UTXO *counts*; neither
answers how many bytes of the chain are inscription payload.

## Headline

Across the inscription era — blocks **767,430 to 962,292**, 194,863 blocks,
December 2022 to August 2026:

| Measure | Value |
|---|---|
| Block bytes | 296.2 GB |
| Witness bytes | 163.2 GB (**55.10%** of block bytes) |
| **Inscription envelope payload** | **37.1 GB** |
| — as share of witness data | **22.71%** |
| — as share of block bytes | **12.51%** |
| Envelopes found | 130,502,370 |
| Transactions parsed | 628,773,234 |

Of those envelopes, **127,600,564 (36.2 GB)** carry the `ord` protocol marker.
**2,901,806 (921.9 MB)** do not — other protocols using the same technique.

Mean payload per envelope is roughly **305 bytes**, and there are about **670
envelopes per block** on average. The bulk of inscription volume is therefore
small JSON-style payloads rather than large images.

## What this does and does not say

**It says:** inscription payloads account for 37.1 GB of Bitcoin's block data,
12.51% of blocks mined since inscriptions began, and 22.71% of witness data in
that period.

**It does not say** that witness data is spam. Over three quarters of witness
bytes in this era are ordinary signatures — the data that authorises real
payments. Any proposal to discard witness data discards far more signature data
than inscription data.

**It does not measure** non-witness data carriers. OP_RETURN payloads, stamp-style
bare multisig, and scriptSig-embedded data are not counted here; published
figures put those under 0.5% of chain bytes combined.

**Whole-chain share:** pending. This measurement covers the inscription era
only. The pre-767,430 chain contains no inscriptions by definition, so the
whole-chain percentage will be substantially lower than 12.51%.

## Method

For every block in range, read directly from `blk*.dat` — no RPC:

1. Parse each transaction, including SegWit marker, flag and witness stacks.
2. Identify taproot script-path spends: the final witness item is a control
   block of 33 + 32m bytes whose leading byte has leaf version `0xc0` after
   masking the parity bit (BIP341).
3. Parse the tapscript — the second-to-last witness item.
4. Locate unexecutable branches: a provably false condition followed by `OP_IF`,
   closed by the matching `OP_ENDIF`, with nesting tracked.
5. Sum the bytes of all data pushes inside that branch.

**Falsity is evaluated by script semantics, not by matching opcode literals.**
`OP_0`, an empty push, and a push of `0x00` all open an envelope. Matching only
the literal `OP_FALSE` byte would miss trivially re-encoded variants.

Payload is counted as **the bytes of data pushed inside the branch**. Control
blocks, signatures, stack arguments and the surrounding tapscript are excluded —
this measures the embedded data, not the machinery carrying it.

### Note on obfuscated block files

Bitcoin Core 28 and later (and Knots) XOR-obfuscate `blk*.dat` against a random
8-byte key stored in `blocks/xor.dat`, applied cyclically by absolute file
offset. Any tool reading block files directly on a modern node must undo this or
it will find nothing. This surprised me and is worth flagging for anyone
reproducing the work.

## Validation

**Cross-implementation agreement.** An independent RPC-based implementation was
run over blocks 767,430–776,098 and produced byte-identical payload totals to
the file-reading implementation at every checkpoint. Two separate code paths,
same answer.

**False-positive test.** The parser was run over blocks **709,632 to 715,000** —
the window between Taproot activation and the first inscription. That range
contains 9,847,964 transactions and 2.7 GB of witness data, including genuine
taproot script-path spends.

> **Result: 0 envelopes, 0 bytes, 0 malformed scripts.**

The parser does not match ordinary script-path spends.

**Marker consistency.** 97.8% of envelopes found carry the `ord` marker. In the
earliest era the figure was 100%. A parser matching noise would show no such
correlation with a protocol identifier it does not search for structurally.

**Parse failures.** 2,645 scripts across 130.5 million envelopes (0.002%)
resembled envelopes but failed to parse cleanly and were excluded rather than
estimated. This slightly understates the total.

## Known limitations

- **Grammar-bound.** Counts data in unexecutable taproot branches. Inscriptions
  using a materially different structure would be missed.
- **Witness-only.** Data in outputs, `OP_RETURN`, or `scriptSig` is not counted.
- **Payload-only.** Excludes the tapscript framing, control block and signatures
  that accompany an inscription, so the total on-chain cost of inscription
  activity exceeds the payload figure reported here.
- **Single node, single run.** Figures reflect one node's block files at tip
  962,292 on 13 August 2026.

## Reproducing

```
python3 inscription_scan_local.py \
  --blocks /path/to/bitcoin/blocks \
  --start 767430 --end 962292 \
  --csv results.csv
```

Requires a non-pruned node. Standard library only, no dependencies. The scan
took 5h29m on Umbrel-class hardware, plus ~30 minutes to index block files.
Per-block output is in `results.csv`: height, block bytes, transaction count,
witness bytes, envelope count, payload bytes, `ord`-marked counts, and parse
failures.

## Licence

Scanner and results released under BSD-2-Clause. Corrections and independent
reruns welcome — particularly disagreements about where the grammar boundary
should sit.
