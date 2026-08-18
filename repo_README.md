# inscription-payload-scan

Tools for measuring how much of Bitcoin's blockchain and UTXO set is
inscription data, by reading block files and UTXO snapshots directly.

Measured 13–17 August 2026 at chain tip 962,292. To my knowledge these are the
first published figures separating inscription **payload bytes** from witness
data generally, and the first independent reproduction of the inscription-era
UTXO share by a method that does not rely on an Ordinals indexer.

## Results

**Blocks 767,430 – 962,292** (194,863 blocks, Dec 2022 – Aug 2026):

| | |
|---|---|
| Block bytes | 296.2 GB |
| Witness bytes | 163.2 GB (55.10% of blocks) |
| **Inscription envelope payload** | **37.1 GB** |
| — share of witness | 22.71% |
| — share of block bytes | 12.51% |
| Envelopes | 130,502,370 |
| Transactions parsed | 628,773,234 |

**UTXO set** at block `…5e02eb7`, 165,858,242 outputs, 11.8 GB serialised:

| | |
|---|---|
| Outputs below 1,000 sats | 46.69% of outputs, 49.12% of bytes |
| **P2TR dust created ≥ 767,430** | **28.70% of outputs, 30.84% of bytes** |
| Created after block 767,430 (all types) | 67.67% of outputs |
| P2TR share of UTXO set | 32.72% by count, 35.15% by bytes |
| Bare multisig (Stamps) | 2,646,140 outputs, 384 MB |

Full detail and caveats in [RESULTS.md](RESULTS.md).

## Three findings worth pulling out

**Taproot adoption is mostly inscription residue.** P2TR is the largest script
type in the UTXO set, but 47.6 million of its 54.3 million outputs are
sub-1000-sat outputs from the inscription era — about 88%.

**Two thirds of the UTXO set is younger than three and a half years.** 112.2
million of 165.9 million outputs postdate block 767,430.

**Witness data is not synonymous with spam.** Inscription payload is 22.71% of
witness bytes; the remaining three quarters are ordinary signatures. Proposals
to discard witness data discard considerably more signature data than
inscription data.

## Tools

### `inscription_scan_local.py`

Reads `blk*.dat` directly and counts envelope payload bytes per block.

```
python3 inscription_scan_local.py \
  --blocks /path/to/bitcoin/blocks \
  --start 767430 --end 962292 \
  --csv results.csv
```

Requires a non-pruned node. Builds its own block index from prev-hash links,
since block files do not record heights. Handles the XOR-obfuscated blocksdir
introduced in Core 28. Resumable with `--resume`.

Roughly 5h30m on Umbrel-class hardware plus 30 minutes indexing.

### `utxo_scan.py`

Reads a `dumptxoutset` snapshot and reports composition by script type, value
band, and creation era.

```
bitcoin-cli -named dumptxoutset path=/path/utxos.dat type=latest
python3 utxo_scan.py /path/utxos.dat
```

About 23 minutes for 165 million outputs. Streams the file; memory stays flat.

## Method

For each transaction, identify taproot script-path spends (BIP341: the final
witness item is a control block of 33 + 32m bytes with leaf version `0xc0`
after masking the parity bit), parse the tapscript, locate unexecutable
branches, and sum the data pushed inside them.

**Falsity is evaluated by script semantics, not opcode literal.** `OP_0`, an
empty push, and a push of `0x00` all open an envelope. Matching only the
literal `OP_FALSE` byte would miss re-encoded variants.

Payload counts only the data pushed inside the branch. Control blocks,
signatures, stack arguments and surrounding tapscript are excluded — this
measures the embedded data, not the machinery carrying it. **The figure is
therefore a floor**, not a ceiling, on the on-chain cost of inscription
activity.

## Validation

**False positives.** Run over blocks 709,632–715,000 — after Taproot
activation, before the first inscription. 9,847,964 transactions, 2.7 GB of
witness data, real script-path spends.

> **0 envelopes, 0 bytes, 0 parse failures.**

**Cross-implementation.** An independent RPC-based implementation over blocks
767,430–776,098 produced byte-identical totals at every checkpoint.

**Marker consistency.** 97.8% of envelopes carry the `ord` marker, rising to
100% in the earliest blocks. The parser does not search for that marker
structurally, so the correlation is evidence it is matching inscriptions rather
than arbitrary script patterns.

**Independent corroboration.** The UTXO figure of 28.70% is within one
percentage point of mempool.space's 29.6% (May 2025), derived by matching
txids against an Ordinals index — a completely different method.

**Supply check.** The UTXO scanner's total came to 20,071,432 BTC, matching
expected circulating supply. A fault in the amount decompression would show up
immediately here.

**Parse failures.** 2,645 scripts of 130.5 million (0.002%) resembled envelopes
but failed to parse and were excluded rather than estimated.

## Note for anyone reproducing this

Bitcoin Core 28 and later XOR-obfuscate `blk*.dat` against an 8-byte key stored
in `blocks/xor.dat`, applied cyclically by absolute file offset. A reader that
ignores this finds zero blocks **and reports no error** — it simply sees no
magic bytes and stops. `inscription_scan_local.py` detects and handles it.

Note also that the UTXO snapshot format uses two different integer encodings:
CompactSize for counts and output indices, Core's base-128 VARINT for coin
fields. Mixing them desyncs the parser immediately.

## Limitations

- Grammar-bound: counts data in unexecutable taproot branches. A materially
  different construction would be missed.
- Witness-only: `OP_RETURN`, stamp-style bare multisig, and scriptSig-embedded
  data are not counted in the block figure.
- The UTXO inscription figure is a proxy. A UTXO does not record whether its
  creating transaction carried an envelope, so it counts dust taproot outputs
  from the inscription era — including some ordinary small payments, excluding
  any inscription output above the dust threshold.
- Single node, single run, one tip height.

## Licence

BSD-2-Clause. Independent reruns and disagreements about where the grammar
boundary should sit are the most useful contributions anyone could make.
