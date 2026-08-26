# Raw run output

The unedited logs behind every figure published in this repository. Kept so
that anyone checking the work can see what the tools actually printed rather
than only what was written up.

All runs were on a Raspberry Pi 5 Umbrel with Bitcoin Knots, chain tip 962,292,
August 2026. Storage read at roughly 12 MB/s, which is why the timings are long.

| File | Command | What it shows |
|---|---|---|
| `mindex.log` | `mindex.py --blocks $BLOCKS` | Block index build. 963,373 blocks in 9m41s, reading 1.81 GB of 696 GB — 0.26% — because only the 88 bytes per block that an index needs are read. |
| `mstore.log` | `monetary_store.py --blocks $BLOCKS --start 767430 --end 962292 --out ~/mstore` | The full strip. Per-carrier totals, transaction treatment counts, and 194,863 merkle roots verified in memory with zero failures. 7h24m. |
| `verify.log` | `monetary_store.py --verify ~/mstore` | The result that matters: 194,863 blocks reconstructed from the 247.4 GB store alone, with no block file opened, every one matching its own header. 0 failed, 0 corrupt. 3h26m. |
| `strip_test.log` | `monetary_store.py --start 900000 --end 902000` | A 2,001-block run used to check behaviour before committing to the full pass. |
| `spend_check.log` | `spend_check.py --store ~/mstore --start-height 767430 --verify-sigs 200` | Filter index sufficiency. 806,626 dropped outputs, 7 ever spent, all 7 with their entry, 6 with signatures re-verified against recovered scriptPubKeys. 8h50m. |
| `scan.json` | `wallet_check.py --store ~/mstore_test --start-height 900000` | Balances and history for 40 sampled addresses, computed from the stripped store. |
| `addr.txt` | derived from block 900,500 | The address sample used for the wallet comparison. Taken from a single block so the selection is not cherry-picked. |

## Reading these honestly

**Figures in the write-ups should match these logs.** If one does not, the log
is correct and the write-up is wrong — please open an issue.

**Some numbers here are superseded.** Earlier runs used a bare multisig detector
that reported 0 bytes because it checked key prefixes, which Stamps deliberately
make look standard. Logs from before that fix under-report the multisig carrier.
The correction is documented in `docs/STRIP_RESULTS.md`.

**The timings are hardware-bound, not algorithm-bound.** A 12 MB/s drive
dominates every figure here. On an NVMe the same work takes a small fraction of
the time.
