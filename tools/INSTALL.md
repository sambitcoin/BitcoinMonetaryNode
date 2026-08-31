# Running a monetary node

From a synced Bitcoin node to a store that strips spam automatically.

Nothing here touches your node, your wallet, or your chain data. The tools read
blocks and write a separate store. If you delete that store, nothing is lost
except the store.

---

## Read this first: today this costs disk space, it does not save it

Your node keeps its `blk*.dat` files. The store is **additional**. Running this
now means roughly 250 GB on top of what you already have.

The saving only exists once a node stores blocks this way *instead of* keeping
complete ones — which needs either a pruned node with the store as its archive,
or changes inside Core or Knots that do not exist yet.

**So what is this for?** It is a working demonstration that the model holds:
blocks still verify with the data removed, dropped outputs stay spendable,
wallets see no difference, and two of these can sync each other without spam
crossing the wire. All measured, all reproducible, every log published.

Install it to check that work, disagree with it, or build on it. Do not install
it expecting a smaller node yet.

Measured savings, so you know what is at stake: **48.7 GB** across blocks
767,430–962,292, which is 16.46% of that era and **6.4% of the full chain**. The
pre-2023 chain is nearly clean, so almost all of the saving comes from the
inscription era.

---

## What you need

- **A fully synced Bitcoin Knots or Core node.** Not pruned — the tools read
  historical blocks.
- **Python 3.8 or later.** No dependencies. Everything is standard library.
- **Free disk space.** About 85% of the size of the block range you strip. For
  the inscription era (blocks 767,430 to today) that is roughly 250 GB.
- **Patience, or a fast disk.** Every timing below was measured on a Raspberry
  Pi 5 with storage doing 12 MB/s. On an NVMe, divide by twenty or more.

---

## 1. Get the tools onto the node

```bash
git clone https://github.com/YOURNAME/YOURREPO
cd YOURREPO/tools
python3 monetary_store.py --help
```

If you cannot clone directly onto the node, copy `tools/*.py` across with
`scp` and check the byte counts match — a truncated Python file fails in
confusing ways.

**Verify before trusting.** Every tool self-tests:

```bash
python3 test_monetary_store.py     # 42 checks
python3 spend_check.py --selftest  # 21 checks, incl. secp256k1
python3 monetary_ibd.py --selftest # 24 checks
python3 monetary_ibd.py --attack-suite   # 14 attacks, all must be rejected
python3 monetary_daemon.py --selftest    # 11 checks
python3 commit_scan.py --selftest        # 13 checks
```

If any of these fail on your machine, stop and open an issue. They pass on
Python 3.8 through 3.13.

---

## 2. Find your blocks directory

```bash
find / -name "blk00000.dat" 2>/dev/null | head
```

On Umbrel with Knots:

```
/home/umbrel/umbrel/app-data/bitcoin-knots/data/bitcoin/blocks
```

Set it once per session — shell variables do not survive a disconnect:

```bash
BLOCKS=/path/to/your/blocks
ls $BLOCKS | head
```

You should see `blk00000.dat` and friends.

---

## 3. Build the block index

Block files do not record heights. They store blocks in arrival order, each
pointing only at its parent, so finding "block 800,000" means reading every
header on disk and walking the chain from genesis.

```bash
python3 -u mindex.py --blocks $BLOCKS
```

**About 10 minutes**, reading 1.8 GB of your 700+ GB — only the 88 bytes per
block that an index needs. Cached afterwards and updated incrementally, so this
is a one-time cost.

Sanity check first if you like:

```bash
python3 -u mindex.py --blocks $BLOCKS --benchmark 20
```

---

## 4. Strip a small range first

Do not start with the whole chain. Prove it works on 2,000 blocks:

```bash
python3 -u monetary_store.py --blocks $BLOCKS \
  --start 900000 --end 902000 --out ~/mstore_test
```

**A few minutes**, about 2.5 GB. What you want to see at the end:

```
merkle verified in memory  2,001 ok, 0 failed
...
verified from disk in ...
  blocks verified     2,001
  blocks failed       0
```

The second one is the real result. It re-reads the store with **no original
block file open** and proves each block still matches its own header.

Independently:

```bash
python3 monetary_store.py --verify ~/mstore_test
```

---

## 5. Strip the inscription era

Only once step 4 is clean.

```bash
setsid nohup python3 -u monetary_store.py --blocks $BLOCKS \
  --start 767430 --end 962292 --out ~/mstore \
  > ~/mstore.log 2>&1 < /dev/null &
```

`setsid nohup` detaches it, so a dropped SSH connection will not kill several
hours of work. Check progress with `cat ~/mstore.log`.

**About 7.5 hours and 250 GB** on slow storage. Change `--end` to your current
tip: `bitcoin-cli getblockcount`.

Verification runs automatically at the end and takes another few hours. It is
worth it — that is the number the whole thing rests on.

---

## 6. Compute the commitment

```bash
setsid nohup python3 -u monetary_commit.py ~/mstore \
  --csv ~/commitments.csv > ~/commit.log 2>&1 < /dev/null &
```

Produces one 32-byte value summarising every stripping decision you made.
**Compare it with other people's.** Same range, same rules, same value — or you
disagree somewhere and the per-block CSV says which block.

Published reference for blocks 767,430–962,292:

```
f0e4c825e753cc9469a2027425c9625801f2bf8662f2e6b3cdbc4647b8406b61
```

---

## 7. Keep it current

This is the part that makes it a node rather than a snapshot.

**Find your RPC credentials.** A cookie file is simplest:

```bash
ls -la /path/to/bitcoin/datadir/.cookie
ss -ltn | grep 8332          # or 9332 on Umbrel
```

**Test the connection first:**

```bash
python3 monetary_daemon.py --test-rpc --rpc-port 8332 \
  --rpc-cookie /path/to/.cookie
```

You want `header check ok`.

**Adopt your existing store** — the daemon refuses to append to a store whose
position it does not know:

```bash
python3 monetary_daemon.py --adopt --store ~/mstore --start-height 767430
```

Adopt sets the commitment to zero because it cannot know your history. If you
computed C in step 6, put it back:

```bash
python3 -c "
import json, sys
p='$HOME/mstore/state.json'
s=json.load(open(p)); s['commitment']=sys.argv[1]
json.dump(s,open(p,'w'),indent=1)" <your C from step 6>
```

**Check, then run:**

```bash
python3 monetary_daemon.py --status --store ~/mstore
```

Wants `store tail  matches state`. Then catch up:

```bash
python3 -u monetary_daemon.py --store ~/mstore --once \
  --rpc-port 8332 --rpc-cookie /path/to/.cookie
```

And leave it following:

```bash
setsid nohup python3 -u monetary_daemon.py --store ~/mstore \
  --rpc-port 8332 --rpc-cookie /path/to/.cookie \
  > ~/daemon.log 2>&1 < /dev/null &
```

Every new block is now stripped six confirmations deep and appended
automatically. Blocks nearer the tip are left alone, so a shallow reorg never
touches the store.

---

## 8. Optional: serve other monetary nodes

```bash
python3 -u monetary_ibd.py --serve ~/mstore --start-height 767430 --port 8451
```

From another machine, with the hash of the block **before** your first:

```bash
python3 -u monetary_ibd.py --sync YOURHOST:8451 \
  --anchor-height 767430 --anchor-hash <hash of block 767429> \
  --out ~/mstore_synced --limit 5000
```

The receiver trusts nothing: it recomputes every block hash, rebuilds every
merkle root, checks proof-of-work against the target each header encodes, and
recomputes Bitcoin's difficulty retarget itself. No spam crosses the wire.

---

## Checking your own results

None of these need the whole chain.

```bash
# Can dropped outputs still be spent? Verifies real ECDSA signatures
# against scriptPubKeys recovered from the index.
python3 -u spend_check.py --store ~/mstore --start-height 767430 --verify-sigs 200

# Do wallets still work? Diffs against any Electrum server.
python3 -u wallet_check.py --store ~/mstore_test --start-height 900000 \
  --addresses addr.txt --electrum electrum.blockstream.info:50002 --ssl

# How much is inscription commit machinery?
python3 -u commit_scan.py --store ~/mstore --start-height 767430 --window 200

# What does dust cost in the UTXO set?
bitcoin-cli -named dumptxoutset path=/path/utxos.dat type=latest
python3 chainstate_filter.py /path/utxos.dat
```

---

## Things that will trip you up

**XOR-obfuscated block files.** Core 28+ obfuscates `blk*.dat` against a key in
`blocks/xor.dat`. A reader that ignores this finds zero blocks **and reports no
error**. These tools handle it, but if you write your own, this will cost you an
afternoon.

**Shell variables do not survive SSH disconnects.** Set `$BLOCKS` again in each
session. A blank variable produces `--blocks: expected one argument`.

**Use `setsid nohup` for anything long.** Plain foreground runs die with your
connection, and hours of work go with them.

**Do not run two heavy tools at once.** They compete for the same disk and each
takes roughly twice as long. One at a time is faster than both together.

**`tail -f` locks your prompt.** Anything you type queues up behind it and fires
when you interrupt. Use `cat` instead.

---

## What this does not do

It does not change what your node validates, relays, or mines. It does not
reject anything. It reads blocks your node has already accepted and decides only
what to keep on disk.

A store cannot serve initial block download to a conventional full node — those
need complete blocks. Monetary nodes serve each other.

Coverage is not complete and cannot be: data hidden in hash fields is
indistinguishable from a legitimate output. See `CARRIERS.md` for the full audit,
including three known gaps.

---

## If something goes wrong

Every tool prints what it did and why it stopped. The logs are the record — if a
figure in a write-up disagrees with a log, **the log is right**.

Open an issue with the command you ran and the output. Disagreements about
where the classification boundaries should sit are the most useful thing anyone
can contribute.
