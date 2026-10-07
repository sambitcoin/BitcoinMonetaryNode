# Installing a monetary node

Start to finish, on a fresh machine. Every step is reversible except the
last one, which is marked.

**This is alpha software, unreviewed by anyone but its author.** Use a node
you can afford to lose and re-sync. Keep seed words offline on a hardware
wallet; fund any hot wallet pointed at this node with an amount you would
not mind losing. These tools hold no keys and never touch a wallet — the
risk is to your node's block data.

---

## 1. What you need

| | |
|---|---|
| Disk | **2 TB.** The chain is ~720 GB and the store another ~670 GB. Both exist at once during the build. |
| RAM | 8 GB minimum, 16 GB better — a larger `dbcache` shortens the initial sync considerably. |
| CPU | Any x86-64 or ARM64 with four cores. Sync is bound by signature verification. |
| Storage type | **NVMe or SSD.** Not a USB hard drive. Chainstate is random I/O; a spinning disk turns a one-day sync into a week and makes the store build impractical. |
| OS | Linux. Developed on Debian 13 and Raspberry Pi OS. |
| Python | 3.8 or later. No packages to install — every tool is standard library only. |

A 1 TB disk can work if you delete the node's blocks as the build proceeds,
but that makes every bug destructive instead of recoverable. Not recommended
for a first run.

## 2. Basics

```sh
sudo apt update
sudo apt install -y git python3 tmux curl gnupg
```

`tmux` matters more than it looks. The store build runs for hours; tying it
to an SSH session that dies when your laptop sleeps is how you lose a day.

## 3. Bitcoin Core

Download the release, the checksums, and the signatures from
<https://bitcoincore.org/en/download/>, then **verify before extracting**:

```sh
git clone https://github.com/bitcoin-core/guix.sigs
gpg --import guix.sigs/builder-keys/*
gpg --verify SHA256SUMS.asc SHA256SUMS      # want: Good signature
sha256sum --ignore-missing --check SHA256SUMS   # want: OK
tar xzf bitcoin-*-x86_64-linux-gnu.tar.gz
sudo install -m0755 bitcoin-*/bin/* /usr/local/bin/
```

A "key is not certified with a trusted signature" warning is normal — it
means you have not personally marked the key as trusted, not that
verification failed. Several independent builders sign the same checksums;
that agreement is the point.

**On which implementation.** Use Bitcoin Core. In August 2026 a chain split
at height 961,632 produced a fork that changed proof-of-work from SHA256d to
BLAKE2b, and releases from the project that led it follow that chain. Signing
keys prove *who built* a binary, not *what chain it follows* — every
signature can verify and you can still end up somewhere else. Section 6
checks this rather than assuming it.

## 4. Tor

Not optional in this setup. Without it, every peer you connect to learns your
home IP, and your node advertises that address to the wider network.

```sh
./tor_setup.sh
```

That installs Tor, enables its control port, adds you to `debian-tor`, writes
the four required lines into `bitcoin.conf`, and installs a systemd unit with
`Requires=tor.service` so the node will not start without Tor.

**Log out and back in** afterwards — the group change does not apply to your
current session.

The distinction the script exists to enforce: **`proxy` alone is not
enough.** With `proxy` set and `onlynet` unset, bitcoind still dials clearnet
peers and your IP stays visible. Only `onlynet=onion` stops it. Many guides
stop at `proxy`.

Expect a lower peer count. Onion peers are slower to find and slower
generally; this is normal.

## 5. Configure and sync

`~/.bitcoin/bitcoin.conf`, in addition to what `tor_setup.sh` added:

```
server=1
dbcache=8000
prune=0
txindex=0
blockfilterindex=1
```

`prune=0` because the store build needs complete blocks. `blockfilterindex=1`
now, because adding it later means a rescan — compact block filters are how a
wallet finds its history without an address indexer.

```sh
sudo systemctl enable --now bitcoind
bitcoin-cli -getinfo
```

A full sync takes roughly a day on the hardware above. Watch
`verificationprogress` — it is weighted by work, so it crawls early and
accelerates later. That is not a stall.

## 6. Confirm you are on Bitcoin

**Before anything else touches your data:**

```sh
python3 tools/chain_check.py
```

Wants `SAFE TO PROCEED` and all checkpoints matching. It compares block
hashes against known values including height 961,632, the split.

This is not theoretical. During development, a node synced with the wrong
release reached a plausible height, reported `chain: main`, showed no
warnings, and was on the BLAKE2b fork. It cost several days. The check takes
two seconds.

## 7. Build the store

```sh
tmux new -s build
python3 tools/monetary_store.py \
    --blocks ~/.bitcoin/blocks \
    --start 0 --end $(bitcoin-cli getblockcount) \
    --out ~/mstore
```

**Pass `--start 0` explicitly.** A wrong default here once cost the author
blocks 0–767,429 permanently, and a store that does not begin at genesis
cannot bootstrap anyone.

Ctrl-b then d to detach. Six to twelve hours; it prints progress per
thousand blocks. Watch free disk — you need the chain and the store at once.

## 8. Verify

```sh
python3 tools/monetary_store.py --verify ~/mstore
```

Every block reconstructed from the store alone — no original block file
opened — and checked against its own header. **Nothing else happens until
this passes with zero failures.** It re-reads the whole store, so allow a few
hours.

## 9. Commitment

```sh
python3 tools/monetary_commit.py ~/mstore
```

Produces the value another node must match exactly if it applied the same
rules to the same range. **Record it together with the block height** — a
commitment without its height is unverifiable, and it advances with every
block the daemon adds.

## 10. Follow the tip

```sh
python3 tools/monetary_daemon.py --store ~/mstore \
    --rpc-cookie ~/.bitcoin/.cookie --adopt --start-height 0
python3 tools/monetary_daemon.py --store ~/mstore \
    --rpc-cookie ~/.bitcoin/.cookie --status
```

`--adopt` takes ownership of a store the daemon did not create. `--status`
must report `store tail matches state`; a mismatch means the two disagree
about where they are, and appending would corrupt the store.

Adopt sets the commitment to zero. Put the real value back into
`~/mstore/state.json` before running the daemon, or it starts a fresh
commitment chain no genesis-computing node could ever match.

Then, continuously:

```sh
python3 tools/monetary_daemon.py --store ~/mstore \
    --rpc-cookie ~/.bitcoin/.cookie --depth 6 &
```

`--depth 6` keeps six confirmations between the tip and anything stripped, so
a shallow reorg never touches stored data.

## 11. Dashboard

```sh
python3 tools/monetary_ui.py
```

Then from your own machine:

```sh
ssh -N -L 8080:127.0.0.1:8080 user@node
```

and open <http://127.0.0.1:8080>. It binds localhost only and refuses other
addresses — the page shows your height, peers, tip, wallet activity and store
layout.

Read-only by design: no buttons, no shell. A terminal over HTTP would be
remote code execution on your node behind a page with no authentication.

The TOR card is a verdict, not decoration. It counts your peers by network
and says **NOT TOR ONLY** if even one is clearnet.

To watch an indexer as well:

```sh
python3 tools/monetary_ui.py --electrum 127.0.0.1:50001        # electrs
python3 tools/monetary_ui.py --electrum 127.0.0.1:50002 --electrum-ssl  # Fulcrum
```

## 12. Pruning — irreversible

Everything above can be undone by deleting `~/mstore`. This cannot.

```sh
python3 tools/prune_behind.py        # read its --help first
```

It deletes the node's block files behind the daemon, leaving the store as the
archive. **That is where the disk saving actually arrives** — until then the
store costs you space rather than saving it, because you hold both.

Do not run it until the verify in section 8 has passed, the daemon has been
stable for a while, and you are watching. A pruned node cannot serve complete
blocks to a legacy peer and cannot be un-pruned without re-downloading the
chain.

Note that an address indexer needs a non-pruned node. If you want electrs or
Fulcrum, it must finish indexing *before* you prune, or run against a
different node.

## Getting help

Every tool takes `--selftest` and `--help`. To check the whole tree at once:

```sh
./release_check.sh
```

A failing self-test on your machine is more useful than a passing one on the
author's — please open an issue with the output.
