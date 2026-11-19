# Sambitcoin — an Umbrel community app store

One app: **Monetary Node**, a Bitcoin node that validates every consensus
rule and then stores the chain with the data carriers removed.

## Install

In umbrelOS, go to the **App Store**, open the menu at the top right and
choose **Community App Stores**, then add:

```
https://github.com/sambitcoin/monetary-app-store
```

Monetary Node then appears in your app list.

## Read this before you install

**It needs 2 TB.** 1.5 TB is the floor. The node keeps the whole
blockchain *and* a monetary store derived from it, because the address
index will not run against a pruned node — roughly 740 GB of chain,
700 GB of store and 80 GB of index. The app measures free space before
it starts and refuses to run if it will not fit. Filling the disk takes
down every app on the machine, not just this one, so it stops first.

**The first run takes days.** Core downloads and validates the chain
over Tor, the stripper reads it, then the index is built. On a Raspberry
Pi, expect several days before a wallet can connect.

**It is alpha.** No promises and no roadmap. One person wrote it, four
code reviews found real bugs in it, and the component that deletes
blocks behind the stripper has never run in a release configuration —
it ships disabled.

## What it does

A block's merkle root commits to transaction IDs, not to transaction
data. Keep the 32-byte txid of a transaction you modify or discard and
the block still verifies against the proof-of-work in its own header.
Nothing is forked, nothing is confiscated, no permission is required.

Measured genesis to height 970,000: 36.6 GiB of carriers removed, 720.3
GiB of blocks became a 674.7 GiB store — a 6.33% saving, which is the
honest figure and smaller than people expect. 91.79% of 1.45 billion
transactions are stored completely untouched.

Wallets connect over the Electrum protocol on port 50001. You are never
asked for an extended public key, a seed, or anything that can spend.

## Layout

```
umbrel-app-store.yml           store id (and the required app-id prefix)
sambitcoin-monetary-node/
  umbrel-app.yml               the listing
  docker-compose.yml           one service, digest-pinned
  icon.svg
  gallery/                     screenshots shown in the listing
```

The app id must begin with the store id, so the app is
`sambitcoin-monetary-node` here and the directory name matches it. That
prefix also determines the environment variables umbrelOS exports to the
compose file (`APP_SAMBITCOIN_MONETARY_NODE_IP`), which is why this
compose file differs by those names from the one in the source
repository.

## Source

https://github.com/sambitcoin/BitcoinMonetaryNode

The image is pinned by digest. A tag can be moved; a digest cannot.

BSD-2-Clause.
