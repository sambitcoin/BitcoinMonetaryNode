# Advertising as a monetary node

The `software` row in the dashboard's NODE card is `getnetworkinfo.subversion`
— the string your node sends to every peer in its `version` message. Stock
Core v31 sends:

```
/Satoshi:31.0/
```

You want `monetarynode`. Two ways, and they are not equivalent.

## The name is a compile-time constant

`uacomment` cannot replace it. That option only appends:

```
uacomment=monetarynode      ->   /Satoshi:31.0(monetarynode)/
```

That is the no-rebuild option and it is honest — it says "Core, with
something added". If that is enough, add the line and restart. Nothing else
in this file is needed.

To actually replace the name you patch `src/clientversion.cpp` and rebuild.

## The patch

```diff
--- a/src/clientversion.cpp
+++ b/src/clientversion.cpp
@@
-const std::string CLIENT_NAME("Satoshi");
+const std::string CLIENT_NAME("monetarynode");
```

That is the whole change. Verify the line first, because the surrounding code
has moved between releases:

```sh
grep -n 'CLIENT_NAME' src/clientversion.cpp
sed -i 's/CLIENT_NAME("Satoshi")/CLIENT_NAME("monetarynode")/' src/clientversion.cpp
grep -n 'CLIENT_NAME' src/clientversion.cpp      # confirm before building
```

Then rebuild, restart, and check:

```sh
bitcoin-cli getnetworkinfo | grep subversion
```

Expect `/monetarynode:31.0/`. The dashboard picks it up on the next poll with
no change to `monetary_ui.py`.

## On the separator

You wrote `monetarynode.31`. `FormatSubVersion()` builds `/name:version/`, so
setting `CLIENT_NAME` gives you `/monetarynode:31.0/` with a colon. That is
BIP14, and it is what every crawler expects.

A literal `monetarynode.31` would mean breaking the separator, and the
crawlers that would count monetary nodes — Bitnodes, Luke's node-count pages
— split the subversion on `:` to get name and version. A node that does not
split becomes an unparsed outlier rather than a counted implementation.
Getting counted is most of the reason to rename at all, so the colon form is
almost certainly what you want. Say the word if you want the literal dot
anyway; it is the same one-line change.

## What this costs

The subversion is broadcast to every peer you connect to. Today your node is
indistinguishable from tens of thousands of others. After this it announces,
to everyone it meets, that it is running unreviewed alpha software that
stores blocks differently from every other node on the network.

Tor keeps that from being tied to your home IP, which is most of the risk.
What remains is that you are advertising an interesting target, and that a
population of one is not anonymous within itself — every `monetarynode` peer
seen anywhere on the network for a while will be you.

That may be exactly the point. Knots is countable because it renamed, and a
visible count is how an implementation stops being one person's experiment.
But make it a decision rather than a side effect, and consider leaving the
Umbrel reference node stock so you keep one ordinary-looking node.
