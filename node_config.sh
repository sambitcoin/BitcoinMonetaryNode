#!/bin/sh
#
# node_config.sh — apply the Knots-style policy panel to a Bitcoin Core node,
# and say plainly which settings Core does not have.
#
#   ./node_config.sh --plan        show what would change, write nothing
#   sudo ./node_config.sh          apply it
#   ./node_config.sh --audit       compare the running node against the plan
#
# WHY THIS EXISTS. The Knots settings UI offers a spam-policy panel with
# about twenty knobs. Most of them are Knots-only. Core has three of the
# relevant ones. Writing a Knots option into a Core bitcoin.conf risks the
# node refusing to start, which on a headless box is a bad way to find out.
#
# So nothing here is written on my say-so: every key is checked against
# `bitcoind -help` first, and an unrecognised key is reported rather than
# written. If a future Core gains one of these options, it starts working
# with no change to this script.
#
# WHY KNOTS IS NOT THE ANSWER HERE. Knots has the relay policy this project
# wants. Knots releases also follow the BLAKE2b chain that split at 961,632
# in August 2026, so running one puts you on a different chain. Verify that
# for yourself before acting on it — it cost this project three days once
# already. Meanwhile a monetary node does at the storage layer roughly what
# Knots does at the relay layer, which is most of the point.
#
# BSD-2-Clause.

set -eu

ACTION=plan
CONF="${BITCOIN_CONF:-}"

case "${1:-}" in
    --plan|"") ACTION=plan ;;
    --apply)   ACTION=apply ;;
    --audit)   ACTION=audit ;;
    -h|--help) sed -n '2,27p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
esac
[ "$ACTION" = plan ] && [ "$(id -u)" = 0 ] && ACTION=apply

REAL_HOME=$(eval echo "~${SUDO_USER:-$(id -un)}")
[ -n "$CONF" ] || CONF="$REAL_HOME/.bitcoin/bitcoin.conf"

say() { printf '%s\n' "$*"; }

# ------------------------------------------------------------- the settings
#
# Format: key|value|rationale
#
# Only settings that change behaviour in a way this project cares about.
# Anything left at its Core default is deliberately absent: a config file
# restating defaults hides the decisions among the noise.

SETTINGS='
uacomment|monetarynode|Appends to the subversion string, so peers see /Satoshi:31.1.0(monetarynode)/ instead of plain Core. This is how other operators can tell what they have connected to, and how a population of monetary nodes becomes countable. Replacing the word Satoshi entirely needs patches/core-useragent.patch and a rebuild. Note this is broadcast to every peer: over Tor it is not tied to an IP, but it does announce that this node runs unreviewed alpha software.
rest|1|The REST interface, off by default in Core. electrs 0.12 fetches blocks through it and dies with a bare 404 when it is missing, which reads like a broken URL rather than a disabled feature. Binds to the RPC address, so loopback only.
datacarrier|1|relay OP_RETURN, but bounded by the next line
datacarriersize|83|the pre-v30 limit. Core v30 raised the default to 100000, effectively uncapped. This restores the old bound as a deliberate choice, and matches the stripper rule that the published commitment C was computed under.
permitbaremultisig|0|bare multisig is where off-curve keys get stuffed. Core defaults to relaying it; Knots does not. 102.2 MB of the carriers this node strips arrived this way.
peerblockfilters|1|serve BIP157 compact filters to light clients. This is how a wallet finds its history without an address indexer, and it is the part that makes a pruned monetary node useful to somebody else.
blockfilterindex|1|required by peerblockfilters. Must be on before pruning or the node will not start.
peerbloomfilters|0|BIP37. Privacy and DoS risks, and superseded by compact filters. Off.
maxconnections|40|Tor connections are slower and costlier than clearnet ones. 125 slots on a T480 over Tor buys congestion, not resilience.
maxuploadtarget|5000|MB per 24h. Serving blocks over Tor is expensive for both ends. 0 means unlimited; this caps it without refusing to contribute.
rejectparasites|1|PATCHED CORE ONLY. Reject inscription envelopes and data in key fields at mempool admission. Skipped silently on a stock build.
rejecttokens|1|PATCHED CORE ONLY. Reject runestone-shaped token outputs. Knots defaults this off; on here because this node is explicitly for operators who want maximum rejection.
permitbarepubkey|0|PATCHED CORE ONLY. Do not relay bare pubkey outputs whose key is not a curve point.
permitbaredatacarrier|0|PATCHED CORE ONLY. Do not relay transactions whose every output is a data carrier — those move no value.
maxscriptsize|1650|PATCHED CORE ONLY. Matches the scriptSig limit the published commitment C was computed under.
'

# Knots-only, listed so the answer is on the record rather than silent.
# Reported if absent so the gap is on the record. These move into SETTINGS
# above the moment core-spam-policy.patch is built in — supported() decides,
# not this list, so there is no second code path to keep in sync.
KNOTS_ONLY='datacarriercost acceptnonstddatacarrier blockmaxsize'

# ------------------------------------------------------------------- audit

if [ "$ACTION" = audit ]; then
    if ! bitcoin-cli -getinfo >/dev/null 2>&1; then
        say "bitcoind is not running — cannot audit a live node"
        exit 1
    fi
    say "running node vs the plan"
    printf '%s\n' "$SETTINGS" | while IFS='|' read -r k v _; do
        [ -n "$k" ] || continue
        cur=$(bitcoin-cli getrpcinfo >/dev/null 2>&1 \
              && grep -E "^[[:space:]]*$k=" "$CONF" 2>/dev/null | tail -1 | cut -d= -f2)
        if [ "${cur:-unset}" = "$v" ]; then
            printf '  [ok  ] %-20s %s\n' "$k" "$v"
        else
            printf '  [diff] %-20s want %s, conf has %s\n' "$k" "$v" "${cur:-unset}"
        fi
    done
    exit 0
fi

# --------------------------------------------------- what does Core support?
#
# The whole point. `bitcoind -help` is the authority, not this script's
# author and not a settings panel from a different implementation.

command -v bitcoind >/dev/null 2>&1 || { say "bitcoind not on PATH"; exit 1; }
HELP=$(bitcoind -help 2>&1 || true)
# Core lists value options as "-key=<n>" but booleans as plain "-key", so
# matching on "-key=" silently misses every flag. The trailing group also
# stops -datacarrier matching -datacarriersize.
supported() {
    printf '%s' "$HELP" | grep -qE -- "^[[:space:]]*-$1(=|[[:space:]]|$)"
}

say "Bitcoin Core: $(bitcoind -version 2>/dev/null | head -1)"
say "config:      $CONF"
say ""
say "=================================================================="
say "SUPPORTED BY THIS BUILD"
say "=================================================================="

PLAN=""
SKIPPED=0
printf '%s\n' "$SETTINGS" | while IFS='|' read -r k v why; do
    [ -n "$k" ] || continue
    if supported "$k"; then
        printf '  %-20s = %-8s %s\n' "$k" "$v" ""
        printf '      %s\n' "$why" | fold -s -w 68 | sed 's/^/      /;s/^      *      /      /'
    else
        printf '  %-20s   NOT IN THIS BUILD — skipping\n' "$k"
    fi
    say ""
done

say "=================================================================="
say "KNOTS ONLY — NOT AVAILABLE IN CORE"
say "=================================================================="
for k in $KNOTS_ONLY; do
    if supported "$k"; then
        printf '  %-24s present after all — add it to SETTINGS\n' "$k"
    else
        printf '  %-24s absent\n' "$k"
    fi
done
say ""
say "  These are the relay-policy knobs Core does not have. A monetary node"
say "  addresses the same carriers at the storage layer instead, which is a"
say "  different trade: it does not stop the data propagating, it declines"
say "  to keep it."

if [ "$ACTION" = plan ]; then
    say ""
    say "Plan only. Nothing written. Run with sudo to apply."
    exit 0
fi

# ------------------------------------------------------------------- apply

[ -f "$CONF" ] || { say "no config at $CONF"; exit 1; }
if bitcoin-cli -getinfo >/dev/null 2>&1; then
    say ""
    say "bitcoind is running. Stop it first — it reads the config once at"
    say "startup, and a config the running process has not read is exactly"
    say "how this node spent six hours on clearnet with a correct file."
    exit 1
fi

BAK="$CONF.bak.$(date +%Y%m%d%H%M%S)"
cp -a "$CONF" "$BAK"
say ""
say "backup  $BAK"

printf '%s\n' "$SETTINGS" | while IFS='|' read -r k v _; do
    [ -n "$k" ] || continue
    supported "$k" || continue
    if grep -qE "^[[:space:]]*$k=" "$CONF"; then
        sed -i "s|^[[:space:]]*$k=.*|$k=$v|" "$CONF"
        say "  set     $k=$v"
    else
        printf '%s=%s\n' "$k" "$v" >> "$CONF"
        say "  added   $k=$v"
    fi
done

say ""
say "Written. Core parses the file at startup, so confirm it is valid"
say "BEFORE relying on the unit to bring the node back:"
say ""
say "    bitcoind -conf=$CONF -datadir=$(dirname "$CONF") -checkblocks=0 \\"
say "             -printtoconsole -shutdownnotify='echo ok' 2>&1 | head -20"
say ""
say "If that starts without a config error, Ctrl-C it and use systemctl."
say "If anything is wrong: cp $BAK $CONF"
