#!/bin/sh
#
# services_setup.sh — make a monetary node come back by itself after a reboot.
#
# Installs systemd units for the store daemon, the dashboard, and optionally
# electrs, chained behind the bitcoind unit that tor_setup.sh already wrote.
# Idempotent: safe to run again after changing a flag.
#
#   ./services_setup.sh --store ~/mstore
#   ./services_setup.sh --store ~/mstore --electrum 127.0.0.1:50001
#   ./services_setup.sh --store ~/mstore --electrs      # also manage electrs
#   ./services_setup.sh --store ~/mstore --print   # show units, install none
#   ./services_setup.sh --status
#   ./services_setup.sh --uninstall
#
# What it deliberately does NOT do:
#
#   - It does not write or overwrite bitcoind.service. That unit carries
#     Requires=tor.service from tor_setup.sh, and rewriting it here is how a
#     node quietly starts dialling clearnet again. If it is missing, this
#     script stops and tells you to run tor_setup.sh.
#   - It does not pass --adopt. Adoption resets the commitment to zero and is
#     a one-time decision a human makes, not something a boot script repeats.
#   - It never runs prune_behind.py. Nothing irreversible belongs in a unit
#     that fires unattended at 3am.
#
# BSD-2-Clause.

set -eu

STORE=""
COOKIE=""
DEPTH=6
PORT=8080
HOST="127.0.0.1"
ELECTRUM=""
ELECTRUM_SSL=0
WITH_ELECTRS=0
ACTION=install
DRYRUN=0

TOOLS="$(cd "$(dirname "$0")" && pwd)"
[ -f "$TOOLS/monetary_daemon.py" ] || [ ! -d "$TOOLS/tools" ] || TOOLS="$TOOLS/tools"

usage() { sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }

while [ $# -gt 0 ]; do
    case "$1" in
        --store)        STORE="$2"; shift 2 ;;
        --cookie)       COOKIE="$2"; shift 2 ;;
        --depth)        DEPTH="$2"; shift 2 ;;
        --port)         PORT="$2"; shift 2 ;;
        --host)         HOST="$2"; shift 2 ;;
        --electrum)     ELECTRUM="$2"; shift 2 ;;
        --electrum-ssl) ELECTRUM_SSL=1; shift ;;
        --electrs)      WITH_ELECTRS=1; shift ;;
        --tools)        TOOLS="$2"; shift 2 ;;
        --status)       ACTION=status; shift ;;
        --print)        ACTION=print; DRYRUN=1; shift ;;
        --uninstall)    ACTION=uninstall; shift ;;
        --dry-run)      DRYRUN=1; shift ;;
        -h|--help)      usage ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

say() { printf '%s\n' "$*"; }
run() { if [ "$DRYRUN" -eq 1 ]; then say "  would: $*"; else "$@"; fi; }

UNITS="monetary-daemon.service monetary-ui.service"
[ "$WITH_ELECTRS" -eq 1 ] && UNITS="electrs.service $UNITS"

# ------------------------------------------------------------------ status

if [ "$ACTION" = status ]; then
    for u in bitcoind.service tor.service $UNITS electrs.service; do
        [ -f "/etc/systemd/system/$u" ] || [ -f "/lib/systemd/system/$u" ] \
            || continue
        en=$(systemctl is-enabled "$u" 2>/dev/null) || true
        ac=$(systemctl is-active  "$u" 2>/dev/null) || true
        printf '  %-26s %-10s %s\n' "$u" "${en:--}" "${ac:--}"
    done
    exit 0
fi

# --------------------------------------------------------------- uninstall

if [ "$ACTION" = uninstall ]; then
    say "Removing monetary units. bitcoind and tor are left alone."
    for u in $UNITS; do
        case "$u" in electrs.service) ;; *)
            run sudo systemctl disable --now "$u" 2>/dev/null || true
            run sudo rm -f "/etc/systemd/system/$u"
            say "  removed $u" ;;
        esac
    done
    run sudo systemctl daemon-reload
    say "Done. The store on disk is untouched."
    exit 0
fi

# ------------------------------------------------------------ sanity first
#
# Every check here is something that has actually gone wrong during this
# project. A unit that starts at boot and fails silently is worse than no
# unit at all, because nobody is watching when it happens.

if [ "$ACTION" != print ]; then
    command -v systemctl >/dev/null 2>&1 \
        || { say "no systemd on this machine — nothing to install"; exit 1; }
fi

[ -n "$STORE" ] || { say "--store is required (e.g. --store ~/mstore)"; exit 2; }
STORE="$(cd "$STORE" 2>/dev/null && pwd)" \
    || { say "store not found: set --store to an existing directory"; exit 1; }
[ -f "$STORE/state.json" ] \
    || { say "no state.json in $STORE — run monetary_daemon.py --adopt by"
         say "hand once first. Adoption resets the commitment and is not"
         say "something a boot script should decide."; exit 1; }

for f in monetary_daemon.py monetary_ui.py; do
    [ -f "$TOOLS/$f" ] || { say "$f not in $TOOLS — pass --tools"; exit 1; }
done

PY="$(command -v python3)" || { say "python3 not found"; exit 1; }
USER_NAME="$(id -un)"
GROUP_NAME="$(id -gn)"
HOME_DIR="$HOME"
[ -n "$COOKIE" ] || COOKIE="$HOME_DIR/.bitcoin/.cookie"
# Derived from the cookie so the two always name the same datadir. A panel
# editing one node's config while the dashboard reads another's would be a
# hard bug to see.
BITCOIN_CONF="${BITCOIN_CONF:-$(dirname "$COOKIE")/bitcoin.conf}"
# Monetary-node options live apart from bitcoin.conf on purpose: Core warns
# about keys it does not recognise, and an operator chasing a warning for a
# setting Core was never meant to read is a waste of an evening.
MONETARY_CONF="${MONETARY_CONF:-$HOME_DIR/.monetary/monetary.conf}"

if [ "$ACTION" != print ]; then
    if [ ! -f /etc/systemd/system/bitcoind.service ] \
       && [ ! -f /lib/systemd/system/bitcoind.service ]; then
        say "No bitcoind.service found."
        say ""
        say "Run ./tor_setup.sh first. It writes that unit with"
        say "Requires=tor.service, so the node cannot start without Tor. This"
        say "script will not write a bitcoind unit itself: one without that line"
        say "leaks your IP to every peer, and you would not notice."
        exit 1
    fi

    if ! grep -qi 'tor' /etc/systemd/system/bitcoind.service 2>/dev/null; then
        say "WARNING: bitcoind.service does not mention tor. Check it, or rerun"
        say "tor_setup.sh, before relying on this at boot."
    fi
fi

# The daemon appends to the store. Two of them racing would corrupt it, so the
# unit must be the only writer — refuse if one is already running by hand.
#
# "By hand" is the important word. A bare pgrep also matches the unit's own
# process, so once the unit is running this refused every subsequent run and
# there was no way to update the units at all. Compare against the unit's
# MainPID: its own process is expected and is about to be restarted anyway.
if [ "$ACTION" != print ]; then
    UNIT_PID=$(systemctl show -p MainPID --value monetary-daemon 2>/dev/null \
               || echo 0)
    STRAY=""
    for pid in $(pgrep -f "monetary_daemon.py.*$STORE" 2>/dev/null); do
        [ "$pid" = "$UNIT_PID" ] && continue
        STRAY="$STRAY $pid"
    done
    # The dashboard has the same problem with a worse failure mode. A stray
    # copy holding the port makes the unit fail with "Address already in use"
    # and exit 1, so systemd sits in activating (auto-restart) forever while
    # curl gets a cheerful 200 from the old process serving code loaded weeks
    # ago. Every symptom says "running"; nothing says "wrong binary".
    #
    # Matched on the filename alone: a hand-started copy may carry no
    # arguments at all, which is exactly how the first one escaped a pattern
    # that expected --store.
    UI_PID=$(systemctl show -p MainPID --value monetary-ui 2>/dev/null \
             || echo 0)
    UI_STRAY=""
    for pid in $(pgrep -f "monetary_ui\.py" 2>/dev/null); do
        [ "$pid" = "$UI_PID" ] && continue
        UI_STRAY="$UI_STRAY $pid"
    done
    if [ -n "$UI_STRAY" ]; then
        say "A monetary_ui.py is running outside systemd. PID(s):$UI_STRAY"
        say ""
        say "It is holding port $PORT, so the unit cannot bind and will"
        say "crash-restart forever while that process keeps serving stale"
        say "code. Nothing in systemctl status says so."
        say ""
        say "    kill$UI_STRAY"
        say "    sudo systemctl restart monetary-ui"
        say ""
        say "The dashboard writes nothing but its own log, so killing it"
        say "cannot corrupt anything."
        exit 1
    fi

    if [ -n "$STRAY" ]; then
        say "A monetary_daemon.py is running against $STORE outside systemd."
        say "PID(s):$STRAY"
        say ""
        say "The unit and a hand-started copy would both append to the same"
        say "store, which corrupts it. Hand it over first:"
        say ""
        say "    kill -INT$STRAY"
        say ""
        say "It finishes the block it is on before exiting, so give it up to"
        say "a minute — an RPC fetch in flight has to return first. Wait for"
        say "the process to disappear, then run this again:"
        say ""
        say "    while kill -0$STRAY 2>/dev/null; do sleep 2; done; echo gone"
        say ""
        say "Do not use kill -9. It can leave a half-written record that the"
        say "daemon then refuses to start against."
        exit 1
    fi
fi

# ----------------------------------------------------------------- install

say "Installing units as user $USER_NAME"
say "  tools   $TOOLS"
say "  store   $STORE"
say "  cookie  $COOKIE"
say "  ui      http://$HOST:$PORT"
[ -n "$ELECTRUM" ] && say "  indexer $ELECTRUM"
say ""

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# --- daemon -----------------------------------------------------------------
#
# Restart=always with a generous RestartSec: the commonest failure is the node
# not answering RPC yet at boot, which cures itself in a minute. StartLimit is
# left off so it keeps trying rather than giving up overnight.

cat > "$TMP/monetary-daemon.service" <<EOF
[Unit]
Description=Monetary node store daemon
Documentation=https://github.com/sambitcoin/BitcoinMonetaryNode
Requires=bitcoind.service
After=bitcoind.service network-online.target

[Service]
Type=simple
User=$USER_NAME
Group=$GROUP_NAME
ExecStart=$PY $TOOLS/monetary_daemon.py --store $STORE \\
    --rpc-cookie $COOKIE --depth $DEPTH
Restart=always
RestartSec=30
TimeoutStopSec=120
KillSignal=SIGINT
# Progress to the file, failures to the journal. Same reasoning as the
# dashboard below: a traceback in a file nobody opens is a crash with no
# cause, and systemctl status is where anyone debugging a dead unit looks.
StandardOutput=append:$HOME_DIR/monetary-daemon.log
StandardError=journal

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=read-only
ReadWritePaths=$STORE $HOME_DIR

[Install]
WantedBy=multi-user.target
EOF

# --- dashboard ---------------------------------------------------------------
#
# Wants=, not Requires=: a dashboard that refuses to start because the daemon
# is down is a dashboard that cannot tell you the daemon is down.

# monetary_ui.py takes --cookie; monetary_daemon.py takes --rpc-cookie.
# They differ, and a unit with the wrong one fails only at boot.
# --conf is what the advanced settings panel edits. It defaults to the
# datadir's bitcoin.conf, but naming it here means the unit says out loud
# which file a web form can rewrite.
UI_ARGS="--store $STORE --cookie $COOKIE --host $HOST --port $PORT"
UI_ARGS="$UI_ARGS --conf $BITCOIN_CONF"
UI_ARGS="$UI_ARGS --monetary-conf $MONETARY_CONF"
[ -n "$ELECTRUM" ] && UI_ARGS="$UI_ARGS --electrum $ELECTRUM"
[ "$ELECTRUM_SSL" -eq 1 ] && UI_ARGS="$UI_ARGS --electrum-ssl"

cat > "$TMP/monetary-ui.service" <<EOF
[Unit]
Description=Monetary node dashboard
Documentation=https://github.com/sambitcoin/BitcoinMonetaryNode
Wants=bitcoind.service monetary-daemon.service
After=bitcoind.service monetary-daemon.service

[Service]
Type=simple
User=$USER_NAME
Group=$GROUP_NAME
ExecStart=$PY $TOOLS/monetary_ui.py $UI_ARGS
Restart=always
RestartSec=10
# Normal output goes to the file the LOG card tails. Failures go to the
# JOURNAL, because that is where systemctl status and journalctl -u look —
# and sending stderr to a file meant a crash showed up as a bare
# "status=1/FAILURE" with the actual traceback in a file nobody thinks to
# open. A failure has to be visible where people go looking for it.
StandardOutput=append:$HOME_DIR/monetary-ui.log
StandardError=journal

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=read-only
ReadOnlyPaths=$STORE
ReadWritePaths=$HOME_DIR

[Install]
WantedBy=multi-user.target
EOF

if [ "$ACTION" = print ]; then
    for u in monetary-daemon.service monetary-ui.service; do
        say "----- /etc/systemd/system/$u -----"
        cat "$TMP/$u"
        say ""
    done
    say "Nothing installed. Drop --print to install these."
    exit 0
fi

for u in monetary-daemon.service monetary-ui.service; do
    run sudo install -m 0644 "$TMP/$u" "/etc/systemd/system/$u"
    say "  wrote /etc/systemd/system/$u"
done

# --- electrs (optional) ------------------------------------------------------

if [ "$WITH_ELECTRS" -eq 1 ]; then
    if [ -f /etc/systemd/system/electrs.service ]; then
        say "  electrs.service already exists — leaving it, enabling only"
    elif command -v electrs >/dev/null 2>&1; then
        cat > "$TMP/electrs.service" <<EOF
[Unit]
Description=electrs address index
Requires=bitcoind.service
After=bitcoind.service

[Service]
Type=simple
User=$USER_NAME
Group=$GROUP_NAME
ExecStart=$(command -v electrs) --conf $HOME_DIR/.electrs/config.toml
Restart=always
RestartSec=30
TimeoutStopSec=300

[Install]
WantedBy=multi-user.target
EOF
        run sudo install -m 0644 "$TMP/electrs.service" \
            /etc/systemd/system/electrs.service
        say "  wrote /etc/systemd/system/electrs.service"
    else
        say "  electrs not on PATH — skipping its unit"
        UNITS="monetary-daemon.service monetary-ui.service"
    fi
fi

run sudo systemctl daemon-reload
for u in $UNITS; do
    [ -f "/etc/systemd/system/$u" ] || continue
    run sudo systemctl enable "$u"
done
run sudo systemctl enable bitcoind.service 2>/dev/null || true

say ""
say "Enabled at boot. Starting now:"
for u in $UNITS; do
    [ -f "/etc/systemd/system/$u" ] || continue
    run sudo systemctl restart "$u"
    sleep 1
    printf '  %-26s %s\n' "$u" \
        "$(systemctl is-active "$u" 2>/dev/null || echo failed)"
done

say ""
say "=================================================================="
say "The dashboard is on $HOST:$PORT, bound to localhost. From your own"
say "machine:"
say "    ssh -N -L $PORT:127.0.0.1:$PORT $USER_NAME@\$(hostname)"
say "then open http://127.0.0.1:$PORT"
say ""
say "  ./services_setup.sh --status        what is enabled and running"
say "  journalctl -u monetary-daemon -f    daemon output"
say "  tail -f ~/monetary-daemon.log       same, from the file"
say ""
say "Check the TOR card on the dashboard after this reboots. Units start"
say "in a different order than you do by hand, and that card is the only"
say "thing that will tell you if the node came up before Tor was ready."
