#!/bin/sh
#
# deploy.sh — push this tree to the node and restart what needs it.
#
# Run on the Mac. Replaces the save-from-chat, scp, ssh, sudo dance with one
# command, and refuses to send anything whose own self-test does not pass.
#
#   ./deploy.sh                 test, sync, restart the services
#   ./deploy.sh --dry-run       show what would change, send nothing
#   ./deploy.sh --no-restart    sync only, leave the daemon alone
#   ./deploy.sh --bringup       sync, then start everything ON THE NODE
#   ./deploy.sh --status        what is running on the node
#   ./deploy.sh --logs          follow the daemon log
#   ./deploy.sh --shell         drop into a shell there
#   ./deploy.sh --tunnel        forward the dashboard here and print the URL
#   ./deploy.sh --wallet        forward electrs here for Sparrow or Electrum
#
# The restart is deliberately narrow: the dashboard and the store daemon,
# never bitcoind and never tor. Restarting bitcoind to pick up a Python
# change would be a fifteen-minute reindex for nothing, and tor_setup.sh owns
# that unit.
#
# BSD-2-Clause.

set -eu

HOST="${MONETARY_HOST:-neal@btcserver.local}"
DEST="${MONETARY_DEST:-monetary-node}"
HERE="$(cd "$(dirname "$0")" && pwd)"

DRY=""
RESTART=1
ACTION=deploy

while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run)    DRY="--dry-run"; shift ;;
        --no-restart) RESTART=0; shift ;;
        --status)     ACTION=status; shift ;;
        --bringup)    ACTION=bringup; shift ;;
        --logs)       ACTION=logs; shift ;;
        --shell)      ACTION=shell; shift ;;
        --tunnel)     ACTION=tunnel; shift ;;
        --wallet)     ACTION=wallet; shift ;;
        --host)       HOST="$2"; shift 2 ;;
        -h|--help)    sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

say() { printf '%s\n' "$*"; }

# Refuse to run on the node itself.
#
# Run here, deploy.sh syncs the node's tree over the node's tree — a no-op
# that looks exactly like success, while the files you actually edited sit
# on the Mac untouched. The failure surfaces later as "No such file or
# directory" for a script you just watched "deploy".
TARGET_HOST=${HOST#*@}
LOCAL_SHORT=$(hostname -s 2>/dev/null || hostname)
case "$LOCAL_SHORT" in
    "${TARGET_HOST%%.*}")
        printf '%s\n' "This is $LOCAL_SHORT — the deploy target."
        printf '%s\n' ""
        printf '%s\n' "deploy.sh runs on the Mac and pushes here. Running it"
        printf '%s\n' "here would sync this tree over itself and silently do"
        printf '%s\n' "nothing, leaving your edits on the Mac."
        printf '%s\n' ""
        printf '%s\n' "On the Mac:  cd ~/monetary-node && ./deploy.sh"
        exit 1 ;;
esac

case "$ACTION" in
  status) exec ssh -t "$HOST" "cd $DEST && ./services_setup.sh --status" ;;
  logs)   exec ssh -t "$HOST" "journalctl -u monetary-daemon -f" ;;
  shell)  exec ssh -t "$HOST" "cd $DEST && exec bash -l" ;;
esac

# ----------------------------------------------------------------- tunnel
#
# The dashboard binds loopback on the node, so reaching it means an ssh
# forward. Doing that by hand has cost this project more time than any real
# bug: `ssh -N -L 8080:...` prints nothing and holds the terminal, so it
# looks hung; a forward left running in another window makes the next attempt
# die with "Address already in use"; and running it on the NODE forwards the
# box to itself and collides with the dashboard it is trying to reach.
#
# So: pick a local port that is actually free, say the URL out loud, and say
# that silence is success.

if [ "$ACTION" = tunnel ]; then
    PORT=8080
    while [ "$PORT" -lt 8110 ]; do
        if command -v lsof >/dev/null 2>&1; then
            lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1 || break
        elif command -v nc >/dev/null 2>&1; then
            nc -z 127.0.0.1 "$PORT" >/dev/null 2>&1 || break
        else
            break
        fi
        PORT=$((PORT + 1))
    done

    printf '%s\n' ""
    printf '%s\n' "  Open:  http://127.0.0.1:$PORT"
    printf '%s\n' ""
    if [ "$PORT" -ne 8080 ]; then
        printf '%s\n' "  (8080 was busy here, so the forward uses $PORT. The"
        printf '%s\n' "   node is unchanged — only this end moved.)"
        printf '%s\n' ""
    fi
    printf '%s\n' "  This terminal now holds the tunnel. It will print nothing"
    printf '%s\n' "  else — that is success, not a hang. Ctrl-C closes it, and"
    printf '%s\n' "  the dashboard becomes unreachable when you do."
    printf '%s\n' ""
    exec ssh -N -L "$PORT:127.0.0.1:8080" "$HOST"
fi

# ----------------------------------------------------------------- wallet
#
# electrs listens on loopback on the node and its unit carries
# IPAddressDeny=any, so nothing on the LAN can reach it. That is the right
# default: an Electrum server learns the complete address set of every client
# that connects to it, so it should serve exactly one person.
#
# This forwards it to this machine so Sparrow or Electrum can use it over the
# SSH connection you already trust, with no new listener, no port forward and
# no fourth onion address.

if [ "$ACTION" = wallet ]; then
    EPORT="${ELECTRUM_PORT:-50011}"
    LOCAL="$EPORT"
    while [ "$LOCAL" -lt $((EPORT + 30)) ]; do
        if command -v lsof >/dev/null 2>&1; then
            lsof -nP -iTCP:"$LOCAL" -sTCP:LISTEN >/dev/null 2>&1 || break
        elif command -v nc >/dev/null 2>&1; then
            nc -z 127.0.0.1 "$LOCAL" >/dev/null 2>&1 || break
        else
            break
        fi
        LOCAL=$((LOCAL + 1))
    done

    say ""
    say "=================================================================="
    say "SPARROW"
    say "=================================================================="
    say "  Preferences -> Server -> Private Electrum"
    say ""
    say "    URL          127.0.0.1"
    say "    Port         $LOCAL"
    say "    Use SSL      OFF"
    say "    Proxy        OFF"
    say ""
    say "  SSL off is correct: electrs serves plain TCP, and the encryption"
    say "  here is the SSH tunnel. Proxy off matters too — Sparrow set to"
    say "  route through Tor will try to reach 127.0.0.1 via Tor and fail."
    say ""
    say "=================================================================="
    say "ELECTRUM"
    say "=================================================================="
    say "  electrum --oneserver --server 127.0.0.1:$LOCAL:t"
    say ""
    say "  The :t means plain TCP. --oneserver stops it quietly falling back"
    say "  to a public server, which would hand your addresses to a stranger"
    say "  the first time your tunnel drops."
    say ""
    if [ "$LOCAL" -ne "$EPORT" ]; then
        say "  ($EPORT was busy on this machine, so the forward uses $LOCAL."
        say "   The node is unchanged.)"
        say ""
    fi
    say "This terminal now holds the tunnel and will print nothing else."
    say "Your wallet stops syncing when you close it."
    say ""
    exec ssh -N -L "$LOCAL:127.0.0.1:$EPORT" "$HOST"
fi

# ---------------------------------------------------------------- bringup
#
# Everything past the sync runs on the NODE, not here. Typing those commands
# into the Mac's shell is the single most repeated mistake in this project:
# they fail against /Users/neal/.bitcoin and "no systemd on this machine",
# which looks like a broken script rather than a wrong machine.
#
# One ssh -t so sudo can prompt once, and the whole sequence stops at the
# first failure instead of charging on.

if [ "$ACTION" = bringup ]; then
    say "syncing first"
    "$0" --no-restart || exit 1
    say ""
    say "=================================================================="
    say "BRINGUP — everything below runs on $HOST"
    say "=================================================================="
    exec ssh -t "$HOST" "set -e
        cd \$HOME/$DEST

        echo; echo '=== 1/6  tor verify ==='
        ./tor_lockdown.sh --verify

        echo; echo '=== 2/6  electrs config on port 50011 ==='
        # 50001 belongs to the virtual node suite. electrs takes 50011.
        sudo ./electrs_setup.sh --port 50011

        echo; echo '=== 3/6  electrs start ==='
        ./electrs_setup.sh --start || true

        echo; echo '=== 4/6  store daemon: where is it? ==='
        python3 tools/monetary_daemon.py --store \$HOME/mstore \
            --rpc-cookie \$HOME/.bitcoin/.cookie --status

        echo; echo '=== 5/6  hand the daemon to systemd ==='
        if pgrep -f 'monetary_daemon.py.*mstore' >/dev/null; then
            echo 'stopping the hand-started daemon (SIGINT, same as the unit)'
            pkill -INT -f 'monetary_daemon.py.*mstore' || true
            n=0
            while pgrep -f 'monetary_daemon.py.*mstore' >/dev/null; do
                n=\$((n+1)); [ \$n -gt 30 ] && break
                sleep 2; echo '  waiting'
            done
            pgrep -f 'monetary_daemon.py.*mstore' >/dev/null \
                && { echo 'it did not stop — leaving everything alone'; exit 1; }
            echo 'stopped'
        else
            echo 'none running'
        fi
        ./services_setup.sh --store \$HOME/mstore --electrum 127.0.0.1:50011

        echo; echo '=== 6/6  status ==='
        ./services_setup.sh --status
        echo
        python3 tools/monetary_daemon.py --store \$HOME/mstore \
            --rpc-cookie \$HOME/.bitcoin/.cookie --status
        echo
        echo 'Dashboard: ssh -N -L 8080:127.0.0.1:8080 $HOST  then http://127.0.0.1:8080'
    "
fi

# ------------------------------------------------------------ test first
#
# Shipping a file whose self-test fails is how a unit that starts at boot
# starts failing at boot. Cheaper to find out here.

say "self-tests"
FAILED=0
cd "$HERE/tools"
for t in carrier_policy.py sbtc_scan.py monetary_ui.py quips.py \
         chain_check.py flag_count.py monetary_daemon.py tx_query.py \
         status_page.py node_settings.py tip_race.py \
         monetary_supervisor.py monetary_electrum.py fit_store.py; do
    [ -f "$t" ] || continue
    printf '  %-24s ' "$t"
    if out=$(python3 "$t" --selftest 2>&1); then
        # Some suites print "N/N passed" and some print a bare "ok".
        # The extractor returned empty for the second kind, so three
        # tools showed a blank result and looked like they had not run.
        n=$(printf '%s' "$out" | grep -Eo '[0-9]+/[0-9]+ passed' | tail -1)
        if [ -z "$n" ]; then
            n=$(printf '%s' "$out" | grep -cE '^PASS ') 
            [ "$n" -gt 0 ] && n="$n passed" || n="ok"
        fi
        printf '%s\n' "$n"
    else
        printf 'FAILED\n'
        # The FAILING checks, not the last five lines. tail -5 showed the
        # three checks that passed just before the summary, which told you
        # nothing and cost several rounds of guessing.
        fails=$(printf '%s\n' "$out" | grep -E '^ *(FAIL|\[FAIL\])' || true)
        if [ -n "$fails" ]; then
            printf '%s\n' "$fails" | sed 's/^ */        /'
        else
            printf '%s\n' "$out" | tail -12 | sed 's/^/        /'
        fi
        FAILED=$((FAILED + 1))
    fi
done
cd "$HERE"

if [ "$FAILED" -gt 0 ]; then
    say ""
    say "$FAILED self-test(s) failed. Nothing sent."
    exit 1
fi

# ---------------------------------------------------------------- sync

say ""
say "sync  $HERE -> $HOST:$DEST"

EX="--exclude=__pycache__ --exclude=*.pyc --exclude=.DS_Store
    --exclude=results --exclude=store --exclude=*.log"

# macOS attaches com.apple.provenance to everything it touches, and GNU tar
# on the node prints a warning per file about not understanding it. Sixteen
# scary-looking lines in the middle of a deploy that is working fine. Don't
# write the attributes in the first place.
#
# --no-xattrs exists in bsdtar (macOS) and GNU tar 1.27+, so this is safe
# whichever end runs it; the fallback keeps the deploy working on anything
# older rather than failing over cosmetics.
XA="--no-xattrs"
if ! tar --no-xattrs -cf /dev/null -T /dev/null 2>/dev/null; then
    XA=""
fi

# Debian minimal does not ship rsync, and installing things on the node to
# make a deploy script work is backwards. Fall back to tar over ssh, which
# needs nothing at either end.
#
# --delete is deliberately absent from both paths. The node's tree holds
# results, logs and a store this Mac has never seen, and deleting those to
# match a working copy is the kind of tidiness that loses a day's build.

if ssh "$HOST" 'command -v rsync >/dev/null 2>&1'; then
    # shellcheck disable=SC2086
    rsync -az --itemize-changes $DRY $EX "$HERE"/ "$HOST:$DEST/"
else
    say "  (no rsync on the node — using tar over ssh)"
    if [ -n "$DRY" ]; then
        say "  would send:"
        # shellcheck disable=SC2086
        tar -czf /dev/null -v $XA $EX -C "$HERE" . 2>&1 \
            | grep -v '/$' | sed 's|^\./|    |'
    else
        # shellcheck disable=SC2086
        tar -czf - $XA $EX -C "$HERE" . \
            | ssh "$HOST" "mkdir -p $DEST && tar -xzf - -C $DEST" \
            || { say "  transfer failed"; exit 1; }
        say "  sent"
    fi
fi

if [ -n "$DRY" ]; then
    say ""
    say "Dry run. Nothing was sent and nothing was restarted."
    exit 0
fi

ssh "$HOST" "chmod +x $DEST/*.sh 2>/dev/null || true"

if [ "$RESTART" -eq 0 ]; then
    say ""
    say "Synced. Services left alone."
    exit 0
fi

# -------------------------------------------------------------- restart
#
# Only units that already exist. A missing unit means services_setup.sh has
# not been run yet, and silently installing it from a deploy script is not
# this script's job.

say ""
say "restart"
ssh -t "$HOST" "
    for u in monetary-daemon monetary-ui; do
        if systemctl list-unit-files | grep -q \"^\$u.service\"; then
            sudo systemctl restart \$u && echo \"  \$u restarted\"
        else
            echo \"  \$u not installed — run ./services_setup.sh --store ~/mstore\"
        fi
    done
    echo
    cd $DEST 2>/dev/null && ./services_setup.sh --status 2>/dev/null || true
"

say ""
say "Dashboard: ssh -N -L 8080:127.0.0.1:8080 $HOST   then http://127.0.0.1:8080"
