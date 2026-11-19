# Monetary Node — container image for umbrelOS (and anything else with Docker).
#
# Standard library only, so there is nothing to install and nothing to audit
# beyond the base image. No pip, no requirements.txt, no wheels. That is a
# deliberate property of the tools and it makes this Dockerfile boring, which
# is what you want in the thing that runs beside your node.
#
# Build and publish:
#   docker buildx build --platform linux/amd64,linux/arm64 \
#       -t ghcr.io/sambitcoin/monetary-node:0.1.0-alpha --push .
#
# Then pin the DIGEST in docker-compose.yml, not the tag. Umbrel requires it
# and it is right anyway: a tag can be moved, a digest cannot.

# ---------------------------------------------------------------- bitcoind
#
# The node is IN the app. This is the decision the whole design turns on, so
# it is worth stating plainly: the consensus layer here is Bitcoin Core,
# unmodified, embedded as a binary. It is not reimplemented and it never
# will be. Writing your own validation is how you build something that
# accepts a block Bitcoin rejects, and that failure is silent until it costs
# somebody money.
#
# What this project adds is what happens AFTER Core says a block is valid.
#
# The hashes are not optional and there is no default. A build that cannot
# prove which binary it is unpacking does not happen:
#
#     ./umbrel/pin_core.sh          (writes umbrel/bitcoin-release.env)
#     ./umbrel/sideload.sh --build  (reads it, passes it in)

# ARGs used in a FROM must be declared BEFORE the first FROM. Declared
# anywhere else they are stage-scoped, the FROM sees an empty string, and
# the build dies with "base name should not be blank" pointing at a line
# that looks perfectly correct.
#
# The default is a tiny image with no electrs in it, so an unpinned build
# produces a node without an indexer rather than refusing to build.
ARG ELECTRS_IMAGE=debian:bookworm-slim

FROM debian:bookworm-slim AS bitcoind

ARG CORE_VERSION
ARG CORE_SHA256_ARM64
ARG CORE_SHA256_AMD64
ARG TARGETARCH

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

RUN set -eu; \
    if [ -z "${CORE_VERSION:-}" ]; then \
        echo "CORE_VERSION is not set. Run ./umbrel/pin_core.sh first."; \
        exit 1; \
    fi; \
    case "$TARGETARCH" in \
        arm64) arch=aarch64-linux-gnu;  want="$CORE_SHA256_ARM64" ;; \
        amd64) arch=x86_64-linux-gnu;   want="$CORE_SHA256_AMD64" ;; \
        *) echo "unsupported architecture: $TARGETARCH"; exit 1 ;; \
    esac; \
    if [ -z "$want" ]; then \
        echo "No pinned SHA256 for $TARGETARCH."; \
        echo "Run ./umbrel/pin_core.sh and build through sideload.sh."; \
        exit 1; \
    fi; \
    f="bitcoin-$CORE_VERSION-$arch.tar.gz"; \
    echo "downloading $f"; \
    curl -fsSL --max-time 900 \
        "https://bitcoincore.org/bin/bitcoin-core-$CORE_VERSION/$f" -o /tmp/b.tar.gz; \
    got=$(sha256sum /tmp/b.tar.gz | awk '{print $1}'); \
    if [ "$got" != "$want" ]; then \
        echo "SHA256 MISMATCH for $f"; \
        echo "  expected $want"; \
        echo "  got      $got"; \
        echo "Refusing to build. Do not work around this."; \
        exit 1; \
    fi; \
    echo "sha256 ok: $got"; \
    mkdir -p /out; \
    tar -xzf /tmp/b.tar.gz -C /tmp; \
    cp "/tmp/bitcoin-$CORE_VERSION/bin/bitcoind" /out/; \
    cp "/tmp/bitcoin-$CORE_VERSION/bin/bitcoin-cli" /out/; \
    strip /out/bitcoind /out/bitcoin-cli 2>/dev/null || true; \
    /out/bitcoind --version | head -1


# ---------------------------------------------------------------- electrs
#
# The address index. Taken from a published image rather than built here.
#
# This is the decision the whole wallet story turns on, so it is worth
# stating plainly: a full scripthash index is tens of gigabytes and
# billions of writes, and Python on a Raspberry Pi cannot build one in a
# time anybody would accept. Without an indexer the only way to serve a
# wallet is to ask its owner for an extended public key — which is asking
# for every address they will ever use. Refusing that is reasonable, so
# the indexer is not optional and it is not ours.
#
# ELECTRS_IMAGE is pinned BY DIGEST by umbrel/pin_core.sh. A missing one
# is a warning rather than a build failure: a node that validates, strips
# and stores but cannot serve wallets is degraded, not broken, and it is
# better to ship that and say so than to refuse to build at all.

FROM ${ELECTRS_IMAGE} AS electrs_src

FROM debian:bookworm-slim AS electrs
COPY --from=electrs_src / /src/
RUN set -eu; \
    mkdir -p /out; \
    found=$(find /src/usr/local/bin /src/usr/bin /src/bin /src/app \
                 -maxdepth 2 -name electrs -type f 2>/dev/null | head -1); \
    if [ -n "$found" ]; then \
        cp "$found" /out/electrs; \
        chmod 0755 /out/electrs; \
        echo "electrs taken from the pinned image"; \
    else \
        echo "WARNING: no electrs binary in the pinned image."; \
        echo "The node will run without an indexer and no wallet will"; \
        echo "be able to connect. Run ./umbrel/pin_core.sh to pin one."; \
    fi


# ------------------------------------------------------------------- app

FROM python:3.12-slim-bookworm

# Nothing here needs a compiler, a shell beyond /bin/sh, or root at runtime.
# netcat is for the entrypoint's bitcoind reachability check; coreutils' df
# is already present in the base image.
# tor is here because "everything in one app" cannot quietly exclude the one
# requirement that is not negotiable on this project. A node that silently
# falls back to clearnet because the image shipped without a proxy is worse
# than one that refuses to start.
# tor is here because "everything in one app" cannot quietly exclude the
# one requirement that is not negotiable on this project.
#
# i2pd is here for the same reason in reverse: the settings panel offers
# an I2P switch, and offering a switch that turns on a feature the image
# cannot provide is worse than not offering it. Without a router,
# bitcoind logs "Cannot connect to 127.0.0.1:7656" every three seconds
# forever and the operator has no way to tell that from a bug.
RUN apt-get update \
    && apt-get install -y --no-install-recommends netcat-openbsd tor i2pd \
    && rm -rf /var/lib/apt/lists/*

# A real user, created at build time so the numeric id is stable across
# rebuilds. Umbrel bind-mounts host directories; a shifting uid means a data
# volume the app can suddenly no longer write.
RUN useradd --uid 1000 --create-home --shell /usr/sbin/nologin monetary

COPY --from=bitcoind /out/bitcoind /out/bitcoin-cli /usr/local/bin/
COPY --from=electrs /out/ /usr/local/bin/
RUN chmod 0755 /usr/local/bin/bitcoind /usr/local/bin/bitcoin-cli \
    && bitcoind --version | head -1

WORKDIR /app
COPY tools/ /app/tools/
COPY umbrel/docker-entrypoint.sh /app/

# Permissions, explicitly, rather than whatever the build host happened to
# have.
#
# COPY preserves the source file's mode. This project's files arrive on the
# build machine by tar over ssh from macOS and land as 0600, so they came
# into the image readable by root alone — and `chmod +x` on a 0600 file
# produces 0700, which is still root alone. The container runs as uid 1000
# and died with "cannot open /app/docker-entrypoint.sh: Permission denied",
# a read error wearing an execute error's clothes.
#
# a+rX sets read for everyone, and execute only where it already applies
# (directories and files that were executable), which is what you want for
# a tree of modules plus one script.
RUN chmod -R a+rX /app && chmod 0755 /app/docker-entrypoint.sh

# Fail the build rather than ship a broken image. Every tool's self-test runs
# here, with no node, no chain and no network — which is exactly the property
# that makes it possible.
#
# Run AS the unprivileged user. The permission bug above survived a green
# build precisely because these ran as root: everything passed, and the image
# then failed on its first line at runtime. A build-time check that does not
# use the runtime's identity is checking the wrong thing.
USER monetary
RUN for t in carrier_policy sbtc_scan monetary_ui quips chain_check \
             flag_count monetary_daemon tx_query status_page node_settings \
             tip_race monetary_supervisor; do \
        echo "== $t"; \
        if ! out=$(python3 /app/tools/$t.py --selftest 2>&1); then \
            echo "$out" | grep -E "^ *(FAIL|\[FAIL\])" || echo "$out" | tail -25; \
            exit 1; \
        fi; \
    done \
    && python3 /app/tools/test_monetary_store.py > /dev/null \
    && test -r /app/docker-entrypoint.sh \
    && test -x /app/docker-entrypoint.sh \
    && test -x /usr/local/bin/bitcoind \
    && command -v tor >/dev/null \
    && command -v i2pd >/dev/null \
    && bitcoind --version | head -1 \
    && echo "all self-tests passed as uid $(id -u)"
USER root

# A fingerprint of the sources this image was built from.
#
# A build from stale sources looks exactly like a build from fresh ones:
# same tag, same size, same "REBUILT since last run". A fix that was never
# copied to the build machine then gets debugged twice, from an identical
# traceback, which is a particularly demoralising way to lose an hour.
ARG BUILD_STAMP=unknown
ENV MONETARY_BUILD_STAMP=$BUILD_STAMP

# Managed mode is NOT set here any more. It means "another app owns
# bitcoin.conf, render those rows read-only" — true when this app read the
# Bitcoin app's node, false now that it runs its own. Leaving it on hid
# every network and policy row in the advanced panel.
ENV PYTHONUNBUFFERED=1

USER monetary
ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["web"]
