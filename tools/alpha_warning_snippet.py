#!/usr/bin/env python3
#
# alpha_warning_snippet.py — paste this into each tool.
#
# The tools are deliberately standalone: no imports between them, no
# dependencies, so any one of them can be copied to a machine on its own and
# still run. That means this is duplicated rather than shared. Copy the
# function below into each tool and call it once at the top of main().
#
# Apply to, at minimum, the tools that touch a live node or its data:
#
#     monetary_daemon.py
#     monetary_convert.py
#     prune_behind.py
#     monetary_store.py
#     monetary_ibd.py
#
# Not needed in the pure self-test paths, but harmless there.
#
# BSD-2-Clause.

import os
import sys

ALPHA_WARNING = """\
------------------------------------------------------------------
ALPHA SOFTWARE

  This is an alpha release. It has not been reviewed or audited by
  anyone but its author. An earlier version contained a bug that
  permanently deleted block data from a node.

  Use a node you can afford to lose and re-sync from scratch.

WALLETS

  Keep your seed words offline, on a hardware wallet.

  If you connect a hot wallet to this node, fund it with an amount
  you would not mind losing entirely.

  These tools hold no keys and never touch a wallet. The risk is to
  your node's block data, and to any wallet trusting this node for
  its view of the chain.

  Set MONETARY_NO_WARN=1 to silence this.
------------------------------------------------------------------
"""


def alpha_warning(stream=sys.stderr):
    """Print the alpha warning unless explicitly silenced.

    Goes to stderr so it never contaminates piped output, and returns
    silently when MONETARY_NO_WARN is set, so scripted and scheduled runs
    are not spammed by it.
    """
    if os.environ.get("MONETARY_NO_WARN"):
        return
    stream.write(ALPHA_WARNING)
    stream.flush()


# ---------------------------------------------------------------- usage
#
# In each tool:
#
#     def main():
#         alpha_warning()
#         args = parse_args()
#         ...
#
# Call it before argument parsing so it shows even on a usage error, and
# before any work starts. Do not gate it behind a flag the user has to find.
#
# For monetary_convert.py specifically, print it a second time immediately
# before stage 7, where the irreversible pruning happens. A warning seen
# once at the start of a multi-hour run has been forgotten by then.


if __name__ == "__main__":
    alpha_warning()
    print("Warning printed above. Set MONETARY_NO_WARN=1 to silence.")
