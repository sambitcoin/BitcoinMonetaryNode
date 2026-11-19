#!/usr/bin/env python3
"""
gallery_pages.py — render dashboard pages for the app store gallery.

    ./tools/gallery_pages.py --out app-store/sambitcoin-monetary-node/gallery
    ./tools/gallery_pages.py --selftest

WHY THIS EXISTS

An app store listing needs pictures of the app. Two of the four states
worth showing cannot be photographed on a working node: you would have
to break it first. Nobody is going to fill a disk to get a screenshot of
the disk warning, and if they did they would not be able to take the
picture afterwards.

So these pages go through the SAME render() the live node uses, with
figures from real runs rather than invented ones. What comes out is what
the app looks like in that state — not a mockup of it, and not a
redrawing that can quietly disagree with the code.

The honest limit: a page rendered here was not photographed on a running
node. The states that CAN be photographed on one (a synced dashboard,
the settings panel) should be, and the printed instructions say so.

BSD-2-Clause.
"""

import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import monetary_ui as ui  # noqa: E402


# Figures from the measured genesis-to-970,000 run and from the node as
# it stands. Real numbers, so the pictures cannot promise something the
# software does not do.
TIP = 975189
STORE_TIP = 975183
CARRIERS = 39298021376          # 36.6 GiB
BYTES_IN = 773418364928         # 720.3 GiB
BYTES_OUT = 724474920140        # 674.7 GiB


def _base(**over):
    """A complete render() input, with the parts a page needs overridden."""
    d = {
        "generated": "2026-11-09 14:02:11Z",
        "store_path": "/data/mstore",
        "errors": [],
        "node": {"chain": "main", "blocks": TIP, "headers": TIP,
                 "ibd": False, "progress": 1.0, "size_on_disk": 794568130560,
                 "pruned": False},
        "state": {"height": STORE_TIP, "carriers": CARRIERS,
                  "bytes_in": BYTES_IN, "bytes_out": BYTES_OUT,
                  "records": STORE_TIP + 1,
                  "commitment": "7b" * 32},
        "build": {"version": "0.1.0-alpha"},
        "supervisor": {
            "node_height": TIP, "node_headers": TIP,
            "store_height": STORE_TIP,
            "index_enabled": True, "index_height": TIP,
            "index_building": False, "tor": True, "i2p": True,
            "chain": "main", "phase": "following",
            "disk_free": 420 * 1024 ** 3,
        },
        "logs": [], "log_dir": "/data", "lag": 6,
        "store_bytes": BYTES_OUT, "store_files": 388,
        "daemon_pid": 41, "tor_required": True,
        "peers": [], "netinfo": None,
    }
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(d.get(k), dict):
            d[k] = dict(d[k], **v)
        else:
            d[k] = v
    return d


def pages():
    """(filename, title, what it shows, render input)."""
    return [
        ("1-running.html", "Running",
         "A synced node with wallets able to connect.",
         _base()),

        ("2-syncing.html", "First sync",
         "Both progress bars moving during the first run.",
         _base(node={"blocks": 412003, "headers": 975189, "ibd": True,
                     "progress": 0.4227},
               state={"height": 411900, "carriers": 8_100_000_000,
                      "bytes_in": 190_000_000_000,
                      "bytes_out": 181_000_000_000},
               supervisor={"node_height": 412003, "node_headers": 975189,
                           "store_height": 411900, "index_height": 390112,
                           "index_building": True, "phase": "syncing"},
               lag=103)),

        ("3-redownload.html", "Re-downloading",
         "The state that cannot be photographed on a healthy node: a "
         "pruned data directory being rebuilt.",
         _base(node={"blocks": 412003, "headers": 975189, "ibd": True},
               # The index cannot be ahead of a chain being re-downloaded.
               # It read as "block 975,189" beside "42% synced" in the
               # first render of this page, which is the kind of detail
               # that makes a reviewer distrust every other number on it.
               supervisor={"reindexing": True, "reindex_redownload": True,
                           "blocks_bytes": 15 * 1024 ** 3,
                           "node_height": 412003, "node_headers": 975189,
                           "index_height": None, "index_building": False,
                           "disk_free": 62 * 1024 ** 3,
                           "phase": "syncing"})),

        ("4-disk.html", "Out of disk",
         "The watchdog stopping the node before it fills the drive. Also "
         "unphotographable: taking this picture requires the machine it "
         "would be taken on.",
         _base(supervisor={"disk_halted": True,
                           "disk_free": 5 * 1024 ** 3,
                           "disk_halt_gib": 20,
                           "node_error": None})),
    ]


def write(out_dir):
    os.makedirs(out_dir, exist_ok=True)
    written = []
    for name, title, blurb, data in pages():
        html = ui.render(data)
        path = os.path.join(out_dir, name)
        with open(path, "w") as fh:
            fh.write(html)
        written.append((path, title, blurb))
    return written


def selftest():
    ok = fail = 0

    def check(what, cond):
        nonlocal ok, fail
        if cond:
            ok += 1
            print("PASS  " + what)
        else:
            fail += 1
            print("FAIL  " + what)

    rendered = {n: ui.render(d) for n, _t, _b, d in pages()}
    for name, html in rendered.items():
        check("%s renders a whole page" % name,
              html.startswith("<!doctype html") and len(html) > 2000)
        check("%s has the status bar" % name, "class='sbar" in html
              or 'class="sbar' in html or "<div class='sbar" in html)

    check("the running page says wallets can connect",
          "wallets can connect" in rendered["1-running.html"])
    check("the syncing page shows both bars",
          "lv-bar-node" in rendered["2-syncing.html"]
          and "lv-bar-index" in rendered["2-syncing.html"])
    check("the re-download page does not claim otherwise",
          "nothing is being re-downloaded"
          not in rendered["3-redownload.html"].lower())
    check("the disk page says nothing was deleted",
          "Nothing has been deleted" in rendered["4-disk.html"])

    # The figures must be the measured ones. A gallery that quotes a
    # number the software does not produce is the listing lying in
    # pictures, which is harder to catch than lying in text.
    check("the saving shown is the measured 6.33%",
          "6.33" in rendered["1-running.html"])
    check("and the carrier figure is the measured 36.6 GiB",
          "36.6 GiB" in rendered["1-running.html"])

    # No page may show an index ahead of the chain it indexes. A gallery
    # image that contradicts itself costs more credibility than a missing
    # one.
    import re as _re
    for name, html in rendered.items():
        m_h = _re.search(r"id=lv-sb-height>([0-9,]+)<", html)
        m_i = _re.search(r"id=lv-sb-index>block ([0-9,]+)<", html)
        if m_h and m_i:
            _h = int(m_h.group(1).replace(",", ""))
            _i = int(m_i.group(1).replace(",", ""))
            check("%s: the index is not ahead of the chain" % name, _i <= _h)

    print("\n%d/%d passed" % (ok, ok + fail))
    return 0 if fail == 0 else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default="gallery")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        sys.exit(selftest())

    written = write(a.out)
    print("wrote %d pages to %s\n" % (len(written), a.out))
    for path, title, blurb in written:
        print("  %-14s %s" % (title, os.path.basename(path)))
        print("                 %s" % blurb)
    print()
    print("These are HTML. Open each in a browser at about 1280 wide and")
    print("screenshot it, saving as PNG beside them.")
    print()
    print("Take the first two from the LIVE node instead if you can —")
    print("http://btcserver.local:3570/ — a photograph of the running")
    print("thing is worth more than a render of it, and the last two are")
    print("here only because they cannot be photographed.")


if __name__ == "__main__":
    main()
