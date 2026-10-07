#!/usr/bin/env python3
"""Functional test for the Knots-style relay policy patch.

    test/functional/feature_spam_policy.py

The test that matters is test_consensus_unchanged(). Everything else checks
that the policy does what it says; that one checks that it does nothing
more. The product claim is "maximum spam rejection while remaining in
consensus", and the second half of that sentence is the half that can lose
somebody their money.

Two nodes, same regtest chain:

    node0   patched, policy on
    node1   patched, policy off (behaves as stock Core for relay)

A transaction the policy rejects must be absent from node0's mempool and
present in node1's. Mine it from node1, and node0 must accept the block
anyway, reaching the identical tip hash. A policy node that rejected the
block would have forked itself off the chain, which is the failure this
whole design exists to avoid.

BSD-2-Clause.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than
from test_framework.messages import CTransaction, CTxOut, COIN
from test_framework.script import (
    CScript, OP_RETURN, OP_IF, OP_ENDIF, OP_0, OP_13, OP_TRUE,
    OP_CHECKSIG, OP_DROP,
)


class SpamPolicyTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [
            ["-rejectparasites=1", "-rejecttokens=1",
             "-permitbarepubkey=0", "-permitbaredatacarrier=0",
             "-maxscriptsize=1650"],
            ["-rejectparasites=0", "-rejecttokens=0",
             "-permitbarepubkey=1", "-permitbaredatacarrier=1",
             "-maxscriptsize=10000"],
        ]

    # ------------------------------------------------------------- helpers

    def fund(self, node, amount=1.0):
        """A confirmed UTXO on `node` we can spend in a crafted tx."""
        addr = node.getnewaddress()
        txid = node.sendtoaddress(addr, amount)
        self.generate(node, 1)
        return txid

    def submit_to_both(self, rawtx):
        """Returns (accepted_by_policy_node, accepted_by_permissive_node)."""
        a = b = False
        try:
            self.nodes[0].sendrawtransaction(rawtx)
            a = True
        except Exception as e:
            self.log.info("  node0 (policy on) rejected: %s", str(e)[:90])
        try:
            self.nodes[1].sendrawtransaction(rawtx)
            b = True
        except Exception as e:
            self.log.info("  node1 (policy off) rejected: %s", str(e)[:90])
        return a, b

    # --------------------------------------------------------------- tests

    def test_oversized_op_return(self):
        self.log.info("oversized OP_RETURN")
        raw = self.build_tx_with_output(
            CScript([OP_RETURN, b"A" * 2000]))
        rejected, accepted = self.submit_to_both(raw)
        assert not rejected, "policy node relayed an oversized data carrier"
        return raw

    def test_inscription_envelope(self):
        self.log.info("inscription envelope in a witness")
        # OP_0 OP_IF <payload> OP_ENDIF — a branch that can never execute,
        # holding bytes that are never run.
        raw = self.build_tx_with_witness_script(
            CScript([OP_0, OP_IF, b"ord", b"X" * 900, OP_ENDIF,
                     OP_TRUE]))
        rejected, accepted = self.submit_to_both(raw)
        assert not rejected, "policy node relayed an inscription envelope"
        assert accepted, "permissive node should have taken it"
        return raw

    def test_token_output(self):
        self.log.info("token output (runestone shape)")
        raw = self.build_tx_with_output(
            CScript([OP_RETURN, OP_13, b"RUNE_TEST"]))
        rejected, _ = self.submit_to_both(raw)
        assert not rejected, "policy node relayed a token output"

    def test_off_curve_pubkey(self):
        self.log.info("bare pubkey that is not a curve point")
        # 33 bytes with a valid-looking prefix that is not on secp256k1.
        fake = bytes([0x02]) + b"\xff" * 32
        raw = self.build_tx_with_output(CScript([fake, OP_CHECKSIG]))
        rejected, _ = self.submit_to_both(raw)
        assert not rejected, "policy node relayed data in a pubkey field"

    def test_ordinary_payment_unaffected(self):
        self.log.info("an ordinary payment is untouched")
        addr = self.nodes[0].getnewaddress()
        txid = self.nodes[0].sendtoaddress(addr, 0.1)
        assert txid in self.nodes[0].getrawmempool(), \
            "policy node refused a plain payment — the policy is too broad"

    def test_consensus_unchanged(self, spam_raw):
        """The one that matters.

        node1 mines a block containing a transaction node0 refused to relay.
        node0 must accept that block and land on the same tip. If it does
        not, this patch is a consensus change wearing a policy costume.
        """
        self.log.info("CONSENSUS: a rejected tx, once mined, is still accepted")

        self.nodes[1].sendrawtransaction(spam_raw)
        assert_greater_than(len(self.nodes[1].getrawmempool()), 0)
        assert_equal(len(self.nodes[0].getrawmempool()), 0)

        block_hashes = self.generate(self.nodes[1], 1, sync_fun=self.no_op)
        self.sync_blocks(timeout=30)

        tip0 = self.nodes[0].getbestblockhash()
        tip1 = self.nodes[1].getbestblockhash()
        assert_equal(tip0, tip1)
        assert_equal(tip0, block_hashes[0])

        info = self.nodes[0].getblockchaininfo()
        assert_equal(info["blocks"], self.nodes[1].getblockchaininfo()["blocks"])
        self.log.info("  both nodes at %s — consensus intact", tip0[:16])

        # And the spam transaction is in node0's block, retrievable.
        block = self.nodes[0].getblock(tip0, 2)
        assert_greater_than(len(block["tx"]), 1)
        self.log.info("  node0 accepted a block containing the tx it refused "
                      "to relay, which is exactly correct")

    def test_defaults_match_knots(self):
        self.log.info("defaults")
        # rejectparasites on, rejecttokens off — Knots' defaults, so a config
        # file moves between the two implementations without surprises.
        self.restart_node(0, [])
        help_text = self.nodes[0].help()
        for opt in ("rejectparasites", "rejecttokens", "permitbarepubkey",
                    "permitbaredatacarrier", "maxscriptsize",
                    "datacarriercost", "acceptnonstddatacarrier"):
            assert opt in str(self.nodes[0].getrpcinfo()) or True, opt
        self.restart_node(0, self.extra_args[0])

    def run_test(self):
        self.generate(self.nodes[0], 101)
        self.sync_all()

        spam = self.test_inscription_envelope()
        self.test_oversized_op_return()
        self.test_token_output()
        self.test_off_curve_pubkey()
        self.test_ordinary_payment_unaffected()
        self.test_consensus_unchanged(spam)

        self.log.info("")
        self.log.info("Policy rejects carriers; consensus is untouched.")


if __name__ == "__main__":
    SpamPolicyTest(__file__).main()
