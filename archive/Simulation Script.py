"""
monetary_node/simulation.py

Full simulation demonstrating Monetary Node behavior.
"""

import hashlib
import struct
import random
from typing import List, Tuple
from dataclasses import dataclass

from classification import (
    OutPoint, TxOutput, TxInput, Transaction,
    classify_transaction, OP_0, OP_IF, OP_ENDIF, OP_RETURN
)
from state import Block, MonetaryState
from node import MonetaryNode, SnapshotMetadata


def make_txid() -> bytes:
    return bytes([random.randint(0, 255) for _ in range(32)])


def make_block_hash() -> bytes:
    return bytes([random.randint(0, 255) for _ in range(32)])


def create_monetary_tx(prevout: OutPoint, value: int, script_type: str = "p2pkh") -> Transaction:
    if script_type == "p2pkh":
        script_pubkey = bytes([0x76, 0xa9, 0x14] + [0x00]*20 + [0x88, 0xac])
    else:
        script_pubkey = bytes([0x00, 0x14] + [0x00]*20)

    return Transaction(
        txid=make_txid(),
        version=2,
        inputs=[TxInput(prevout, b'', [b'\x00'*72, b'\x00'*33], 0xffffffff)],
        outputs=[TxOutput(value - 1000, script_pubkey), TxOutput(500, script_pubkey)],
        locktime=0,
        is_segwit=True
    )


def create_inscription_tx(prevout: OutPoint, value: int) -> Transaction:
    inscription_witness = [
        b'',
        bytes([OP_0, OP_IF]) + b'\x01' + b'image/png' + b'\x00' + b'FAKE_IMAGE_DATA' + bytes([OP_ENDIF]),
        b'\x02' * 32,
    ]
    script_pubkey = bytes([0x00, 0x14] + [0x00]*20)

    return Transaction(
        txid=make_txid(),
        version=2,
        inputs=[TxInput(prevout, b'', inscription_witness, 0xffffffff)],
        outputs=[TxOutput(value - 1000, script_pubkey)],
        locktime=0,
        is_segwit=True
    )


def create_opreturn_token_tx(prevout: OutPoint, value: int, protocol: str = "ord") -> Transaction:
    script_pubkey = bytes([0x00, 0x14] + [0x00]*20)
    opreturn_script = bytes([OP_RETURN, len(protocol)]) + protocol.encode()

    return Transaction(
        txid=make_txid(),
        version=2,
        inputs=[TxInput(prevout, b'', [], 0xffffffff)],
        outputs=[
            TxOutput(value - 2000, script_pubkey),
            TxOutput(1000, opreturn_script)
        ],
        locktime=0
    )


def create_bare_multisig_data_tx(prevout: OutPoint, value: int) -> Transaction:
    multisig_script = bytes([0x51, 0x03, 0xab, 0xcd, 0xef, 0x51, 0xae])

    return Transaction(
        txid=make_txid(),
        version=2,
        inputs=[TxInput(prevout, b'', [], 0xffffffff)],
        outputs=[TxOutput(value - 1000, multisig_script)],
        locktime=0
    )


def generate_test_chain(start_height: int, num_blocks: int, initial_utxos: int = 10) -> List[Block]:
    random.seed(42)

    available_utxos: List[Tuple[OutPoint, int]] = []
    for i in range(initial_utxos):
        txid = make_txid()
        available_utxos.append((OutPoint(txid, 0), 50000))

    blocks = []
    prev_hash = make_block_hash()

    for h in range(start_height, start_height + num_blocks):
        transactions = []

        # Coinbase tx
        coinbase = Transaction(
            txid=make_txid(),
            version=2,
            inputs=[TxInput(OutPoint(b'\x00'*32, 0xffffffff), b'\x03'*4, [], 0)],
            outputs=[TxOutput(625000000, bytes([0x76, 0xa9, 0x14] + [0x00]*20 + [0x88, 0xac]))],
            locktime=0
        )
        transactions.append(coinbase)

        # Add new UTXO from coinbase
        available_utxos.append((OutPoint(coinbase.txid, 0), 625000000))

        # Mix of transaction types
        num_txs = random.randint(2, 5)
        for _ in range(num_txs):
            if not available_utxos:
                break

            prevout, value = available_utxos.pop(0)
            tx_type = random.random()

            if tx_type < 0.5:
                tx = create_monetary_tx(prevout, value)
            elif tx_type < 0.7:
                tx = create_inscription_tx(prevout, value)
            elif tx_type < 0.85:
                tx = create_opreturn_token_tx(prevout, value)
            else:
                tx = create_bare_multisig_data_tx(prevout, value)

            transactions.append(tx)

            # Add outputs to available UTXOs
            for i, out in enumerate(tx.outputs):
                if out.script_pubkey[0:1] != bytes([OP_RETURN]):
                    available_utxos.append((OutPoint(tx.txid, i), out.value))

        block = Block(
            block_hash=make_block_hash(),
            prev_hash=prev_hash,
            height=h,
            timestamp=1609459200 + h * 600,
            transactions=transactions
        )
        blocks.append(block)
        prev_hash = block.block_hash

    return blocks


def run_simulation():
    print("=" * 70)
    print("BITCOIN MONETARY NODE - WORKING ALPHA SIMULATION")
    print("=" * 70)

    # Phase 1: Generate test chain
    print("\n[PHASE 1] Generating test chain...")
    start_height = 679_995
    num_blocks = 20
    blocks = generate_test_chain(start_height, num_blocks)
    print(f"Generated {len(blocks)} blocks (heights {start_height} to {start_height + num_blocks - 1})")
    print(f"Activation height: {MonetaryNode.ACTIVATION_HEIGHT}")

    # Phase 2: Initialize Monetary Node and connect blocks
    print("\n[PHASE 2] Initializing Monetary Node and connecting blocks...")
    node = MonetaryNode(node_id="alpha_node_1")

    for block in blocks:
        commitment = node.connect_block(block)

        if block.height >= MonetaryNode.ACTIVATION_HEIGHT:
            print(f"  Block {block.height}: Legacy UTXOs={len(node.state.legacy_utxo):4d} | "
                  f"Monetary UTXOs={len(node.state.monetary_utxo):4d} | "
                  f"Filtered={len(node.state.filter_index):4d} | "
                  f"C_h={commitment.paired_commitment.hex()[:16]}...")

    # Phase 3: Show final statistics
    print("\n[PHASE 3] Final state statistics:")
    stats = node.get_status()
    for key, value in stats.items():
        if isinstance(value, float):
            print(f"  {key}: {value:.4f}")
        else:
            print(f"  {key}: {value}")

    # Phase 4: Snapshot creation and bootstrap
    print("\n[PHASE 4] Snapshot creation and bootstrap test...")
    snapshot_height = start_height + num_blocks - 1
    snapshot = node.state.create_snapshot(snapshot_height)
    snapshot_hash = hashlib.sha256(hashlib.sha256(snapshot).digest()).digest()

    print(f"  Snapshot size: {len(snapshot)} bytes")
    print(f"  Snapshot hash: {snapshot_hash.hex()[:32]}...")

    # Create new node and bootstrap from snapshot
    new_node = MonetaryNode(node_id="bootstrap_node_1")
    success = new_node.load_snapshot(snapshot, snapshot_hash)
    print(f"  Bootstrap success: {success}")

    if success:
        print(f"  Bootstrapped node height: {new_node.state.height}")
        print(f"  Bootstrapped monetary UTXOs: {len(new_node.state.monetary_utxo)}")
        print(f"  Bootstrapped filter index: {len(new_node.state.filter_index)}")

    # Phase 5: Background verification
    print("\n[PHASE 5] Background verification...")
    verify_result = new_node.perform_background_verification(blocks)
    print(f"  Background verification result: {verify_result}")

    # Phase 6: Reorganization test
    print("\n[PHASE 6] Reorganization test...")
    reorg_height = start_height + num_blocks - 3
    print(f"  Disconnecting block at height {reorg_height}...")
    node.disconnect_block(reorg_height)
    print(f"  After disconnect: height={node.state.height}")
    print(f"  After disconnect: legacy_utxo={len(node.state.legacy_utxo)}")
    print(f"  After disconnect: monetary_utxo={len(node.state.monetary_utxo)}")

    # Reconnect
    print(f"  Reconnecting block at height {reorg_height}...")
    node.connect_block(blocks[reorg_height - start_height])
    print(f"  After reconnect: height={node.state.height}")

    # Phase 7: Consistency audit
    print("\n[PHASE 7] P2P consistency audit simulation...")
    node.add_peer("peer_1", is_monetary=True)
    audit_results = node.audit_peer_commitments("peer_1", MonetaryNode.ACTIVATION_HEIGHT, 5)
    print(f"  Audited {len(audit_results)} blocks for consistency")

    # Phase 8: Mempool policy
    print("\n[PHASE 8] Mempool policy check...")
    policy = node.get_mempool_policy()
    for key, value in policy.items():
        print(f"  {key}: {value}")

    # Phase 9: Transaction validation
    print("\n[PHASE 9] Transaction validation test...")
    test_tx = create_inscription_tx(OutPoint(make_txid(), 0), 10000)
    mempool_result = node.validate_transaction(test_tx, is_block=False)
    block_result = node.validate_transaction(test_tx, is_block=True)
    print(f"  Inscription tx in mempool: {mempool_result} (expected: False)")
    print(f"  Inscription tx in block: {block_result} (expected: True)")

    print("\n" + "=" * 70)
    print("SIMULATION COMPLETE")
    print("=" * 70)

    return node, blocks


if __name__ == "__main__":
    run_simulation()
