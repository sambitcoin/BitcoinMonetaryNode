"""
monetary_node/node.py

Monetary Node implementation with P2P messaging, snapshot bootstrap,
and full validation simulation.
"""

import hashlib
import struct
import time
import random
from typing import Dict, List, Optional, Set, Callable
from dataclasses import dataclass, field
from enum import IntEnum

from classification import (
    OutPoint, TxOutput, TxInput, Transaction, 
    classify_transaction, classify_output
)
from state import MonetaryState, Block, BlockCommitment, FilterIndexEntry


# P2P Message types (simplified)
class MsgType(IntEnum):
    VERSION = 0
    VERACK = 1
    GETSTATEROOTS = 2
    STATEROOTS = 3
    GETMONETARYSNAPSHOT = 4
    MONETARYSNAPSHOT = 5
    GETDATA = 6
    BLOCK = 7
    INV = 8


@dataclass
class Peer:
    """Represents a connected peer."""
    peer_id: str
    is_monetary: bool = False
    height: int = 0
    connection_time: float = field(default_factory=time.time)

    # Callbacks for message sending
    _send_callback: Optional[Callable] = None

    def send_message(self, msg_type: MsgType, payload: bytes):
        if self._send_callback:
            self._send_callback(msg_type, payload)


@dataclass
class SnapshotMetadata:
    """Metadata for a checkpoint snapshot."""
    height: int
    hash: bytes
    paired_commitment: bytes
    release_version: str


class MonetaryNode:
    """
    Monetary Node - full validating node with spam filtering.

    Key properties:
    - Full consensus validation (Section 4)
    - Non-monetary tx relay filtering (Section 3)
    - Dual state roots with paired commitments (Section 5)
    - Filter index for reconstruction (Section 6)
    - Snapshot bootstrap (Section 7.2)
    - P2P protocol extensions (Section 7.3)
    """

    ACTIVATION_HEIGHT = 680_000

    def __init__(self, node_id: str = "monetary_node_1"):
        self.node_id = node_id
        self.state = MonetaryState()

        # P2P
        self.peers: Dict[str, Peer] = {}
        self.is_monetary_node = True
        self.service_bits = 0x01  # NODE_NETWORK

        # Snapshot metadata (release-committed)
        self.snapshots: Dict[int, SnapshotMetadata] = {}

        # Background verification state
        self.background_verification_complete = False
        self.background_verification_height = 0

        # Configuration
        self.relay_non_monetary = False  # Always False for Monetary Nodes
        self.max_filter_reconstruct_per_block = 16

        # Statistics
        self.stats = {
            'blocks_validated': 0,
            'tx_classified_non_monetary': 0,
            'outputs_filtered': 0,
            'snapshot_served': 0,
        }

    def add_peer(self, peer_id: str, is_monetary: bool = False) -> Peer:
        """Add a peer connection."""
        peer = Peer(peer_id=peer_id, is_monetary=is_monetary)
        self.peers[peer_id] = peer
        return peer

    def remove_peer(self, peer_id: str):
        """Remove a peer."""
        if peer_id in self.peers:
            del self.peers[peer_id]

    def validate_transaction(self, tx: Transaction, is_block: bool = False) -> bool:
        """
        Validate a transaction.
        For mempool: reject non-monetary.
        For blocks: accept all valid transactions.
        """
        # Basic validation (simplified - real implementation would check signatures, etc.)
        if not tx.inputs or not tx.outputs:
            return False

        # Check for non-monetary classification
        is_nm, _ = classify_transaction(tx)

        if is_nm and not is_block:
            # Section 3.1: MUST NOT admit non-monetary transactions to mempool
            return False

        if is_nm:
            self.stats['tx_classified_non_monetary'] += 1

        return True

    def connect_block(self, block: Block) -> BlockCommitment:
        """
        Connect a block to the chain.
        Section 4: Full consensus validation.
        Section 5: Remove non-monetary outputs from chainstate.
        """
        height = block.height

        # Validate all transactions
        for tx in block.transactions:
            if not self.validate_transaction(tx, is_block=True):
                raise ValueError(f"Invalid transaction in block {height}")

        # Update state
        commitment = self.state.connect_block(block, height)

        self.stats['blocks_validated'] += 1

        # Count filtered outputs
        if height >= self.ACTIVATION_HEIGHT:
            for tx in block.transactions:
                _, nm_indices = classify_transaction(tx)
                self.stats['outputs_filtered'] += len(nm_indices)

        # Update peer heights
        for peer in self.peers.values():
            if peer.height < height:
                peer.height = height

        return commitment

    def disconnect_block(self, height: int):
        """Handle reorganization. Section 8."""
        self.state.disconnect_block(height)

    def handle_getstateroots(self, start_height: int, count: int, peer_id: str) -> bytes:
        """
        Handle getstateroots request. Section 7.3.
        Returns serialized state roots and paired commitments.
        """
        results = []
        for h in range(start_height, start_height + count):
            if h in self.state.commitments:
                c = self.state.commitments[h]
                results.append(
                    c.block_hash +
                    c.legacy_state_root +
                    c.monetary_state_root +
                    c.paired_commitment
                )
        return b''.join(results)

    def handle_getmonetarysnapshot(self, height: int) -> Optional[bytes]:
        """
        Handle getmonetarysnapshot request. Section 7.2.
        Returns serialized snapshot or None if not available.
        """
        if height not in self.snapshots:
            return None

        snapshot = self.state.create_snapshot(height)
        self.stats['snapshot_served'] += 1
        return snapshot

    def load_snapshot(self, snapshot: bytes, expected_hash: bytes) -> bool:
        """
        Bootstrap from snapshot. Section 7.2.
        1. Verify against release-committed hash
        2. Load monetary UTXO set and filter index
        3. Mark background verification as pending
        """
        # Verify hash
        actual_hash = hashlib.sha256(hashlib.sha256(snapshot).digest()).digest()
        if actual_hash != expected_hash:
            print(f"[SECURITY] Snapshot hash mismatch! Expected: {expected_hash.hex()}, Got: {actual_hash.hex()}")
            return False

        # Parse snapshot
        offset = 0
        height = struct.unpack('<I', snapshot[offset:offset+4])[0]
        offset += 4

        paired_commitment = snapshot[offset:offset+32]
        offset += 32

        utxo_len = struct.unpack('<I', snapshot[offset:offset+4])[0]
        offset += 4
        utxo_data = snapshot[offset:offset+utxo_len]
        offset += utxo_len

        filter_len = struct.unpack('<I', snapshot[offset:offset+4])[0]
        offset += 4
        filter_data = snapshot[offset:offset+filter_len]

        # Load UTXO set
        self.state.monetary_utxo.clear()
        self.state.monetary_accumulator = self.state.monetary_accumulator.__class__()

        uoffset = 0
        while uoffset < len(utxo_data):
            txid = utxo_data[uoffset:uoffset+32]
            vout = struct.unpack('<I', utxo_data[uoffset+32:uoffset+36])[0]
            value = struct.unpack('<Q', utxo_data[uoffset+36:uoffset+44])[0]
            script_len = utxo_data[uoffset+44]
            script = utxo_data[uoffset+45:uoffset+45+script_len]
            uoffset += 45 + script_len

            outpoint = OutPoint(txid, vout)
            output = TxOutput(value, script)
            key = self.state._utxo_key(outpoint)
            self.state.monetary_utxo[key] = output
            self.state.monetary_accumulator.add(outpoint, output)

        # Load filter index
        self.state.filter_index.clear()
        foffset = 0
        while foffset < len(filter_data):
            entry = FilterIndexEntry.deserialize(filter_data[foffset:foffset+53])
            key = self.state._utxo_key(entry.outpoint)
            self.state.filter_index[key] = entry
            foffset += 53

        self.state.height = height
        self.background_verification_complete = False
        self.background_verification_height = 0

        print(f"[BOOTSTRAP] Loaded snapshot at height {height}")
        print(f"[BOOTSTRAP] Monetary UTXOs: {len(self.state.monetary_utxo)}")
        print(f"[BOOTSTRAP] Filter index entries: {len(self.state.filter_index)}")

        return True

    def perform_background_verification(self, historical_blocks: List[Block]) -> bool:
        """
        Section 7.2: Mandatory background verification.
        Re-validate all blocks from genesis to snapshot height.
        """
        print(f"[VERIFY] Starting background verification of {len(historical_blocks)} blocks...")

        # Save current state
        saved_monetary_root = self.state.monetary_accumulator.digest()
        saved_filter_count = len(self.state.filter_index)

        # Reset and re-validate
        temp_state = MonetaryState()

        for block in historical_blocks:
            temp_state.connect_block(block, block.height)

        # Verify
        if temp_state.monetary_accumulator.digest() == saved_monetary_root:
            self.background_verification_complete = True
            self.background_verification_height = len(historical_blocks)
            print("[VERIFY] Background verification PASSED")
            return True
        else:
            print("[VERIFY] Background verification FAILED - snapshot invalid!")
            # In production: discard snapshot and re-sync from genesis
            return False

    def get_mempool_policy(self) -> dict:
        """Get current mempool filtering policy."""
        return {
            'accept_non_monetary': False,
            'op_return_limit': 83,
            'filter_inscriptions': True,
            'filter_bare_multisig_data': True,
            'filter_token_protocols': True,
        }

    def audit_peer_commitments(self, peer_id: str, start_height: int, count: int) -> List[dict]:
        """
        Section 7.1: Consistency auditing between Monetary Nodes.
        Request state roots from peer and compare.
        """
        if peer_id not in self.peers:
            return []

        peer = self.peers[peer_id]
        if not peer.is_monetary:
            return []

        divergences = []
        for h in range(start_height, start_height + count):
            if h in self.state.commitments:
                local = self.state.commitments[h]
                # In real implementation, would request from peer and compare
                # Here we simulate
                divergences.append({
                    'height': h,
                    'local_paired': local.paired_commitment.hex()[:16],
                    'status': 'would_compare'
                })

        return divergences

    def reconstruct_output(self, outpoint: OutPoint) -> Optional[TxOutput]:
        """
        Section 6: Reconstruct a filtered output for spend validation.
        Method 1: Local reconstruction from block store.
        """
        key = self.state._utxo_key(outpoint)
        if key not in self.state.filter_index:
            return None

        entry = self.state.filter_index[key]

        # Check local block store
        if entry.block_height in self.state.blocks:
            block = self.state.blocks[entry.block_height]
            if entry.tx_index < len(block.transactions):
                tx = block.transactions[entry.tx_index]
                if outpoint.vout < len(tx.outputs):
                    return tx.outputs[outpoint.vout]

        # Method 2: Would request from peer via getdata/block
        return None

    def get_status(self) -> dict:
        """Get full node status."""
        state_stats = self.state.get_stats()
        return {
            **state_stats,
            **self.stats,
            'node_id': self.node_id,
            'is_monetary': self.is_monetary_node,
            'peer_count': len(self.peers),
            'monetary_peers': sum(1 for p in self.peers.values() if p.is_monetary),
            'background_verification': self.background_verification_complete,
            'mempool_policy': self.get_mempool_policy(),
        }
