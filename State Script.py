"""
monetary_node/state.py

Dual state root computation (legacy + monetary) using MuHash-style accumulator.
Paired commitments per Section 5.0 of the BIP.
"""

import hashlib
import struct
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict

from classification import OutPoint, TxOutput, Transaction, classify_transaction


# MuHash3072 implementation (simplified - using 256-bit for prototype)
# In production, this would be the full MuHash3072 from Bitcoin Core
class MuHashAccumulator:
    """
    Simplified MuHash-style accumulator for UTXO set commitment.
    Uses SHA256d of serialized outpoints for incremental hashing.

    Full MuHash3072 would use 3072-bit integers and elliptic curve operations.
    This prototype demonstrates the interface and incremental update semantics.
    """

    def __init__(self):
        self.numerator = 1
        self.denominator = 1
        self.modulus = 2**256 - 2**32 - 977  # secp256k1 prime (placeholder for 3072)
        self._items: Dict[bytes, bool] = {}  # Track for debugging

    def _hash_item(self, outpoint: OutPoint, output: TxOutput) -> int:
        """Hash an outpoint+output to a field element."""
        # Serialize: txid(32) + vout(4) + value(8) + script_pubkey
        ser = outpoint.txid + struct.pack('<I', outpoint.vout)
        ser += struct.pack('<Q', output.value)
        ser += output.script_pubkey
        h = hashlib.sha256(ser).digest()
        return int.from_bytes(h, 'big') % self.modulus

    def add(self, outpoint: OutPoint, output: TxOutput):
        """Add an item to the accumulator."""
        h = self._hash_item(outpoint, output)
        self.numerator = (self.numerator * h) % self.modulus
        key = outpoint.txid + struct.pack('<I', outpoint.vout)
        self._items[key] = True

    def remove(self, outpoint: OutPoint, output: TxOutput):
        """Remove an item from the accumulator."""
        h = self._hash_item(outpoint, output)
        self.denominator = (self.denominator * h) % self.modulus
        key = outpoint.txid + struct.pack('<I', outpoint.vout)
        if key in self._items:
            del self._items[key]

    def digest(self) -> bytes:
        """Compute the final hash."""
        if self.denominator == 0:
            return hashlib.sha256(b'\x00').digest()
        result = (self.numerator * pow(self.denominator, -1, self.modulus)) % self.modulus
        return hashlib.sha256(result.to_bytes(32, 'big')).digest()

    def clone(self) -> 'MuHashAccumulator':
        """Create a copy of the accumulator."""
        acc = MuHashAccumulator()
        acc.numerator = self.numerator
        acc.denominator = self.denominator
        acc._items = dict(self._items)
        return acc


@dataclass
class FilterIndexEntry:
    """Entry in the filter index for a removed non-monetary output."""
    outpoint: OutPoint
    amount: int  # satoshis
    block_height: int
    tx_index: int  # index within block
    spent: bool = False

    def serialize(self) -> bytes:
        return (
            self.outpoint.txid +
            struct.pack('<I', self.outpoint.vout) +
            struct.pack('<Q', self.amount) +
            struct.pack('<I', self.block_height) +
            struct.pack('<I', self.tx_index) +
            struct.pack('<?', self.spent)
        )

    @classmethod
    def deserialize(cls, data: bytes) -> 'FilterIndexEntry':
        txid = data[:32]
        vout = struct.unpack('<I', data[32:36])[0]
        amount = struct.unpack('<Q', data[36:44])[0]
        block_height = struct.unpack('<I', data[44:48])[0]
        tx_index = struct.unpack('<I', data[48:52])[0]
        spent = struct.unpack('<?', data[52:53])[0]
        return cls(OutPoint(txid, vout), amount, block_height, tx_index, spent)


@dataclass
class BlockCommitment:
    """Paired commitment C_h for a block."""
    block_hash: bytes
    legacy_state_root: bytes
    monetary_state_root: bytes
    paired_commitment: bytes

    def verify(self) -> bool:
        """Verify that paired commitment is correctly computed."""
        computed = hashlib.sha256(
            hashlib.sha256(
                self.block_hash + self.legacy_state_root + self.monetary_state_root
            ).digest()
        ).digest()
        return computed == self.paired_commitment


class MonetaryState:
    """
    Maintains dual UTXO state: legacy (full) and monetary (filtered).
    """

    ACTIVATION_HEIGHT = 680_000

    def __init__(self):
        # Legacy UTXO set (full) - we only store what's needed for validation
        # In production, this would be a LevelDB/RocksDB backend
        self.legacy_utxo: Dict[bytes, TxOutput] = {}  # key = txid+vout

        # Monetary UTXO set (filtered)
        self.monetary_utxo: Dict[bytes, TxOutput] = {}

        # Filter index: tracks removed non-monetary outputs
        self.filter_index: Dict[bytes, FilterIndexEntry] = {}

        # State root accumulators
        self.legacy_accumulator = MuHashAccumulator()
        self.monetary_accumulator = MuHashAccumulator()

        # Per-block commitments
        self.commitments: Dict[int, BlockCommitment] = {}

        # Current height
        self.height = 0

        # Block storage (simplified - in production, raw block files)
        self.blocks: Dict[int, 'Block'] = {}

        # Undo data for reorgs
        self.undo_data: Dict[int, List[Tuple]] = {}

    def _utxo_key(self, outpoint: OutPoint) -> bytes:
        return outpoint.txid + struct.pack('<I', outpoint.vout)

    def _make_key(self, txid: bytes, vout: int) -> bytes:
        return txid + struct.pack('<I', vout)

    def connect_block(self, block: 'Block', height: int) -> BlockCommitment:
        """
        Connect a block and update both UTXO sets.
        For blocks >= ACTIVATION_HEIGHT, filter non-monetary outputs.
        """
        self.height = height
        self.blocks[height] = block

        undo_entries = []

        for tx_index, tx in enumerate(block.transactions):
            # Classify transaction
            is_non_monetary, nm_output_indices = classify_transaction(tx)

            # Process inputs (spends)
            for inp in tx.inputs:
                key = self._utxo_key(inp.prevout)

                if key in self.legacy_utxo:
                    output = self.legacy_utxo[key]

                    # Remove from legacy accumulator
                    self.legacy_accumulator.remove(inp.prevout, output)
                    del self.legacy_utxo[key]

                    # If it was in monetary set, remove from there too
                    if key in self.monetary_utxo:
                        self.monetary_accumulator.remove(inp.prevout, output)
                        del self.monetary_utxo[key]

                    # Record for undo
                    undo_entries.append(('spend', inp.prevout, output, key in self.monetary_utxo))
                elif key in self.filter_index:
                    # Spending a filtered output - need to reconstruct
                    entry = self.filter_index[key]
                    # Mark as spent
                    entry.spent = True
                    # In a real implementation, we'd reconstruct from block data here
                    undo_entries.append(('spend_filtered', inp.prevout, entry))

            # Process outputs
            for vout, output in enumerate(tx.outputs):
                outpoint = OutPoint(tx.txid, vout)
                key = self._utxo_key(outpoint)

                # Always add to legacy set
                self.legacy_utxo[key] = output
                self.legacy_accumulator.add(outpoint, output)

                # Determine if monetary
                is_filtered = (height >= self.ACTIVATION_HEIGHT and 
                              (is_non_monetary or vout in nm_output_indices))

                if not is_filtered:
                    # Add to monetary set
                    self.monetary_utxo[key] = output
                    self.monetary_accumulator.add(outpoint, output)
                else:
                    # Add to filter index
                    self.filter_index[key] = FilterIndexEntry(
                        outpoint=outpoint,
                        amount=output.value,
                        block_height=height,
                        tx_index=tx_index
                    )

                undo_entries.append(('create', outpoint, output, not is_filtered))

        # Store undo data
        self.undo_data[height] = undo_entries

        # Compute commitments
        legacy_root = self.legacy_accumulator.digest()
        monetary_root = self.monetary_accumulator.digest()

        paired = hashlib.sha256(
            hashlib.sha256(
                block.block_hash + legacy_root + monetary_root
            ).digest()
        ).digest()

        commitment = BlockCommitment(
            block_hash=block.block_hash,
            legacy_state_root=legacy_root,
            monetary_state_root=monetary_root,
            paired_commitment=paired
        )

        self.commitments[height] = commitment

        return commitment

    def disconnect_block(self, height: int):
        """Disconnect a block for reorganization."""
        if height not in self.undo_data:
            raise ValueError(f"No undo data for height {height}")

        undo_entries = self.undo_data[height]

        # Process in reverse
        for entry in reversed(undo_entries):
            op = entry[0]

            if op == 'create':
                outpoint = entry[1]
                output = entry[2]
                was_monetary = entry[3]
                key = self._utxo_key(outpoint)

                # Remove from legacy
                if key in self.legacy_utxo:
                    self.legacy_accumulator.remove(outpoint, self.legacy_utxo[key])
                    del self.legacy_utxo[key]

                # Remove from monetary if present
                if key in self.monetary_utxo:
                    self.monetary_accumulator.remove(outpoint, self.monetary_utxo[key])
                    del self.monetary_utxo[key]

                # Remove from filter index if present
                if key in self.filter_index:
                    del self.filter_index[key]

            elif op == 'spend':
                outpoint = entry[1]
                output = entry[2]
                was_monetary = entry[3]
                key = self._utxo_key(outpoint)

                # Restore to legacy
                self.legacy_utxo[key] = output
                self.legacy_accumulator.add(outpoint, output)

                if was_monetary:
                    self.monetary_utxo[key] = output
                    self.monetary_accumulator.add(outpoint, output)

            elif op == 'spend_filtered':
                outpoint = entry[1]
                entry_data = entry[2]
                key = self._utxo_key(outpoint)
                self.filter_index[key] = entry_data

        del self.undo_data[height]
        del self.blocks[height]
        if height in self.commitments:
            del self.commitments[height]

        self.height = height - 1

    def get_stats(self) -> dict:
        """Get current state statistics."""
        return {
            'height': self.height,
            'legacy_utxo_count': len(self.legacy_utxo),
            'monetary_utxo_count': len(self.monetary_utxo),
            'filter_index_count': len(self.filter_index),
            'filtered_ratio': len(self.filter_index) / max(len(self.legacy_utxo), 1),
            'legacy_state_root': self.legacy_accumulator.digest().hex()[:16] + '...',
            'monetary_state_root': self.monetary_accumulator.digest().hex()[:16] + '...',
        }

    def create_snapshot(self, height: int) -> bytes:
        """Create a monetary snapshot at given height."""
        if height not in self.commitments:
            raise ValueError(f"No commitment at height {height}")

        commitment = self.commitments[height]

        # Serialize monetary UTXO set
        utxo_data = b''
        for key, output in sorted(self.monetary_utxo.items()):
            utxo_data += key + struct.pack('<Q', output.value) + bytes([len(output.script_pubkey)]) + output.script_pubkey

        # Serialize filter index (unspent only)
        filter_data = b''
        for key, entry in sorted(self.filter_index.items()):
            if not entry.spent:
                filter_data += entry.serialize()

        # Combine with commitment
        snapshot = (
            struct.pack('<I', height) +
            commitment.paired_commitment +
            struct.pack('<I', len(utxo_data)) +
            utxo_data +
            struct.pack('<I', len(filter_data)) +
            filter_data
        )

        return snapshot

    def verify_snapshot(self, snapshot: bytes, expected_hash: bytes) -> bool:
        """Verify a snapshot against expected hash."""
        actual_hash = hashlib.sha256(hashlib.sha256(snapshot).digest()).digest()
        return actual_hash == expected_hash


@dataclass
class Block:
    """Simplified block representation."""
    block_hash: bytes
    prev_hash: bytes
    height: int
    timestamp: int
    transactions: List[Transaction]
    nonce: int = 0
