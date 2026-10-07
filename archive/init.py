"""
Bitcoin Monetary Node - Working Alpha

A prototype implementation of the Monetary Node BIP proposal.
Provides deterministic spam filtering, dual state roots, paired commitments,
snapshot bootstrap, and full validation simulation.
"""

from .classification import (
    OutPoint, TxOutput, TxInput, Transaction,
    classify_transaction, classify_output
)
from .state import MonetaryState, Block, BlockCommitment, FilterIndexEntry
from .node import MonetaryNode, SnapshotMetadata

__version__ = "0.1.0-alpha"
__all__ = [
    'OutPoint', 'TxOutput', 'TxInput', 'Transaction',
    'classify_transaction', 'classify_output',
    'MonetaryState', 'Block', 'BlockCommitment', 'FilterIndexEntry',
    'MonetaryNode', 'SnapshotMetadata'
]
