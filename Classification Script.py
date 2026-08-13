"""
monetary_node/classification.py

Deterministic, syntactic classification of non-monetary outputs.
Rules A-C from the BIP specification.
"""

import struct
from typing import List, Tuple, Optional, Set
from dataclasses import dataclass

# Opcodes
OP_0 = 0x00
OP_FALSE = 0x00
OP_IF = 0x63
OP_ENDIF = 0x68
OP_RETURN = 0x6a
OP_PUSHDATA1 = 0x4c
OP_PUSHDATA2 = 0x4d
OP_PUSHDATA4 = 0x4e

# Token protocol markers (Rule C)
TOKEN_PROTOCOL_MARKERS: Set[bytes] = {
    b'ord',           # Ordinals
    b'runes',         # Runes
    b'brc-20',        # BRC-20
    b'stamp:',        # SRC-20/Stamps
}

@dataclass(frozen=True)
class OutPoint:
    txid: bytes  # 32 bytes
    vout: int

    def __str__(self):
        return f"{self.txid.hex()}:{self.vout}"

@dataclass
class TxOutput:
    value: int  # satoshis
    script_pubkey: bytes

@dataclass  
class TxInput:
    prevout: OutPoint
    script_sig: bytes
    witness: List[bytes]  # Witness stack for segwit
    sequence: int

@dataclass
class Transaction:
    txid: bytes
    version: int
    inputs: List[TxInput]
    outputs: List[TxOutput]
    locktime: int
    is_segwit: bool = False


def decode_pushdata(script: bytes, offset: int) -> Tuple[Optional[bytes], int]:
    """Decode a pushdata operation from script. Returns (data, new_offset) or (None, -1) on failure."""
    if offset >= len(script):
        return None, -1

    opcode = script[offset]

    if opcode <= 0x4b:
        # Direct push of opcode bytes
        push_len = opcode
        if offset + 1 + push_len > len(script):
            return None, -1
        return script[offset+1:offset+1+push_len], offset + 1 + push_len

    elif opcode == OP_PUSHDATA1:
        if offset + 2 > len(script):
            return None, -1
        push_len = script[offset + 1]
        if offset + 2 + push_len > len(script):
            return None, -1
        return script[offset+2:offset+2+push_len], offset + 2 + push_len

    elif opcode == OP_PUSHDATA2:
        if offset + 3 > len(script):
            return None, -1
        push_len = struct.unpack('<H', script[offset+1:offset+3])[0]
        if offset + 3 + push_len > len(script):
            return None, -1
        return script[offset+3:offset+3+push_len], offset + 3 + push_len

    elif opcode == OP_PUSHDATA4:
        if offset + 5 > len(script):
            return None, -1
        push_len = struct.unpack('<I', script[offset+1:offset+5])[0]
        if offset + 5 + push_len > len(script):
            return None, -1
        return script[offset+5:offset+5+push_len], offset + 5 + push_len

    else:
        # Not a pushdata
        return None, -1


def is_false_push(opcode: int, data: Optional[bytes]) -> bool:
    """
    Check if a push evaluates to logical false per standard script semantics.
    False: OP_0/OP_FALSE, empty push, or push of zero byte(s)
    """
    if opcode == OP_0:
        return True
    if data is not None and len(data) == 0:
        return True
    if data is not None and all(b == 0 for b in data):
        return True
    return False


def find_inscription_envelope(witness: List[bytes]) -> bool:
    """
    Rule A: Detect inscription envelope in witness.
    Looks for: false_push OP_IF ... OP_ENDIF pattern in witness script.
    """
    if not witness:
        return False

    # The witness script is typically the last element (for P2WSH) or
    # the script itself for Taproot. We scan all witness elements.
    for element in witness:
        if len(element) < 3:
            continue

        offset = 0
        while offset < len(element):
            # Try to decode as pushdata
            data, new_offset = decode_pushdata(element, offset)
            if data is None:
                # Not a push, check if it's OP_0 directly
                if element[offset] == OP_0 and offset + 1 < len(element):
                    if element[offset + 1] == OP_IF:
                        # Found OP_FALSE OP_IF
                        # Now find matching OP_ENDIF
                        depth = 1
                        search = offset + 2
                        while search < len(element) and depth > 0:
                            if element[search] == OP_IF:
                                depth += 1
                            elif element[search] == OP_ENDIF:
                                depth -= 1
                            search += 1
                        if depth == 0:
                            return True
                offset += 1
                continue

            # Check if this push is followed by OP_IF
            opcode = element[offset]
            if new_offset < len(element) and element[new_offset] == OP_IF:
                if is_false_push(opcode, data):
                    # Found false push + OP_IF
                    # Find matching OP_ENDIF
                    depth = 1
                    search = new_offset + 1
                    while search < len(element) and depth > 0:
                        if element[search] == OP_IF:
                            depth += 1
                        elif element[search] == OP_ENDIF:
                            depth -= 1
                        search += 1
                    if depth == 0:
                        return True

            offset = new_offset

    return False


def is_bare_multisig_data_encoding(script: bytes) -> bool:
    """
    Rule B: Detect bare multisig with data-encoding patterns.
    Simplified: check for bare multisig pattern with non-standard pubkeys.
    """
    # Bare multisig pattern: M OP_CHECKMULTISIG
    # or: M <pubkey1> ... <pubkeyN> N OP_CHECKMULTISIG
    if len(script) < 3:
        return False

    if script[-1] != 0xae:  # OP_CHECKMULTISIG = 0xae
        return False

    # Check for M-of-N pattern
    # Minimum: OP_1 <pubkey> OP_1 OP_CHECKMULTISIG (4 bytes)
    m = script[0]
    if not (0x51 <= m <= 0x60):  # OP_1 to OP_16
        return False

    m_val = m - 0x50

    # Scan for pubkeys - look for invalid/unspendable pubkeys
    offset = 1
    pubkey_count = 0
    has_invalid_pubkey = False

    while offset < len(script) - 2:  # -2 for N + CHECKMULTISIG
        data, new_offset = decode_pushdata(script, offset)
        if data is None:
            break

        pubkey_count += 1

        # Check if pubkey is valid
        # Valid secp256k1 pubkeys are 33 or 65 bytes
        if len(data) not in (33, 65):
            has_invalid_pubkey = True
        else:
            # Check prefix byte for compressed/uncompressed
            if data[0] not in (0x02, 0x03, 0x04):
                has_invalid_pubkey = True

        offset = new_offset

    # Check N value
    if offset < len(script) - 1:
        n = script[offset]
        if 0x51 <= n <= 0x60:
            n_val = n - 0x50
            if n_val == pubkey_count and has_invalid_pubkey:
                return True

    return False


def has_token_protocol_marker(script: bytes) -> bool:
    """
    Rule C: Detect OP_RETURN outputs with token protocol markers.
    """
    if len(script) < 2 or script[0] != OP_RETURN:
        return False

    # Parse OP_RETURN payload
    offset = 1
    while offset < len(script):
        data, new_offset = decode_pushdata(script, offset)
        if data is None:
            break

        # Check against known protocol markers
        for marker in TOKEN_PROTOCOL_MARKERS:
            if data.startswith(marker):
                return True

        # Also check for JSON-like BRC-20 content
        if b'{' in data and b'"' in data:
            # Heuristic: likely JSON-encoded token data
            if any(kw in data.lower() for kw in [b'brc', b'tick', b'amt', b'op']):
                return True

        offset = new_offset

    return False


def classify_output(output: TxOutput, tx: Transaction, vout: int) -> bool:
    """
    Classify an output as non-monetary.
    Returns True if the output is NON-MONETARY (should be filtered).
    """
    script = output.script_pubkey

    # Rule B: Bare multisig data encoding
    if is_bare_multisig_data_encoding(script):
        return True

    # Rule C: Token protocol markers in OP_RETURN
    if has_token_protocol_marker(script):
        return True

    return False


def classify_transaction(tx: Transaction) -> Tuple[bool, List[int]]:
    """
    Classify a transaction as non-monetary and return indices of non-monetary outputs.
    Returns (is_non_monetary, non_monetary_output_indices)
    """
    non_monetary_outputs = []

    # Rule A: Check witness for inscription envelope
    has_inscription = False
    for inp in tx.inputs:
        if find_inscription_envelope(inp.witness):
            has_inscription = True
            break

    # Check each output
    for i, output in enumerate(tx.outputs):
        if classify_output(output, tx, i):
            non_monetary_outputs.append(i)

    is_non_monetary = has_inscription or len(non_monetary_outputs) > 0

    return is_non_monetary, non_monetary_outputs


# Test vectors
TEST_VECTORS = [
    # (description, script, expected_non_monetary)
    ("Standard P2PKH", bytes([0x76, 0xa9, 0x14] + [0x00]*20 + [0x88, 0xac]), False),
    ("OP_RETURN with ord marker", bytes([0x6a, 0x03]) + b'ord', True),
    ("OP_RETURN with runes marker", bytes([0x6a, 0x05]) + b'runes', True),
    ("OP_RETURN 83 bytes (standard)", bytes([0x6a, 0x53]) + b'x'*83, False),
    ("Bare multisig with invalid pubkey", bytes([0x51, 0x03, 0xab, 0xcd, 0xef, 0x51, 0xae]), True),
]

def run_tests():
    print("=== Classification Tests ===")
    for desc, script, expected in TEST_VECTORS:
        output = TxOutput(value=1000, script_pubkey=script)
        dummy_tx = Transaction(
            txid=b'\x00'*32,
            version=2,
            inputs=[],
            outputs=[output],
            locktime=0
        )
        result = classify_output(output, dummy_tx, 0)
        status = "PASS" if result == expected else "FAIL"
        print(f"[{status}] {desc}: expected={expected}, got={result}")

    # Test inscription envelope
    witness_with_inscription = [
        b'',  # signature placeholder
        bytes([0x00, 0x63]) + b'random data' + bytes([0x68]),  # OP_FALSE OP_IF ... OP_ENDIF
        b'\x02' * 32,  # internal key
    ]
    dummy_insc_tx = Transaction(
        txid=b'\x01'*32,
        version=2,
        inputs=[TxInput(OutPoint(b'\x00'*32, 0), b'', witness_with_inscription, 0xffffffff)],
        outputs=[TxOutput(1000, bytes([0x22, 0x00, 0x14] + [0x00]*20))],
        locktime=0,
        is_segwit=True
    )
    is_nm, nm_outs = classify_transaction(dummy_insc_tx)
    status = "PASS" if is_nm else "FAIL"
    print(f"[{status}] Inscription envelope detection: expected=True, got={is_nm}")

if __name__ == "__main__":
    run_tests()
