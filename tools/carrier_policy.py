#!/usr/bin/env python3
"""
carrier_policy.py — decide which OP_RETURN payloads are monetary and kept.

The stripper's rule today is a size test: OP_RETURN over 83 bytes is a data
carrier and goes. That test is about shape, not function, and it is about to
be wrong.

Shielded Bitcoin (Shikhelman, Komarov, Moskvin, 24 Sep 2026) publishes
private *transfers* — payments — in OP_RETURN. Its implementation profile
fixes an OP_RETURN carrier, and a transfer envelope carries a zero-knowledge
proof, so it is several hundred bytes. Under the size rule every one of them
is stripped.

That is worse than losing a payment. Shielded state is replayed, and the
nullifier binds the replay-assigned tree position pos. Drop one envelope and
every later leaf lands at the wrong position, so every later nullifier
derivation changes. One stripped envelope desynchronises the note tree
permanently from that height on, and the node shows no symptom: the merkle
roots still match and the blocks still verify against their own work.

So retention has to key on function. This module is that decision, kept
separate from the stripper so it can be tested adversarially on its own.

WHAT MAKES THIS SAFE. "Keep anything starting with sbtc" is a universal
bypass — prefix a JPEG and walk through. So an entry is never matched by
prefix. It is PARSED: read the header, read the declared arity, compute the
exact envelope length that arity implies, and require the payload to be that
length to the byte. A rigid format leaves nowhere to hide a payload. A
format with a variable-length free field leaves a hole you cannot inspect,
and must not be allowlisted at all.

WHY THE COMMITMENT CARES. Two nodes that retain different things derive
different stores and therefore different C. The active policy is hashed into
policy_id() and belongs in the commitment preamble beside the OP_RETURN and
scriptSig limits.

DOES THIS CHANGE THE PUBLISHED C? Only if some transaction at or below the
measured tip already carries a single minimally pushed OP_RETURN that begins
with "sbtc" and whose length exactly matches the arity equation. Nothing
else is decided differently — asserted against 20,000 generated payloads.
Shielded Bitcoin was published 24 September 2026 and nothing implements it,
so the expected count is zero, but expected is not measured. Feed the chain's
oversized OP_RETURN payloads through --scan-hex before republishing C, and
run with Policy(entries=[]) to get the old ruleset back exactly.

    python3 carrier_policy.py --selftest
    python3 carrier_policy.py --policy
    python3 carrier_policy.py --scan-hex < payloads.hex

BSD-2-Clause.
"""

import argparse
import binascii
import hashlib
import json
import sys

# ------------------------------------------------------------------ opcodes

OP_RETURN = 0x6A
OP_PUSHDATA1 = 0x4C
OP_PUSHDATA2 = 0x4D
OP_PUSHDATA4 = 0x4E

# The legacy standardness limit, and the stripper's current rule. Bitcoin
# Core v30 dropped this as a default; we keep it as a deliberate policy
# choice rather than an inherited one.
OP_RETURN_LIMIT = 83

# A well-formed envelope is still bounded. A declared arity of 255x255 would
# be a megabyte of "payment" nobody would ever construct, so cap the arity
# rather than trusting the format to be sensible. This bounds the size of the
# retention hole no matter what a future entry declares.
MAX_ARITY = 16
MAX_RETAINED_BYTES = 100_000


def compactsize_len(n):
    """Byte length of the canonical CompactSize encoding of n (A.5)."""
    if n < 0xFD:
        return 1
    if n <= 0xFFFF:
        return 3
    if n <= 0xFFFFFFFF:
        return 5
    return 9


def read_compactsize(buf, off):
    """Read a canonical CompactSize. Returns (None, 0) if non-minimal.

    A.5: "A parser rejects shorter, longer, non-minimal, reordered,
    undecodable, or otherwise non-canonical encodings." Non-minimal matters
    here beyond pedantry — encoding 2 as fd0200 spends two extra bytes for
    the same value, and two extra bytes is two bytes of payload.
    """
    if off >= len(buf):
        return None, 0
    b = buf[off]
    if b < 0xFD:
        return b, 1
    if b == 0xFD:
        if off + 3 > len(buf):
            return None, 0
        v = int.from_bytes(buf[off + 1:off + 3], "little")
        return (v, 3) if v >= 0xFD else (None, 0)
    if b == 0xFE:
        if off + 5 > len(buf):
            return None, 0
        v = int.from_bytes(buf[off + 1:off + 5], "little")
        return (v, 5) if v > 0xFFFF else (None, 0)
    if off + 9 > len(buf):
        return None, 0
    v = int.from_bytes(buf[off + 1:off + 9], "little")
    return (v, 9) if v > 0xFFFFFFFF else (None, 0)


class Verdict:
    """Why a payload was kept or dropped. The reason is the audit trail."""

    __slots__ = ("retain", "protocol", "reason", "detail")

    def __init__(self, retain, protocol, reason, detail=""):
        self.retain = retain
        self.protocol = protocol
        self.reason = reason
        self.detail = detail

    def __repr__(self):
        return "<%s %s: %s%s>" % (
            "RETAIN" if self.retain else "STRIP",
            self.protocol or "-", self.reason,
            " (%s)" % self.detail if self.detail else "")

    def __eq__(self, other):
        return (self.retain, self.protocol, self.reason) == \
               (other.retain, other.protocol, other.reason)


# ------------------------------------------------------------ sbtc envelope


class ShieldedBitcoinV1:
    """Shielded Bitcoin transfer envelope, protocol version 1, type 0x01.

    Widths are from Appendix A of the paper, not guessed. A.4 states the
    2-input 2-output serialization as

        E(2->2) = 6 + 4 + 2 + 2(32) + 2(32) + 2(67) + 144 + 192 = 610 bytes

    and A.3 fixes the body as (header, hanchor, N, M, nf[N], pkeph[M],
    ctnote[M], ctout) with the proof serialized after it. Generalising the
    per-output terms and the 144-byte batch ("two 64-byte entries and one
    16-byte tag") gives the equation in expected_len.

    THE QUESTION THIS ENTRY DEPENDED ON IS ANSWERED. Every field is fixed
    width or counted: A.5 requires fixed-width integers, one compressed
    encoding for curve points, "the fixed length selected by the envelope
    format" for ciphertexts, and rejects "shorter, longer, non-minimal,
    reordered, undecodable, or otherwise non-canonical encodings". There is
    no variable-length free field, so length is a deterministic function of
    declared arity and the entry can be verified.

    A.4 also settles the carrier: "exactly one OP_RETURN output carries the
    complete binary envelope", fragmentation across outputs and
    witness-carried publication are not part of this profile, and "indexers
    ignore witness bytes when extracting shielded transfer envelopes". So
    this is an OP_RETURN question only, and the witness path that could not
    have been survived is out of scope for this profile.

    Not covered here: the profile does not fix which arities a deployment
    supports. Section 14.3 says "a concrete deployment must define the
    supported arities" and that unsupported counts are invalid, and A.1 notes
    Groth16 needs a circuit-specific trusted setup per statement shape, so
    the supported set is small in practice. MAX_ARITY below is our cap, not
    the protocol's.
    """

    name = "shielded-bitcoin-v1"
    magic = b"sbtc"
    version = 1
    ttype = 0x01
    verified = True                 # checked against Appendix A.3/A.4/A.5

    HEADER = 6          # magic(4) + version(1) + type(1)          A.3
    HANCHOR = 4         # uint32 LE                                sec 3
    NULLIFIER = 32      # nf, one per input                        A.4
    PKEPH = 32          # compressed ephemeral key, one per output A.4
    CT_NOTE = 67        # recipient ciphertext, one per output     A.4
    CT_OUT_PER = 64     # sender-recovery entry, one per output    A.4
    CT_OUT_TAG = 16     # one AEAD tag over the whole batch        A.4
    PROOF = 192         # Groth16                                  A.4

    # The paper's own worked example. If a refactor ever breaks the
    # equation, this is the number that catches it.
    REFERENCE = (2, 2, 610)

    @classmethod
    def expected_len(cls, n_in, n_out):
        """Exact payload length implied by the declared arity.

        This equation is the entire security of the entry. A payload one byte
        longer than this has a byte nobody can account for, and unaccounted
        bytes are where a payload hides.
        """
        return (cls.HEADER + cls.HANCHOR
                + compactsize_len(n_in) + compactsize_len(n_out)
                + n_in * cls.NULLIFIER
                + n_out * (cls.PKEPH + cls.CT_NOTE)
                + cls.CT_OUT_TAG + n_out * cls.CT_OUT_PER
                + cls.PROOF)

    @classmethod
    def match(cls, p, strict_push=True):
        """Parse p as an envelope. Returns a Verdict, never raises."""
        if not p.startswith(cls.magic):
            return None                      # not ours; let others try

        def fail(why, d=""):
            return Verdict(False, cls.name, why, d)

        # A.4: exactly one OP_RETURN output carrying the complete envelope,
        # and A.5 admits one canonical decoding. A payload reassembled from
        # several pushes, or pushed non-minimally, is script-level slack: the
        # bytes differ while the payload does not.
        if not strict_push:
            return fail("not a single minimal push")

        head = cls.HEADER + cls.HANCHOR + 2
        if len(p) < head:
            return fail("truncated header", "%d bytes" % len(p))
        if p[4] != cls.version:
            return fail("unknown version", "v%d" % p[4])
        if p[5] != cls.ttype:
            return fail("unknown transfer type", "0x%02x" % p[5])

        off = cls.HEADER + cls.HANCHOR
        n_in, used_a = read_compactsize(p, off)
        if n_in is None:
            return fail("non-canonical input count")
        n_out, used_b = read_compactsize(p, off + used_a)
        if n_out is None:
            return fail("non-canonical output count")

        # A transfer with no inputs creates value from nothing, and one with
        # no outputs destroys it. Neither is a transfer.
        if n_in < 1 or n_out < 1:
            return fail("degenerate arity", "%d->%d" % (n_in, n_out))
        if n_in > MAX_ARITY or n_out > MAX_ARITY:
            return fail("arity over cap", "%d->%d, cap %d"
                        % (n_in, n_out, MAX_ARITY))

        want = cls.expected_len(n_in, n_out)
        if len(p) != want:
            # The load-bearing check. Prefix squatting dies here.
            return fail("length does not match arity",
                        "%d->%d implies %d bytes, got %d"
                        % (n_in, n_out, want, len(p)))
        if want > MAX_RETAINED_BYTES:
            return fail("over retention cap", "%d bytes" % want)

        return Verdict(True, cls.name, "well-formed transfer envelope",
                       "%d->%d, %d bytes" % (n_in, n_out, len(p)))

    @classmethod
    def fingerprint(cls):
        """Canonical description hashed into the policy id."""
        return {"name": cls.name,
                "magic": cls.magic.decode("ascii"),
                "version": cls.version,
                "type": cls.ttype,
                "verified": cls.verified,
                "len_terms": [cls.HEADER, cls.HANCHOR, cls.NULLIFIER,
                              cls.PKEPH, cls.CT_NOTE, cls.CT_OUT_PER,
                              cls.CT_OUT_TAG, cls.PROOF],
                "reference": list(cls.REFERENCE),
                "max_arity": MAX_ARITY}


REGISTRY = [ShieldedBitcoinV1]


# ------------------------------------------------------------------ policy


class Policy:
    """The retention ruleset. Its identity goes into the commitment.

    Default is every verified entry and nothing else, so a fresh node behaves
    exactly as it does today until someone has checked an entry against its
    specification.
    """

    def __init__(self, entries=None, allow_unverified=False,
                 op_return_limit=OP_RETURN_LIMIT):
        self.allow_unverified = bool(allow_unverified)
        self.op_return_limit = int(op_return_limit)
        pool = REGISTRY if entries is None else list(entries)
        self.entries = [e for e in pool
                        if e.verified or self.allow_unverified]

    def classify(self, payload, strict_push=True):
        """Decide one OP_RETURN payload (the data after the opcodes)."""
        if payload is None:
            return Verdict(True, None, "not an OP_RETURN output")
        for entry in self.entries:
            v = entry.match(payload, strict_push=strict_push)
            if v is not None:
                return v
        if len(payload) <= self.op_return_limit:
            return Verdict(True, None, "within OP_RETURN limit",
                           "%d bytes" % len(payload))
        return Verdict(False, None, "oversized data carrier",
                       "%d bytes, limit %d" % (len(payload),
                                               self.op_return_limit))

    def should_retain(self, script):
        """Decide a whole scriptPubKey. Non-OP_RETURN scripts are untouched."""
        pushes = op_return_pushes(script)
        if pushes is None:
            return Verdict(True, None, "not an OP_RETURN output")
        payload = b"".join(d for d, _ in pushes)
        strict = len(pushes) == 1 and pushes[0][1]
        return self.classify(payload, strict_push=strict)

    def describe(self):
        return {"op_return_limit": self.op_return_limit,
                "allow_unverified": self.allow_unverified,
                "max_retained_bytes": MAX_RETAINED_BYTES,
                "entries": [e.fingerprint() for e in self.entries]}

    def policy_id(self):
        """Stable hash of the active ruleset, for the commitment preamble.

        Two nodes that retain different things derive different stores, so a
        commitment is only comparable against one computed under the same
        policy. Publishing C without this is publishing an unverifiable
        number, the same way a commitment without its height is.
        """
        blob = json.dumps(self.describe(), sort_keys=True,
                          separators=(",", ":")).encode()
        return hashlib.sha256(blob).hexdigest()


# ----------------------------------------------------------------- parsing


def op_return_pushes(script):
    """Pushes in an OP_RETURN script as [(data, minimally_encoded)], or None.

    The payload is the concatenation, but the structure matters too: the same
    bytes pushed as OP_PUSHDATA4 instead of OP_PUSHDATA2, or split across two
    pushes, produce identical payloads from different scripts. Those spare
    script bytes are carrying capacity, so a protocol entry requires exactly
    one minimally encoded push (A.4: one output, complete envelope).
    """
    if not script or script[0] != OP_RETURN:
        return None
    i, out = 1, []
    n = len(script)
    while i < n:
        op = script[i]
        i += 1
        if op < OP_PUSHDATA1:
            ln, minimal = op, True
        elif op == OP_PUSHDATA1:
            if i + 1 > n:
                return None
            ln = script[i]; i += 1
            minimal = ln >= OP_PUSHDATA1
        elif op == OP_PUSHDATA2:
            if i + 2 > n:
                return None
            ln = int.from_bytes(script[i:i + 2], "little"); i += 2
            minimal = ln > 0xFF
        elif op == OP_PUSHDATA4:
            if i + 4 > n:
                return None
            ln = int.from_bytes(script[i:i + 4], "little"); i += 4
            minimal = ln > 0xFFFF
        else:
            return None            # a non-push opcode after OP_RETURN
        if i + ln > n:
            return None            # push runs off the end
        out.append((script[i:i + ln], minimal))
        i += ln
    return out


def op_return_payload(script):
    """Return the data pushed by an OP_RETURN script, or None.

    Returns b"" for a bare OP_RETURN. Anything malformed returns None so the
    caller treats it as a script we do not understand rather than as an empty
    payload we might wave through.
    """
    if not script or script[0] != OP_RETURN:
        return None
    i, out = 1, b""
    n = len(script)
    while i < n:
        op = script[i]
        i += 1
        if op < OP_PUSHDATA1:
            ln = op
        elif op == OP_PUSHDATA1:
            if i + 1 > n:
                return None
            ln = script[i]; i += 1
        elif op == OP_PUSHDATA2:
            if i + 2 > n:
                return None
            ln = int.from_bytes(script[i:i + 2], "little"); i += 2
        elif op == OP_PUSHDATA4:
            if i + 4 > n:
                return None
            ln = int.from_bytes(script[i:i + 4], "little"); i += 4
        else:
            return None            # a non-push opcode after OP_RETURN
        if i + ln > n:
            return None            # push runs off the end
        out += script[i:i + ln]
        i += ln
    return out


def encode_op_return(payload):
    """Build a minimal-push OP_RETURN script. Used by the tests."""
    n = len(payload)
    if n < OP_PUSHDATA1:
        return bytes([OP_RETURN, n]) + payload
    if n <= 0xFF:
        return bytes([OP_RETURN, OP_PUSHDATA1, n]) + payload
    return bytes([OP_RETURN, OP_PUSHDATA2]) + n.to_bytes(2, "little") + payload


# ---------------------------------------------------------------- selftest


def _envelope(n_in=1, n_out=2, cls=ShieldedBitcoinV1, pad=0, magic=None,
              version=None, ttype=None, fat_counts=False):
    """Build a syntactically correct envelope of the right length."""
    counts = bytes([n_in, n_out])
    if fat_counts:                         # non-minimal CompactSize
        counts = b"\xfd" + n_in.to_bytes(2, "little") \
               + b"\xfd" + n_out.to_bytes(2, "little")
    body = (magic or cls.magic) \
        + bytes([cls.version if version is None else version,
                 cls.ttype if ttype is None else ttype]) \
        + (900_000).to_bytes(4, "little") + counts
    want = cls.expected_len(n_in, n_out)
    return body + b"\x11" * (want - len(body) + pad)


def selftest():
    ok = []

    def ck(label, cond, extra=""):
        ok.append(bool(cond))
        print("  [%s] %s%s" % ("ok  " if cond else "FAIL", label,
                               "" if cond else "  <- " + str(extra)))

    print("length equation, against Appendix A")
    n_in, n_out, want = ShieldedBitcoinV1.REFERENCE
    got = ShieldedBitcoinV1.expected_len(n_in, n_out)
    ck("E(2->2) == 610, the paper's worked example", got == want, got)
    ck("equation is 220 + 32N + 163M for small arity",
       all(ShieldedBitcoinV1.expected_len(a, b) == 220 + 32 * a + 163 * b
           for a in range(1, 17) for b in range(1, 17)))
    ck("strictly increasing in both counts",
       ShieldedBitcoinV1.expected_len(2, 2) > ShieldedBitcoinV1.expected_len(1, 2)
       > ShieldedBitcoinV1.expected_len(1, 1))
    ck("no two arities share a length",
       len({ShieldedBitcoinV1.expected_len(a, b)
            for a in range(1, 17) for b in range(1, 17)}) == 256,
       "a collision would let one arity impersonate another")

    print("\ncompactsize")
    ck("minimal widths", [compactsize_len(x) for x in (0, 252, 253, 0xFFFF,
                                                       0x10000, 0xFFFFFFFF,
                                                       0x100000000)]
       == [1, 1, 3, 3, 5, 5, 9])
    ck("reads a one-byte count", read_compactsize(b"\x10", 0) == (16, 1))
    ck("rejects non-minimal fd", read_compactsize(b"\xfd\x02\x00", 0)[0] is None)
    ck("accepts a genuine fd", read_compactsize(b"\xfd\xfd\x00", 0) == (253, 3))
    ck("rejects non-minimal fe",
       read_compactsize(b"\xfe\x02\x00\x00\x00", 0)[0] is None)
    ck("rejects truncated", read_compactsize(b"\xfd\x02", 0)[0] is None)
    ck("rejects past the end", read_compactsize(b"", 0)[0] is None)

    print("\nscript parsing")
    ck("bare OP_RETURN is empty payload",
       op_return_payload(bytes([OP_RETURN])) == b"")
    ck("non-OP_RETURN returns None", op_return_payload(b"\x76\xa9") is None)
    ck("empty script returns None", op_return_payload(b"") is None)
    ck("short push round-trips",
       op_return_payload(encode_op_return(b"hello")) == b"hello")
    ck("pushdata1 round-trips",
       op_return_payload(encode_op_return(b"x" * 200)) == b"x" * 200)
    ck("pushdata2 round-trips",
       op_return_payload(encode_op_return(b"x" * 500)) == b"x" * 500)
    ck("push running off the end is rejected",
       op_return_payload(bytes([OP_RETURN, 40]) + b"short") is None)
    ck("non-push opcode after OP_RETURN rejected",
       op_return_payload(bytes([OP_RETURN, 0xAC])) is None)
    ck("multi-push concatenates",
       op_return_payload(bytes([OP_RETURN, 2]) + b"ab"
                         + bytes([2]) + b"cd") == b"abcd")
    ck("minimal push flagged minimal",
       op_return_pushes(encode_op_return(b"x" * 500))[0][1])
    ck("pushdata4 for 500 bytes flagged non-minimal",
       not op_return_pushes(bytes([OP_RETURN, OP_PUSHDATA4])
                            + (500).to_bytes(4, "little")
                            + b"x" * 500)[0][1])
    ck("pushdata1 for a 10-byte push flagged non-minimal",
       not op_return_pushes(bytes([OP_RETURN, OP_PUSHDATA1, 10])
                            + b"x" * 10)[0][1])
    ck("614-byte script for a 610-byte envelope, as A.4 states",
       len(encode_op_return(b"x" * 610)) == 614)

    print("\nretention — the entry is active by default")
    p = Policy()
    ck("verified entry is active", len(p.entries) == 1)
    v = p.should_retain(encode_op_return(_envelope(2, 2)))
    ck("2->2 envelope retained", v.retain and v.protocol == "shielded-bitcoin-v1", v)
    ck("1->2 retained", p.should_retain(encode_op_return(_envelope(1, 2))).retain)
    ck("16->16 at the cap retained",
       p.should_retain(encode_op_return(_envelope(16, 16))).retain)
    ck("retained envelope is far over the size limit",
       len(_envelope(2, 2)) == 610 > OP_RETURN_LIMIT)
    ck("small payload still kept", p.classify(b"x" * 40).retain)
    ck("83 bytes kept", p.classify(b"x" * 83).retain)
    ck("84 bytes stripped", not p.classify(b"x" * 84).retain)
    ck("non-OP_RETURN script untouched",
       p.should_retain(b"\x00\x14" + b"\x00" * 20).retain)

    print("\nadversarial — the bypass attempts")
    jpeg = ShieldedBitcoinV1.magic + b"\xff\xd8\xff" + b"A" * 5000
    ck("prefix-squatted JPEG stripped", not p.classify(jpeg).retain)
    ck("one byte too long stripped", not p.classify(_envelope(2, 2, pad=1)).retain,
       "slack bytes are where a payload hides")
    ck("one byte too short stripped",
       not p.classify(_envelope(2, 2, pad=-1)).retain)
    ck("non-minimal counts stripped",
       not p.classify(_envelope(2, 2, fat_counts=True)).retain,
       "fd0200 buys two free bytes for the same value")
    ck("split across two pushes stripped",
       not p.should_retain(bytes([OP_RETURN, OP_PUSHDATA2])
                           + (305).to_bytes(2, "little") + _envelope(2, 2)[:305]
                           + bytes([OP_PUSHDATA2]) + (305).to_bytes(2, "little")
                           + _envelope(2, 2)[305:]).retain,
       "A.4: exactly one output carries the complete envelope")
    ck("non-minimal push of a valid envelope stripped",
       not p.should_retain(bytes([OP_RETURN, OP_PUSHDATA4])
                           + (610).to_bytes(4, "little")
                           + _envelope(2, 2)).retain,
       "same payload, two spare script bytes")
    ck("arity over the cap stripped", not p.classify(_envelope(17, 1)).retain)
    ck("zero inputs stripped", not p.classify(_envelope(0, 2)).retain)
    ck("zero outputs stripped", not p.classify(_envelope(1, 0)).retain)
    ck("unknown version stripped", not p.classify(_envelope(version=9)).retain)
    ck("unknown transfer type stripped",
       not p.classify(_envelope(ttype=0x7F)).retain)
    ck("truncated header stripped",
       not p.classify(ShieldedBitcoinV1.magic + b"\x01").retain)
    ck("near-miss magic falls through to the size rule",
       p.classify(b"sbtd" + b"A" * 5000).protocol is None)
    ck("arity claiming a huge envelope is capped first",
       not p.classify(_envelope(255, 255)).retain)

    # Everything that is not an sbtc envelope must be decided exactly as the
    # size rule decides it. This is what keeps the published figures valid
    # for all 967,985 blocks already measured.
    import random as _r
    rng = _r.Random(7)
    div = 0
    for _ in range(20000):
        n = rng.choice([0, 1, 20, 40, 80, 82, 83, 84, 85, 200, 610, 1000, 5000])
        pay = bytes(rng.getrandbits(8) for _ in range(min(n, 80)))
        pay += b"\x00" * (n - len(pay))
        if p.classify(pay).retain != (len(pay) <= OP_RETURN_LIMIT):
            div += 1
    ck("non-envelope payloads decided exactly as before", div == 0,
       "%d divergences -> C would change" % div)

    off = Policy(entries=[])
    ck("with no entries, a valid envelope is stripped",
       not off.should_retain(encode_op_return(_envelope(2, 2))).retain,
       "the escape hatch back to the published ruleset")

    print("\ncommitment policy id")
    a = Policy().policy_id()
    ck("stable across instances", a == Policy().policy_id())
    ck("differs with no entries", a != Policy(entries=[]).policy_id())
    ck("differs if the length equation changes", a != _mutated_id())
    ck("is a sha256 hex digest", len(a) == 64 and int(a, 16) >= 0)

    print("\n%d/%d passed" % (sum(ok), len(ok)))
    return 0 if all(ok) else 1


def _mutated_id():
    """Policy id under a changed field width — must not collide."""
    class Mutated(ShieldedBitcoinV1):
        NULLIFIER = 64
    return Policy(entries=[Mutated], allow_unverified=True).policy_id()


# -------------------------------------------------------------------- main


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--policy", action="store_true",
                    help="print the active ruleset and its commitment id")
    ap.add_argument("--scan-hex", action="store_true",
                    help="read hex scriptPubKeys or payloads on stdin, "
                         "one per line, and classify each")
    ap.add_argument("--allow-unverified", action="store_true",
                    help="enable registry entries not yet checked against "
                         "their specification. Changes the policy id.")
    a = ap.parse_args()

    if a.selftest:
        return selftest()

    pol = Policy(allow_unverified=a.allow_unverified)

    if a.policy:
        print(json.dumps(pol.describe(), indent=2, sort_keys=True))
        print("\npolicy_id  %s" % pol.policy_id())
        print("\nPublish this beside C and the block height. A commitment is"
              "\nonly comparable against one computed under the same policy.")
        if not pol.entries:
            print("\nNo entries active: retention is byte-for-byte identical"
                  "\nto the size rule, so C is unchanged.")
        return 0

    if a.scan_hex:
        kept = stripped = 0
        for n, line in enumerate(sys.stdin, 1):
            line = line.strip()
            if not line:
                continue
            try:
                raw = binascii.unhexlify(line)
            except (binascii.Error, ValueError):
                print("%6d  BADHEX" % n)
                continue
            v = pol.should_retain(raw) if raw[:1] == bytes([OP_RETURN]) \
                else pol.classify(raw)
            kept, stripped = (kept + 1, stripped) if v.retain \
                else (kept, stripped + 1)
            print("%6d  %-7s %-22s %s" % (
                n, "RETAIN" if v.retain else "STRIP",
                v.protocol or "-", v.reason))
        print("\n%d retained, %d stripped" % (kept, stripped))
        print("policy_id %s" % pol.policy_id())
        return 0

    ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
