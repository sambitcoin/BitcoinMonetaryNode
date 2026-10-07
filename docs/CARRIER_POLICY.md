# Carrier policy: keeping private payments

Status: implemented and enabled. Shielded Bitcoin transfer envelopes are
retained; everything else is decided exactly as before. Widths taken from
Appendix A of the paper, not estimated. 53/53 self-tests.

## The problem

The stripper's rule is a size test: `OP_RETURN` over 83 bytes is a data
carrier and goes. That classifies on shape. It is about to be wrong.

[Shielded Bitcoin][sb] (Shikhelman, Komarov, Moskvin, 24 September 2026)
publishes private *transfers* on Bitcoin L1 with no consensus changes. Its
implementation profile fixes an `OP_RETURN` carrier. A transfer envelope
carries a header, an anchor height, arity counts, one nullifier per input,
one ephemeral key and one ciphertext per output, a batched sender-recovery
ciphertext, and a succinct zero-knowledge proof. A Groth16 proof alone is 192
bytes at BN254. Every envelope is hundreds of bytes, and every one of them is
a payment.

Under the size rule, a monetary node strips all of them.

## Why this is worse than losing a payment

Shielded state is reconstructed by deterministic replay. The nullifier is
`Hnf(sknf, ρ, pos)`, where `pos` is the **replay-assigned** note-tree
position (paper §9, §19.2).

Drop one envelope and every subsequent leaf is appended at the wrong
position, so every subsequent nullifier derivation changes. One stripped
envelope desynchronises the note tree permanently from that height onward. It
is not a lost payment; it is a wrong state with no recovery short of
resyncing from a node that kept the data.

And nothing looks broken. The merkle roots still match, the blocks still
verify against their own proof-of-work, `--verify` still passes with zero
failures. A monetary node in this condition reports perfect health.

## The rule

Retention keys on **function**, established by parsing — never by prefix.

"Keep anything beginning with `sbtc`" is a universal bypass: prefix a JPEG
and walk through. So an entry:

1. matches its magic, version and transfer-type discriminator;
2. reads the declared `input_count` and `output_count`;
3. computes the **exact** payload length that arity implies;
4. retains only if the payload is that length to the byte.

A rigid format leaves nowhere to hide a payload. One slack byte is one byte
of spam capacity, so the length check is exact rather than a bound. Arity is
capped at 16 either way, so a declared `255->255` cannot conjure a megabyte
of "payment".

## The question is answered

Appendix A settles it. A.3 fixes the body order, A.4 gives the worked size

```
E(2->2) = 6 + 4 + 2 + 2(32) + 2(32) + 2(67) + 144 + 192 = 610 bytes
```

and A.5 requires fixed-width integers, one compressed encoding for curve
points, "the fixed length selected by the envelope format" for ciphertexts,
CompactSize vector counts, and rejects "shorter, longer, non-minimal,
reordered, undecodable, or otherwise non-canonical encodings."

There is no variable-length free field. Generalising A.4's terms:

```
E(N, M) = 6 + 4 + cs(N) + cs(M) + 32N + (32 + 67)M + (64M + 16) + 192
        = 220 + 32N + 163M          for N, M < 253
```

`E(2,2) = 610`, matching the paper. That identity is a self-test: if the
equation ever drifts, the paper's own number catches it.

Length is a deterministic function of declared arity, so the entry is
`verified = True` and active. Three extra properties fall out and are
enforced:

- **Arity is recoverable from length.** No two arities in `1..16` share a
  length, so one arity cannot impersonate another.
- **Counts must be minimal CompactSize.** Encoding `2` as `fd0200` buys two
  free bytes for the same value. Rejected.
- **One minimally encoded push.** A.4: *"exactly one OP_RETURN output carries
  the complete binary envelope"*, fragmentation across outputs is not part of
  the profile. The same 610 bytes pushed with `OP_PUSHDATA4` instead of
  `OP_PUSHDATA2` is two spare script bytes. Rejected.

`MAX_ARITY = 16` is our cap, not the protocol's. §14.3 leaves supported
arities to the deployment, and A.1 requires a Groth16 trusted setup per
statement shape, so the real set is small.

## Does this change the published C?

Only if some transaction at or below 967,984 already carries a single
minimally pushed `OP_RETURN` beginning with `sbtc` whose length exactly
matches the arity equation. Nothing else is decided differently — asserted
against 20,000 generated payloads with zero divergences.

The paper was published 24 September 2026 and nothing implements it, so the
expected count is zero. Expected is not measured. **Feed the chain's
oversized `OP_RETURN` payloads through `--scan-hex` before republishing C.**
`Policy(entries=[])` restores the old ruleset exactly, and a test asserts
that it strips a valid envelope.

The timing argument still holds for the ruleset itself: the preamble is part
of what makes `C` meaningful, and changing it after a protocol has traffic
means a chain-wide rebuild. It is close to free exactly once.

## Commitment preamble

`policy_id()` joins the published rules:

```
OP_RETURN limit      83
scriptSig limit    1650
envelopes          false push before OP_IF, true push before OP_NOTIF,
                   in taproot script-path and P2WSH witness scripts
data keys          not on secp256k1
carrier policy     d4141831063597f35542c8327314be85b1a719439dbde33a283a75c4ecea2c3e
```

That value is the default policy with the Shielded Bitcoin entry active. It
changes if any width, the arity cap, or the entry set changes, which is the
point: two nodes that retain
different things derive different stores, and a commitment is only comparable
against one computed under the same policy. A commitment published without it
is as unverifiable as one published without its height.

## Integration

`carrier_policy.py` is standalone and has no dependency on the store. In
`monetary_store.py`, at the point where an output is currently tested against
the size limit:

```python
from carrier_policy import Policy
POLICY = Policy()          # Policy(entries=[]) for the pre-Shielded ruleset

# was:  if is_op_return(spk) and len(payload) > 83: strip
verdict = POLICY.should_retain(spk)
if not verdict.retain:
    strip(...)             # and record verdict.reason in the carrier audit
```

`should_retain()` returns `retain=True` for every non-`OP_RETURN` script, so
it is safe to call on all outputs. Record `verdict.protocol` and
`verdict.reason` alongside the carrier counts — when the first real envelope
lands, that log is how you find out.

Write `POLICY.policy_id()` into `state.json` when the store is created, and
refuse to append to a store whose recorded policy differs from the running
one. Two policies in one store is the same class of corruption as two daemons
appending at once.

## The witness carrier — retracted

I previously flagged witness-carried publication as the case this approach
could not survive, on the strength of §11 listing it as an option. **A.4
rules it out of this profile:**

> Fragmentation across several outputs, witness-carried publication, and
> alternative carrier locations are not part of this profile. Indexers ignore
> witness bytes when extracting shielded transfer envelopes.

So for Shielded Bitcoin as specified, this is an `OP_RETURN` question only
and the unrecoverable case does not arise. A.4 does cost it out — the
witness route is 438 vB against 625 vB for `OP_RETURN` — so a future profile
could revisit it on fee grounds. If one ever does, the inscription detector
would match the envelope and witness data is the one thing the store deletes
permanently. Worth a line in `CARRIERS.md`; not worth building for now.

A.4 also confirms the relay assumption: the profile depends on Core v30.0
raising the `-datacarriersize` default from 83 to 100,000, and notes
operators can restore 83. Your node is one of the operators who did.

## Status

- `carrier_policy.py` — 53/53 self-tests, standard library only
- Widths from Appendix A; `E(2,2) == 610` asserted against the paper
- Shielded Bitcoin entry **enabled**
- Not yet wired into `monetary_store.py`
- No chain scan run yet, so C is expected-unchanged, not measured-unchanged

[sb]: https://www.allocinit.xyz/uploads/shielded-bitcoin.pdf
