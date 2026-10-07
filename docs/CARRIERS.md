# Data carrier coverage audit

Every way I know of to embed data in Bitcoin, and whether this project catches
it. Written because "we remove all spam" is a claim that invites exactly one
question — *all of it?* — and the answer needs to be a table, not an assertion.

**I cannot claim complete coverage.** Some carriers are undetectable in
principle, some are deliberately retained, and some were gaps that have since
been closed. All are listed below rather than discovered by someone else.

---

## Detected and removed

| Carrier | Method | Era-wide |
|---|---|---|
| **Inscription envelopes** | Data inside an unexecutable branch: a false push before `OP_IF`, or a true push before `OP_NOTIF`. Falsity by script semantics, so `OP_0`, an empty push and a push of `0x00` all qualify. Detected in taproot script-path *and* P2WSH witness scripts. | 37.1 GB |
| **Stamp-style bare multisig** | Public keys that are not points on secp256k1 (`y² = x³ + 7 mod p`, Euler's criterion). | 77.5 MB |
| **Fake keys in bare P2PK** | Same on-curve test applied to `<key> OP_CHECKSIG`, not only to multisig. | not yet measured |
| **OP_RETURN over 83 bytes** | Outputs exceeding the historic datacarrier limit. | 12.3 MB |
| **Witness of modified transactions** | Signatures, control blocks and tapscript wrapper of any transaction that carried a carrier. | 15.4 GB |
| **Commit outputs** | The taproot output a reveal spends. Identified exactly, never heuristically. Free to remove: provably already spent, so no filter entry needed. **Measured, not yet removed.** | 4.97 GB |

---

## Detected, deliberately retained

**Dust outputs** — sub-1000-sat P2TR from the inscription era, 127,021,924 of
them. Kept in block storage because a 43-byte output costs an 82-byte filter
entry to remove; excluded from chainstate, where the saving is real. Arithmetic,
not preference.

**OP_RETURN under 83 bytes** — policy-compliant, provably unspendable, never
enters the UTXO set. Total across the era is small.

---

## Closed gaps

Three carriers listed here as gaps have since been detected and are now removed.
Recorded rather than quietly edited out, because the fact that they were missing
is as informative as the fact that they are covered.

### `OP_NOTIF` envelopes — closed

The detector looked for a *false* push followed by `OP_IF`. The mirror
construction is equally unexecutable and carries data identically:

    OP_1 OP_NOTIF <arbitrary data> OP_ENDIF

Now detected, with the falsity rule made symmetric.

Two negative tests matter more than the positive one. `OP_0 OP_NOTIF` and
`OP_1 OP_IF` both *execute* their branch — data inside would be run as script
and the spend would fail — so they are not carriers, and flagging them would
mean stripping data from transactions that legitimately contain it.

### Envelopes outside taproot — closed

Detection required a taproot script-path spend: a control block of 33 + 32m
bytes with leaf version `0xc0`. The same `OP_FALSE OP_IF` construction inside a
**P2WSH** witness script carries data just as well, only without the discount.

Now detected via the final witness item when the taproot test does not match.
Tested to confirm taproot spends still take the taproot path, so a payload is
read from the tapscript rather than the control block and is not counted twice.

### Fake keys in bare P2PK — closed

The on-curve test ran only on scripts ending in `OP_CHECKMULTISIG`. A bare
`<33 bytes> OP_CHECKSIG` output with data in the key position is the same trick
one opcode away.

Now covered by `is_data_pubkey()`, applying the same secp256k1 test. Genuine
compressed and uncompressed keys are checked not to trigger it.

**These changed the classifier, so they changed the commitment.** The published
value `f0e4c825…` remains correct for the *previous* rules over blocks
767,430–962,292. A store built with the current rules produces a different one.
Two C values from different rule sets are not comparable and neither is wrong.

## Still open

### Oversized scriptSig — counted, never removed

This table previously listed oversized scriptSigs under "detected and
removed", at 13.8 KB across the era. **That was wrong.** They are detected and
counted. They are not removed, and the saving is zero.

`strip_block()` adds an input's script length to `st["scriptsig"]` when it
exceeds the limit, and that is enough to mark the transaction as `touched`, so
it is stored as *modified*. But `rebuild_without()` copies every input
verbatim — prevout, scriptSig, sequence — and only rewrites the output list.
The scriptSig survives into the stored body untouched.

Demonstrated on a constructed transaction, 2000-byte scriptSig against a
1650-byte limit:

    counted as scriptsig spam: 2000 bytes
    original 2084 bytes -> stored body 2084 bytes
    scriptSig still present in stored body: True
    bytes actually saved: 0

So the transaction pays 32 bytes for a stored txid and saves nothing. For a
SegWit transaction there is still an incidental saving, because witness data
is discarded for anything marked modified — but that is the witness rule
doing the work, not this one.

The 13.8 KB figure is a measurement of what was **identified**, and it is
correct as such. It was published under a heading that claimed it had been
removed.

Two ways to close this. Strip the scriptSig in `rebuild_without()`, which
recovers 13.8 KB across the whole era and changes `C`. Or leave the behaviour
and keep it documented here. The magnitude does not justify a rule change on
its own; the reason to fix it is that a detector which counts without acting
will eventually be wired to something that matters.

### Runestones under 83 bytes

Runes use `OP_RETURN` payloads that mostly fall under the datacarrier limit, so
they pass the current rule. This conflicts with the stated target list.

It is a policy question rather than a detection failure: *should* small
`OP_RETURN` be removed? Doing so would also catch legitimate protocol usage, and
the measured total for compliant `OP_RETURN` across the whole inscription era is
small. Unresolved deliberately.

### Commit outputs

Measured at 4.97 GB across 121,474,801 outputs, and identifiable exactly — a
reveal's input points straight at the commit output it spends. Not yet removed,
because the commit sits in an earlier block than the reveal that identifies it,
so stripping at the tip cannot know. The depth buffer in the daemon makes it
possible; the stripping logic does not do it yet.

## Undetectable in principle

These cannot be distinguished from monetary outputs by inspecting the chain.
Listing them because pretending otherwise would be dishonest.

**Data in hash fields.** A P2PKH output commits to a 20-byte hash160; a P2WSH
or P2TR output to a 32-byte program. Those bytes can be arbitrary data instead
of a real hash or key. The output looks *identical* to a legitimate one. The
only difference is that nobody can ever spend it — which you cannot know until
forever has passed.

This is the fundamental ceiling on any content-based filter. Bitcoin outputs
have space for arbitrary bytes by construction, and no rule distinguishes
"hash of a key I control" from "20 bytes of a JPEG."

**Steganography in amounts, ordering, nonces, or timestamps.** Bandwidth is
minuscule — a few bits per transaction — but it exists and cannot be filtered
without breaking the chain.

**The witness annex.** BIP341 reserves a witness element prefixed `0x50` that
can carry arbitrary data. Currently non-standard so unused in practice, but if
policy changes it becomes a carrier and nothing here would see it.

---

## What this means for the claim

The accurate statement is **not** "all spam is removed." It is:

> Every data carrier known to be in significant use is detected and removed,
> with the exceptions listed above: one policy question, one measured but not
> yet implemented, and a class that is undetectable in principle.

That is weaker than the slogan and stronger than the slogan can survive. A
content-based filter cannot be complete, because Bitcoin outputs can hold
arbitrary bytes that are indistinguishable from legitimate ones. Any project
claiming otherwise has not thought about hash fields.

**What the design does guarantee** is different and more defensible: whatever
*is* removed, the block still verifies against its own proof-of-work, nothing is
confiscated, and every dropped output remains spendable and locally validatable.
Coverage is a moving target; correctness is not.

---

## Remaining work

1. **Commit outputs** — 4.97 GB, measured, identifiable exactly. Needs the
   daemon's depth buffer wired into the stripping logic, because the commit
   sits in an earlier block than the reveal that identifies it.
2. **Oversized scriptSig** — decide whether to strip it or keep documenting
   that it is only counted. Either is defensible; the current state, where the
   code and the table disagreed, was not.
3. **Small Runestones** — decide the policy question before implementing
   anything.
4. **Measure what the three closed detectors actually find.** They are tested
   against constructed cases but have never run against the chain. The marginal
   contribution of each should be on the record separately rather than folded
   into a total — and if one of them finds nothing, that is worth publishing
   too.

Test coverage: 56 checks in `test_monetary_store.py`, including negative cases
for constructions that *look* like carriers but execute — `OP_0 OP_NOTIF` and
`OP_1 OP_IF` — where a false positive would mean stripping data from
transactions that legitimately contain it.
