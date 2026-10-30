# tinycloud-threshold protocol specification

Section numbers track the approved TinyCloud plan. §§3.1–3.6 are frozen for S0.1 except the explicit request-digest amendment below.

### 3.0 Protocol model, parameter budgets and authenticated contexts

**Parties.** The owner's device authorizes ceremonies and certificates, orders each ceremony round and closes it with a signed round closure. Members are node processes with node keys (Ed25519 `did:key`). Readers hold transport keys.

**Ceremony model.** The membership and faulty-member set are fixed before each ceremony. A member in both the old and new cohort of a reshare counts in both. Cross-epoch operation requires the lifecycle in §3.11 and the integration storage contract.

**Owner relay.** The owner's device is trusted to authorize contexts and to close each round once, without equivocating. Owner equivocation is outside this model; divergent transcript hashes are detectable.

**Parameter budgets** (f = faulty members in the ceremony model):

| Operation | Allowed parameters | Required outcome within budget | Refused |
|---|---|---|---|
| Genesis DKG (GJKR New-DKG) | 2 ≤ t ≤ n ≤ 16 **and n ≥ 2t−1**; f = t−1 | Every participating conforming member and the public verifier finish with the same QUAL, commitments and transcript outcome | n < 2t−1 → `Error::UnsupportedFaultBudget`. Example: 3-of-4 genesis is refused. There is no separate, smaller f in slice 0. |
| Reshare / refresh | Old cohort (t, n) from the verified certificate; new 2 ≤ t′ ≤ n′ ≤ 16; the model permits ≤ t−1 faulty old **and** ≤ t′−1 faulty new members; completion needs ≥ t old members with valid dealings | mpk unchanged; honest new members' shares consistent with the public commitments | t′ < 2; fewer than t valid dealers → abort, old epoch stays in force |
| Threshold decryption | t shares of one key context | Correct key for any t honest shares; each bad share attributed | Mixed contexts refused before any algebra (§3.6) |

Reshare pins every dealer constant B_i0 to the old public share pk_i before evaluation. For selected old indices D, the weighted constants satisfy Σ λ_i^D·pk_i = mpk. A new cohort need not satisfy the genesis inequality; it must still supply t′ valid decryption shares. The complaint/answer extension and deterministic first-t dealer selection are TinyCloud protocol choices; Wong–Wang–Wing assume conforming new receivers.

**Raw inputs, authenticated contexts, node-asserted contexts.** Secret-releasing functions never take raw inputs alone.

| Kind | Types | Who establishes it |
|---|---|---|
| Raw / decoded | `DecryptRequest`, `SignedCertificate`, ceremony messages, `SignedStatement` | Decoders (validation only) |
| Crate-authenticated | `VerifiedCertificate`, `AuthorizedCeremony`, `ClosedRound<M>`, `KeyContext` | The crate, from a caller-supplied `TrustAnchor` plus owner/member signatures checked through the injected `DidSignatureVerifier` |
| Node-asserted (one narrow constructor) | `AuthorizedDerivation` | The node, after its existing UCAN capability check, by passing the URN, key path and version that check authorized; the crate rebuilds the identity from them and requires equality with the request's identity. No second authorization system. |

`TrustAnchor { expected_owner: Did, network: NetworkUrn }` always comes from the node's authorization context (the space's owner and the authorized network URN), never from a candidate certificate. "Current certificate" (freshness, no rollback) is decided by the node from the trusted authorization-log head (gate B, TC-2225); the crate provides lineage checks against a pinned predecessor but cannot know what is newest.

### 3.1 Notation and groups (frozen for S0.1)

- BLS12-381: G1, G2, GT, prime order r, standard generators g1, g2, reduced (optimal Ate, final exponentiation applied) pairing e.
- Master secret s ∈ Zr; **mpk = s·g2 ∈ G2**; share s_i; public share pk_i = s_i·g2.
- Identities hash to G1: H1(id). Derived key k = s·H1(id) ∈ G1. Transport key tsk ∈ Zr*, tpk = tsk·g1.
- t-of-n with polynomials of degree t−1; member indices are the Shamir x-coordinates 1..=n, never 0.
- λ_i^S = ∏_{j∈S, j≠i} j/(j−i) mod r.
- **Key generation** = (re-key counter, epoch). Epoch increases by 1 on every reshare and on every re-key and is never reset; the re-key counter increases by 1 on each re-key. Both use checked arithmetic (overflow is an error). Requests also bind the certificate digest, so the generation alone is never the only identifier.

### 3.2 Encodings (frozen for S0.1)

- **Scalars:** 32-byte big-endian, value < r; non-canonical encodings rejected. Secret scalars are sampled as 64 CSPRNG bytes read big-endian and reduced mod r (bias ≤ 2^-256), redrawn if zero where non-zero is required. Never reduce only 32 random bytes.
- **G1:** 48-byte compressed; **G2:** 96-byte compressed; the ZCash compressed serialization as described in the pairing-friendly-curves draft (as produced by blst `*_compress`). Decoders reject wrong length, bad flag bits, x ≥ p, off-curve, and points outside the prime-order subgroup (subgroup check performed explicitly, separate from decompression). Identity is accepted or rejected **by field role** (table below).
- **GT** (hashed only, never decoded): 576 bytes = 12 base-field elements, each 48-byte big-endian, in tower-coefficient order c0.c0.c0, c0.c0.c1, c0.c1.c0, c0.c1.c1, c0.c2.c0, c0.c2.c1, c1.c0.c0, c1.c0.c1, c1.c1.c0, c1.c1.c1, c1.c2.c0, c1.c2.c1, for the tower Fp2 = Fp[u]/(u²+1), Fp6 = Fp2[v]/(v³−(u+1)), Fp12 = Fp6[w]/(w²−v). Always the reduced pairing value, never a raw Miller-loop output. The S0.1 independent checker pins e(g1, g2) under this encoding as a known-answer vector.
- **Structures:** 1-byte format version; fields in a fixed order; variable-length fields as u32 big-endian length + bytes; lists as u16 count + elements sorted by member index; optional fields as 0x00 (absent) or 0x01 + value. Decoders reject trailing bytes, unsorted or duplicate entries, and lengths over the caps (checked before allocating).
- **Caps:** n ≤ 16; URN and key path 1..=1024 bytes UTF-8; DID ≤ 256 bytes; signature ≤ 512 bytes; any single message ≤ 64 KiB; a whole transcript ≤ 4 MiB.
- **Tagged hash:** TH(tag, body) = SHA-256(u32be(len(tag)) ‖ tag ‖ body).

Identity-point rules by role (N1):

| Field | Identity allowed? |
|---|---|
| mpk; every public share pk_i in a certificate or key set; tpk; IBE U; encrypted-share c1 and c2 (r_i ≠ 0) | No |
| Encrypted-share c3; aggregates C1, C2, C3 inside `combine` | Yes (c3 must still be a valid subgroup point) |
| Individual commitment coefficients (Pedersen C_ik, Feldman A_ik, B_ik, B′_k) and internal accumulators | Yes, except the constant and top coefficients named below |
| Aggregate DKG commitments: A_0 (= mpk) and A_{t−1}; reshare B_i0 (must equal pk_i), B_i,t′−1 and aggregate B′_{t′−1} | No |
| Derived key k | No |

### 3.3 Domain-separation tags (frozen for S0.1)

| Use | Primitive | DST / tag |
|---|---|---|
| H1: identity → G1 | RFC 9380 hash_to_curve, BLS12381G1_XMD:SHA-256_SSWU_RO_ | `TC-THRESHOLD-V1-IBE-ID_BLS12381G1_XMD:SHA-256_SSWU_RO_` |
| Pedersen h ∈ G2 (msg `pedersen-h`) | RFC 9380 hash_to_curve, BLS12381G2_XMD:SHA-256_SSWU_RO_ | `TC-THRESHOLD-V1-PEDERSEN-H_BLS12381G2_XMD:SHA-256_SSWU_RO_` |
| FO H2: GT bytes → 32 bytes | expand_message_xmd (SHA-256), len 32 | `TC-THRESHOLD-V1-IBE-H2` |
| FO H3: (σ ‖ M) → Zr | hash_to_field with **modulus r** (scalar field, not the base field p), L = 48, count = 1 (RFC 9380 §5) | `TC-THRESHOLD-V1-IBE-H3` |
| FO H4: σ → 32 bytes | expand_message_xmd (SHA-256), len 32 | `TC-THRESHOLD-V1-IBE-H4` |
| Identity encoding prefix | — | `TC-THRESHOLD-V1-IBE-ID-ENC` |
| Key-context digest | TH | `TC-THRESHOLD-V1-KEY-CONTEXT` |
| Decryption request digest | TH | `TC-THRESHOLD-V1-DECRYPT-REQUEST` |
| Share response signing preimage | TH | `TC-THRESHOLD-V1-DECRYPT-SHARE` |
| Commitment-vector hash | TH | `TC-THRESHOLD-V1-COMMITMENTS` |
| Ceremony authorization statement | TH | `TC-THRESHOLD-V1-CEREMONY-AUTH` |
| Ceremony message signing preimage | TH | `TC-THRESHOLD-V1-CEREMONY-MSG` |
| Round closure | TH | `TC-THRESHOLD-V1-ROUND-CLOSE` |
| Transcript hash | TH | `TC-THRESHOLD-V1-TRANSCRIPT` |
| Certificate digest | TH | `TC-THRESHOLD-V1-NETWORK-CERT` |
| Owner certificate statement | TH | `TC-THRESHOLD-V1-CERT-STATEMENT` |
| Readiness receipt | TH | `TC-THRESHOLD-V1-READY` |
| Activation statement | TH | `TC-THRESHOLD-V1-ACTIVATE` |
| HPKE `info` for dealings | RFC 9180 | `TC-THRESHOLD-V1-DEALING` ‖ authorized-ceremony digest ‖ round ‖ sender ‖ recipient |

Tags are distinct; the context binding comes from the context fields inside each preimage (§3.6, §3.9) and is tested by context-mismatch cases (§6 S6).

Key-use rule: s·H1(id) is a BLS signature on id under DST H1 (BLS 2001; Boldyreva 2003). s and the H1 DST are used for derivation only; the crate exposes no signing with s or with shares of s.

### 3.4 IBE identity (frozen for S0.1)

`IbeIdentity` bytes = `TC-THRESHOLD-V1-IBE-ID-ENC` as a length-prefixed field ‖ version 0x01 ‖ mode (0x01 record, 0x02 session) ‖ lp(network URN) ‖ lp(key path) ‖ key_version u64be ‖ (record only) 16-byte nonce. URN and path are taken as given (the node builds them from the authorized URN). One parse only; property-tested for round-trip and injectivity on adversarial splits. `IbeIdentity::network()` exposes the encoded network; `DecryptRequest` requires it to equal the request's outer network.

### 3.5 IBE wrap and unwrap: Boneh–Franklin FullIdent with Fujisaki–Okamoto (frozen for S0.1)

wrap(mpk, id, M ∈ {0,1}^256):
1. σ ← 32 CSPRNG bytes; ρ = H3(σ ‖ M). If ρ = 0: return `Error::DegenerateRandomness` (probability ≈ 2^-255; specified so both implementations agree).
2. U = ρ·g2; V = σ ⊕ H2(GT-encode(e(ρ·H1(id), mpk))); W = M ⊕ H4(σ). Use the scalar multiplication ρ·H1(id) in G1 (the fixed-width secret-scalar path), not an exponentiation in GT.
3. Ciphertext (U, V, W) = 96 + 32 + 32 bytes.

unwrap(k: &DerivedKey, expected_id, (U, V, W)):
1. If k's identity ≠ expected_id: `Error::WrongIdentity` (DerivedKey carries its identity, §5).
2. Decode U (subgroup, non-identity). σ = V ⊕ H2(GT-encode(e(k, U))); M = W ⊕ H4(σ); ρ = H3(σ ‖ M).
3. Accept only if ρ ≠ 0 and ρ·g2 = U (constant-time comparison of encodings); otherwise the single error `Error::InvalidCiphertext`.

**Q15 resolved:** keep H3(σ ‖ M) as in FullIdent. Adding U is circular (U is computed from H3's output). The identity association lives in `DerivedKey` (above) and in the envelope AAD at integration.

### 3.6 Key context, requests and encrypted decryption shares (vetKD; frozen for S0.1)

**KeyContext** = (network URN, re-key counter, epoch, certificate digest, threshold). Every `PublicKeySet` and `KeyShare` carries exactly one. Production key contexts come only from a `VerifiedCertificate` (S0.2); in S0.1 only the `#[cfg(test)]` dealer creates them.

**DecryptRequest** (raw) = (key context digest, network URN, re-key counter, epoch, certificate digest, IbeIdentity, tpk). Its digest = TH(`…DECRYPT-REQUEST`, encode(request)). Validation: identity's network = outer network; tpk decodes (subgroup, non-identity).

**AuthorizedDerivation** (node-asserted, §3.0) = a `DecryptRequest` plus the URN, path and version the node's capability check authorized; constructor rebuilds the identity from them and requires byte equality with the request's identity.

- **Issue** (member i, `KeyShare` with context X): require the request's context fields equal X exactly, else `Error::ContextMismatch` (no share released). r_i ← Zr* (§3.2 sampling). Share = (i, context digest, request digest, c1 = r_i·g1, c2 = r_i·g2, c3 = s_i·H1(id) + r_i·tpk). The request digest is the approved S0.1 amendment recorded below.
- **Response signing preimage** = TH(`…DECRYPT-SHARE`, request digest ‖ certificate digest ‖ u16be(i) ‖ encode(share)). The node signs it with its node key.
- **Verify** against the `PublicKeySet` of context X: first the context check (share's and request's context = X; share's request digest = request digest; member i in X); a mismatch is `ContextMismatch`, never `InvalidShare`. Then e(c1, g2) = e(g1, c2) and e(c3, g2) = e(H1(id), pk_i)·e(tpk, c2), each checked as one multi-pairing; failure is `ShareError::Invalid { member }`. These equations follow the published aggregatable vetBLS scheme.
- **Combine:** context check on every share first (mixed contexts → `CombineError::MixedContexts`; this check is unconditional, independently of the final pairing result). Each share verified individually; duplicates by member counted once; needs ≥ t; uses the t lowest indices. C_j = Σ λ_i^S·c_{j,i}.
- **Decrypt key:** k = C3 − tsk·C1. Accept only if k ≠ identity and e(k, g2) = e(H1(id), mpk). Returns `DerivedKey { identity, key context digest, k }`. This final check checks the key against id and mpk; context and authorization checks run separately first.

### 3.7 Genesis DKG: GJKR New-DKG (normative; implemented in S0.3)

Preconditions: an `AuthorizedCeremony` of kind `genesis` (§3.8 step 0 applies to genesis too) whose parameters satisfy §3.0's genesis budget (n ≥ 2t−1); each member's ceremony-scoped HPKE key from that context. Generators g2 and h in G2.

**Rounds.** Every round is a `ClosedRound`: the owner's signed closure over (authorized-ceremony digest, round number, TH of the ordered message list, previous transcript hash). Members process only closed rounds and only messages signed by authorized members for that ceremony and round.

1. **R1 deal.** Dealer i picks f_i, f′_i of degree t−1 (§3.2 sampling); publishes C_ik = a_ik·g2 + b_ik·h (k = 0..t−1); seals (s_ij, s′_ij) to each member j (§3.10), AAD = TH(`…COMMITMENTS`, C_i).
2. **R2 complain.** Member j complains against i if the sealed share does not open or s_ij·g2 + s′_ij·h ≠ Σ_k j^k·C_ik.
3. **R3 answer.** Dealer i publishes (s_ij, s′_ij) for each complaint against it. **A valid answer replaces j's missing or bad private value.**
4. **QUAL** (fixed here, never changed later). i is disqualified if: it is missing from closed R1; its R1 is malformed; it sent two different R1 messages; it has complaints from ≥ t distinct authorized complainers; it fails to answer a complaint in closed R3; or an answer fails the Pedersen check. Abort if |QUAL| < t.
5. **R4 extract.** Each i ∈ QUAL publishes A_ik = a_ik·g2 (k = 0..t−1).
6. **R5 extraction complaints: global barrier.** **Every** member sends an R5 message, possibly with an empty complaint list, and **no member finalizes before consuming the same closed R5 round.** Member j's R5 lists each i ∈ QUAL with s_ij·g2 ≠ Σ_k j^k·A_ik, attaching (s_ij, s′_ij), which anyone checks against C_i (Pedersen-valid) and A_i (Feldman-invalid). Also, by the public rules, every i ∈ QUAL whose R4 is missing, malformed (wrong length, invalid point, identity where forbidden) or equivocated is an **extraction fault**. Members keep all received (s_ij, s′_ij) until the barrier and any R6 complete.
7. **R6 reconstruct.** If any QUAL dealer has an extraction fault or a valid R5 complaint, every member publishes its Pedersen-valid (s_ij, s′_ij) for each such dealer. Anyone interpolates f_i from t Pedersen-valid values and recomputes A_ik. The dealer **stays in QUAL**; its fixed contribution is recovered, never removed (the fixed contribution is retained). Under §3.0's budget there are always ≥ t honest values, so missing R6 messages from corrupt members can't stall it.
8. **Output.** s_j = Σ_{i∈QUAL} s_ij (with R3 replacements); A_k = Σ_{i∈QUAL} A_ik (with R6 recoveries); mpk = A_0; pk_j = Σ_k j^k·A_k. Reject if mpk, A_{t−1} or any pk_j is the identity. Transcript hash = TH(`…TRANSCRIPT`, the ordered closed rounds).

**Determinism rules** (members and `dkg_verify_transcript` apply the same ones):
- A message counts only if it is in the closed round, signed by an authorized member of this ceremony, and decodes.
- Byte-identical retransmissions are deduplicated, no fault.
- Two different messages from one sender in one round: in R1–R3 the sender is disqualified (QUAL is not fixed yet); in R4 it is an extraction fault (reconstruction, not removal); in R5/R6 that sender's messages for the round are ignored.
- Complaints are counted per distinct authorized complainer; self-complaints are ignored.
- Missing R3 answer → disqualified; missing R4 → extraction fault; missing R5 → treated as an empty complaint list; missing R6 → that member contributes no values.
- If any round closes without the messages needed under the budget (for example fewer than t Pedersen-valid R6 values), the ceremony aborts with a typed error; it never returns a partial key.

### 3.8 Resharing (Desmedt–Jajodia redistribution, Feldman verification after Wong–Wang–Wing, refresh per Herzberg et al.; normative; implemented in S0.4)

0. **Authorization before any secret leaves a dealer (also applies to genesis).** An old member deals only under an `AuthorizedCeremony`: an owner-signed ceremony statement, checked through the verifier against the `TrustAnchor`, over: kind (genesis / reshare / refresh / re-key), a fresh 32-byte ceremony id, network, owner, the **current certificate digest** (reshare, refresh, re-key), the new threshold t′ and n′, the new key generation, and the recipient directory: index → (node DID, **ceremony-scoped HPKE public key**). The current certificate must be the `VerifiedCertificate` the node treats as current, and the statement's certificate digest must equal it. Recipient keys come only from this statement, never from the old certificate. The owner's device signs it under the existing membership approval (no extra prompt; the carrier is Q10).
   - A dealer deals at most once per ceremony id. A retry is a new ceremony id with fresh randomness; a dealing is bound to its context and is never re-sent to a changed recipient or index map. Persisting a "dealt for ceremony X" marker across crashes is an integration duty (§12).
   - Dealers release sub-shares only to the authorized directory. The holder of t shares can reconstruct the scalar.
1. **R1 deal.** Old member i picks g_i of degree t′−1 with g_i(0) = s_i; publishes B_ik = b_ik·g2 with exactly t′ entries; seals g_i(j) to each new member j. Public checks: B_i0 = pk_i of the current key context; length = t′; B_i,t′−1 ≠ identity.
2. **R2 complain / R3 answer**, as §3.7 steps 2–3 (Feldman check g_i(j)·g2 = Σ_k j^k·B_ik); answers are secret-bearing and also require the `AuthorizedCeremony`.
3. **Dealers D** = the first t old members in closed-round order whose R1 passed the public checks and that have no upheld complaint. Abort if fewer than t; the old epoch stays active.
4. **Output (a candidate).** s′_j = Σ_{i∈D} λ_i^D·g_i(j); B′_k = Σ_{i∈D} λ_i^D·B_ik; require B′_0 = mpk and B′_{t′−1} ≠ identity; pk′_j = Σ_k j^k·B′_k. The new shares belong to a **candidate** key context (epoch + 1) and are not usable until activation (§3.12).
5. An epoch tag doesn't erase anything: old shares keep working with the old certificate until their secrets are actually unrecoverable (§3.11).
6. A fresh genesis-style DKG under kind `re-key` is the only way to change mpk.

### 3.9 Network certificate, trust anchor and fault proofs (normative; implemented in S0.2)

**Body:** format version; network URN; owner DID; re-key counter; epoch; genesis t (t of the DKG that created this mpk); t; n; members [(index, node DID)] (no long-term HPKE keys); mpk; commitment vector (exactly t entries); transcript hash; previous certificate digest (absent only at genesis); previous mpk (present only on a re-key). Certificate digest = TH(`…NETWORK-CERT`, body). The owner signs TH(`…CERT-STATEMENT`, certificate digest).

**`verify_certificate(anchor, signed, verifier)` → `VerifiedCertificate`:**
- owner DID = `anchor.expected_owner` and network = `anchor.network` (an otherwise valid self-signed certificate naming another owner is rejected);
- the owner signature verifies through the injected verifier (principle 2's allow-list lives behind it, in tinycloud-auth);
- validation of the **decoded** object, not just of constructors: 2 ≤ t ≤ n ≤ 16; genesis t ≥ 2; indices 1..=n, distinct, sorted; member DIDs distinct (no weighted membership); commitments length t; commitment[0] = mpk; commitment[t−1] ≠ identity; every evaluated public share valid and non-identity; field combinations: genesis ⇒ no previous digest, no previous mpk, epoch 0, re-key counter 0, genesis t = t and n ≥ 2t−1 (§3.0 genesis budget); reshare successor ⇒ previous digest, no previous mpk; re-key ⇒ previous digest and previous mpk, previous mpk ≠ mpk and re-key counter ≥ 1; every successor (previous digest present) ⇒ epoch ≥ 1 and re-key counter ≤ epoch.

**`verify_successor(pinned: &VerifiedCertificate, next, verifier)`:** same owner and network (re-checked against the anchor); next.previous digest = pinned digest; epoch = pinned + 1 (checked); and either (reshare/refresh) the same mpk, re-key counter and genesis t, or (re-key) re-key counter + 1, previous mpk = pinned mpk, new mpk, genesis t = new t. Rollback and alternate lineages are rejected relative to the pinned certificate; which certificate is pinned as current comes from the trusted log head (gate B), not from the crate.

`VerifiedCertificate::key_context()` yields the `KeyContext`; `KeyShare::bind(candidate, &VerifiedCertificate)` checks s_i·g2 equals the certificate's pk_i and the transcript hash matches.

**Fault proof** = (request, share, response signature, the share's certificate). Order of checks: (1) the certificate is a `VerifiedCertificate` under the anchor; (2) request and share context = that certificate's context, and the member is in it; (3) the member's signature over the §3.6 preimage verifies; (4) §3.6 Verify fails. Only then is it a fault proof naming the member. Any failure in (1)–(3) returns `NotAFault(reason)`. A genuine old response replayed against a re-keyed or different certificate therefore never accuses its signer.

### 3.10 Sealed dealings and ceremony-scoped recipient keys (implemented in S0.3)

- HPKE (RFC 9180) base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305, composed from rust-hpke (no hand-written HPKE). One-shot contexts; fresh encapsulation randomness per dealing; invalid or all-zero X25519 results rejected as RFC 9180 requires.
- `info` = §3.3 tag ‖ authorized-ceremony digest ‖ round ‖ sender index ‖ recipient index; AAD = commitment-vector hash. Base mode has no sender authentication; the member signature on the closed-round message authenticates the envelope.
- **Recipient keys are ceremony-scoped.** Each recipient generates a fresh X25519 key pair for each ceremony, independently random (never derived from a node root or any retained secret), and its public key is bound into the `AuthorizedCeremony` directory. Long-lived node encryption keys are never used for dealings.

### 3.11 Erasure inventory and lifecycle (contract fixed now; durable storage is integration)

Secrets that must become unrecoverable, and when:

| Secret | Erase when |
|---|---|
| Ceremony HPKE recipient secret key | After the member's new share is durably installed and the ceremony is closed (after R6, or after the reshare candidate is installed), or on abort |
| Dealer polynomial coefficients a_ik, blinding coefficients b_ik, reshare g_i | After the last round in which the dealer may need to answer (closed R3; for genesis, after the R5 barrier and any R6), or on abort |
| Received private values s_ij, s′_ij, g_i(j), and decrypted plaintext buffers | After the member's share is computed and the R5 barrier and any R6 are complete |
| RNG seed or state from which any of the above can be regenerated | Same time as the secrets it generated |
| Crash-recovery copies of ceremony state | Same time as the in-memory originals; they live only on the gate-A volume |
| Old-epoch share s_i | At retirement (§3.12), never earlier |
| σ, ρ, candidate plaintext, tsk, k, combine intermediates | Before the function returns, on success and error paths |

Public ciphertext transcripts may be kept once the matching recipient keys are unrecoverable. In memory the crate zeroizes on drop and avoids hidden copies (blst `Copy` types are wiped explicitly where they hold secrets); `ZeroizeOnDrop` is an in-memory operation; durable storage is handled by integration. Durable erasure, snapshots, swap and core dumps are gate A's acceptance (§12).

The `seal` module's lifecycle behavior covers only accessible owned storage. `CeremonyHpkeSecretKey` clears its owned 32-byte array on explicit zeroization or drop. Internal plaintext/candidate buffers use `Zeroizing`, including error paths; a successful seal transfers ciphertext out of that buffer. Opened plaintext is returned in `Zeroizing<Vec<u8>>`. The borrowed sealing input belongs to the caller and is not cleared by the module.

HPKE 0.12's `PrivateKey`, `AeadCtxS` and `AeadCtxR` are opaque dependency-managed values. This owned-buffer description makes no claim about zeroization of their internal storage.

### 3.12 Activation boundary (contract fixed now; durable state record is integration)

An owner signature on a new certificate is **not** an erasure trigger. Transition states:

1. **Prepared.** New holders validate their shares, bind them to the candidate certificate (`KeyShare::bind`), install them durably, and each sends a **readiness receipt**: node-signed TH(`…READY`, candidate certificate digest ‖ transcript hash ‖ u16be(index) ‖ pk′_index). A receipt is the node's signed statement of durable installation.
2. **Activated.** The owner signs an activation statement TH(`…ACTIVATE`, candidate certificate digest ‖ sorted receipt hashes) only when receipts reach the **ready quorum**: by default **every** new holder (n′). A lower quorum t′ + o is allowed only for an explicitly declared total unavailable-ready-holder budget o (including dishonest or unavailable signers); t′ alone is never enough. For the 2-of-3 any-one-node-failure claim, all three must be ready. The node records activation in a durable, monotonic state record.
3. **Retired.** Only after activation do old holders erase old-epoch shares and their ceremony secrets.

Abort at any point before activation leaves the old epoch fully usable. A restart must not restore a retired epoch or reuse an old ceremony's randomness. The crate provides the receipt and activation preimages and `verify_activation(candidate, receipts, quorum, verifier)`; persistence, the state record and fault injection belong to gate A and TC-2226.


## S0.1 byte layouts and approved §3.6 amendment

**Deliberate amendment to §3.6:** encrypted shares carry the request digest, also included explicitly in the response signing preimage, so identity/tpk transplants return `ContextMismatch` before algebra; required by S6 test `request_transplants_fail_before_algebra`.

All integer fields below are big-endian. `lp` is u32 length followed by bytes.

- Key-context digest body: `01 || lp(network) || rekey:u64 || epoch:u64 || certificate:32 || t:u16 || n:u16`.
- Request: `01 || context_digest:32 || lp(network) || rekey:u64 || epoch:u64 || certificate:32 || lp(identity) || tpk:48`.
- Encrypted share: `01 || member:u16 || context_digest:32 || request_digest:32 || c1:48 || c2:96 || c3:48`.
- Share signing preimage: `TH(DECRYPT_SHARE, request_digest || certificate_digest || member:u16 || encode(share))`. The share request digest must equal the supplied request digest.
- IBE ciphertext: the fixed-width `U:96 || V:32 || W:32` FullIdent tuple (160 bytes); no additional structure header.
- No S0.1 public decoder consumes a member list; lists introduced in later slices use the §3.2 sorted/count rules.
- An availability budget counts all unavailable ready signers, including dishonest claims: `q - b >= t′`. All four ready holders in 3-of-4 support one unavailable holder, not two. `WithOutageBudget(0)` is not accepted.

## Implemented surface through S0.4

S0.1 implements §§3.1–3.6 and the typed parameters in §3.0. S0.2 adds the authenticated-context boundaries in §3.0, the certificate and fault-proof APIs in §3.9, and the receipt/activation verification in §3.12:

- `TrustAnchor` and the injected `DidSignatureVerifier` establish the owner/network and signature inputs.
- `AuthorizedCeremony` verifies owner-authorized genesis and successor statements. `ClosedRound<M>` verifies the signed member envelopes, owner closure, ordered-message commitment and previous transcript hash.
- `verify_certificate` validates decoded certificate fields and the external anchor. `verify_successor` checks a pinned predecessor and generation/lineage fields.
- `VerifiedCertificate` supplies `KeyContext` and `PublicKeySet`; `KeyShare::bind` checks a candidate's transcript, member index and scalar against that certificate's public share. Candidate scalar construction remains crate-private.
- Fault verification checks certificate context, request/share binding and the member signature before classifying a failed share equation.
- Readiness and activation APIs construct the defined preimages and verify every supplied receipt signature before quorum evaluation, receipt hashing or sorting.

S0.3 adds the §3.10 sealed dealings with ceremony-scoped recipient keys and the §3.7 genesis DKG: consume-self member states over owner-closed rounds R1–R6, and `dkg_verify_transcript`, which recomputes the outcome from the raw signed round records. Its byte layouts and deterministic rules are in the S0.3 genesis DKG appendix below.

S0.4 adds the §3.8 redistribution for reshare and refresh: dealer and recipient consume-self states over owner-closed rounds R1–R3, and `reshare_verify_transcript`. The output is a candidate for the successor certificate. Its byte layouts and deterministic rules are in the S0.4 redistribution appendix below.

The dealer remains test-only. Durable storage/retirement and node-runtime integration are separate slices. The crate remains an unwired workspace member.

## Verifier conformance

Two verifiers of the same raw transcript or certificate conform when they agree on the **outcome**: accept or reject; QUAL (genesis) or D (redistribution); the final mpk, commitments and public shares; and which dealers are disqualified or excluded. These outcomes are normative. Typed error codes, reason codes and the order in which checks run (and so which code a multiply-defective input reports) are informative; an implementation may report a different code for an input it rejects, provided it rejects it.

## S0.2 canonical byte appendix

All integers below are unsigned big-endian. `lp(x)` is `len(x):u32 || x`; strings use exact UTF-8 without normalization. `option(x)` is `00` when absent or `01 || x` when present; other markers are rejected. Symbolic tag names refer to the literal domain strings in §3.3, and `TH` is defined in §3.2.

Directory indices are contiguous `1..=n`, strictly increasing, with distinct node DIDs within each directory. Thresholds satisfy `2 <= t <= n <= 16`. DIDs contain 1..=256 bytes; network URNs contain 1..=1024 bytes. Signatures are at most 512 bytes, each message at most 65536 bytes, and ordered round/transcript inputs at most 4194304 bytes. Decoding checks lengths before allocation and rejects trailing bytes. Point encodings and role rules remain those of §3.2.

### Owner-authorized ceremony

The canonical authorization body is:

```text
01 || kind:u8 || ceremony_id:32 || lp(network) || lp(owner)
   || option(current_certificate_digest:32)
   || t:u16 || n:u16 || rekey:u64 || epoch:u64 || count:u16
   || [(index:u16 || lp(node_DID) || ceremony_HPKE_public_key:32)]
```

Kinds are genesis `1`, reshare `2`, refresh `3`, and re-key `4`. The owner signs `TH(CEREMONY_AUTH, body)`; those same 32 bytes are the authorized-ceremony digest. The raw `SignedStatement.bytes` contains the canonical body, with its signature stored separately.

Genesis has no current certificate, zero counters and `n >= 2t-1`. A successor names the exact externally pinned certificate and uses checked `epoch+1`; re-key also uses checked `rekey+1` and the genesis parameter budget. Other successor kinds preserve the re-key counter. Owner and network match the supplied anchor.

### Member envelope and closed round

The canonical member envelope is:

```text
01 || authorized_ceremony_digest:32 || round:u8 || cohort:u8
   || index:u16 || lp(payload)
```

The member signs `TH(CEREMONY_MSG, exact envelope)`. Cohort `1` identifies authorized recipients; cohort `2` identifies current-certificate dealers. Resolve the index and DID only in the signed cohort, with no fallback. Genesis/re-key use recipients only. Reshare/refresh consumers apply the phase roles: R1/R3 old dealers and R2 new recipients. A member in both cohorts has distinct signed roles.

After validating the canonical outer envelope, ceremony/round/cohort/member and signature, a closed round retains the exact raw `SignedStatement` and the inner payload's `Result<M, Error>`. Authenticated malformed inner payloads, byte-identical retransmissions and distinct messages from one sender remain in owner order for later phase-specific handling.

The ordered message-list encoding and hash are:

```text
ordered_list = count:u16 || [lp(exact member envelope) || lp(member signature)]
ordered_message_list_hash = TH(TRANSCRIPT, ordered_list)
```

The list preserves owner order; it is not sorted by member. The canonical owner-closure body is:

```text
01 || authorized_ceremony_digest:32 || round:u8
   || ordered_message_list_hash:32 || previous_transcript_hash:32
```

The owner signs `TH(ROUND_CLOSE, exact closure body)`. Closure verification checks the supplied previous hash, ceremony, round and ordered-list commitment. The transcript update is:

```text
TH(TRANSCRIPT,
   previous_hash:32 || lp(exact closure body) || lp(owner closure signature))
```

The trusted owner-relay model in §3.0 applies.

### Certificate body and candidate binding

The canonical certificate body is:

```text
01 || lp(network) || lp(owner) || rekey:u64 || epoch:u64
   || genesis_t:u16 || t:u16 || n:u16 || member_count:u16
   || [(index:u16 || lp(node_DID))]
   || mpk:96 || commitment_count:u16
   || [commitment:96 in ascending polynomial degree]
   || transcript_hash:32 || option(previous_certificate_digest:32)
   || option(previous_mpk:96)
```

The certificate digest is `TH(NETWORK_CERT, body)`. The owner signs `TH(CERT_STATEMENT, certificate_digest:32)`.

Certificates contain no HPKE keys. The commitment count equals `t`; the constant equals `mpk`; constant/top coefficients and evaluated public shares are non-identity. Genesis has absent predecessor fields, zero counters, `genesis_t = t` and `n >= 2t-1`. Any certificate with a previous digest has `epoch >= 1` and `rekey <= epoch`. A pinned successor has the exact previous digest and checked `epoch+1`. Reshare/refresh preserve `mpk`, `rekey` and `genesis_t`; re-key changes `mpk` (previous `mpk` ≠ `mpk`), names the previous `mpk`, has `rekey >= 1`, increments `rekey` and sets `genesis_t` to the new `t`.

Verification uses the caller's expected owner/network. The caller's authorization-log integration selects the current pinned certificate. Candidate binding checks transcript and member index, then `scalar*g2` against the certificate's evaluated public share.

### Signed response and fault classification

The S0.1 amended 259-byte share and signing body remain unchanged:

```text
share = 01 || member:u16 || context_digest:32 || request_digest:32
           || c1:48 || c2:96 || c3:48
preimage = TH(DECRYPT_SHARE,
              request_digest:32 || certificate_digest:32 || member:u16 || encode(share))
```

`EncryptedKeyShare::signing_preimage` returns `Result<Vec<u8>, Error>` and requires equality between the stored and supplied request digests before computing the signing hash. A mismatch returns `ContextMismatch`. Fault verification maps certificate-context, binding/helper or signature failures to `NotAFault` before algebra; only a correctly bound, member-signed response that fails a share equation yields `Fault(member)`.

### Readiness receipts and activation

The readiness signing preimage is:

```text
TH(READY,
   candidate_certificate_digest:32 || transcript_hash:32
   || index:u16 || candidate_public_share:96)
```

The canonical signed receipt and its hash are:

```text
receipt = 01 || index:u16 || lp(signature)
receipt_hash = TH(READY, exact receipt encoding)
```

`verify_activation` rejects duplicate/nonmember indices and verifies **every** supplied node signature against the exact candidate/transcript/index/public-share readiness preimage before quorum evaluation, receipt hashing or sorting. Duplicate indices or repeated signatures add no vote.

Sort the resulting 32-byte receipt hashes in binary lexicographic order, independent of input order:

```text
activation.bytes = TH(ACTIVATE,
                      candidate_certificate_digest:32 || concatenated_sorted_receipt_hashes)
```

The owner signs exactly those 32 activation bytes. Unlike ceremony/closure statements, activation `SignedStatement.bytes` already contains the domain-separated signing preimage rather than a raw body.

The default quorum is all `n` holders. `WithOutageBudget(b)` requires `b > 0` and checked `q = t+b <= n`; at least `q` unique verified members must be ready. The budget includes all unavailable ready signers. Receipts are signed installation statements; durable storage, monotonic activation state and retirement remain integration operations.

## S0.3 genesis DKG appendix

This appendix records the byte layouts and deterministic rules that members and `dkg_verify_transcript` apply to §3.7. Integers are unsigned big-endian; `lp`, `TH`, point and scalar encodings are as in §3.2 and the S0.2 appendix. Rounds are numbered R1 = 1 through R6 = 6. Every DKG message uses the S0.2 member envelope with cohort `1` (authorized recipients); genesis has no dealer cohort.

### Initial link and transcript

```text
H0 = TH("TC-THRESHOLD-V1-DKG-START", authorized_ceremony_digest:32)
```

`dkg_initial_transcript(c)` returns `H0`. The tag is specific to this link and is not part of the §3.3 table; it is distinct from, and not a prefix of, every §3.3 tag. Closed R1 names `H0` as its previous hash; each later round names the S0.2 transcript update of the round before it. The DKG transcript hash is the transcript update after closed R5, or after closed R6 when R6 is required.

Each member transition first requires the closed round's authorized-ceremony digest, round number and previous hash to equal the values the consuming state holds; otherwise it returns `InvalidRound` before reading any message.

`DkgTranscript` is the list of raw round records: the exact owner closure (body and signature) and the exact member statements in owner order. `dkg_verify_transcript` first sums the byte lengths of every closure body, closure signature, member envelope and member signature and returns `LimitExceeded` above 4194304 bytes, before any signature check. It then verifies R1–R5 as closed rounds, verifies R6 exactly when the R5 rules require it, and rejects missing or additional records with `InvalidRound`. It derives the outcome from the authenticated records only.

### Pedersen generator and dealing context

`h = hash_to_curve_G2("pedersen-h", PEDERSEN_H DST)` as in §3.3. The commitment-vector hash used as HPKE AAD is:

```text
TH(COMMITMENTS, t:u16 || C_0:96 || … || C_(t−1):96)
```

HPKE `info` is `DEALING || authorized_ceremony_digest:32 || 01 || dealer:u16 || recipient:u16`. The sealed plaintext is exactly `s_ij:32 || s′_ij:32`, both canonical scalars.

Dealers draw randomness in this order: the t coefficients of f_i (constant first), then the t coefficients of f′_i, each as 64 bytes reduced mod r and redrawn if zero; then one HPKE encapsulation per recipient in index order.

### Payloads

```text
R1 deal         = 01 || t:u16 || [C_k:96]  || n:u16 || [(recipient:u16 || lp(sealed_dealing))]
R2 complaints   = 01 || count:u16 || [dealer:u16]
R3 answers      = 01 || count:u16 || [(recipient:u16 || s:32 || s′:32)]
R4 feldman      = 01 || t:u16 || [A_k:96]
R5 extraction   = 01 || count:u16 || [(dealer:u16 || s:32 || s′:32)]
R6 values       = 01 || count:u16 || [(dealer:u16 || s:32 || s′:32)]
```

`sealed_dealing` is the §3.10 envelope `01 || enc:32 || lp(ciphertext)`; the ciphertext is at least 16 bytes (the AEAD tag), and a shorter one makes that R1 malformed. Every count is at most 16 and is checked before allocation; index lists are strictly increasing member indices 1..=16; point coefficients are canonical G2 encodings and individual coefficients may be the identity (§3.2 role table); scalars are canonical. Trailing bytes and other versions are rejected. A payload that fails this decoding is *malformed*.

### Classifying a round

Within a closed round, authenticated messages are grouped by sender. Messages with byte-identical envelopes are one message regardless of their signature bytes. Two messages from one sender with different envelope bytes are *conflicting*; this compares the signed content, including malformed payloads. A sender with no message is *missing*.

### R1–R3 and QUAL

For each member index i, in this order, the first applicable reason disqualifies dealer i:

1. `MissingDeal`: no R1 from i.
2. `Equivocated { round: 1 }`: conflicting R1.
3. `MalformedDeal`: R1 is malformed, has a commitment count other than t, or its recipient list is not exactly 1..=n.
4. `Equivocated { round: 2 }`: conflicting R2 from i.
5. `Equivocated { round: 3 }`: conflicting R3 from i.
6. `Complaints`: at least t distinct complainers counted against i (below).
7. `InvalidAnswer`: i's decoded R3 contains any answer that fails `s·g2 + s′·h = Σ_k j^k·C_ik` at its recipient j, whether or not that answer was required.
8. `MissingAnswer`: a required answer is absent: i's R3 is missing or malformed, or omits a required recipient.

R2 counting: a complaint by j against i counts once per distinct j, only from a non-conflicting, decodable R2 whose dealer indices are all at most n, and never when j = i. A malformed R2 supplies no complaints; a conflicting R2 supplies no complaints and disqualifies its sender as a dealer under rule 4. The required answers for dealer i are exactly the counted complainers against i.

R3 rules: an R3 is used only if it decodes and all recipient indices are at most n; otherwise it is malformed. A missing or malformed R3 disqualifies i only when i has required answers. A valid answer that was not required is ignored and creates no complaint. A valid required answer replaces the complainer's private pair from i.

QUAL is every dealer not disqualified, fixed after closed R3. If |QUAL| < t the ceremony returns `InsufficientQualified`. A member that lacks a Pedersen-valid pair from some QUAL dealer after R3 returns `LocalShareUnavailable`; this only arises when a member's own complaint is absent from closed R2.

Members complain in R2 about every dealer whose valid R1 dealing to them fails to open, decode or satisfy the Pedersen relation. A dealer answers in R3 every counted complaint against it when its own R1 was accepted. Every member sends R2 and R3, possibly empty.

### R4–R6 and output

For each i in QUAL, an *extraction fault* is a missing, conflicting or malformed R4, or an R4 whose coefficient count is not t. R4 from a sender outside QUAL is ignored.

Every member sends R5, possibly empty, listing each other QUAL dealer i whose valid R4 fails `s_ij·g2 = Σ_k j^k·A_ik` for its own pair. An R5 entry by sender j against dealer i is *upheld* when i ≠ j, i is in QUAL without an extraction fault, the pair satisfies the Pedersen relation for C_i at j, and the Feldman relation for A_i at j fails. Other entries are ignored. Missing, malformed and conflicting R5 messages count as empty lists. No member finishes before consuming closed R5.

The *reconstructed* set is the extraction faults plus every dealer with an upheld R5 entry. If it is empty the ceremony finishes after R5. Otherwise every member sends R6 with its Pedersen-valid pair for each reconstructed dealer, and the ceremony finishes after R6. For each reconstructed dealer i, the values used are those from non-conflicting, decodable R6 messages whose entry for i satisfies the Pedersen relation at the sender index; the t lowest sender indices are interpolated to the coefficients of f_i, and A_ik = a_ik·g2 replaces i's published vector. Dealer i stays in QUAL. Fewer than t such values return `InsufficientRecovery`. Missing, malformed and conflicting R6 messages contribute no values.

Output: A_k = Σ_{i∈QUAL} A_ik; mpk = A_0; pk_j = Σ_k j^k·A_k; identity mpk, A_(t−1) or pk_j is rejected (§3.2). The member's candidate scalar is Σ_{i∈QUAL} s_ij using R3 replacements. `DkgOutput` carries the public material, QUAL, the disqualification reasons, the reconstructed set and the transcript hash.

### Scope

Agreement among members and the verifier relies on the §3.0 owner relay closing each round once and delivering every conforming member's message. Round equivocation compares conflicting authenticated message content from the same sender; a different signature encoding alone is not equivocation. A relay that omits or substitutes messages produces the failure outcomes above, not agreement; the protocol does not implement reliable broadcast.

### In-memory lifecycle

`CeremonyHpkeSecretKey` is dropped when R1 has been processed. Polynomial coefficients are dropped when R4 has been produced. Received private pairs remain in the state until the member finishes after R5 or R6. States are consumed by each transition, so an error drops the state; scalars clear their storage on drop and states have redacted `Debug`. The caller's RNG state and any durable copies are outside this crate (§3.11).

## S0.4 redistribution appendix

This appendix records the byte layouts and deterministic rules that members and `reshare_verify_transcript` apply to §3.8 for ceremony kinds reshare (`2`) and refresh (`3`). Integers are unsigned big-endian; `lp`, `TH`, point and scalar encodings are as in §3.2 and the S0.2 appendix. Rounds are numbered R1 = 1 through R3 = 3. Dealers are the members of the pinned current certificate (cohort `2`); recipients are the authorized directory (cohort `1`). R1 and R3 count only cohort-`2` envelopes and R2 counts only cohort-`1` envelopes; an authenticated envelope under the other cohort is ignored for that round and attributes nothing to either role. A node in both cohorts signs each role separately.

### Authorization and refresh

Every entry point (`reshare_deal`, `reshare_start_receiver`, `reshare_verify_transcript`) first requires an `AuthorizedCeremony` of kind reshare or refresh (`InvalidCeremony` otherwise) authorized against the pinned current certificate: its current-certificate digest must be present and equal the supplied `VerifiedCertificate` (`InvalidCeremony` otherwise, for a stale or absent digest). Refresh additionally requires t′ = t, n′ = n and a directory whose index→DID map equals the current certificate's members (`InvalidCeremony` otherwise). A dealer's `KeyShare` must carry the current certificate's key context (`ContextMismatch`). A recipient's ceremony key must derive the directory key at its index (`ContextMismatch`; unknown index `InvalidIndex`). These checks precede any randomness, opening or emitted message.

### Initial link and transcript

```text
H0 = TH("TC-THRESHOLD-V1-RESHARE-START", authorized_ceremony_digest:32)
```

`reshare_initial_transcript(c)` returns `H0` for both reshare and refresh; the authorized-ceremony digest binds the kind. The label is distinct from, and not a prefix of, every §3.3 tag and the DKG start label. Closed R1 names `H0`; R2 and R3 name the S0.2 transcript update of the preceding round. The redistribution transcript hash is the update after closed R3. Each transition checks the closed round's ceremony digest, round number and previous hash before reading any message (`InvalidRound`).

`ReshareTranscript` holds exactly three raw round records. `reshare_verify_transcript` sums every closure and member byte length and signature length first and returns `LimitExceeded` above 4194304 bytes before any signature check; missing or additional records return `InvalidRound`.

### Dealing

Dealer i samples g_i of degree t′−1 with g_i(0) = s_i and coefficients 1..t′−1 drawn in order as 64 bytes reduced mod r, redrawn if zero; then one HPKE encapsulation per recipient in index order. It publishes B_ik = b_ik·g2 for k = 0..t′−1.

```text
R1 deal       = 01 || t′:u16 || [B_k:96] || n′:u16 || [(recipient:u16 || lp(sealed_dealing))]
R2 complaints = 01 || count:u16 || [dealer:u16]
R3 answers    = 01 || count:u16 || [(recipient:u16 || value:32)]
```

R1 and R2 reuse the genesis R1/R2 layouts. HPKE `info` is `DEALING || authorized_ceremony_digest:32 || 01 || dealer:u16 || recipient:u16`; AAD is `TH(COMMITMENTS, t′:u16 || B_0 || … || B_(t′−1))`; the sealed plaintext is exactly the canonical scalar g_i(j):32. Counts are at most 16 and checked before allocation; index lists are strictly increasing; trailing bytes and other versions are rejected. A payload that fails decoding is *malformed*. Messages with byte-identical envelopes are one message; different envelopes from one sender in one round are *conflicting*.

### Exclusion and dealer selection

R1 *public checks* for dealer i: a single non-conflicting decodable R1, exactly t′ coefficients, B_i0 = pk_i of the current certificate, B_i,t′−1 ≠ identity, and recipient entries exactly 1..=n′.

A complaint by recipient j against dealer i counts once per distinct j, only from a non-conflicting, decodable R2 whose dealer indices are all at most n. Malformed and conflicting R2 supply no complaints and have no effect on the sender's dealer role. Required answers for i are its counted complainers.

An R3 is used only if it is non-conflicting, decodes and names recipients at most n′; otherwise it is malformed. For each dealer i, the first applicable reason excludes it:

1. `MissingDeal`: no R1 from i.
2. `Equivocated { round: 1 }`: conflicting R1.
3. `MalformedDeal`: R1 fails the public checks.
4. `Equivocated { round: 3 }`: conflicting R3.
5. `Complaints`: at least t′ distinct counted complainers.
6. `InvalidAnswer`: any answer in i's decoded R3 fails g·g2 = Σ_k j^k·B_ik at its recipient j, required or not.
7. `MissingAnswer`: a required answer is absent (R3 missing, malformed, or omitting a complainer).

A valid answer that was not required is ignored. A valid required answer replaces the complainer's value from i. D is the first t dealers, in order of each dealer's first R1 message in the owner's closed list, that are not excluded; fewer than t return `InsufficientQualified` and the current epoch stays in force.

A dealer answers in R3 only when its R1 passes the public checks and carries its own commitment vector, and it has fewer than t′ counted complainers; with t′ or more it publishes an empty answer list, so it never publishes t′ points of g_i. Every dealer sends R3 and every recipient sends R2, possibly empty.

### Output

λ_i = λ_i^D over the old indices in D. B′_k = Σ_{i∈D} λ_i·B_ik; B′_0 must equal the current mpk and B′_(t′−1) and every pk′_j must be non-identity. Recipient j's candidate scalar is Σ_{i∈D} λ_i·g_i(j) with R3 replacements; a recipient without a valid value from some dealer in D returns `LocalShareUnavailable`, which only arises when its own complaint is absent from closed R2. `ReshareOutput` carries the public material, D in selection order, the exclusion reasons and the transcript hash. The candidate belongs to the successor certificate (`CertificateBody::successor`, epoch + 1) and is usable only after `KeyShare::bind`.

### Scope

Completion requires the §3.0 owner relay to close each round once and deliver every conforming member's message, and at least t old dealers that pass the rules above. Faulty old dealers within the secrecy budget can still leave fewer than t valid dealers; the ceremony then refuses with `InsufficientQualified`. Completion also does not hold if a selected dealer can read other dealers' R1 before its own R1 is closed and acts with a new member: it can then choose a dealing that passes every check but makes a new public share the identity, and every recipient and the verifier refuse with `IdentityPoint` without attributing a dealer; this affects completion only, and the current epoch stays in force. The protocol does not implement reliable broadcast. Redistribution does not erase anything: old shares remain valid for the old certificate until integration erases them (§3.11, §3.12); old and new shares carry different key contexts and are refused together by `verify_share` and `combine`.

### In-memory lifecycle

`ReshareDealer` holds g_i until `answer` consumes it. `ReshareReceiving` holds the ceremony recipient key until `complain` consumes it; `ReshareComplained` holds the opened values until `finish` consumes it. Scalars clear their storage on drop and every state has redacted `Debug`. The dealer's `KeyShare`, the caller's RNG state and any durable copies are outside this crate (§3.11).
