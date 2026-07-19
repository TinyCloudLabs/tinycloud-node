# Email-claim N4 Share manifest adapter

This Node lane intentionally consumes a narrow, operator-authenticated
authority-material record. It does not derive authority from a Share object,
request fields, or a pre-seeded positive database row.

After the concurrent Share lane commits its manifest amendment, update only
the adapter boundary in `tinycloud-core/src/share_email/authority.rs` and the
fixture wiring. The final manifest must provide, inside the signed authority
material preimage:

- the exact existing #117 `policyAuthority` and `policyEnforcement` signed
  bytes, including their EIP-191 signatures;
- the raw/BLAKE3-256 CID strings for those exact bytes and an explicit
  `sharePolicyCid`/`shareDelegationCid` mapping;
- a validated `amh_*` handle and the SHA-256 digest of the exact signed
  authority-material JCS bytes;
- one independently signed status observation per parent, with parent CID,
  sequence, checked/fresh timestamps, state, and irreversible revocation;
- the signed enrollment and attestation records, including their trust-anchor
  material and the local configured root signer binding.

The adapter must preserve exact bytes and signatures while translating only
the Share-ID mapping into `AuthorityMaterialBundle`. It must not copy the
manifest's policy capabilities into #117 authority or accept a second profile.
When the manifest shape changes, add a production mounted test using
`tinycloud-core/src/policy_authority/contract_accepted.json` and the real
signing helpers, then update the strict DTO/preimage fixtures if and only if
the committed Share contract requires it. Do not copy uncommitted files from
the sibling worktree.
