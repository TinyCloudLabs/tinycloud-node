//! Real-ceremony chain: genesis, redistribution, refresh and re-key with owner
//! certificates, readiness receipts and activation at every generation, plus the
//! frozen chain vectors and the re-key authorization tests. Details: TC-2223
//!
//! Every ceremony here runs the production member states over a signing owner
//! relay (`dkg_relay`, `reshare_relay`); no test dealer supplies a key. The
//! chain keeps each retired generation's shares only to prove the new
//! generation refuses them. Nothing here claims old shares are erased.

use std::collections::BTreeMap;

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde_json::{json, Value};

use crate::{
    activation::{
        activation_preimage, readiness_preimage, verify_activation, ReadinessReceipt, ReadyQuorum,
    },
    ceremony::{
        tests::Signers, AuthorizedCeremony, CeremonyKind, CeremonyStatement, SignedStatement,
    },
    cert::{
        verify_certificate, verify_successor, CandidateShare, CertificateBody, SignedCertificate,
        VerifiedCertificate,
    },
    checkpoint::{authorize, identity},
    curve::Scalar,
    derive::{
        combine, decrypt_derived_key, issue_share, verify_share, DecryptRequest, EncryptedKeyShare,
        KeyShare, TransportSecretKey,
    },
    dkg::{dkg_initial_transcript, dkg_start, dkg_verify_transcript, DkgOutput, DkgRoundRecord},
    dkg_relay,
    error::{CombineError, Error, ShareError},
    ibe::{unwrap_key, IbeCiphertext},
    ids::*,
    reshare::{
        reshare_initial_transcript, reshare_verify_transcript, ReshareOutput, ReshareTranscript,
    },
    reshare_relay,
};

fn idx(i: u16) -> MemberIndex {
    MemberIndex::new(i).unwrap()
}

/// One ceremony of the chain.
#[derive(Clone, Copy, Debug)]
enum Step {
    Reshare(u16, u16, u8),
    Refresh(u16, u16, u8),
    Rekey(u16, u16, u8),
}

/// Everything a verifier needs for one activated generation.
#[derive(Clone)]
struct Generation {
    kind: CeremonyKind,
    statement: SignedStatement,
    ceremony_digest: [u8; 32],
    initial_transcript: TranscriptHash,
    rounds: Vec<DkgRoundRecord>,
    certificate: SignedCertificate,
    verified: VerifiedCertificate,
    receipts: Vec<ReadinessReceipt>,
    activation: SignedStatement,
}

/// A data key wrapped under one master key.
struct Wrapped {
    rekey: u64,
    path: String,
    data: [u8; 32],
    ciphertext: IbeCiphertext,
}

struct Chain {
    signers: Signers,
    generations: Vec<Generation>,
    shares: BTreeMap<u16, KeyShare>,
    wrapped: Vec<Wrapped>,
}

/// The steps both the chain test and the frozen vectors run.
const STEPS: [Step; 7] = [
    Step::Reshare(3, 4, 0xd2),
    Step::Reshare(2, 3, 0xd3),
    Step::Refresh(2, 3, 0xd4),
    Step::Rekey(3, 4, 0xd5),
    Step::Reshare(2, 3, 0xd6),
    Step::Rekey(2, 3, 0xd7),
    Step::Reshare(3, 4, 0xd8),
];

fn all(n: u16) -> Vec<u16> {
    (1..=n).collect()
}

fn signed_pair(body: &CertificateBody, signers: &Signers) -> SignedCertificate {
    crate::cert::tests::sign(body.clone(), signers)
}

fn receipts_for(
    cert: &VerifiedCertificate,
    signers: &Signers,
    members: &[u16],
) -> Vec<ReadinessReceipt> {
    members
        .iter()
        .map(|i| ReadinessReceipt {
            index: idx(*i),
            signature: signers.sign(
                &Signers::did(*i as u8),
                &readiness_preimage(cert.body(), idx(*i)).unwrap(),
            ),
        })
        .collect()
}

fn activation_for(
    cert: &VerifiedCertificate,
    receipts: &[ReadinessReceipt],
    signers: &Signers,
) -> SignedStatement {
    let bytes = activation_preimage(cert.body(), receipts).unwrap();
    SignedStatement {
        signature: signers.sign(&cert.anchor().expected_owner, &bytes),
        bytes,
    }
}

/// Derive the record key under `cert` from the t lowest shares.
fn derive(
    cert: &VerifiedCertificate,
    shares: &BTreeMap<u16, KeyShare>,
    path: &str,
    seed: u8,
) -> (DecryptRequest, crate::derive::DerivedKey) {
    let context = cert.key_context();
    let t = usize::from(context.threshold().t());
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    let tsk = TransportSecretKey::generate(&mut rng);
    let req = DecryptRequest::new(&context, identity(&context, path), tsk.public_key()).unwrap();
    let auth = authorize(req.clone());
    let issued: Vec<EncryptedKeyShare> = shares
        .values()
        .take(t)
        .map(|s| issue_share(s, &auth, &mut rng).unwrap())
        .collect();
    let aggregate = combine(cert.public_key_set(), &req, &issued).unwrap();
    let key = decrypt_derived_key(&aggregate, &tsk, cert.public_key_set(), &req).unwrap();
    (req, key)
}

/// The retired generation's shares are refused in the new context everywhere
/// a share can enter: issuing, verifying, combining and binding.
fn old_context_refused(
    old: &VerifiedCertificate,
    old_shares: &BTreeMap<u16, KeyShare>,
    new: &VerifiedCertificate,
    new_shares: &BTreeMap<u16, KeyShare>,
    seed: u8,
) {
    let (old_context, new_context) = (old.key_context(), new.key_context());
    assert_ne!(old_context.digest(), new_context.digest());
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    let tsk = TransportSecretKey::generate(&mut rng);
    let request = |context: &crate::context::KeyContext| {
        DecryptRequest::new(
            context,
            identity(context, "records/refused"),
            tsk.public_key(),
        )
        .unwrap()
    };
    let (old_req, new_req) = (request(&old_context), request(&new_context));
    let old_issued = issue_share(&old_shares[&1], &authorize(old_req.clone()), &mut rng).unwrap();
    let new_issued: Vec<EncryptedKeyShare> = new_shares
        .values()
        .map(|s| issue_share(s, &authorize(new_req.clone()), &mut rng).unwrap())
        .collect();
    assert!(matches!(
        issue_share(&old_shares[&1], &authorize(new_req.clone()), &mut rng),
        Err(Error::ContextMismatch)
    ));
    assert_eq!(
        verify_share(new.public_key_set(), &new_req, &old_issued),
        Err(ShareError::ContextMismatch)
    );
    assert_eq!(
        verify_share(new.public_key_set(), &old_req, &old_issued),
        Err(ShareError::ContextMismatch)
    );
    assert!(matches!(
        combine(
            new.public_key_set(),
            &new_req,
            &[new_issued[0].clone(), old_issued.clone()]
        ),
        Err(CombineError::MixedContexts)
    ));
    assert!(matches!(
        combine(
            old.public_key_set(),
            &old_req,
            &[old_issued.clone(), new_issued[1].clone()]
        ),
        Err(CombineError::MixedContexts)
    ));
    let old_scalar = Scalar::from_bytes(&old_shares[&1].scalar.to_bytes()).unwrap();
    assert!(matches!(
        KeyShare::bind(
            CandidateShare::new(new.body().transcript_hash(), idx(1), old_scalar),
            new
        ),
        Err(Error::CandidateMismatch)
    ));
}

/// Owner activation: every holder ready, a lower declared quorum, and the
/// refusals that must not activate.
fn activation_rules(
    cert: &VerifiedCertificate,
    signers: &Signers,
    previous: Option<&VerifiedCertificate>,
) {
    let threshold = cert.key_context().threshold();
    let (t, n) = (threshold.t(), threshold.n());
    let receipts = receipts_for(cert, signers, &all(n));
    let activation = activation_for(cert, &receipts, signers);
    verify_activation(
        cert,
        &receipts,
        ReadyQuorum::AllHolders,
        &activation,
        signers,
    )
    .unwrap();

    // t′ alone never activates under the default quorum.
    let few = receipts_for(cert, signers, &all(t));
    let few_activation = activation_for(cert, &few, signers);
    assert_eq!(
        verify_activation(
            cert,
            &few,
            ReadyQuorum::AllHolders,
            &few_activation,
            signers
        ),
        Err(Error::NotEnoughReady)
    );
    // A declared outage budget raises the quorum above t′; it never lowers it.
    verify_activation(
        cert,
        &receipts,
        ReadyQuorum::WithOutageBudget(n - t),
        &activation,
        signers,
    )
    .unwrap();
    let outage = receipts_for(cert, signers, &all(n - 1));
    let outage_activation = activation_for(cert, &outage, signers);
    assert_eq!(
        verify_activation(
            cert,
            &outage,
            ReadyQuorum::AllHolders,
            &outage_activation,
            signers
        ),
        Err(Error::NotEnoughReady)
    );
    assert_eq!(
        verify_activation(
            cert,
            &outage,
            ReadyQuorum::WithOutageBudget(n - t),
            &outage_activation,
            signers
        ),
        Err(Error::NotEnoughReady)
    );
    assert_eq!(
        verify_activation(
            cert,
            &receipts,
            ReadyQuorum::WithOutageBudget(0),
            &activation,
            signers
        ),
        Err(Error::InvalidReadiness)
    );
    assert_eq!(
        verify_activation(
            cert,
            &receipts,
            ReadyQuorum::WithOutageBudget(n - t + 1),
            &activation,
            signers
        ),
        Err(Error::InvalidReadiness)
    );
    // An activation over another receipt set is not the owner's statement.
    assert_eq!(
        verify_activation(
            cert,
            &receipts,
            ReadyQuorum::AllHolders,
            &few_activation,
            signers
        ),
        Err(Error::InvalidReadiness)
    );
    // Owner approval is the owner's signature, not a member's.
    let mut forged = activation.clone();
    forged.signature = signers.sign(&Signers::did(1), &activation.bytes);
    assert_eq!(
        verify_activation(cert, &receipts, ReadyQuorum::AllHolders, &forged, signers),
        Err(Error::InvalidSignature)
    );
    // Receipts for the previous candidate do not carry over to this one.
    if let Some(previous) = previous {
        let pn = previous.key_context().threshold().n().min(n);
        let stale = receipts_for(previous, signers, &all(pn));
        let stale_activation = activation_for(cert, &stale, signers);
        assert_eq!(
            verify_activation(
                cert,
                &stale,
                ReadyQuorum::AllHolders,
                &stale_activation,
                signers
            ),
            Err(Error::InvalidSignature)
        );
    }
}

impl Chain {
    /// A real signed 2-of-3 DKG, its genesis certificate and activation.
    fn genesis(t: u16, n: u16, seed: u8) -> Self {
        let run = dkg_relay::honest(t, n, seed);
        let output = dkg_relay::agreed(&run, &all(n));
        let dkg_relay::Run {
            fixture,
            outcomes,
            transcript,
            ..
        } = run;
        let signers = fixture.signers;
        let anchor = signers.anchor();
        let body = CertificateBody::genesis(
            &anchor,
            &fixture.ceremony,
            &output.public,
            &output.transcript_hash,
        )
        .unwrap();
        let certificate = signed_pair(&body, &signers);
        let verified = verify_certificate(&anchor, &certificate, &signers).unwrap();
        let shares: BTreeMap<u16, KeyShare> = outcomes
            .into_iter()
            .map(|(i, o)| (i, KeyShare::bind(o.unwrap().0, &verified).unwrap()))
            .collect();
        activation_rules(&verified, &signers, None);
        let receipts = receipts_for(&verified, &signers, &all(n));
        let activation = activation_for(&verified, &receipts, &signers);
        let generation = Generation {
            kind: CeremonyKind::Genesis,
            statement: fixture.statement,
            ceremony_digest: fixture.ceremony.digest(),
            initial_transcript: dkg_initial_transcript(&fixture.ceremony),
            rounds: transcript.rounds,
            certificate,
            verified,
            receipts,
            activation,
        };
        let mut chain = Self {
            signers,
            generations: vec![generation],
            shares,
            wrapped: Vec::new(),
        };
        chain.wrap("records/genesis", seed);
        chain.records_behave(seed);
        chain
    }

    fn current(&self) -> &Generation {
        self.generations.last().unwrap()
    }

    /// Wrap a fixed data key to `path` under the current master key.
    fn wrap(&mut self, path: &str, seed: u8) {
        let cert = &self.current().verified;
        let (data, ciphertext) = reshare_relay::wrapped(cert, path, seed);
        self.wrapped.push(Wrapped {
            rekey: cert.key_context().rekey().get(),
            path: path.to_string(),
            data,
            ciphertext,
        });
    }

    /// Records under the current master key unwrap through every t-subset;
    /// records under an earlier master key do not.
    fn records_behave(&self, seed: u8) {
        let cert = &self.current().verified;
        let rekey = cert.key_context().rekey().get();
        let t = cert.key_context().threshold();
        for record in &self.wrapped {
            if record.rekey == rekey {
                assert_eq!(
                    reshare_relay::unwraps_through_every_subset(
                        cert,
                        &self.shares,
                        &record.path,
                        &record.data,
                        &record.ciphertext,
                        seed,
                    ),
                    subsets(t.t(), t.n())
                );
            } else {
                let (request, key) = derive(cert, &self.shares, &record.path, seed);
                assert!(matches!(
                    unwrap_key(&key, request.identity(), &record.ciphertext),
                    Err(Error::InvalidCiphertext)
                ));
            }
        }
    }

    /// Run one real ceremony from the current generation, install and activate
    /// its successor.
    fn step(&mut self, step: Step) {
        let current = self.current().verified.clone();
        let (kind, t, n, seed) = match step {
            Step::Reshare(t, n, seed) => (CeremonyKind::Reshare, t, n, seed),
            Step::Refresh(t, n, seed) => (CeremonyKind::Refresh, t, n, seed),
            Step::Rekey(t, n, seed) => (CeremonyKind::Rekey, t, n, seed),
        };
        let members = all(n);
        let old_shares = std::mem::take(&mut self.shares);
        let signers = &self.signers;
        let (ceremony, statement, rounds, public, transcript_hash, initial, candidates, retired) =
            if kind == CeremonyKind::Rekey {
                let fixture = dkg_relay::rekey_fixture_on(&current, t, n, seed);
                let run = dkg_relay::drive(fixture, signers, |_| {});
                let output = dkg_relay::agreed(&run, &members);
                assert!(output.disqualified.is_empty() && output.reconstructed.is_empty());
                let dkg_relay::Run {
                    fixture,
                    outcomes,
                    transcript,
                    ..
                } = run;
                let initial = dkg_initial_transcript(&fixture.ceremony);
                let candidates: BTreeMap<u16, CandidateShare> = outcomes
                    .into_iter()
                    .map(|(i, o)| (i, o.unwrap().0))
                    .collect();
                (
                    fixture.ceremony,
                    fixture.statement,
                    transcript.rounds,
                    output.public,
                    output.transcript_hash,
                    initial,
                    candidates,
                    old_shares,
                )
            } else {
                let dids: Vec<u8> = (1..=n as u8).collect();
                let fixture = reshare_relay::fixture_on(
                    current.clone(),
                    old_shares.into_values(),
                    kind,
                    t,
                    n,
                    seed,
                    &dids,
                );
                let run = reshare_relay::run_with(fixture, |_| {});
                let output = reshare_relay::agreed(&run, &members);
                assert!(output.excluded.is_empty());
                reshare_relay::public_shares_interpolate_to_mpk(&output.public);
                let reshare_relay::Run {
                    fixture,
                    outcomes,
                    transcript,
                    ..
                } = run;
                let initial = reshare_initial_transcript(&fixture.ceremony);
                let candidates: BTreeMap<u16, CandidateShare> = outcomes
                    .into_iter()
                    .map(|(i, o)| (i, o.unwrap().0))
                    .collect();
                (
                    fixture.ceremony,
                    fixture.statement,
                    transcript.rounds,
                    output.public,
                    output.transcript_hash,
                    initial,
                    candidates,
                    fixture.shares,
                )
            };

        let body =
            CertificateBody::successor(&current, &ceremony, &public, &transcript_hash).unwrap();
        let certificate = signed_pair(&body, signers);
        let verified = verify_successor(&current, &certificate, signers).unwrap();
        let mpk = |c: &VerifiedCertificate| c.public_key_set().master_public_key().encode();
        match kind {
            CeremonyKind::Rekey => {
                assert_ne!(
                    mpk(&verified),
                    mpk(&current),
                    "re-key changes the master key"
                );
                assert_eq!(
                    verified.key_context().rekey().get(),
                    current.key_context().rekey().get() + 1
                );
            }
            _ => {
                assert_eq!(
                    mpk(&verified),
                    mpk(&current),
                    "{kind:?} keeps the master key"
                );
                assert_eq!(
                    verified.key_context().rekey(),
                    current.key_context().rekey()
                );
            }
        }
        assert_eq!(
            verified.key_context().epoch().get(),
            current.key_context().epoch().get() + 1
        );
        assert_eq!(
            verified.key_context().threshold(),
            Threshold::new(t, n).unwrap()
        );

        // A ceremony authorized against the retired certificate cannot be
        // replayed against its successor.
        assert!(matches!(
            AuthorizedCeremony::verify_for(&verified, &statement, signers),
            Err(Error::InvalidCeremony)
        ));

        self.shares = candidates
            .into_iter()
            .map(|(i, c)| (i, KeyShare::bind(c, &verified).unwrap()))
            .collect();
        old_context_refused(&current, &retired, &verified, &self.shares, seed ^ 0x5c);
        activation_rules(&verified, signers, Some(&current));
        let receipts = receipts_for(&verified, signers, &members);
        let activation = activation_for(&verified, &receipts, signers);
        self.generations.push(Generation {
            kind,
            statement,
            ceremony_digest: ceremony.digest(),
            initial_transcript: initial,
            rounds,
            certificate,
            verified,
            receipts,
            activation,
        });
        if kind == CeremonyKind::Rekey {
            self.wrap(&format!("records/rekey-{seed}"), seed);
        }
        self.records_behave(seed);
    }

    fn run() -> Self {
        let mut chain = Self::genesis(2, 3, 0xd1);
        for step in STEPS {
            chain.step(step);
        }
        chain
    }
}

/// The number of t-subsets of n members.
fn subsets(t: u16, n: u16) -> usize {
    (0u32..(1u32 << n))
        .filter(|mask| mask.count_ones() == u32::from(t))
        .count()
}

#[test]
fn real_chain_keeps_the_master_key_through_redistribution_and_changes_it_only_on_rekey() {
    let chain = Chain::run();
    let summary: Vec<_> = chain
        .generations
        .iter()
        .map(|g| {
            let c = g.verified.key_context();
            (
                g.kind,
                c.rekey().get(),
                c.epoch().get(),
                c.threshold().t(),
                c.threshold().n(),
                g.verified.public_key_set().master_public_key().encode(),
            )
        })
        .collect();
    use CeremonyKind::*;
    let expected = [
        (Genesis, 0, 0, 2, 3),
        (Reshare, 0, 1, 3, 4),
        (Reshare, 0, 2, 2, 3),
        (Refresh, 0, 3, 2, 3),
        (Rekey, 1, 4, 3, 4),
        (Reshare, 1, 5, 2, 3),
        (Rekey, 2, 6, 2, 3),
        (Reshare, 2, 7, 3, 4),
    ];
    assert_eq!(summary.len(), expected.len());
    for (got, want) in summary.iter().zip(expected) {
        assert_eq!((got.0, got.1, got.2, got.3, got.4), want);
    }
    // The master key is shared within a run of non-re-key steps and differs
    // across every re-key.
    let keys: Vec<&[u8; 96]> = summary.iter().map(|s| &s.5).collect();
    assert!(keys[..4].iter().all(|k| *k == keys[0]));
    assert_ne!(keys[4], keys[3]);
    assert_eq!(keys[4], keys[5]);
    assert_ne!(keys[6], keys[5]);
    assert_eq!(keys[6], keys[7]);
    let distinct: std::collections::BTreeSet<_> = keys.iter().collect();
    assert_eq!(distinct.len(), 3);

    // genesis t follows the ceremony that created the master key.
    let genesis_t: Vec<u16> = chain
        .generations
        .iter()
        .map(|g| g.verified.body().genesis_t())
        .collect();
    assert_eq!(genesis_t, [2, 2, 2, 2, 3, 3, 2, 2]);
}

// ------------------------------------------------------------------- vectors

fn hex_statement(s: &SignedStatement) -> Value {
    json!({"body": hex::encode(&s.bytes), "signature": hex::encode(&s.signature)})
}

fn hex_certificate(c: &SignedCertificate) -> Value {
    json!({
        "body": hex::encode(c.body.encode()),
        "owner_signature": hex::encode(&c.owner_signature),
    })
}

fn rounds_json(rounds: &[DkgRoundRecord]) -> Value {
    json!(rounds
        .iter()
        .map(|r| json!({
            "closure": hex_statement(&r.closure),
            "messages": r.messages.iter().map(hex_statement).collect::<Vec<_>>(),
        }))
        .collect::<Vec<_>>())
}

fn public_json(p: &crate::cert::PublicMaterial) -> Value {
    let n = p.threshold().n();
    json!({
        "threshold": p.threshold().t(),
        "members": n,
        "mpk": hex::encode(p.master_public_key().encode()),
        "commitments": p.commitments().map(hex::encode).collect::<Vec<_>>(),
        "public_shares": (1..=n).map(|j| json!({
            "member": j,
            "point": hex::encode(p.public_share(idx(j)).unwrap()),
        })).collect::<Vec<_>>(),
    })
}

fn kind_name(kind: CeremonyKind) -> &'static str {
    match kind {
        CeremonyKind::Genesis => "genesis",
        CeremonyKind::Reshare => "reshare",
        CeremonyKind::Refresh => "refresh",
        CeremonyKind::Rekey => "rekey",
    }
}

/// Recompute every output from the published inputs the way the checker must.
fn outputs(
    signers: &Signers,
    g: &Generation,
    previous: Option<&VerifiedCertificate>,
) -> Result<Value, Error> {
    let anchor = signers.anchor();
    let transcript = crate::dkg::DkgTranscript {
        rounds: g.rounds.clone(),
    };
    let (ceremony, public, transcript_hash, detail) = match (g.kind, previous) {
        (CeremonyKind::Genesis, None) => {
            let ceremony = AuthorizedCeremony::verify_genesis(&anchor, &g.statement, signers)?;
            let output: DkgOutput = dkg_verify_transcript(&ceremony, &transcript, signers)?;
            let detail = json!({
                "qual": output.qual.iter().map(|i| i.get()).collect::<Vec<_>>(),
                "reconstructed": output.reconstructed.iter().map(|i| i.get()).collect::<Vec<_>>(),
            });
            (ceremony, output.public, output.transcript_hash, detail)
        }
        (CeremonyKind::Rekey, Some(previous)) => {
            let ceremony = AuthorizedCeremony::verify_for(previous, &g.statement, signers)?;
            let output = dkg_verify_transcript(&ceremony, &transcript, signers)?;
            let detail = json!({
                "qual": output.qual.iter().map(|i| i.get()).collect::<Vec<_>>(),
                "reconstructed": output.reconstructed.iter().map(|i| i.get()).collect::<Vec<_>>(),
            });
            (ceremony, output.public, output.transcript_hash, detail)
        }
        (CeremonyKind::Reshare | CeremonyKind::Refresh, Some(previous)) => {
            let ceremony = AuthorizedCeremony::verify_for(previous, &g.statement, signers)?;
            let output: ReshareOutput = reshare_verify_transcript(
                &ceremony,
                previous,
                &ReshareTranscript {
                    rounds: g.rounds.clone(),
                },
                signers,
            )?;
            let detail = json!({
                "dealers": output.dealers.iter().map(|i| i.get()).collect::<Vec<_>>(),
            });
            (ceremony, output.public, output.transcript_hash, detail)
        }
        _ => return Err(Error::InvalidCeremony),
    };
    assert_eq!(ceremony.digest(), g.ceremony_digest);
    let verified = match previous {
        None => verify_certificate(&anchor, &g.certificate, signers)
            .map_err(|_| Error::InvalidEncoding)?,
        Some(previous) => verify_successor(previous, &g.certificate, signers)
            .map_err(|_| Error::InvalidEncoding)?,
    };
    // The certificate commits to this ceremony's outcome and nothing else.
    let expected = match previous {
        None => CertificateBody::genesis(&anchor, &ceremony, &public, &transcript_hash)?,
        Some(previous) => {
            CertificateBody::successor(previous, &ceremony, &public, &transcript_hash)?
        }
    };
    if expected.encode() != g.certificate.body.encode() {
        return Err(Error::InvalidEncoding);
    }
    let activation = &g.activation;
    verify_activation(
        &verified,
        &g.receipts,
        ReadyQuorum::AllHolders,
        activation,
        signers,
    )?;
    let context = verified.key_context();
    let mut out = public_json(&public);
    out["kind"] = json!(kind_name(g.kind));
    out["epoch"] = json!(context.epoch().get());
    out["rekey"] = json!(context.rekey().get());
    out["genesis_t"] = json!(verified.body().genesis_t());
    out["transcript_hash"] = json!(hex::encode(transcript_hash.as_bytes()));
    out["certificate_digest"] = json!(hex::encode(verified.digest().as_bytes()));
    out["activation"] = json!(hex::encode(&activation.bytes));
    out["ceremony"] = detail;
    Ok(out)
}

fn chain_vectors() -> Value {
    let chain = Chain::run();
    let signers = Signers::new();
    let mut cases = Vec::new();
    let mut previous: Option<&Generation> = None;
    for (position, g) in chain.generations.iter().enumerate() {
        let c = g.verified.key_context();
        let name = format!(
            "chain_{position}_{}_{}of{}",
            kind_name(g.kind),
            c.threshold().t(),
            c.threshold().n()
        );
        let inputs = json!({
            "previous_certificate": previous.map(|p| hex_certificate(&p.certificate)),
            "ceremony": hex_statement(&g.statement),
            "ceremony_digest": hex::encode(g.ceremony_digest),
            "initial_transcript": hex::encode(g.initial_transcript.as_bytes()),
            "rounds": rounds_json(&g.rounds),
            "certificate": hex_certificate(&g.certificate),
            "receipts": g.receipts.iter().map(|r| json!({
                "member": r.index.get(),
                "signature": hex::encode(&r.signature),
            })).collect::<Vec<_>>(),
            "quorum": "all_holders",
            "activation": hex_statement(&g.activation),
        });
        let outputs = outputs(&signers, g, previous.map(|p| &p.verified)).unwrap();
        cases.push(json!({
            "name": name,
            "description": format!(
                "Generation {position}: a real {} ceremony, its owner certificate chained to the pinned predecessor, one readiness receipt per holder and the owner activation.",
                kind_name(g.kind)
            ),
            "operation": "chain_step",
            "inputs": inputs,
            "outputs": outputs,
        }));
        previous = Some(g);
    }
    let signer_keys: Vec<_> = (0..=8u8)
        .map(|i| {
            json!({
                "did": Signers::did(i).as_str(),
                "ed25519_public_key": hex::encode(ed25519_dalek::SigningKey::from_bytes(&[i; 32]).verifying_key().to_bytes()),
            })
        })
        .collect();
    let anchor = signers.anchor();
    json!({
        "format_version": 1,
        "suite": "BLS12-381 G2 GJKR New-DKG, Feldman redistribution and re-key; owner certificates, readiness receipts and activation; Ed25519 test signatures",
        "spec_sections": ["3.7", "3.8", "3.9", "3.12", "S0.5 re-key appendix", "S0.5 chain appendix"],
        "encoding": "hex; statements are exact signed bytes; certificates are the canonical body plus the owner signature",
        "seeds": {"genesis": 0xd1u8, "steps": STEPS.iter().map(|s| match s {
            Step::Reshare(_, _, seed) | Step::Refresh(_, _, seed) | Step::Rekey(_, _, seed) => *seed,
        }).collect::<Vec<_>>()},
        "dst": {
            "dkg_start": String::from_utf8_lossy(crate::dkg::DKG_START),
            "reshare_start": String::from_utf8_lossy(crate::reshare::RESHARE_START),
            "commitments": String::from_utf8_lossy(crate::dst::COMMITMENTS),
            "dealing": String::from_utf8_lossy(crate::dst::DEALING),
            "ceremony_auth": String::from_utf8_lossy(crate::dst::CEREMONY_AUTH),
            "ceremony_msg": String::from_utf8_lossy(crate::dst::CEREMONY_MSG),
            "round_close": String::from_utf8_lossy(crate::dst::ROUND_CLOSE),
            "transcript": String::from_utf8_lossy(crate::dst::TRANSCRIPT),
            "network_cert": String::from_utf8_lossy(crate::dst::NETWORK_CERT),
            "cert_statement": String::from_utf8_lossy(crate::dst::CERT_STATEMENT),
            "ready": String::from_utf8_lossy(crate::dst::READY),
            "activate": String::from_utf8_lossy(crate::dst::ACTIVATE),
        },
        "anchor": {"owner": anchor.expected_owner.as_str(), "network": anchor.network.as_str()},
        "signers": signer_keys,
        "cases": cases,
    })
}

#[test]
fn chain_vectors_regenerate_byte_for_byte_and_replay() {
    let encoded = format!(
        "{}\n",
        serde_json::to_string_pretty(&chain_vectors()).unwrap()
    );
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("vectors/v1/chain.json");
    if std::env::var("TC_THRESHOLD_REGEN_VECTORS").as_deref() == Ok("1") {
        std::fs::write(&path, &encoded).unwrap();
    }
    let published = std::fs::read_to_string(&path).unwrap();
    assert_eq!(published, encoded);

    // Replay from the published bytes alone.
    let file: Value = serde_json::from_str(&published).unwrap();
    let signers = Signers::new();
    let bytes = |v: &Value| hex::decode(v.as_str().unwrap()).unwrap();
    let statement = |v: &Value| SignedStatement {
        bytes: bytes(&v["body"]),
        signature: bytes(&v["signature"]),
    };
    let certificate = |v: &Value| SignedCertificate {
        body: CertificateBody::decode(&bytes(&v["body"])).unwrap(),
        owner_signature: bytes(&v["owner_signature"]),
    };
    let mut pinned: Option<VerifiedCertificate> = None;
    for case in file["cases"].as_array().unwrap() {
        let inputs = &case["inputs"];
        let signed = certificate(&inputs["certificate"]);
        let generation = Generation {
            kind: match case["outputs"]["kind"].as_str().unwrap() {
                "genesis" => CeremonyKind::Genesis,
                "reshare" => CeremonyKind::Reshare,
                "refresh" => CeremonyKind::Refresh,
                _ => CeremonyKind::Rekey,
            },
            statement: statement(&inputs["ceremony"]),
            ceremony_digest: bytes(&inputs["ceremony_digest"]).try_into().unwrap(),
            initial_transcript: TranscriptHash::new(
                bytes(&inputs["initial_transcript"]).try_into().unwrap(),
            ),
            rounds: inputs["rounds"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| DkgRoundRecord {
                    closure: statement(&r["closure"]),
                    messages: r["messages"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(statement)
                        .collect(),
                })
                .collect(),
            certificate: signed.clone(),
            verified: verify_certificate(&signers.anchor(), &signed, &signers).unwrap(),
            receipts: inputs["receipts"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| ReadinessReceipt {
                    index: idx(r["member"].as_u64().unwrap() as u16),
                    signature: bytes(&r["signature"]),
                })
                .collect(),
            activation: statement(&inputs["activation"]),
        };
        match (&pinned, inputs["previous_certificate"].is_null()) {
            (None, true) => {}
            (Some(p), false) => {
                assert_eq!(
                    hex::encode(p.body().encode()),
                    inputs["previous_certificate"]["body"].as_str().unwrap()
                );
            }
            _ => panic!("chain order broken at {}", case["name"]),
        }
        assert_eq!(
            outputs(&signers, &generation, pinned.as_ref()).unwrap(),
            case["outputs"],
            "{}",
            case["name"]
        );
        pinned = Some(generation.verified);
    }
}

// --------------------------------------------------- re-key authorization

fn rekey_statement_body(statement: &SignedStatement) -> CeremonyStatement {
    CeremonyStatement::decode(&statement.bytes).unwrap()
}

#[test]
fn rekey_authorization_follows_the_pinned_certificate_and_the_genesis_budget() {
    let (signers, statement, current) =
        dkg_relay::statement_in(dkg_relay::Setup::Rekey, 2, 3, 0x71);
    let current = current.unwrap();
    let ok = AuthorizedCeremony::verify_for(&current, &statement, &signers).unwrap();
    assert_eq!(ok.kind(), CeremonyKind::Rekey);
    assert_eq!(ok.statement().rekey.get(), 1);
    assert_eq!(ok.statement().epoch.get(), 1);

    let body = rekey_statement_body(&statement);
    let refused = |body: CeremonyStatement| {
        AuthorizedCeremony::verify_for(&current, &signers.statement(&body), &signers).err()
    };
    // The counters must be the checked successors.
    let mut stale_counter = body.clone();
    stale_counter.rekey = current.key_context().rekey();
    assert_eq!(refused(stale_counter), Some(Error::InvalidCeremony));
    let mut skipped_counter = body.clone();
    skipped_counter.rekey = RekeyCounter::new(2);
    assert_eq!(refused(skipped_counter), Some(Error::InvalidCeremony));
    let mut skipped_epoch = body.clone();
    skipped_epoch.epoch = Epoch::new(2);
    assert_eq!(refused(skipped_epoch), Some(Error::InvalidCeremony));
    // It must name exactly the pinned certificate.
    let mut other_digest = body.clone();
    other_digest.current = Some(CertDigest::new([7; 32]));
    assert_eq!(refused(other_digest), Some(Error::InvalidCeremony));
    let mut absent = body.clone();
    absent.current = None;
    assert_eq!(refused(absent), Some(Error::InvalidCeremony));
    // The genesis fault budget applies; each shape is refused before any dealing.
    for (t, n) in [(2, 2), (3, 3), (4, 4), (4, 5), (4, 6), (5, 8)] {
        let (_, statement, _) = dkg_relay::statement_in(dkg_relay::Setup::Rekey, t, n, 0x72);
        assert_eq!(
            AuthorizedCeremony::verify_for(&current, &statement, &signers).err(),
            Some(Error::UnsupportedFaultBudget),
            "{t}-of-{n}"
        );
    }
    // Kind and verifier entry point must agree.
    assert_eq!(
        AuthorizedCeremony::verify_genesis(&signers.anchor(), &statement, &signers).err(),
        Some(Error::InvalidCeremony)
    );
    let genesis = dkg_relay::genesis_statement(&signers, 2, 3, 0x73);
    assert_eq!(
        AuthorizedCeremony::verify_for(&current, &genesis, &signers).err(),
        Some(Error::InvalidCeremony)
    );
    // The owner signature is checked against the anchor.
    let mut forged = statement.clone();
    forged.signature[0] ^= 1;
    assert_eq!(
        AuthorizedCeremony::verify_for(&current, &forged, &signers).err(),
        Some(Error::InvalidSignature)
    );
}

#[test]
fn the_dkg_serves_only_genesis_and_rekey() {
    let signers = Signers::new();
    let (current, _) = crate::cert::tests::genesis(&signers);
    let f = dkg_relay::rekey_fixture_on(&current, 2, 3, 0x74);
    let mut rng = f.member_rng(1);
    dkg_start(&f.ceremony, idx(1), f.secret(1), &mut rng).unwrap();
    let transcript = crate::dkg::DkgTranscript { rounds: Vec::new() };
    for kind in [CeremonyKind::Reshare, CeremonyKind::Refresh] {
        let (_, _, other) = crate::cert::tests::successor(
            &signers,
            &current,
            kind,
            Threshold::new(2, 3).unwrap(),
            // Seed 11 keeps the test-dealer master key.
            11,
        );
        assert!(matches!(
            dkg_start(&other, idx(1), f.secret(1), &mut rng),
            Err(Error::InvalidCeremony)
        ));
        assert_eq!(
            dkg_verify_transcript(&other, &transcript, &signers).err(),
            Some(Error::InvalidCeremony)
        );
    }
}

#[test]
fn a_genesis_transcript_is_not_a_rekey_transcript_and_the_reverse() {
    // Same seed, shape and signers: only the authorized ceremony differs.
    let genesis = dkg_relay::run_in(dkg_relay::Setup::Genesis, 2, 3, 0x75, |_| {});
    let rekey = dkg_relay::run_in(dkg_relay::Setup::Rekey, 2, 3, 0x75, |_| {});
    genesis.verify().unwrap();
    rekey.verify().unwrap();
    assert_ne!(
        genesis.fixture.ceremony.digest(),
        rekey.fixture.ceremony.digest()
    );
    assert_ne!(
        dkg_initial_transcript(&genesis.fixture.ceremony),
        dkg_initial_transcript(&rekey.fixture.ceremony)
    );
    assert_eq!(
        dkg_verify_transcript(
            &rekey.fixture.ceremony,
            &genesis.transcript,
            &genesis.fixture.signers
        )
        .err(),
        Some(Error::InvalidRound)
    );
    assert_eq!(
        dkg_verify_transcript(
            &genesis.fixture.ceremony,
            &rekey.transcript,
            &rekey.fixture.signers
        )
        .err(),
        Some(Error::InvalidRound)
    );
}

#[test]
fn a_rekey_with_a_reconstructed_dealer_yields_a_certified_key_every_subset_derives() {
    let signers = Signers::new();
    let (current, old_shares) = crate::cert::tests::genesis(&signers);
    let old_shares: BTreeMap<u16, KeyShare> = old_shares
        .into_iter()
        .map(|s| (s.index().get(), s))
        .collect();
    // Member 4 of the new 3-of-4 cohort is faulty: its R4 vector passes only
    // its own check and it withholds R6; the three honest values recover it.
    let fixture = dkg_relay::rekey_fixture_on(&current, 3, 4, 0x76);
    let mut constants = BTreeMap::new();
    let run = dkg_relay::drive(fixture, &signers, |out| match out.round() {
        4 => {
            dkg_relay::constants(out, &mut constants);
            let forged = dkg_relay::vanishing_feldman(&out.payload(4), &[4]);
            out.replace(4, &forged);
        }
        6 => out.remove(4),
        _ => {}
    });
    let output = dkg_relay::agreed(&run, &[1, 2, 3]);
    assert_eq!(output.reconstructed, dkg_relay::members(&[4]));
    assert_eq!(
        output.public.master_public_key().encode(),
        dkg_relay::sum(output.qual.iter().map(|i| constants[&i.get()]))
    );
    let dkg_relay::Run {
        fixture, outcomes, ..
    } = run;
    let body = CertificateBody::successor(
        &current,
        &fixture.ceremony,
        &output.public,
        &output.transcript_hash,
    )
    .unwrap();
    let cert = verify_successor(&current, &signed_pair(&body, &signers), &signers).unwrap();
    assert_ne!(
        cert.public_key_set().master_public_key().encode(),
        current.public_key_set().master_public_key().encode()
    );
    let shares: BTreeMap<u16, KeyShare> = outcomes
        .into_iter()
        .map(|(i, o)| (i, KeyShare::bind(o.unwrap().0, &cert).unwrap()))
        .collect();
    let (data, ct) = reshare_relay::wrapped(&cert, "records/faulty-rekey", 0x76);
    assert_eq!(
        reshare_relay::unwraps_through_every_subset(
            &cert,
            &shares,
            "records/faulty-rekey",
            &data,
            &ct,
            0x77
        ),
        4
    );
    // The old generation's shares are unusable in the re-keyed context.
    old_context_refused(&current, &old_shares, &cert, &shares, 0x78);
}
