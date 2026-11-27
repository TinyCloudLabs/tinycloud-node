// Own-message inclusion before R6, the R6 reconstruction floor and the
// genesis/re-key activation quorum, under genesis and re-key ceremonies.
// Included by `dkg_relay`. Details: TC-2226

use super::*;
use crate::{
    activation::{
        activation_preimage, readiness_preimage, verify_activation, ReadinessReceipt, ReadyQuorum,
    },
    cert::verify_successor,
    poly,
};

const SETUPS: [Setup; 2] = [Setup::Genesis, Setup::Rekey];
const SHAPES: [(u16, u16); 4] = [(2, 3), (3, 4), (3, 5), (4, 7)];

fn faults(t: u16, n: u16) -> u16 {
    Threshold::new(t, n).unwrap().genesis_faults()
}

fn r6_senders(run: &Run) -> BTreeSet<u16> {
    run.transcript
        .rounds
        .get(5)
        .map(|r| r.messages.iter().map(sender).collect())
        .unwrap_or_default()
}

fn stopped_with(run: &Run, member: u16, error: Error) -> bool {
    matches!(&run.outcomes[&member], Err(e) if *e == error)
}

/// g2 times the sum of every dealer constant that t public R6 values interpolate.
fn published_constants(run: &Run) -> [u8; 96] {
    let t = usize::from(run.fixture.t());
    let mut per_dealer: BTreeMap<MemberIndex, Vec<(MemberIndex, Scalar)>> = BTreeMap::new();
    if let Some(r6) = run.transcript.rounds.get(5) {
        for message in &r6.messages {
            let values = DkgReconstruction::decode(&message.bytes[41..]).unwrap();
            for (dealer, pair) in values.values {
                per_dealer
                    .entry(dealer)
                    .or_default()
                    .push((idx(sender(message)), pair.value.add(&Scalar::from_u64(0))));
            }
        }
    }
    let mut recovered = Scalar::from_u64(0);
    for points in per_dealer.values().filter(|p| p.len() >= t) {
        let used = &points[..t];
        for (x, y) in used {
            let l = poly::lagrange(*x, used.iter().map(|(x, _)| *x)).unwrap();
            recovered = recovered.add(&l.mul(y));
        }
    }
    G2::generator().mul(&recovered).encode()
}

// ------------------------------------------------------- own R4/R5 inclusion

#[test]
fn omitting_every_r4_stops_every_member_before_r6() {
    for setup in SETUPS {
        for (t, n) in SHAPES {
            let run = run_in(setup, t, n, 0x70, |out| {
                if out.round() == 4 {
                    for i in 1..=n {
                        out.remove(i);
                    }
                }
            });
            let label = format!("{setup:?} {t}-of-{n}");
            assert_eq!(run.transcript.rounds.len(), 5, "{label}: no R6 round");
            for i in 1..=n {
                assert!(
                    stopped_with(&run, i, Error::ExcessiveReconstruction),
                    "{label} member {i}"
                );
            }
            assert_eq!(
                run.verify().err(),
                Some(Error::ExcessiveReconstruction),
                "{label}"
            );
        }
    }
}

#[test]
fn omitting_one_dealers_r4_stops_only_that_dealer_and_keeps_its_value_private() {
    for setup in SETUPS {
        let mut constants_seen = BTreeMap::new();
        let run = run_in(setup, 3, 5, 0x71, |out| {
            if out.round() == 4 {
                constants(out, &mut constants_seen);
                out.remove(1);
            }
        });
        assert!(stopped_with(&run, 1, Error::OwnMessageOmitted), "{setup:?}");
        assert_eq!(r6_senders(&run), BTreeSet::from([2, 3, 4, 5]), "{setup:?}");
        let output = agreed(&run, &[2, 3, 4, 5]);
        assert_eq!(output.reconstructed, members(&[1]), "{setup:?}");
        let mpk = output.public.master_public_key().encode();
        assert_eq!(mpk, genuine_mpk(&constants_seen, &output.qual), "{setup:?}");
        assert_ne!(published_constants(&run), mpk, "{setup:?}");
    }
}

#[test]
fn a_member_without_exactly_one_own_r4_or_r5_in_the_closed_round_stops_before_r6() {
    for setup in SETUPS {
        // A second, conflicting R4 next to member 4's own.
        let conflicting = run_in(setup, 3, 5, 0x73, |out| {
            if out.round() == 4 {
                let second = vanishing_feldman(&out.payload(4), &[]);
                out.push(4, &second);
            }
        });
        assert!(stopped_with(&conflicting, 4, Error::OwnMessageOmitted));
        assert!(!r6_senders(&conflicting).contains(&4));
        assert_eq!(
            agreed(&conflicting, &[1, 2, 3, 5]).reconstructed,
            members(&[4])
        );

        // A second, conflicting R5 next to member 3's own, when no R6 follows.
        let r5_conflicting = run_in(setup, 2, 3, 0x74, |out| {
            if out.round() == 5 {
                let complaint = DkgExtractionComplaints {
                    complaints: vec![(idx(1), pair(5, 6))],
                };
                out.push(3, &complaint.encode());
            }
        });
        assert!(stopped_with(&r5_conflicting, 3, Error::OwnMessageOmitted));
        assert_eq!(r5_conflicting.transcript.rounds.len(), 5);
        assert!(agreed(&r5_conflicting, &[1, 2]).reconstructed.is_empty());

        // Member 1's R5 omitted while faulty dealer 5 is reconstructed.
        let r5_omitted = run_in(setup, 3, 5, 0x75, |out| match out.round() {
            4 => {
                let forged = vanishing_feldman(&out.payload(5), &[]);
                out.replace(5, &forged);
            }
            5 => out.remove(1),
            6 => out.remove(5),
            _ => {}
        });
        assert!(stopped_with(&r5_omitted, 1, Error::OwnMessageOmitted));
        assert_eq!(r6_senders(&r5_omitted), BTreeSet::from([2, 3, 4]));
        assert_eq!(agreed(&r5_omitted, &[2, 3, 4]).reconstructed, members(&[5]));
    }
}

#[test]
fn r6_from_a_member_whose_own_r4_or_r5_is_missing_or_conflicting_is_refused() {
    for setup in SETUPS {
        // Member 1's R4 is missing, and an R6 carrying its own value is closed.
        let mut deal = Vec::new();
        let own_r4 = run_in(setup, 3, 5, 0x76, |out| match out.round() {
            1 => deal = out.payload(1),
            4 => out.remove(1),
            6 => {
                let own = DkgReconstruction {
                    values: vec![(idx(1), opened(out.fixture(), &deal, 1, 1))],
                };
                out.push(1, &own.encode());
            }
            _ => {}
        });
        assert!(r6_senders(&own_r4).contains(&1));
        assert_eq!(own_r4.verify().err(), Some(Error::OwnMessageOmitted));
        for i in 1..=5 {
            assert!(stopped_with(&own_r4, i, Error::OwnMessageOmitted), "{i}");
        }

        // Member 1's R5 is missing, and an R6 from it is closed.
        let mut deal = Vec::new();
        let own_r5 = run_in(setup, 3, 5, 0x77, |out| match out.round() {
            1 => deal = out.payload(5),
            4 => {
                let forged = vanishing_feldman(&out.payload(5), &[]);
                out.replace(5, &forged);
            }
            5 => out.remove(1),
            6 => {
                let values = DkgReconstruction {
                    values: vec![(idx(5), opened(out.fixture(), &deal, 5, 1))],
                };
                out.push(1, &values.encode());
            }
            _ => {}
        });
        assert!(r6_senders(&own_r5).contains(&1));
        assert_eq!(own_r5.verify().err(), Some(Error::OwnMessageOmitted));
        for i in 2..=4 {
            assert!(stopped_with(&own_r5, i, Error::OwnMessageOmitted), "{i}");
        }

        // Member 4 has two different R4 in closed R4, and an R6 from it is
        // closed. The conflict alone is an extraction fault, not an error.
        let mut deal = Vec::new();
        let two_r4 = run_in(setup, 3, 5, 0x7d, |out| match out.round() {
            1 => deal = out.payload(4),
            4 => {
                let second = vanishing_feldman(&out.payload(4), &[]);
                out.push(4, &second);
            }
            6 => {
                let own = DkgReconstruction {
                    values: vec![(idx(4), opened(out.fixture(), &deal, 4, 4))],
                };
                out.push(4, &own.encode());
            }
            _ => {}
        });
        assert!(r6_senders(&two_r4).contains(&4));
        assert_eq!(two_r4.verify().err(), Some(Error::OwnMessageOmitted));
        for i in 1..=5 {
            assert!(stopped_with(&two_r4, i, Error::OwnMessageOmitted), "{i}");
        }

        // Member 1 has two different R5 in closed R5, and an R6 from it is
        // closed. The conflict alone makes its R5 count as empty.
        let mut deal = Vec::new();
        let two_r5 = run_in(setup, 3, 5, 0x7e, |out| match out.round() {
            1 => deal = out.payload(5),
            4 => {
                let forged = vanishing_feldman(&out.payload(5), &[]);
                out.replace(5, &forged);
            }
            5 => {
                let second = DkgExtractionComplaints {
                    complaints: vec![(idx(2), pair(5, 6))],
                };
                out.push(1, &second.encode());
            }
            6 => {
                let values = DkgReconstruction {
                    values: vec![(idx(5), opened(out.fixture(), &deal, 5, 1))],
                };
                out.push(1, &values.encode());
            }
            _ => {}
        });
        assert!(r6_senders(&two_r5).contains(&1));
        assert_eq!(two_r5.verify().err(), Some(Error::OwnMessageOmitted));
        for i in 1..=5 {
            assert!(stopped_with(&two_r5, i, Error::OwnMessageOmitted), "{i}");
        }
    }
}

// ------------------------------------------------------------- R6 floor

#[test]
fn reconstruction_stops_before_r6_when_fewer_than_t_dealers_stay_unreconstructed() {
    for setup in SETUPS {
        // |QUAL| = 5: two reconstructed dealers leave t = 3.
        let at = run_in(setup, 3, 5, 0x78, |out| {
            if out.round() == 4 {
                out.remove(1);
                out.remove(2);
            }
        });
        assert_eq!(agreed(&at, &[3, 4, 5]).reconstructed, members(&[1, 2]));
        assert_eq!(at.transcript.rounds.len(), 6);

        // Three would leave two.
        let over = run_in(setup, 3, 5, 0x79, |out| {
            if out.round() == 4 {
                for i in 1..=3 {
                    out.remove(i);
                }
            }
        });
        assert_eq!(over.transcript.rounds.len(), 5);
        for i in 1..=5 {
            assert!(
                stopped_with(&over, i, Error::ExcessiveReconstruction),
                "{i}"
            );
        }
        assert_eq!(over.verify().err(), Some(Error::ExcessiveReconstruction));

        // The floor counts QUAL, not n: with dealer 5 disqualified, one
        // reconstructed dealer leaves t and two do not.
        for (omitted, completes) in [(&[1u16][..], true), (&[1, 2][..], false)] {
            let run = run_in(setup, 3, 5, 0x7a, |out| match out.round() {
                1 => out.remove(5),
                4 => {
                    for i in omitted {
                        out.remove(*i);
                    }
                }
                _ => {}
            });
            if completes {
                let output = agreed(&run, &[2, 3, 4]);
                assert_eq!(output.qual, members(&[1, 2, 3, 4]));
                assert_eq!(output.reconstructed, members(&[1]));
            } else {
                assert_eq!(run.verify().err(), Some(Error::ExcessiveReconstruction));
                assert_eq!(run.transcript.rounds.len(), 5);
            }
        }
    }
}

#[test]
fn the_reconstruction_floor_admits_every_within_budget_fault_count() {
    // The most reconstruction an in-budget ceremony needs: all f faulty
    // dealers publish bad R4 and send no R6; n − f ≥ t dealers stay.
    for setup in SETUPS {
        for (t, n) in SHAPES {
            let f = faults(t, n);
            let faulty: Vec<u16> = (n - f + 1..=n).collect();
            let honest_members: Vec<u16> = (1..=n - f).collect();
            let mut constants_seen = BTreeMap::new();
            let run = run_in(setup, t, n, 0x7b, |out| match out.round() {
                4 => {
                    constants(out, &mut constants_seen);
                    for m in &faulty {
                        let forged = vanishing_feldman(&out.payload(*m), &[]);
                        out.replace(*m, &forged);
                    }
                }
                6 => {
                    for m in &faulty {
                        out.remove(*m);
                    }
                }
                _ => {}
            });
            let label = format!("{setup:?} {t}-of-{n}");
            let output = agreed(&run, &honest_members);
            assert_eq!(output.reconstructed, members(&faulty), "{label}");
            assert!(
                output.qual.len() - output.reconstructed.len() >= usize::from(t),
                "{label}"
            );
            assert_eq!(
                output.public.master_public_key().encode(),
                genuine_mpk(&constants_seen, &output.qual),
                "{label}"
            );
        }
    }
}

/// Coefficients of Π (X − root), constant first.
fn vanishing(roots: &[u16]) -> Vec<Scalar> {
    let mut poly = vec![Scalar::from_u64(1)];
    for root in roots {
        let mut next: Vec<Scalar> = (0..=poly.len()).map(|_| Scalar::from_u64(0)).collect();
        for (k, c) in poly.iter().enumerate() {
            next[k + 1] = next[k + 1].add(c);
            next[k] = next[k].sub(&c.mul(&Scalar::from_u64(u64::from(*root))));
        }
        poly = next;
    }
    poly
}

/// Faulty members are the last f. Dealer n reads every other R4 before
/// publishing its own and adds δ(X)·D, δ vanishing at members 1..t−1, so that
/// mpk = x·g2. The other honest members' R5 are omitted; the faulty members
/// send empty R5.
fn chosen_master_key(setup: Setup, t: u16, n: u16, seed: u8) -> (Run, Scalar) {
    let f = Threshold::new(t, n).unwrap().genesis_faults();
    let x = Scalar::from_u64(0x1234_5678);
    let delta = vanishing(&(1..t).collect::<Vec<_>>());
    let run = run_in(setup, t, n, seed, |out| match out.round() {
        4 => {
            let mut total = G2::identity();
            for i in 1..=n {
                total = total.add(&DkgFeldman::decode(&out.payload(i)).unwrap().commitments[0]);
            }
            let d = G2::generator()
                .mul(&x)
                .sub(&total)
                .mul(&delta[0].inverse().unwrap());
            let mut feldman = DkgFeldman::decode(&out.payload(n)).unwrap();
            for (k, c) in delta.iter().enumerate() {
                feldman.commitments[k] = feldman.commitments[k].add(&d.mul(c));
            }
            out.replace(n, &feldman.encode());
        }
        5 => {
            for i in t..=n - f {
                out.remove(i);
            }
            for i in n - f + 1..=n {
                out.replace(i, &DkgExtractionComplaints { complaints: vec![] }.encode());
            }
        }
        _ => {}
    });
    (run, x)
}

fn certificate(run: &Run, output: &DkgOutput) -> VerifiedCertificate {
    let f = &run.fixture;
    match &f.current {
        None => {
            let body = CertificateBody::genesis(
                &f.signers.anchor(),
                &f.ceremony,
                &output.public,
                &output.transcript_hash,
            )
            .unwrap();
            verify_certificate(
                &f.signers.anchor(),
                &crate::cert::tests::sign(body, &f.signers),
                &f.signers,
            )
            .unwrap()
        }
        Some(current) => {
            let body = CertificateBody::successor(
                current,
                &f.ceremony,
                &output.public,
                &output.transcript_hash,
            )
            .unwrap();
            verify_successor(
                current,
                &crate::cert::tests::sign(body, &f.signers),
                &f.signers,
            )
            .unwrap()
        }
    }
}

/// Readiness receipts from `ready` and the owner's activation over them.
fn signed_activation(
    fixture: &Fixture,
    cert: &VerifiedCertificate,
    ready: &[u16],
) -> (Vec<ReadinessReceipt>, SignedStatement) {
    let receipts: Vec<ReadinessReceipt> = ready
        .iter()
        .map(|i| ReadinessReceipt {
            index: idx(*i),
            signature: fixture.signers.sign(
                &Signers::did(*i as u8),
                &readiness_preimage(cert.body(), idx(*i)).unwrap(),
            ),
        })
        .collect();
    let bytes = activation_preimage(cert.body(), &receipts).unwrap();
    let activation = SignedStatement {
        signature: fixture.signers.sign(&cert.anchor().expected_owner, &bytes),
        bytes,
    };
    (receipts, activation)
}

// ------------------------------------------------ genesis/re-key activation

#[test]
fn a_chosen_master_key_with_omitted_r5_never_activates() {
    for setup in SETUPS {
        for (t, n) in SHAPES {
            let f = faults(t, n);
            let label = format!("{setup:?} {t}-of-{n}");
            let (run, x) = chosen_master_key(setup, t, n, 0x7c);
            // The transcript alone cannot tell an omitted R5 from a silent member.
            let verified = run.verify().unwrap();
            assert_eq!(
                verified.public.master_public_key().encode(),
                G2::generator().mul(&x).encode(),
                "{label}"
            );
            assert!(verified.reconstructed.is_empty(), "{label}");
            assert_eq!(run.transcript.rounds.len(), 5, "{label}");
            let cert = certificate(&run, &verified);
            let fixture = &run.fixture;
            let Run { outcomes, .. } = &run;
            let mut ready: Vec<u16> = outcomes
                .iter()
                .filter(|(i, _)| **i <= n - f)
                .filter_map(|(i, outcome)| {
                    let (candidate, _) = outcome.as_ref().ok()?;
                    let candidate = CandidateShare::from_bytes(&*candidate.to_bytes()).ok()?;
                    KeyShare::bind(candidate, &cert).ok().map(|_| *i)
                })
                .collect();
            assert_eq!(ready, (1..t).collect::<Vec<_>>(), "{label}");
            // Every faulty member signs a readiness claim regardless.
            ready.extend(n - f + 1..=n);
            let (receipts, activation) = signed_activation(fixture, &cert, &ready);
            let check = |q| verify_activation(&cert, &receipts, q, &activation, &fixture.signers);
            assert_eq!(
                check(ReadyQuorum::AllHolders),
                Err(Error::NotEnoughReady),
                "{label}"
            );
            for b in 1..=n {
                let expected = if b < f || t + b > n {
                    Error::InvalidReadiness
                } else {
                    Error::NotEnoughReady
                };
                assert_eq!(
                    check(ReadyQuorum::WithOutageBudget(b)),
                    Err(expected),
                    "{label} budget {b}"
                );
            }
            // Honest members whose R5 was omitted stop; the others hold
            // candidates consistent with the chosen key.
            for i in t..=n - f {
                assert!(
                    stopped_with(&run, i, Error::OwnMessageOmitted),
                    "{label} member {i}"
                );
            }
            agreed(&run, &(1..t).collect::<Vec<_>>());
        }
    }
}

// ------------------------------------------------------------------ vectors

/// Verify the certificate (and its pinned predecessor for a re-key), then the
/// activation, from the published bytes alone.
fn replay_activation(signers: &Signers, inputs: &Value) -> Result<(), Error> {
    let bytes = |v: &Value| hex::decode(v.as_str().unwrap()).unwrap();
    let certificate = |v: &Value| SignedCertificate {
        body: CertificateBody::decode(&bytes(&v["body"])).unwrap(),
        owner_signature: bytes(&v["owner_signature"]),
    };
    let anchor = signers.anchor();
    let candidate = match inputs.get("current_certificate") {
        None => verify_certificate(&anchor, &certificate(&inputs["certificate"]), signers).unwrap(),
        Some(current) => {
            let current = verify_certificate(&anchor, &certificate(current), signers).unwrap();
            verify_successor(&current, &certificate(&inputs["certificate"]), signers).unwrap()
        }
    };
    let receipts: Vec<ReadinessReceipt> = inputs["receipts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| ReadinessReceipt {
            index: idx(r["member"].as_u64().unwrap() as u16),
            signature: bytes(&r["signature"]),
        })
        .collect();
    let quorum = match inputs["quorum"]["with_outage_budget"].as_u64() {
        Some(b) => ReadyQuorum::WithOutageBudget(b as u16),
        None => ReadyQuorum::AllHolders,
    };
    let activation = SignedStatement {
        bytes: bytes(&inputs["activation"]["body"]),
        signature: bytes(&inputs["activation"]["signature"]),
    };
    verify_activation(&candidate, &receipts, quorum, &activation, signers)
}

/// Activation of the certificate over `run` with members 1, 2, 4 and 5 ready,
/// under outage budgets 1 and 2.
fn activation_refusals(kind: &str, run: &Run) -> Vec<Value> {
    let output = run.verify().unwrap();
    let cert = certificate(run, &output);
    let signers = &run.fixture.signers;
    let (receipts, activation) = signed_activation(&run.fixture, &cert, &[1, 2, 4, 5]);
    let mut inputs = json!({
        "certificate": current_json(signers, &cert),
        "receipts": receipts.iter().map(|r| json!({
            "member": r.index.get(),
            "signature": hex::encode(&r.signature),
        })).collect::<Vec<_>>(),
        "activation": hex_statement(&activation),
    });
    if let Some(current) = &run.fixture.current {
        inputs["current_certificate"] = current_json(signers, current);
    }
    [
        (1u16, format!("Activation of the {kind} certificate over the transcript of {kind}_3of5_chosen_master_key with members 1, 2, 4 and 5 ready and an outage budget of 1. A genesis or re-key candidate needs a budget of at least f = 2 for 3-of-5.")),
        (2, format!("The same {kind} activation with an outage budget of 2 needs t + 2 = 5 ready members; four are ready.")),
    ]
    .into_iter()
    .map(|(budget, description)| {
        let mut inputs = inputs.clone();
        inputs["quorum"] = json!({ "with_outage_budget": budget });
        let error = replay_activation(signers, &inputs).expect_err("activation vectors are refused");
        json!({
            "name": format!("{kind}_3of5_chosen_master_key_activation_budget_{budget}"),
            "description": description,
            "operation": "verify_activation",
            "inputs": inputs,
            "error": format!("{error:?}"),
        })
    })
    .collect()
}

fn omission_vectors() -> Value {
    let mut cases = Vec::new();
    let mut seeds = Vec::new();
    for setup in SETUPS {
        let (kind, base) = match setup {
            Setup::Genesis => ("genesis", 0xa0u8),
            Setup::Rekey => ("rekey", 0xb0),
        };
        seeds.extend(base..base + 4);
        let floor = run_in(setup, 3, 5, base, |out| {
            if out.round() == 4 {
                for i in 1..=3 {
                    out.remove(i);
                }
            }
        });
        let mut deal = Vec::new();
        let without_r4 = run_in(setup, 3, 5, base + 1, |out| match out.round() {
            1 => deal = out.payload(1),
            4 => out.remove(1),
            6 => {
                let own = DkgReconstruction {
                    values: vec![(idx(1), opened(out.fixture(), &deal, 1, 1))],
                };
                out.push(1, &own.encode());
            }
            _ => {}
        });
        let mut deal = Vec::new();
        let two_r5 = run_in(setup, 3, 5, base + 2, |out| match out.round() {
            1 => deal = out.payload(5),
            4 => {
                let forged = vanishing_feldman(&out.payload(5), &[]);
                out.replace(5, &forged);
            }
            5 => {
                let second = DkgExtractionComplaints {
                    complaints: vec![(idx(2), pair(5, 6))],
                };
                out.push(1, &second.encode());
            }
            6 => {
                let values = DkgReconstruction {
                    values: vec![(idx(5), opened(out.fixture(), &deal, 5, 1))],
                };
                out.push(1, &values.encode());
            }
            _ => {}
        });
        let (chosen, _) = chosen_master_key(setup, 3, 5, base + 3);
        cases.extend([
            case(&format!("{kind}_3of5_reconstruction_floor"), "The R4 of dealers 1-3 are missing. Reconstructing them would leave two of the five QUAL dealers, fewer than t = 3, so the ceremony stops after R5 and no R6 round exists.", &floor),
            case(&format!("{kind}_3of5_r6_from_member_without_r4"), "Member 1's R4 is missing from closed R4, yet an R6 from member 1 is closed. Every R6 sender must have exactly one R4 and one R5 in the closed rounds.", &without_r4),
            case(&format!("{kind}_3of5_r6_from_member_with_two_r5"), "Member 1 has two different R5 in closed R5, and an R6 from member 1 is closed. Every R6 sender must have exactly one R4 and one R5 in the closed rounds.", &two_r5),
            case(&format!("{kind}_3of5_chosen_master_key"), "Dealer 5's R4 is chosen after the other R4 so that mpk is a fixed point; it passes the checks of members 1 and 2 only. The R5 of members 3 and 4 are missing and member 5's is empty, so the transcript verifies with nothing reconstructed; members 3 and 4 stop after R5.", &chosen),
        ]);
        cases.extend(activation_refusals(kind, &chosen));
    }
    let signers: Vec<_> = (0..=5u8)
        .map(|i| {
            json!({
                "did": Signers::did(i).as_str(),
                "ed25519_public_key": hex::encode(ed25519_dalek::SigningKey::from_bytes(&[i; 32]).verifying_key().to_bytes()),
            })
        })
        .collect();
    let anchor = Signers::new().anchor();
    json!({
        "format_version": 1,
        "suite": "BLS12-381 G2 Pedersen/Feldman GJKR New-DKG under genesis and re-key ceremonies: own-message presence, the R6 reconstruction floor and the genesis/re-key activation budget; Ed25519 test signatures",
        "spec_sections": ["3.7", "3.12", "S0.2 activation appendix", "S0.3 DKG appendix", "S0.5 re-key appendix"],
        "encoding": "hex; statements are exact signed bytes; scalars 32-byte big-endian; G2 96-byte compressed; certificates are the canonical body plus the owner signature; re-key cases carry the pinned current certificate",
        "seeds": {"ceremonies": seeds},
        "dst": {
            "dkg_start": String::from_utf8_lossy(DKG_START),
            "ceremony_auth": String::from_utf8_lossy(dst::CEREMONY_AUTH),
            "ceremony_msg": String::from_utf8_lossy(dst::CEREMONY_MSG),
            "round_close": String::from_utf8_lossy(dst::ROUND_CLOSE),
            "transcript": String::from_utf8_lossy(dst::TRANSCRIPT),
            "network_cert": String::from_utf8_lossy(dst::NETWORK_CERT),
            "cert_statement": String::from_utf8_lossy(dst::CERT_STATEMENT),
            "ready": String::from_utf8_lossy(dst::READY),
            "activate": String::from_utf8_lossy(dst::ACTIVATE),
        },
        "anchor": {"owner": anchor.expected_owner.as_str(), "network": anchor.network.as_str()},
        "signers": signers,
        "cases": cases,
    })
}

/// Regenerate `vectors/v1/dkg-omission.json`, compare it byte for byte with
/// the published file, then replay every case from the published bytes alone.
#[test]
fn omission_vectors_regenerate_byte_for_byte_and_replay() {
    let encoded = format!(
        "{}\n",
        serde_json::to_string_pretty(&omission_vectors()).unwrap()
    );
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("vectors/v1/dkg-omission.json");
    if std::env::var("TC_THRESHOLD_REGEN_VECTORS").as_deref() == Ok("1") {
        std::fs::write(&path, &encoded).unwrap();
    }
    let published = std::fs::read_to_string(&path).unwrap();
    assert_eq!(published, encoded);

    let file: Value = serde_json::from_str(&published).unwrap();
    let signers = Signers::new();
    for case in file["cases"].as_array().unwrap() {
        let inputs = &case["inputs"];
        let result = match case["operation"].as_str().unwrap() {
            "verify_activation" => replay_activation(&signers, inputs).map(|()| Value::Null),
            _ => {
                let setup = if inputs.get("current_certificate").is_some() {
                    Setup::Rekey
                } else {
                    Setup::Genesis
                };
                replay(setup, &signers, inputs)
            }
        };
        match result {
            Ok(outputs) => assert_eq!(outputs, case["outputs"], "{}", case["name"]),
            Err(error) => assert_eq!(
                format!("{error:?}"),
                case["error"].as_str().unwrap(),
                "{}",
                case["name"]
            ),
        }
    }
}
