// DKG relay scenarios, run once under a genesis ceremony and once under a
// re-key ceremony: the rounds, rules and fault budget are the same. Included
// by `dkg_relay` into one module per `SETUP`. Details: TC-2220, TC-2223

use super::*;

fn statement(t: u16, n: u16, seed: u8) -> (Signers, SignedStatement) {
    let (signers, statement, _) = statement_in(SETUP, t, n, seed);
    (signers, statement)
}

fn authorize_statement(
    signers: &Signers,
    statement: &SignedStatement,
) -> Result<AuthorizedCeremony, Error> {
    authorize(SETUP, signers, statement)
}

fn fixture(t: u16, n: u16, seed: u8) -> Fixture {
    fixture_in(SETUP, t, n, seed)
}

fn run(t: u16, n: u16, seed: u8, tamper: impl FnMut(&mut Outbox)) -> Run {
    run_in(SETUP, t, n, seed, tamper)
}

fn honest(t: u16, n: u16, seed: u8) -> Run {
    run(t, n, seed, |_| {})
}

// ---------------------------------------------------------------- completion

#[test]
fn genuine_2of3_completes_with_every_member_and_the_verifier_agreeing() {
    let run = honest(2, 3, 0x31);
    let output = agreed(&run, &[1, 2, 3]);
    assert_eq!(output.qual, members(&[1, 2, 3]));
    assert!(output.disqualified.is_empty());
    assert!(output.reconstructed.is_empty());
    assert_eq!(run.transcript.rounds.len(), 5);
    assert!(run.reconstruct.values().all(|r| !r));
    assert_eq!(output.public.threshold(), Threshold::new(2, 3).unwrap());
    let mut sorted = output.public.commitments().collect::<Vec<_>>();
    assert_eq!(sorted.len(), 2);
    sorted.dedup();
    assert_eq!(sorted.len(), 2);
}

#[test]
fn genuine_3of4_completes_with_every_member_and_the_verifier_agreeing() {
    let run = honest(3, 4, 0x32);
    let output = agreed(&run, &[1, 2, 3, 4]);
    assert_eq!(output.qual, members(&[1, 2, 3, 4]));
    assert!(output.disqualified.is_empty());
    assert!(output.reconstructed.is_empty());
    assert_eq!(run.transcript.rounds.len(), 5);
    assert_eq!(output.public.threshold(), Threshold::new(3, 4).unwrap());
    assert_eq!(output.public.commitments().count(), 3);
}

#[test]
fn genesis_outside_the_budget_is_refused_before_any_dealing() {
    for (t, n) in [(2, 2), (3, 3), (4, 4), (4, 5), (4, 6), (5, 8)] {
        let (signers, statement) = statement(t, n, 0x32);
        assert!(
            matches!(
                authorize_statement(&signers, &statement),
                Err(Error::UnsupportedFaultBudget)
            ),
            "{t}-of-{n}"
        );
    }
}

#[test]
fn three_of_four_with_one_faulty_member_recovers_the_committed_master_key() {
    // Member 4 is faulty. Its R4 vector passes only its own check, so honest
    // members 1-3 complain in R5; it then withholds R6, and the three honest
    // values recover its committed contribution.
    let mut constants_seen = BTreeMap::new();
    let run = run(3, 4, 0x3b, |out| match out.round() {
        4 => {
            constants(out, &mut constants_seen);
            let forged = vanishing_feldman(&out.payload(4), &[4]);
            out.replace(4, &forged);
        }
        6 => out.remove(4),
        _ => {}
    });
    let output = agreed(&run, &[1, 2, 3]);
    assert_eq!(output.qual, members(&[1, 2, 3, 4]));
    assert!(output.disqualified.is_empty());
    assert_eq!(output.reconstructed, members(&[4]));
    assert_eq!(
        output.public.master_public_key().encode(),
        genuine_mpk(&constants_seen, &output.qual)
    );
    for i in [1, 2, 3] {
        assert!(run.reconstruct[&i]);
    }
}

#[test]
fn three_of_five_with_two_faulty_members_recovers_the_committed_master_key() {
    // Members 4 and 5 are faulty. Dealer 5 publishes a Feldman vector that
    // passes only at indices 4 and 5; member 4 files a false R5 complaint
    // against honest dealer 1; both withhold R6.
    let mut constants_seen = BTreeMap::new();
    let run = run(3, 5, 0x33, |out| match out.round() {
        4 => {
            constants(out, &mut constants_seen);
            let forged = vanishing_feldman(&out.payload(5), &[4, 5]);
            out.replace(5, &forged);
        }
        5 => {
            let complaint = DkgExtractionComplaints {
                complaints: vec![(idx(1), pair(11, 12))],
            };
            out.replace(4, &complaint.encode());
        }
        6 => {
            out.remove(4);
            out.remove(5);
        }
        _ => {}
    });
    let output = agreed(&run, &[1, 2, 3]);
    assert_eq!(output.qual, members(&[1, 2, 3, 4, 5]));
    assert!(output.disqualified.is_empty());
    assert_eq!(output.reconstructed, members(&[5]));
    assert_eq!(
        output.public.master_public_key().encode(),
        genuine_mpk(&constants_seen, &output.qual)
    );
    for i in [1, 2, 3] {
        assert!(run.reconstruct[&i]);
    }
}

#[test]
fn one_recipient_bad_private_value_is_replaced_by_a_valid_answer() {
    let mut answer = None;
    let run = run(2, 3, 0x34, |out| match out.round() {
        1 => {
            let forged = bad_dealing(out, 1, 2);
            out.replace(1, &forged);
        }
        2 => assert_eq!(
            DkgComplaints::decode(&out.payload(2)).unwrap().dealers,
            vec![idx(1)]
        ),
        3 => answer = Some(DkgAnswers::decode(&out.payload(1)).unwrap()),
        _ => {}
    });
    let output = agreed(&run, &[1, 2, 3]);
    assert_eq!(output.qual, members(&[1, 2, 3]));
    assert!(output.disqualified.is_empty());
    let answer = answer.unwrap();
    assert_eq!(answer.answers.len(), 1);
    assert_eq!(answer.answers[0].0, idx(2));
}

// ------------------------------------------------------------ R2/R3 rulings

#[test]
fn false_complaint_is_refuted_by_a_valid_answer() {
    let run = run(2, 3, 0x35, |out| {
        if out.round() == 2 {
            out.replace(
                3,
                &DkgComplaints {
                    dealers: vec![idx(1)],
                }
                .encode(),
            );
        }
    });
    let output = agreed(&run, &[1, 2, 3]);
    assert_eq!(output.qual, members(&[1, 2, 3]));
}

#[test]
fn t_distinct_complainers_disqualify_even_with_valid_answers() {
    let run = run(2, 3, 0x36, |out| {
        if out.round() == 1 {
            let forged = bad_dealing(out, 3, 1);
            out.replace(3, &forged);
            let forged = bad_dealing(out, 3, 2);
            out.replace(3, &forged);
        }
    });
    let output = agreed(&run, &[1, 2, 3]);
    assert_eq!(output.qual, members(&[1, 2]));
    assert_eq!(
        output.disqualified,
        BTreeMap::from([(idx(3), DisqualifyReason::Complaints)])
    );
}

#[test]
fn duplicate_complaints_count_once() {
    // t = 3: two distinct complainers, one retransmitting, stay below t.
    let run = run(3, 5, 0x37, |out| {
        if out.round() == 2 {
            let complaint = DkgComplaints {
                dealers: vec![idx(1)],
            }
            .encode();
            out.replace(4, &complaint);
            out.replace(5, &complaint);
            out.duplicate(4);
            out.duplicate(4);
        }
    });
    let output = agreed(&run, &[1, 2, 3, 4, 5]);
    assert_eq!(output.qual, members(&[1, 2, 3, 4, 5]));
}

#[test]
fn self_complaints_are_ignored() {
    // Dealer 3 sends member 1 a bad value and complains against itself. With
    // the self-complaint counted, two complainers would reach t = 2.
    let run = run(2, 3, 0x38, |out| match out.round() {
        1 => {
            let forged = bad_dealing(out, 3, 1);
            out.replace(3, &forged);
        }
        2 => out.replace(
            3,
            &DkgComplaints {
                dealers: vec![idx(3)],
            }
            .encode(),
        ),
        _ => {}
    });
    let output = agreed(&run, &[1, 2, 3]);
    assert_eq!(output.qual, members(&[1, 2, 3]));
}

#[test]
fn malformed_r2_supplies_no_complaints() {
    // A well-formed complaint with a trailing byte is malformed: it creates no
    // required answer, so dealer 1's missing R3 does not disqualify it.
    let run = run(2, 3, 0x39, |out| match out.round() {
        2 => {
            let mut malformed = DkgComplaints {
                dealers: vec![idx(1)],
            }
            .encode();
            malformed.push(0);
            out.replace(3, &malformed);
        }
        3 => out.remove(1),
        _ => {}
    });
    let output = agreed(&run, &[1, 2, 3]);
    assert_eq!(output.qual, members(&[1, 2, 3]));
}

#[test]
fn conflicting_r2_content_is_equivocation_even_when_malformed() {
    let run = run(3, 5, 0x3a, |out| {
        if out.round() == 2 {
            out.replace(5, &[1, 0]);
            out.push(5, &[1, 0, 1]);
            out.replace(4, &[1, 0, 1, 0]);
            out.duplicate(4);
        }
    });
    let output = agreed(&run, &[1, 2, 3, 4]);
    assert_eq!(
        output.disqualified,
        BTreeMap::from([(idx(5), DisqualifyReason::Equivocated { round: 2 })])
    );
    assert_eq!(output.qual, members(&[1, 2, 3, 4]));
}

/// Retransmit a member's first message with an alternate valid signature encoding.
fn alternate_signature(out: &mut Outbox, member: u16) {
    let mut copy = out
        .messages
        .iter()
        .find(|m| sender(m) == member)
        .cloned()
        .unwrap();
    copy.signature.push(0);
    out.messages.push(copy);
}

#[test]
fn different_signature_encoding_is_not_equivocation() {
    let verifier = Malleable(Signers::new());
    let run = drive(fixture(2, 3, 0x3b), &verifier, |out| {
        if out.round() <= 3 {
            alternate_signature(out, 3);
        }
    });
    assert_eq!(run.transcript.rounds[0].messages.len(), 4);
    let verified =
        dkg_verify_transcript(&run.fixture.ceremony, &run.transcript, &verifier).unwrap();
    assert_eq!(verified.qual, members(&[1, 2, 3]));
    assert!(verified.disqualified.is_empty());
    for i in [1, 2, 3] {
        assert_eq!(view(&run.outcomes[&i].as_ref().unwrap().1), view(&verified));
    }

    let changed = drive(fixture(2, 3, 0x3b), &verifier, |out| {
        if out.round() == 1 {
            let forged = bad_dealing(out, 3, 2);
            out.push(3, &forged);
        }
    });
    let verified =
        dkg_verify_transcript(&changed.fixture.ceremony, &changed.transcript, &verifier).unwrap();
    assert_eq!(
        verified.disqualified,
        BTreeMap::from([(idx(3), DisqualifyReason::Equivocated { round: 1 })])
    );
}

#[test]
fn missing_r3_disqualifies_only_with_required_answers() {
    let run = run(2, 3, 0x3c, |out| match out.round() {
        2 => out.replace(
            3,
            &DkgComplaints {
                dealers: vec![idx(1)],
            }
            .encode(),
        ),
        3 => {
            out.remove(1);
            out.remove(2);
        }
        _ => {}
    });
    let output = agreed(&run, &[1, 2, 3]);
    assert_eq!(
        output.disqualified,
        BTreeMap::from([(idx(1), DisqualifyReason::MissingAnswer)])
    );
    assert_eq!(output.qual, members(&[2, 3]));
}

#[test]
fn malformed_r3_disqualifies_only_with_required_answers() {
    let run = run(2, 3, 0x3d, |out| match out.round() {
        2 => out.replace(
            3,
            &DkgComplaints {
                dealers: vec![idx(1)],
            }
            .encode(),
        ),
        3 => {
            for dealer in [1, 2] {
                let mut malformed = out.payload(dealer);
                malformed.push(0);
                out.replace(dealer, &malformed);
            }
        }
        _ => {}
    });
    let output = agreed(&run, &[1, 2, 3]);
    assert_eq!(
        output.disqualified,
        BTreeMap::from([(idx(1), DisqualifyReason::MissingAnswer)])
    );
    assert_eq!(output.qual, members(&[2, 3]));
}

#[test]
fn invalid_unsolicited_answer_disqualifies_its_dealer() {
    let run = run(2, 3, 0x3e, |out| {
        if out.round() == 3 {
            let answer = DkgAnswers {
                answers: vec![(idx(3), pair(5, 6))],
            };
            out.replace(2, &answer.encode());
        }
    });
    let output = agreed(&run, &[1, 2, 3]);
    assert_eq!(
        output.disqualified,
        BTreeMap::from([(idx(2), DisqualifyReason::InvalidAnswer)])
    );
    assert_eq!(output.qual, members(&[1, 3]));
}

#[test]
fn valid_unsolicited_answer_is_ignored() {
    let mut deal = Vec::new();
    let run = run(2, 3, 0x3f, |out| match out.round() {
        1 => deal = out.payload(2),
        3 => {
            let answer = DkgAnswers {
                answers: vec![(idx(3), opened(out.fixture(), &deal, 2, 3))],
            };
            out.replace(2, &answer.encode());
        }
        _ => {}
    });
    let output = agreed(&run, &[1, 2, 3]);
    assert_eq!(output.qual, members(&[1, 2, 3]));
    assert!(output.disqualified.is_empty());
}

#[test]
fn r2_naming_a_dealer_outside_the_cohort_supplies_no_complaints() {
    // Member 3's R2 names dealer 1 and index 4 > n. The list is out of cohort,
    // so it creates no required answer and dealer 1's missing R3 is harmless.
    let run = run(2, 3, 0x5c, |out| match out.round() {
        2 => out.replace(
            3,
            &DkgComplaints {
                dealers: vec![idx(1), idx(4)],
            }
            .encode(),
        ),
        3 => out.remove(1),
        _ => {}
    });
    let output = agreed(&run, &[1, 2, 3]);
    assert_eq!(output.qual, members(&[1, 2, 3]));
    assert!(output.disqualified.is_empty());
}

#[test]
fn r3_naming_a_recipient_outside_the_cohort_is_malformed() {
    // Dealer 2 publishes an unrequested R3 entry for index 4 > n: malformed,
    // and without required answers it does not disqualify. Dealer 1 answers
    // member 3's complaint validly but adds an index-4 entry: malformed, so the
    // required answer counts as absent.
    let run = run(2, 3, 0x5d, |out| match out.round() {
        2 => out.replace(
            3,
            &DkgComplaints {
                dealers: vec![idx(1)],
            }
            .encode(),
        ),
        3 => {
            let mut answers = DkgAnswers::decode(&out.payload(1)).unwrap();
            assert_eq!(answers.answers.len(), 1);
            answers.answers.push((idx(4), pair(5, 6)));
            out.replace(1, &answers.encode());
            let unrequested = DkgAnswers {
                answers: vec![(idx(4), pair(5, 6))],
            };
            out.replace(2, &unrequested.encode());
        }
        _ => {}
    });
    // Assert the verifier's outcome directly, so a counted out-of-cohort entry
    // fails here as a disqualification mismatch rather than inside a helper.
    assert_eq!(
        run.verify().map(|o| o.disqualified),
        Ok(BTreeMap::from([(idx(1), DisqualifyReason::MissingAnswer)]))
    );
    let output = agreed(&run, &[1, 2, 3]);
    assert_eq!(
        output.disqualified,
        BTreeMap::from([(idx(1), DisqualifyReason::MissingAnswer)])
    );
    assert_eq!(output.qual, members(&[2, 3]));
}

#[test]
fn relay_omitted_complaint_fails_only_the_affected_member() {
    // Failure scenario outside the trusted-relay liveness model.
    let run = run(2, 3, 0x40, |out| match out.round() {
        1 => {
            let forged = bad_dealing(out, 1, 2);
            out.replace(1, &forged);
        }
        2 => out.remove(2),
        _ => {}
    });
    assert!(matches!(
        run.outcomes[&2],
        Err(Error::LocalShareUnavailable)
    ));
    let output = agreed(&run, &[1, 3]);
    assert_eq!(output.qual, members(&[1, 2, 3]));
}

// ------------------------------------------------- R4, barrier and R6 rules

#[test]
fn selective_r4_reaches_the_common_barrier_and_is_reconstructed() {
    let mut constants_seen = BTreeMap::new();
    let mut r5 = BTreeMap::new();
    let run = run(2, 3, 0x41, |out| match out.round() {
        4 => {
            constants(out, &mut constants_seen);
            let forged = vanishing_feldman(&out.payload(3), &[1]);
            out.replace(3, &forged);
        }
        5 => {
            for i in 1..=3 {
                r5.insert(
                    i,
                    DkgExtractionComplaints::decode(&out.payload(i))
                        .unwrap()
                        .complaints
                        .len(),
                );
            }
        }
        _ => {}
    });
    // Member 1's own check passed; member 2 complained. Both waited for the
    // same closed R5 and both entered R6.
    assert_eq!(r5, BTreeMap::from([(1, 0), (2, 1), (3, 0)]));
    assert_eq!(
        run.reconstruct,
        BTreeMap::from([(1, true), (2, true), (3, true)])
    );
    let output = agreed(&run, &[1, 2, 3]);
    assert_eq!(output.qual, members(&[1, 2, 3]));
    assert_eq!(output.reconstructed, members(&[3]));
    assert_eq!(
        output.public.master_public_key().encode(),
        genuine_mpk(&constants_seen, &output.qual)
    );
    assert_eq!(run.transcript.rounds.len(), 6);
}

type Mutation = fn(&mut Outbox);

#[test]
fn bad_missing_and_malformed_r4_are_extraction_faults() {
    let cases: [(&str, Mutation); 5] = [
        ("bad", |out| {
            let forged = vanishing_feldman(&out.payload(3), &[]);
            out.replace(3, &forged);
        }),
        ("missing", |out| out.remove(3)),
        ("trailing byte", |out| {
            let mut p = out.payload(3);
            p.push(0);
            out.replace(3, &p);
        }),
        ("wrong length", |out| {
            let mut f = DkgFeldman::decode(&out.payload(3)).unwrap();
            f.commitments.pop();
            out.replace(3, &f.encode());
        }),
        ("invalid point", |out| {
            let mut p = out.payload(3);
            p[3 + 95] ^= 1;
            out.replace(3, &p);
        }),
    ];
    for (name, mutate) in cases {
        let mut constants_seen = BTreeMap::new();
        let run = run(2, 3, 0x42, |out| {
            if out.round() == 4 {
                constants(out, &mut constants_seen);
                mutate(out);
            }
        });
        let output = agreed(&run, &[1, 2, 3]);
        assert_eq!(output.qual, members(&[1, 2, 3]), "{name}");
        assert_eq!(output.reconstructed, members(&[3]), "{name}");
        assert_eq!(
            output.public.master_public_key().encode(),
            genuine_mpk(&constants_seen, &output.qual),
            "{name}"
        );
    }
}

#[test]
fn r1_equivocation_disqualifies_but_r4_equivocation_reconstructs() {
    let mut constants_seen = BTreeMap::new();
    let run = run(3, 5, 0x43, |out| match out.round() {
        1 => {
            let second = bad_dealing(out, 5, 1);
            out.push(5, &second);
        }
        4 => {
            constants(out, &mut constants_seen);
            let second = vanishing_feldman(&out.payload(4), &[]);
            out.push(4, &second);
        }
        _ => {}
    });
    let output = agreed(&run, &[1, 2, 3]);
    assert_eq!(
        output.disqualified,
        BTreeMap::from([(idx(5), DisqualifyReason::Equivocated { round: 1 })])
    );
    assert_eq!(output.qual, members(&[1, 2, 3, 4]));
    assert_eq!(output.reconstructed, members(&[4]));
    assert_eq!(
        output.public.master_public_key().encode(),
        genuine_mpk(&constants_seen, &output.qual)
    );
}

#[test]
fn every_member_sends_r5_and_an_empty_barrier_finishes() {
    let mut r5 = Vec::new();
    let run = run(2, 3, 0x44, |out| {
        if out.round() == 5 {
            for i in 1..=3 {
                r5.push(DkgExtractionComplaints::decode(&out.payload(i)).unwrap());
            }
            assert_eq!(out.messages.len(), 3);
        }
    });
    assert!(r5.iter().all(|r| r.complaints.is_empty()));
    let output = agreed(&run, &[1, 2, 3]);
    assert!(output.reconstructed.is_empty());
    assert_eq!(run.transcript.rounds.len(), 5);
}

#[test]
fn missing_or_malformed_r5_counts_as_an_empty_list() {
    let reference = agreed(&honest(2, 3, 0x45), &[1, 2, 3]);
    for malformed in [false, true] {
        let run = run(2, 3, 0x45, |out| {
            if out.round() == 5 {
                if malformed {
                    out.replace(2, &[1, 0]);
                } else {
                    out.remove(2);
                }
            }
        });
        let output = agreed(&run, &[1, 2, 3]);
        assert!(output.reconstructed.is_empty());
        assert_eq!(output.qual, reference.qual);
        assert_eq!(
            output.public.master_public_key().encode(),
            reference.public.master_public_key().encode()
        );
    }
}

#[test]
fn false_extraction_complaints_are_refuted() {
    // Member 3 complains against dealer 1 with (a) a Pedersen-invalid pair
    // and (b) its genuine, Feldman-valid pair; neither triggers R6.
    for genuine in [false, true] {
        let mut deal = Vec::new();
        let run = run(2, 3, 0x46, |out| match out.round() {
            1 => deal = out.payload(1),
            5 => {
                let value = if genuine {
                    opened(out.fixture(), &deal, 1, 3)
                } else {
                    pair(5, 6)
                };
                let complaint = DkgExtractionComplaints {
                    complaints: vec![(idx(1), value)],
                };
                out.replace(3, &complaint.encode());
            }
            _ => {}
        });
        let output = agreed(&run, &[1, 2, 3]);
        assert!(output.reconstructed.is_empty());
        assert!(run.reconstruct.values().all(|r| !r));
    }
}

#[test]
fn corrupt_dealer_withholding_its_r6_is_recovered_and_kept() {
    let mut constants_seen = BTreeMap::new();
    let run = run(2, 3, 0x47, |out| match out.round() {
        4 => {
            constants(out, &mut constants_seen);
            let forged = vanishing_feldman(&out.payload(3), &[]);
            out.replace(3, &forged);
        }
        6 => out.remove(3),
        _ => {}
    });
    let output = agreed(&run, &[1, 2]);
    assert_eq!(output.qual, members(&[1, 2, 3]));
    assert_eq!(output.reconstructed, members(&[3]));
    assert_eq!(
        output.public.master_public_key().encode(),
        genuine_mpk(&constants_seen, &output.qual)
    );
}

#[test]
fn invalid_or_equivocated_r6_values_do_not_count() {
    // Dealer 3 is faulted; member 2 equivocates in R6 and member 3 sends an
    // invalid value. Only member 1's value is valid, below t = 2.
    let run = run(2, 3, 0x48, |out| match out.round() {
        4 => {
            let forged = vanishing_feldman(&out.payload(3), &[]);
            out.replace(3, &forged);
        }
        6 => {
            let changed = DkgReconstruction {
                values: vec![(idx(3), pair(1, 2))],
            };
            out.push(2, &changed.encode());
            out.replace(3, &changed.encode());
        }
        _ => {}
    });
    for i in [1, 2, 3] {
        assert!(matches!(run.outcomes[&i], Err(Error::InsufficientRecovery)));
    }
    assert!(matches!(run.verify(), Err(Error::InsufficientRecovery)));
}

#[test]
fn insufficient_valid_r6_values_abort_with_a_typed_error() {
    let run = run(2, 3, 0x49, |out| match out.round() {
        4 => {
            let forged = vanishing_feldman(&out.payload(3), &[]);
            out.replace(3, &forged);
        }
        6 => {
            out.remove(2);
            out.remove(3);
        }
        _ => {}
    });
    for i in [1, 2, 3] {
        assert!(matches!(run.outcomes[&i], Err(Error::InsufficientRecovery)));
    }
    assert!(matches!(run.verify(), Err(Error::InsufficientRecovery)));
}

#[test]
fn fewer_than_t_qualified_dealers_abort_with_a_typed_error() {
    let run = run(2, 3, 0x4a, |out| {
        if out.round() == 1 {
            out.remove(2);
            out.remove(3);
        }
    });
    for i in [1, 2, 3] {
        assert!(matches!(
            run.outcomes[&i],
            Err(Error::InsufficientQualified)
        ));
    }
    assert_eq!(run.transcript.rounds.len(), 3);
    assert!(matches!(run.verify(), Err(Error::InsufficientQualified)));
}

#[test]
fn missing_and_malformed_r1_disqualify() {
    let missing = run(3, 5, 0x4b, |out| {
        if out.round() == 1 {
            out.remove(4);
            let mut truncated = out.payload(5);
            truncated.pop();
            out.replace(5, &truncated);
        }
    });
    let output = agreed(&missing, &[1, 2, 3]);
    assert_eq!(
        output.disqualified,
        BTreeMap::from([
            (idx(4), DisqualifyReason::MissingDeal),
            (idx(5), DisqualifyReason::MalformedDeal)
        ])
    );
    let malformed = run(3, 5, 0x4c, |out| {
        if out.round() == 1 {
            let mut deal = DkgDeal::decode(&out.payload(5)).unwrap();
            deal.commitments.pop();
            out.replace(5, &deal.encode());
            let mut deal = DkgDeal::decode(&out.payload(4)).unwrap();
            deal.dealings.pop();
            out.replace(4, &deal.encode());
        }
    });
    let output = agreed(&malformed, &[1, 2, 3]);
    assert_eq!(
        output.disqualified,
        BTreeMap::from([
            (idx(4), DisqualifyReason::MalformedDeal),
            (idx(5), DisqualifyReason::MalformedDeal)
        ])
    );
}

// --------------------------------------------- authorization and state binding

#[test]
fn local_recipient_key_and_context_are_checked_before_any_randomness() {
    let f = fixture(2, 3, 0x50);
    let mut rng = counting();
    assert!(matches!(
        dkg_start(&f.ceremony, idx(1), f.secret(2), &mut rng),
        Err(Error::ContextMismatch)
    ));
    assert!(matches!(
        dkg_start(&f.ceremony, idx(4), f.secret(1), &mut rng),
        Err(Error::InvalidIndex)
    ));
    let signers = Signers::new();
    let (current, _) = crate::cert::tests::genesis(&signers);
    let (_, _, reshare) = crate::cert::tests::successor(
        &signers,
        &current,
        CeremonyKind::Reshare,
        Threshold::new(2, 3).unwrap(),
        // Seed 11 matches the genesis fixture, so the reshare keeps its mpk.
        11,
    );
    assert!(matches!(
        dkg_start(&reshare, idx(1), f.secret(1), &mut rng),
        Err(Error::InvalidCeremony)
    ));
    assert_eq!(rng.draws, 0);
    let (state, message) = dkg_start(&f.ceremony, idx(1), f.secret(1), &mut rng).unwrap();
    assert!(rng.draws > 0);
    assert_eq!(message.round(), 1);
    assert_eq!(format!("{state:?}"), "DkgDealt([REDACTED])");
}

fn close_for<M: Decode>(
    f: &Fixture,
    ceremony: &AuthorizedCeremony,
    round: u8,
    previous: &TranscriptHash,
    messages: &[SignedStatement],
) -> Result<ClosedRound<M>, Error> {
    let bytes = round_closure_body(ceremony, round, previous, messages)?;
    let closure = SignedStatement {
        signature: f.signers.sign(
            &f.signers.anchor().expected_owner,
            &round_closure_preimage(&bytes)?,
        ),
        bytes,
    };
    ClosedRound::<M>::verify(ceremony, round, previous, &closure, messages, &f.signers)
}

#[test]
fn transitions_refuse_other_ceremonies_rounds_and_histories() {
    let f = fixture(2, 3, 0x51);
    let other = fixture(2, 3, 0x52);
    let h0 = dkg_initial_transcript(&f.ceremony);
    let start = |i: u16| {
        let mut rng = f.member_rng(i);
        dkg_start(&f.ceremony, idx(i), f.secret(i), &mut rng).unwrap()
    };
    let r1: Vec<_> = (1..=3).map(|i| f.sign(i, &start(i).1)).collect();
    let closed1 = close_for::<DkgDeal>(&f, &f.ceremony, 1, &h0, &r1).unwrap();

    // Another authorized ceremony, its own correct history.
    let other_r1: Vec<_> = (1..=3)
        .map(|i| {
            let mut rng = other.member_rng(i);
            let (_, m) = dkg_start(&other.ceremony, idx(i), other.secret(i), &mut rng).unwrap();
            other.sign(i, &m)
        })
        .collect();
    let foreign = close_for::<DkgDeal>(
        &other,
        &other.ceremony,
        1,
        &dkg_initial_transcript(&other.ceremony),
        &other_r1,
    )
    .unwrap();
    assert!(matches!(
        start(1).0.complain(&foreign),
        Err(Error::InvalidRound)
    ));
    // The same messages are not accepted under this ceremony's closure.
    assert!(close_for::<DkgDeal>(&f, &f.ceremony, 1, &h0, &other_r1).is_err());

    // Correct ceremony, wrong previous link.
    let rebased =
        close_for::<DkgDeal>(&f, &f.ceremony, 1, &TranscriptHash::new([9; 32]), &r1).unwrap();
    assert!(matches!(
        start(1).0.complain(&rebased),
        Err(Error::InvalidRound)
    ));

    // A round-2 closure presented to the round-1 transition.
    let empty = DkgComplaints { dealers: vec![] }.encode();
    let r2_as_deal: Vec<_> = (1..=3)
        .map(|i| {
            let bytes =
                ceremony_message_body(&f.ceremony, 2, MemberCohort::Recipients, idx(i), &empty)
                    .unwrap();
            let preimage = crate::ceremony::ceremony_message_preimage(&bytes).unwrap();
            SignedStatement {
                signature: f.signers.sign(&Signers::did(i as u8), &preimage),
                bytes,
            }
        })
        .collect();
    let wrong_round = close_for::<DkgDeal>(&f, &f.ceremony, 2, &h0, &r2_as_deal).unwrap();
    assert!(matches!(
        start(1).0.complain(&wrong_round),
        Err(Error::InvalidRound)
    ));

    // Later phase: R3 chained to R1 instead of R2.
    let mut states = BTreeMap::new();
    for i in 1..=3u16 {
        states.insert(i, start(i).0);
    }
    let mut complained = BTreeMap::new();
    let mut r2 = Vec::new();
    for (i, s) in states {
        let (s, m) = s.complain(&closed1).unwrap();
        r2.push(f.sign(i, &m));
        complained.insert(i, s);
    }
    let closed2 =
        close_for::<DkgComplaints>(&f, &f.ceremony, 2, &closed1.transcript_hash(), &r2).unwrap();
    let mut r3 = Vec::new();
    let mut answered = BTreeMap::new();
    for (i, s) in complained {
        let (s, m) = s.answer(&closed2).unwrap();
        r3.push(f.sign(i, &m));
        answered.insert(i, s);
    }
    let skipped =
        close_for::<DkgAnswers>(&f, &f.ceremony, 3, &closed1.transcript_hash(), &r3).unwrap();
    let state = answered.remove(&1).unwrap();
    assert!(matches!(state.extract(&skipped), Err(Error::InvalidRound)));
    let chained =
        close_for::<DkgAnswers>(&f, &f.ceremony, 3, &closed2.transcript_hash(), &r3).unwrap();
    assert!(answered.remove(&2).unwrap().extract(&chained).is_ok());
}

#[test]
fn transitions_refuse_a_foreign_ceremony_closure_on_this_history() {
    // Same owner, round and previous link (this ceremony's H0); only the
    // authorized-ceremony digest differs.
    let f = fixture(2, 3, 0x5a);
    let other = fixture(2, 3, 0x5b);
    let h0 = dkg_initial_transcript(&f.ceremony);
    let other_r1: Vec<_> = (1..=3)
        .map(|i| {
            let mut rng = other.member_rng(i);
            let (_, m) = dkg_start(&other.ceremony, idx(i), other.secret(i), &mut rng).unwrap();
            other.sign(i, &m)
        })
        .collect();
    let foreign = close_for::<DkgDeal>(&other, &other.ceremony, 1, &h0, &other_r1).unwrap();
    assert_eq!(foreign.previous_hash(), h0);
    assert_eq!(foreign.round(), 1);
    assert_ne!(foreign.ceremony_digest(), f.ceremony.digest());
    let mut rng = f.member_rng(1);
    let (state, _) = dkg_start(&f.ceremony, idx(1), f.secret(1), &mut rng).unwrap();
    assert!(matches!(state.complain(&foreign), Err(Error::InvalidRound)));
}

#[test]
fn closed_rounds_reject_wrong_signers_cohorts_and_signatures() {
    let f = fixture(2, 3, 0x53);
    let h0 = dkg_initial_transcript(&f.ceremony);
    let mut rng = f.member_rng(1);
    let (_, message) = dkg_start(&f.ceremony, idx(1), f.secret(1), &mut rng).unwrap();
    let genuine = f.sign(1, &message);
    assert!(close_for::<DkgDeal>(&f, &f.ceremony, 1, &h0, std::slice::from_ref(&genuine)).is_ok());

    let mut wrong_signer = genuine.clone();
    wrong_signer.signature = f
        .signers
        .sign(&Signers::did(2), &message.signing_preimage());
    assert!(matches!(
        close_for::<DkgDeal>(&f, &f.ceremony, 1, &h0, &[wrong_signer]),
        Err(Error::InvalidSignature)
    ));
    let mut flipped = genuine.clone();
    flipped.signature[0] ^= 1;
    assert!(matches!(
        close_for::<DkgDeal>(&f, &f.ceremony, 1, &h0, &[flipped]),
        Err(Error::InvalidSignature)
    ));
    let mut current_cohort = genuine.clone();
    current_cohort.bytes[34] = MemberCohort::Current as u8;
    current_cohort.signature = f.signers.sign(
        &Signers::did(1),
        &crate::ceremony::ceremony_message_preimage(&current_cohort.bytes).unwrap(),
    );
    assert!(close_for::<DkgDeal>(&f, &f.ceremony, 1, &h0, &[current_cohort]).is_err());
}

// -------------------------------------------------------- public verifier

#[test]
fn verifier_recomputes_from_authenticated_records_only() {
    let run = run(2, 3, 0x54, |out| {
        if out.round() == 4 {
            let forged = vanishing_feldman(&out.payload(2), &[]);
            out.replace(2, &forged);
        }
    });
    let output = agreed(&run, &[1, 2, 3]);
    assert_eq!(output.reconstructed, members(&[2]));

    let mut tampered = DkgTranscript {
        rounds: run.transcript.rounds.clone(),
    };
    tampered.rounds[1].messages[0].signature[0] ^= 1;
    assert!(dkg_verify_transcript(&run.fixture.ceremony, &tampered, &run.fixture.signers).is_err());

    let mut swapped = DkgTranscript {
        rounds: run.transcript.rounds.clone(),
    };
    swapped.rounds.swap(2, 3);
    assert!(dkg_verify_transcript(&run.fixture.ceremony, &swapped, &run.fixture.signers).is_err());

    let other = fixture(2, 3, 0x55);
    assert!(dkg_verify_transcript(&other.ceremony, &run.transcript, &run.fixture.signers).is_err());

    let mut missing_r6 = DkgTranscript {
        rounds: run.transcript.rounds.clone(),
    };
    missing_r6.rounds.pop();
    assert!(matches!(
        dkg_verify_transcript(&run.fixture.ceremony, &missing_r6, &run.fixture.signers),
        Err(Error::InvalidRound)
    ));

    let plain = honest(2, 3, 0x56);
    let mut extra = DkgTranscript {
        rounds: plain.transcript.rounds.clone(),
    };
    extra.rounds.push(run.transcript.rounds[5].clone());
    assert!(matches!(
        dkg_verify_transcript(&plain.fixture.ceremony, &extra, &plain.fixture.signers),
        Err(Error::InvalidRound)
    ));
}

struct Refusing;
impl DidSignatureVerifier for Refusing {
    fn verify(&self, _: &Did, _: &[u8], _: &[u8]) -> Result<(), SignatureError> {
        panic!("size bound must precede signature verification")
    }
}

#[test]
fn transcript_bound_of_4_mib_precedes_verification() {
    let f = fixture(2, 3, 0x57);
    let record = |copies: usize| DkgRoundRecord {
        closure: SignedStatement {
            bytes: vec![0; 98],
            signature: vec![0; 64],
        },
        messages: vec![
            SignedStatement {
                bytes: vec![0; 65_536],
                signature: vec![0; 64],
            };
            copies
        ],
    };
    // 64 × (65 536 + 64) + 98 + 64 bytes exceeds 4 194 304.
    let over = DkgTranscript {
        rounds: vec![record(64)],
    };
    assert!(matches!(
        dkg_verify_transcript(&f.ceremony, &over, &Refusing),
        Err(Error::LimitExceeded)
    ));
    let split = DkgTranscript {
        rounds: vec![record(32), record(32)],
    };
    assert!(matches!(
        dkg_verify_transcript(&f.ceremony, &split, &Refusing),
        Err(Error::LimitExceeded)
    ));
    let under = DkgTranscript {
        rounds: vec![record(63)],
    };
    let result = dkg_verify_transcript(&f.ceremony, &under, &f.signers);
    assert!(result.is_err());
    assert!(!matches!(result, Err(Error::LimitExceeded)));
}

// ----------------------------------------------------- within-budget property

fn misbehave(out: &mut Outbox, m: u16, behaviour: u8, target: u16) {
    let present = out.has(m);
    match (out.round(), behaviour) {
        (1, 1) => out.remove(m),
        (1, 2) if present => {
            let mut p = out.payload(m);
            p.pop();
            out.replace(m, &p);
        }
        (1, 3) if present => {
            let second = bad_dealing(out, m, target);
            out.push(m, &second);
        }
        (1, 4) | (1, 5) if present => {
            let forged = bad_dealing(out, m, target);
            out.replace(m, &forged);
        }
        (2, 6) => out.replace(
            m,
            &DkgComplaints {
                dealers: vec![idx(target)],
            }
            .encode(),
        ),
        (2, 7) => out.push(m, &[1, 0, 1, 0, target as u8]),
        (3, 5) => out.remove(m),
        (3, 8) => out.replace(
            m,
            &DkgAnswers {
                answers: vec![(idx(target), pair(5, 6))],
            }
            .encode(),
        ),
        (4, 9) if present => {
            let forged = vanishing_feldman(&out.payload(m), &[m]);
            out.replace(m, &forged);
        }
        (4, 10) => out.remove(m),
        (4, 11) if present => {
            let mut p = out.payload(m);
            p.push(0);
            out.replace(m, &p);
        }
        (4, 12) if present => {
            let second = vanishing_feldman(&out.payload(m), &[]);
            out.push(m, &second);
        }
        (5, 13) => out.replace(
            m,
            &DkgExtractionComplaints {
                complaints: vec![(idx(target), pair(5, 6))],
            }
            .encode(),
        ),
        (6, 13) | (5, 14) | (6, 14) => out.remove(m),
        _ => {}
    }
}

/// The `misbehave` model has 15 behaviours per faulty member.
const BEHAVIOURS: u8 = 15;
/// Fixed fixture seeds; each shape is enumerated under both.
const ENUMERATION_SEEDS: [u8; 2] = [0x01, 0x9c];

// Coverage: the enumeration below runs every behaviour assignment of the
// in-tree `misbehave` model to the last f members, where f is the genesis
// fault budget: t−1 for 2-of-3 and 3-of-5, and 1 for 3-of-4. Under two fixed
// seeds that is 2 × (15 + 15 + 15 × 15) = 510 ceremonies. It covers this
// model only, with honest messages always delivered by the relay; it is not a
// claim about arbitrary faulty behaviour, other seeds or other parameters.

/// One within-budget run: faulty members are the last `behaviours.len()`
/// indices; every honest member and the verifier agree, honest dealers stay in
/// QUAL, and mpk is the sum of the QUAL dealers' committed constants.
fn within_budget_agreement(t: u16, n: u16, seed: u8, behaviours: &[u8]) {
    let f = behaviours.len() as u16;
    assert!(f < t && n - f >= t, "{t}-of-{n} with {f} faulty");
    let honest_members: Vec<u16> = (1..=n - f).collect();
    let faulty: Vec<u16> = (n - f + 1..=n).collect();
    let mut constants_seen = BTreeMap::new();
    let run = run(t, n, seed, |out| {
        if out.round() == 4 {
            constants(out, &mut constants_seen);
        }
        for (m, behaviour) in faulty.iter().zip(behaviours) {
            misbehave(out, *m, *behaviour, 1);
        }
    });
    let output = agreed(&run, &honest_members);
    let faulty_set = members(&faulty);
    assert!(
        members(&honest_members).is_subset(&output.qual),
        "{behaviours:?}"
    );
    assert!(
        output.disqualified.keys().all(|i| faulty_set.contains(i)),
        "{behaviours:?}"
    );
    assert!(
        output.reconstructed.is_subset(&faulty_set),
        "{behaviours:?}"
    );
    assert_eq!(
        output.public.master_public_key().encode(),
        genuine_mpk(&constants_seen, &output.qual),
        "{behaviours:?}"
    );
}

#[test]
fn every_within_budget_fault_pattern_finishes_with_identical_outcomes_2of3() {
    for seed in ENUMERATION_SEEDS {
        for behaviour in 0..BEHAVIOURS {
            within_budget_agreement(2, 3, seed, &[behaviour]);
        }
    }
}

#[test]
fn every_within_budget_fault_pattern_finishes_with_identical_outcomes_3of4() {
    for seed in ENUMERATION_SEEDS {
        for behaviour in 0..BEHAVIOURS {
            within_budget_agreement(3, 4, seed, &[behaviour]);
        }
    }
}

#[test]
fn every_within_budget_fault_pattern_finishes_with_identical_outcomes_3of5() {
    for seed in ENUMERATION_SEEDS {
        for first in 0..BEHAVIOURS {
            for second in 0..BEHAVIOURS {
                within_budget_agreement(3, 5, seed, &[first, second]);
            }
        }
    }
}
