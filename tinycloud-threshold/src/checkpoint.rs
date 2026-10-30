use super::*;
use crate::curve::{hash_g1, Scalar, G1, G2};
use proptest::prelude::*;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

pub(crate) fn dealer(seed: u8, context: KeyContext) -> (PublicKeySet, Vec<KeyShare>, Scalar) {
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    let coefficients: Vec<_> = (0..context.threshold().t())
        .map(|_| Scalar::random(&mut rng, true))
        .collect();
    let public_shares = (1..=context.threshold().n())
        .map(|i| {
            let index = MemberIndex::new(i).unwrap();
            (
                index,
                G2::generator().mul(&crate::poly::evaluate(
                    &coefficients,
                    &Scalar::from_u64(u64::from(i)),
                )),
            )
        })
        .collect();
    let shares = (1..=context.threshold().n())
        .map(|i| KeyShare {
            context: context.clone(),
            index: MemberIndex::new(i).unwrap(),
            scalar: crate::poly::evaluate(&coefficients, &Scalar::from_u64(u64::from(i))),
        })
        .collect();
    let public = PublicKeySet {
        context,
        mpk: MasterPublicKey(G2::generator().mul(&coefficients[0])),
        public_shares,
    };
    (
        public,
        shares,
        Scalar::from_bytes(&coefficients[0].to_bytes()).unwrap(),
    )
}

pub(crate) fn context() -> KeyContext {
    KeyContext::test(
        NetworkUrn::new("tinycloud:test:network").unwrap(),
        RekeyCounter::new(0),
        Epoch::new(0),
        CertDigest::new([7; 32]),
        Threshold::new(2, 3).unwrap(),
    )
}
pub(crate) fn identity(ctx: &KeyContext, path: &str) -> IbeIdentity {
    IbeIdentity::record(
        ctx.network(),
        &KeyPath::new(path).unwrap(),
        KeyVersion::new(4),
        &WriteNonce::new([9; 16]),
    )
    .unwrap()
}
pub(crate) fn authorize(req: DecryptRequest) -> AuthorizedDerivation {
    let id = req.identity().clone();
    AuthorizedDerivation::from_capability_check(req, id.network(), id.key_path(), id.key_version())
        .unwrap()
}
fn setup(
    seed: u8,
) -> (
    PublicKeySet,
    Vec<KeyShare>,
    TransportSecretKey,
    DecryptRequest,
    Vec<EncryptedKeyShare>,
) {
    let (public, shares, _) = dealer(seed, context());
    let mut rng = ChaCha20Rng::from_seed([seed.wrapping_add(1); 32]);
    let tsk = TransportSecretKey::generate(&mut rng);
    let req = DecryptRequest::new(
        public.context(),
        identity(public.context(), "records/key"),
        tsk.public_key(),
    )
    .unwrap();
    let auth = authorize(req.clone());
    let issued = shares
        .iter()
        .map(|s| issue_share(s, &auth, &mut rng).unwrap())
        .collect();
    (public, shares, tsk, req, issued)
}

#[test]
fn signing_preimage_rejects_changed_record_nonce() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../vectors/v1/primitives.json")).unwrap();
    let threshold = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == "threshold_2of3")
        .unwrap();
    let request_bytes = hex::decode(threshold["inputs"]["request"].as_str().unwrap()).unwrap();
    let request = DecryptRequest::decode(&request_bytes).unwrap();
    let response = &threshold["outputs"]["encrypted_shares"][0];
    let share =
        EncryptedKeyShare::decode(&hex::decode(response["encoded"].as_str().unwrap()).unwrap())
            .unwrap();
    let expected = hex::decode(response["signing_preimage"].as_str().unwrap()).unwrap();
    assert_eq!(share.signing_preimage(&request), Ok(expected));

    let mut changed = request_bytes;
    let last_nonce = changed.len() - 49;
    changed[last_nonce] ^= 1;
    let other_request = DecryptRequest::decode(&changed).unwrap();
    assert_eq!(other_request.context_digest, request.context_digest);
    assert_eq!(other_request.tpk, request.tpk);
    assert_ne!(other_request.identity().nonce(), request.identity().nonce());
    assert_ne!(share.request_digest, *other_request.digest().as_bytes());
    assert_eq!(
        share.signing_preimage(&other_request),
        Err(Error::ContextMismatch)
    );
}

#[test]
fn p3_combine_accepts_exact_raw_limit() {
    let (public, _, tsk, req, issued) = setup(11);
    let repeated: [EncryptedKeyShare; 6] =
        std::array::from_fn(|i| issued[i % issued.len()].clone());
    let aggregate = combine(&public, &req, &repeated).unwrap();
    let key = decrypt_derived_key(&aggregate, &tsk, &public, &req).unwrap();
    let data = DataKey::new([0x42; 32]);
    let ciphertext = wrap_key(
        public.master_public_key(),
        req.identity(),
        &data,
        &mut ChaCha20Rng::from_seed([12; 32]),
    )
    .unwrap();
    assert_eq!(
        unwrap_key(&key, req.identity(), &ciphertext)
            .unwrap()
            .as_bytes(),
        data.as_bytes()
    );
}

#[test]
fn p3_combine_counts_duplicate_members_once_at_limit() {
    let (public, _, _, req, issued) = setup(11);
    let repeated: [EncryptedKeyShare; 6] = std::array::from_fn(|_| issued[0].clone());
    assert!(matches!(
        combine(&public, &req, &repeated),
        Err(CombineError::NotEnoughShares)
    ));
}

#[test]
fn p3_combine_rejects_above_raw_limit() {
    let (public, _, _, req, issued) = setup(11);
    for share in &issued {
        assert_eq!(verify_share(&public, &req, share), Ok(()));
    }
    let too_many: [EncryptedKeyShare; 7] =
        std::array::from_fn(|i| issued[i % issued.len()].clone());
    let result = combine(&public, &req, &too_many);
    let maximum = 2 * usize::from(public.context().threshold().n());
    assert!(
        result.is_err(),
        "combine accepted {} raw entries above 2*n={maximum}",
        too_many.len()
    );
    assert_eq!(result.err(), Some(CombineError::TooManyShares));
}

#[test]
fn p3_combine_limit_precedes_context_and_share_checks() {
    let (public, _, _, req, issued) = setup(11);
    let mut too_many: [EncryptedKeyShare; 7] =
        std::array::from_fn(|i| issued[i % issued.len()].clone());
    let mut other_request = req.clone();
    other_request.context_digest[0] ^= 1;
    assert_eq!(
        combine(&public, &other_request, &too_many).unwrap_err(),
        CombineError::TooManyShares
    );
    too_many[6].context_digest[0] ^= 1;
    assert_eq!(
        combine(&public, &req, &too_many).unwrap_err(),
        CombineError::TooManyShares
    );
    too_many[6].context_digest[0] ^= 1;
    too_many[6].c3 = G1::identity();
    assert_eq!(
        combine(&public, &req, &too_many).unwrap_err(),
        CombineError::TooManyShares
    );
}

#[test]
fn p3_verify_share_rejects_canonical_identity_c3_mutation() {
    let (public, _, _, req, issued) = setup(11);
    assert_eq!(verify_share(&public, &req, &issued[0]), Ok(()));
    assert!(!issued[0].c3.is_identity());
    let mut changed = issued[0].clone();
    changed.c3 = G1::identity();
    let changed = EncryptedKeyShare::decode(&changed.encode()).unwrap();
    assert_eq!(
        verify_share(&public, &req, &changed),
        Err(ShareError::Invalid {
            member: issued[0].index()
        })
    );
}

#[test]
fn checkpoint_2of3() {
    let (public, shares, tsk, req, issued) = setup(11);
    assert_eq!(public.context().threshold(), Threshold::new(2, 3).unwrap());
    assert_eq!(public.context().epoch(), Epoch::new(0));
    assert_eq!(public.context().rekey(), RekeyCounter::new(0));
    println!(
        "1. PASS: 2-of-3 test-dealer key; network, rekey=0, epoch=0 and certificate context bound"
    );
    let data = DataKey::new([0x42; 32]);
    let ct = wrap_key(
        public.master_public_key(),
        req.identity(),
        &data,
        &mut ChaCha20Rng::from_seed([12; 32]),
    )
    .unwrap();
    assert_eq!(ct.encode().len(), 160);
    println!("2. PASS: 32-byte data key wrapped to record identity under mpk");
    assert_eq!(issued.len(), 3);
    assert!(shares
        .iter()
        .zip(&issued)
        .all(|(s, i)| s.index() == i.index()));
    println!(
        "3. PASS: capability-authorized derivation; all three members issued encrypted shares"
    );
    for share in &issued {
        verify_share(&public, &req, share).unwrap();
    }
    println!("4. PASS: reader verified each encrypted share");
    let mut keys = Vec::new();
    for (a, b) in [(0, 1), (0, 2), (1, 2)] {
        let encrypted = combine(&public, &req, &[issued[a].clone(), issued[b].clone()]).unwrap();
        let key = decrypt_derived_key(&encrypted, &tsk, &public, &req).unwrap();
        assert_eq!(
            unwrap_key(&key, req.identity(), &ct).unwrap().as_bytes(),
            data.as_bytes()
        );
        keys.push(key.key.encode());
    }
    assert!(keys.windows(2).all(|p| p[0] == p[1]));
    println!("5. PASS: pairs {{1,2}}, {{1,3}}, {{2,3}} derived the same key and unwrapped the original data key");
    let mut bad = issued[1].clone();
    bad.c3 = bad.c3.add(&G1::generator());
    assert_eq!(
        verify_share(&public, &req, &bad),
        Err(ShareError::Invalid {
            member: bad.index()
        })
    );
    println!("6. PASS: mutated c3 rejected as Invalid {{ member: 2 }}");
    assert!(matches!(
        combine(&public, &req, &issued[..1]),
        Err(CombineError::NotEnoughShares)
    ));
    println!("7. PASS: one valid share returned NotEnoughShares");
    for field in 0..4 {
        let mut changed = public.context().clone();
        match field {
            0 => changed.certificate = CertDigest::new([8; 32]),
            1 => changed.network = NetworkUrn::new("tinycloud:other:network").unwrap(),
            2 => changed.epoch = Epoch::new(1),
            _ => changed.rekey = RekeyCounter::new(1),
        }
        let other_id = identity(&changed, "records/key");
        let other_req = DecryptRequest::new(&changed, other_id, tsk.public_key()).unwrap();
        assert_eq!(
            verify_share(&public, &other_req, &issued[0]),
            Err(ShareError::ContextMismatch)
        );
        assert!(matches!(
            issue_share(
                &shares[0],
                &authorize(other_req.clone()),
                &mut ChaCha20Rng::from_seed([0; 32])
            ),
            Err(Error::ContextMismatch)
        ));
        let (other_public, _, _) = dealer(11, changed);
        assert_eq!(
            verify_share(&other_public, &other_req, &issued[0]),
            Err(ShareError::ContextMismatch)
        );
        assert!(matches!(
            combine(&other_public, &other_req, &issued),
            Err(CombineError::MixedContexts)
        ));
    }
    println!("8. PASS: certificate, network, epoch and rekey transplants returned ContextMismatch before algebra");
    let other_req = DecryptRequest::new(
        public.context(),
        identity(public.context(), "records/other"),
        tsk.public_key(),
    )
    .unwrap();
    let auth = authorize(other_req.clone());
    let mut rng = ChaCha20Rng::from_seed([15; 32]);
    let other_shares: Vec<_> = shares
        .iter()
        .map(|s| issue_share(s, &auth, &mut rng).unwrap())
        .collect();
    let ek = combine(&public, &other_req, &other_shares).unwrap();
    let other_key = decrypt_derived_key(&ek, &tsk, &public, &other_req).unwrap();
    assert!(matches!(
        unwrap_key(&other_key, req.identity(), &ct),
        Err(Error::WrongIdentity)
    ));
    println!("9. PASS: key for another identity returned WrongIdentity");
}

#[test]
fn request_transplants_fail_before_algebra() {
    let (public, shares, tsk, req, issued) = setup(21);
    let mut mutations = Vec::new();
    let mut r = req.clone();
    r.identity = identity(public.context(), "other/path");
    mutations.push(r);
    let mut r = req.clone();
    r.tpk = TransportSecretKey::generate(&mut ChaCha20Rng::from_seed([99; 32])).public_key();
    mutations.push(r);
    let mut r = req.clone();
    r.context_digest[0] ^= 1;
    mutations.push(r);
    let mut r = req.clone();
    r.certificate = CertDigest::new([1; 32]);
    mutations.push(r);
    let mut r = req.clone();
    r.network = NetworkUrn::new("other:network").unwrap();
    mutations.push(r);
    let mut r = req.clone();
    r.epoch = Epoch::new(1);
    mutations.push(r);
    let mut r = req.clone();
    r.rekey = RekeyCounter::new(1);
    mutations.push(r);
    for r in mutations {
        assert_eq!(
            verify_share(&public, &r, &issued[0]),
            Err(ShareError::ContextMismatch)
        );
        assert!(matches!(
            combine(&public, &r, &issued),
            Err(CombineError::ContextMismatch | CombineError::MixedContexts)
        ));
        if r.identity == *req.identity() {
            if let Ok(auth) = AuthorizedDerivation::from_capability_check(
                r,
                req.identity().network(),
                req.identity().key_path(),
                req.identity().key_version(),
            ) {
                if auth.request.context_digest != req.context_digest
                    || auth.request.certificate != req.certificate
                    || auth.request.epoch != req.epoch
                    || auth.request.rekey != req.rekey
                    || auth.request.network != req.network
                {
                    assert!(matches!(
                        issue_share(&shares[0], &auth, &mut ChaCha20Rng::from_seed([1; 32])),
                        Err(Error::ContextMismatch)
                    ));
                }
            }
        }
    }
    let mut mixed = issued.clone();
    mixed[2].context_digest = [0; 32];
    assert!(matches!(
        combine(&public, &req, &mixed),
        Err(CombineError::MixedContexts)
    ));
    let ek = combine(&public, &req, &issued).unwrap();
    let wrong_tsk = TransportSecretKey::generate(&mut ChaCha20Rng::from_seed([88; 32]));
    assert!(matches!(
        decrypt_derived_key(&ek, &wrong_tsk, &public, &req),
        Err(Error::ContextMismatch)
    ));
    assert!(decrypt_derived_key(&ek, &tsk, &public, &req).is_ok());
}

#[test]
fn both_share_equations_and_deduplication() {
    let (public, _, _, req, issued) = setup(31);
    for field in 0..3 {
        let mut bad = issued[0].clone();
        match field {
            0 => bad.c1 = bad.c1.add(&G1::generator()),
            1 => bad.c2 = bad.c2.add(&G2::generator()),
            _ => bad.c3 = bad.c3.add(&G1::generator()),
        }
        assert_eq!(
            verify_share(&public, &req, &bad),
            Err(ShareError::Invalid {
                member: bad.index()
            })
        );
        assert!(matches!(
            combine(&public, &req, &[issued[1].clone(), issued[2].clone(), bad]),
            Err(CombineError::Invalid { .. })
        ));
    }
    assert!(matches!(
        combine(&public, &req, &[issued[0].clone(), issued[0].clone()]),
        Err(CombineError::NotEnoughShares)
    ));
    let a = combine(&public, &req, &issued).unwrap();
    let b = combine(
        &public,
        &req,
        &[issued[1].clone(), issued[0].clone(), issued[0].clone()],
    )
    .unwrap();
    assert_eq!(a.c1, b.c1);
    assert_eq!(a.c2, b.c2);
    assert_eq!(a.c3, b.c3);
    let mut outside = issued[0].clone();
    outside.member = MemberIndex::new(4).unwrap();
    assert_eq!(
        verify_share(&public, &req, &outside),
        Err(ShareError::ContextMismatch)
    );
    assert_ne!(
        issued[0].signing_preimage(&req).unwrap(),
        issued[1].signing_preimage(&req).unwrap()
    );
}

#[test]
fn fullident_integrity_degenerate_randomness_and_redacted_secrets() {
    let (public, shares, tsk, req, issued) = setup(41);
    let ek = combine(&public, &req, &issued).unwrap();
    let key = decrypt_derived_key(&ek, &tsk, &public, &req).unwrap();
    let data = DataKey::new([0x5a; 32]);
    let ct = wrap_key(
        public.master_public_key(),
        req.identity(),
        &data,
        &mut ChaCha20Rng::from_seed([42; 32]),
    )
    .unwrap();
    for field in 0..3 {
        let mut bad = ct.clone();
        match field {
            0 => bad.u = bad.u.add(&G2::generator()),
            1 => bad.v[0] ^= 1,
            _ => bad.w[0] ^= 1,
        }
        assert!(matches!(
            unwrap_key(&key, req.identity(), &bad),
            Err(Error::InvalidCiphertext)
        ));
    }
    assert!(matches!(
        crate::ibe::wrap_with_rho(
            public.master_public_key(),
            req.identity(),
            &data,
            zeroize::Zeroizing::new([0; 32]),
            Scalar::from_u64(0)
        ),
        Err(Error::DegenerateRandomness)
    ));
    assert_eq!(format!("{data:?}"), "DataKey([REDACTED])");
    assert_eq!(format!("{tsk:?}"), "TransportSecretKey([REDACTED])");
    assert_eq!(format!("{key:?}"), "DerivedKey([REDACTED])");
    assert_eq!(format!("{:?}", shares[0]), "KeyShare([REDACTED])");
}

#[test]
fn decoded_structures_enforce_roles_lengths_and_network() {
    let (public, _, tsk, req, issued) = setup(51);
    assert_eq!(
        DecryptRequest::decode(&req.encode()).unwrap().encode(),
        req.encode()
    );
    let encoded = issued[0].encode();
    assert_eq!(
        EncryptedKeyShare::decode(&encoded).unwrap().encode(),
        encoded
    );
    let ct = wrap_key(
        public.master_public_key(),
        req.identity(),
        &DataKey::new([1; 32]),
        &mut ChaCha20Rng::from_seed([52; 32]),
    )
    .unwrap();
    for bytes in [&[][..], &ct.encode()[..159], &[0; 161][..]] {
        assert!(IbeCiphertext::decode(bytes).is_err());
    }
    for bytes in [req.encode(), encoded.clone()] {
        for cut in 0..bytes.len() {
            if bytes.len() == encoded.len() {
                assert!(EncryptedKeyShare::decode(&bytes[..cut]).is_err());
            } else {
                assert!(DecryptRequest::decode(&bytes[..cut]).is_err());
            }
        }
    }
    let mut r = req.encode();
    r.push(0);
    assert!(DecryptRequest::decode(&r).is_err());
    let mut s = encoded.clone();
    s.push(0);
    assert!(EncryptedKeyShare::decode(&s).is_err());
    for index in [0u16, 17] {
        let mut s = encoded.clone();
        s[1..3].copy_from_slice(&index.to_be_bytes());
        assert!(EncryptedKeyShare::decode(&s).is_err());
    }
    let mut s = issued[0].clone();
    s.c3 = G1::identity();
    assert_eq!(
        EncryptedKeyShare::decode(&s.encode()).unwrap().c3,
        G1::identity()
    );
    for field in 0..2 {
        let mut s = issued[0].clone();
        if field == 0 {
            s.c1 = G1::identity();
        } else {
            s.c2 = G2::identity();
        }
        assert!(EncryptedKeyShare::decode(&s.encode()).is_err());
    }
    let mut r = req.clone();
    r.network = NetworkUrn::new("other:network").unwrap();
    assert!(matches!(
        DecryptRequest::decode(&r.encode()),
        Err(Error::ContextMismatch)
    ));
    assert!(matches!(
        DecryptRequest::new(
            public.context(),
            identity(
                &KeyContext::test(
                    NetworkUrn::new("other:network").unwrap(),
                    RekeyCounter::new(0),
                    Epoch::new(0),
                    CertDigest::new([7; 32]),
                    Threshold::new(2, 3).unwrap()
                ),
                "key"
            ),
            tsk.public_key()
        ),
        Err(Error::ContextMismatch)
    ));
    assert!(TransportPublicKey::decode(&G1::identity().encode()).is_err());
    assert!(MasterPublicKey::decode(&G2::identity().encode()).is_err());
    let mut r = req.encode();
    r[33..37].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(matches!(
        DecryptRequest::decode(&r),
        Err(Error::LimitExceeded)
    ));
}

#[test]
fn all_threshold_subsets_and_zero_aggregate_masks() {
    for t in 2..=4u16 {
        let ctx = KeyContext::test(
            NetworkUrn::new("subsets").unwrap(),
            RekeyCounter::new(0),
            Epoch::new(0),
            CertDigest::new([3; 32]),
            Threshold::new(t, t + 2).unwrap(),
        );
        let (public, shares, master) = dealer(81, ctx);
        let mut rng = ChaCha20Rng::from_seed([82; 32]);
        let tsk = TransportSecretKey::generate(&mut rng);
        let req = DecryptRequest::new(
            public.context(),
            identity(public.context(), "key"),
            tsk.public_key(),
        )
        .unwrap();
        let auth = authorize(req.clone());
        let issued: Vec<_> = shares
            .iter()
            .map(|s| issue_share(s, &auth, &mut rng).unwrap())
            .collect();
        for mask in 0u32..(1u32 << issued.len()) {
            if mask.count_ones() != u32::from(t) {
                continue;
            }
            let selected: Vec<_> = issued
                .iter()
                .enumerate()
                .filter(|(i, _)| mask & (1 << i) != 0)
                .map(|(_, s)| s.clone())
                .collect();
            let aggregate = combine(&public, &req, &selected).unwrap();
            let key = decrypt_derived_key(&aggregate, &tsk, &public, &req).unwrap();
            assert_eq!(
                key.key.encode(),
                hash_g1(req.identity().as_bytes(), dst::H1)
                    .mul(&master)
                    .encode()
            );
        }
    }
    let (public, shares, tsk, req, mut issued) = setup(83);
    let h = hash_g1(req.identity().as_bytes(), dst::H1);
    // For indices 1,2 the weights are 2,-1: r1=1,r2=2 cancel both masks.
    for (i, share) in issued.iter_mut().take(2).enumerate() {
        let r = Scalar::from_u64((i + 1) as u64);
        share.c1 = G1::generator().mul(&r);
        share.c2 = G2::generator().mul(&r);
        share.c3 = h.mul(&shares[i].scalar).add(&req.tpk.0.mul(&r));
    }
    let aggregate = combine(&public, &req, &issued[..2]).unwrap();
    assert!(aggregate.c1.is_identity());
    assert!(aggregate.c2.is_identity());
    let key = decrypt_derived_key(&aggregate, &tsk, &public, &req).unwrap();
    let data = DataKey::new([0x66; 32]);
    let ct = wrap_key(
        public.master_public_key(),
        req.identity(),
        &data,
        &mut ChaCha20Rng::from_seed([84; 32]),
    )
    .unwrap();
    assert_eq!(
        unwrap_key(&key, req.identity(), &ct).unwrap().as_bytes(),
        data.as_bytes()
    );
}

proptest! {
    #[test]
    fn threshold_roundtrip_property(seed in any::<u8>(), plaintext in any::<[u8;32]>(), nonce in any::<[u8;16]>()) {
        let (public, shares, master) = dealer(seed, context());
        let mut rng = ChaCha20Rng::from_seed([seed.wrapping_add(2);32]);
        let tsk = TransportSecretKey::generate(&mut rng);
        let id = IbeIdentity::record(public.context().network(), &KeyPath::new("a/b").unwrap(), KeyVersion::new(1), &WriteNonce::new(nonce)).unwrap();
        let req = DecryptRequest::new(public.context(), id, tsk.public_key()).unwrap();
        let auth = authorize(req.clone());
        let issued: Vec<_> = shares.iter().map(|s| issue_share(s, &auth, &mut rng).unwrap()).collect();
        let ct = wrap_key(public.master_public_key(), req.identity(), &DataKey::new(plaintext), &mut rng).unwrap();
        for (a,b) in [(0,1),(0,2),(1,2)] {
            let ek = combine(&public,&req,&[issued[a].clone(),issued[b].clone()]).unwrap();
            let dk = decrypt_derived_key(&ek,&tsk,&public,&req).unwrap();
            prop_assert_eq!(dk.key.encode(), hash_g1(req.identity().as_bytes(),dst::H1).mul(&master).encode());
            let unwrapped = unwrap_key(&dk,req.identity(),&ct).unwrap();
            prop_assert_eq!(unwrapped.as_bytes(), &plaintext);
        }
    }
    #[test]
    fn derivation_decoders_reject_or_canonical(bytes in proptest::collection::vec(any::<u8>(),0..1200)) {
        if let Ok(v) = DecryptRequest::decode(&bytes) { prop_assert_eq!(v.encode(), bytes.clone()); }
        if let Ok(v) = EncryptedKeyShare::decode(&bytes) { prop_assert_eq!(v.encode(), bytes.clone()); }
        if let Ok(v) = IbeCiphertext::decode(&bytes) { let encoded = v.encode(); prop_assert_eq!(encoded.as_slice(), bytes.as_slice()); }
    }
    #[test]
    fn structured_derivation_mutations_reject_or_canonical(offset in 0usize..1024, mask in 1u8..=255) {
        let (public, _, _, req, issued) = setup(61);
        let ct = wrap_key(public.master_public_key(),req.identity(),&DataKey::new([3;32]),&mut ChaCha20Rng::from_seed([62;32])).unwrap();
        let mut r=req.encode(); let n=r.len(); r[offset % n]^=mask;
        if let Ok(v)=DecryptRequest::decode(&r) { prop_assert_eq!(v.encode(),r); }
        let mut s=issued[0].encode(); let n=s.len(); s[offset % n]^=mask;
        if let Ok(v)=EncryptedKeyShare::decode(&s) { prop_assert_eq!(v.encode(),s); }
        let mut c=ct.encode(); let n=c.len(); c[offset % n]^=mask;
        if let Ok(v)=IbeCiphertext::decode(&c) { prop_assert_eq!(v.encode(),c); }
    }
}
