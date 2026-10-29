//! Deterministic public fixtures; all scalar/seed inputs here are test material.
use super::*;
use crate::{
    checkpoint::{authorize, context, dealer, identity},
    curve::{hash_g1, hash_g2, pairing, Scalar, G1, G2},
};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use serde_json::{json, Value};

fn primitives() -> Value {
    let ctx = context();
    let (public, shares, master) = dealer(71, ctx.clone());
    let id = identity(&ctx, "records/vector");
    let mut transport_rng = ChaCha20Rng::from_seed([72; 32]);
    let tsk = TransportSecretKey::generate(&mut transport_rng);
    let req = DecryptRequest::new(&ctx, id.clone(), tsk.public_key()).unwrap();
    let auth = authorize(req.clone());
    let mut share_rng = ChaCha20Rng::from_seed([73; 32]);
    let issued: Vec<_> = shares
        .iter()
        .map(|s| issue_share(s, &auth, &mut share_rng).unwrap())
        .collect();
    let aggregate = combine(&public, &req, &issued[..2]).unwrap();
    let derived = decrypt_derived_key(&aggregate, &tsk, &public, &req).unwrap();
    let data = DataKey::new([0x34; 32]);
    let mut sigma = [0; 32];
    ChaCha20Rng::from_seed([74; 32]).fill_bytes(&mut sigma);
    let ct = wrap_key(
        public.master_public_key(),
        &id,
        &data,
        &mut ChaCha20Rng::from_seed([74; 32]),
    )
    .unwrap();
    let gt = pairing(&G1::generator(), &G2::generator()).encode();
    let gt2 = pairing(
        &G1::generator().mul(&Scalar::from_u64(5)),
        &G2::generator().mul(&Scalar::from_u64(7)),
    )
    .encode();
    let h3_input = [0x25; 64];
    let public_shares: Vec<_> = public
        .public_shares
        .iter()
        .map(|(i, p)| json!({"member":i.get(),"point":hex::encode(p.encode())}))
        .collect();
    let scalar_shares: Vec<_> = shares
        .iter()
        .map(|s| json!({"member":s.index().get(),"scalar":hex::encode(s.scalar.to_bytes())}))
        .collect();
    let encrypted_shares:Vec<_>=issued.iter().map(|s|json!({"member":s.index().get(),"encoded":hex::encode(s.encode()),"c1":hex::encode(s.c1.encode()),"c2":hex::encode(s.c2.encode()),"c3":hex::encode(s.c3.encode()),"signing_preimage":hex::encode(s.signing_preimage(&req))})).collect();
    let mut bad_share = issued[0].clone();
    bad_share.c3 = bad_share.c3.add(&G1::generator());
    let mut wrong_context = issued[0].clone();
    wrong_context.context_digest = [0; 32];
    let mut wrong_request = req.clone();
    wrong_request.identity = identity(&ctx, "records/other");
    let mut cases = vec![
        json!({"name":"h1_custom_dst","operation":"hash_g1","inputs":{"message":hex::encode(id.as_bytes()),"dst":String::from_utf8_lossy(dst::H1)},"outputs":{"point":hex::encode(hash_g1(id.as_bytes(),dst::H1).encode())}}),
        json!({"name":"pedersen_h","operation":"hash_g2","inputs":{"message":hex::encode(b"pedersen-h"),"dst":String::from_utf8_lossy(dst::PEDERSEN_H)},"outputs":{"point":hex::encode(hash_g2(b"pedersen-h",dst::PEDERSEN_H).encode())}}),
        json!({"name":"h3_scalar_r","operation":"h3","inputs":{"message":hex::encode(h3_input)},"outputs":{"scalar":hex::encode(dst::h3(&h3_input).to_bytes())}}),
        json!({"name":"h2_gt","operation":"h2","inputs":{"message":hex::encode(gt)},"outputs":{"bytes":hex::encode(dst::h2(&gt))}}),
        json!({"name":"h4_sigma","operation":"h4","inputs":{"message":hex::encode(sigma)},"outputs":{"bytes":hex::encode(dst::h4(&sigma))}}),
        json!({"name":"pairing_generators","operation":"pairing","inputs":{"g1":hex::encode(G1::generator().encode()),"g2":hex::encode(G2::generator().encode())},"outputs":{"gt":hex::encode(gt)}}),
        json!({"name":"pairing_5_7","operation":"pairing","inputs":{"g1":hex::encode(G1::generator().mul(&Scalar::from_u64(5)).encode()),"g2":hex::encode(G2::generator().mul(&Scalar::from_u64(7)).encode())},"outputs":{"gt":hex::encode(gt2)}}),
        json!({"name":"fullident_wrap_unwrap","operation":"fullident","inputs":{"master_scalar":hex::encode(master.to_bytes()),"mpk":hex::encode(public.master_public_key().encode()),"identity":hex::encode(id.as_bytes()),"message":hex::encode(data.as_bytes()),"sigma":hex::encode(sigma)},"outputs":{"ciphertext":hex::encode(ct.encode()),"derived_key":hex::encode(derived.key.encode()),"unwrapped":hex::encode(unwrap_key(&derived,&id,&ct).unwrap().as_bytes())}}),
        json!({"name":"threshold_2of3","operation":"threshold","inputs":{"context":hex::encode(ctx.encode()),"context_digest":hex::encode(ctx.digest()),"certificate_digest":hex::encode(ctx.certificate().as_bytes()),"threshold":2,"members":3,"master_scalar":hex::encode(master.to_bytes()),"mpk":hex::encode(public.master_public_key().encode()),"public_shares":public_shares,"scalar_shares":scalar_shares,"transport_scalar":hex::encode(tsk.0.to_bytes()),"transport_public":hex::encode(tsk.public_key().encode()),"identity":hex::encode(id.as_bytes()),"request":hex::encode(req.encode()),"request_digest":hex::encode(req.digest().as_bytes())},"outputs":{"encrypted_shares":encrypted_shares,"selected_members":[1,2],"aggregate":{"c1":hex::encode(aggregate.c1.encode()),"c2":hex::encode(aggregate.c2.encode()),"c3":hex::encode(aggregate.c3.encode())},"derived_key":hex::encode(derived.key.encode())}}),
        json!({"name":"noncanonical_scalar","operation":"decode_scalar","inputs":{"bytes":"73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001"},"error":"InvalidScalar"}),
        json!({"name":"identity_transport","operation":"decode_transport","inputs":{"bytes":hex::encode(G1::identity().encode())},"error":"IdentityPoint"}),
        json!({"name":"identity_mpk","operation":"decode_mpk","inputs":{"bytes":hex::encode(G2::identity().encode())},"error":"IdentityPoint"}),
        json!({"name":"share_c3_mutated","operation":"verify_share","inputs":{"reference":"threshold_2of3","share":hex::encode(bad_share.encode())},"error":"Invalid","member":1}),
        json!({"name":"share_context_transplanted","operation":"verify_share","inputs":{"reference":"threshold_2of3","share":hex::encode(wrong_context.encode())},"error":"ContextMismatch"}),
        json!({"name":"share_identity_transplanted","operation":"verify_share","inputs":{"reference":"threshold_2of3","request":hex::encode(wrong_request.encode()),"share":hex::encode(issued[0].encode())},"error":"ContextMismatch"}),
    ];
    for field in ["u", "v", "w"] {
        let mut bad = ct.clone();
        match field {
            "u" => bad.u = bad.u.add(&G2::generator()),
            "v" => bad.v[0] ^= 1,
            _ => bad.w[0] ^= 1,
        };
        cases.push(json!({"name":format!("fullident_{field}_mutated"),"operation":"unwrap","inputs":{"reference":"fullident_wrap_unwrap","ciphertext":hex::encode(bad.encode())},"error":"InvalidCiphertext"}));
    }
    json!({"format_version":1,"suite":"BLS12-381 / RFC9380 SHA-256 SSWU_RO / FullIdent / encrypted threshold shares","spec_sections":["3.2","3.3","3.4","3.5","3.6 + request-digest amendment"],"encoding":"hex; GT coefficients in SPEC 3.2 order","seeds":{"dealer":hex::encode([71;32]),"transport":hex::encode([72;32]),"shares":hex::encode([73;32]),"wrap":hex::encode([74;32])},"dst":{"h1":String::from_utf8_lossy(dst::H1),"pedersen_h":String::from_utf8_lossy(dst::PEDERSEN_H),"h2":String::from_utf8_lossy(dst::H2),"h3":String::from_utf8_lossy(dst::H3),"h4":String::from_utf8_lossy(dst::H4)},"cases":cases})
}

#[test]
fn primitive_vectors_regenerate_byte_for_byte() {
    let encoded = format!("{}\n", serde_json::to_string_pretty(&primitives()).unwrap());
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("vectors/v1/primitives.json");
    if std::env::var("TC_THRESHOLD_REGEN_VECTORS").as_deref() == Ok("1") {
        std::fs::write(&path, &encoded).unwrap();
    }
    assert_eq!(std::fs::read_to_string(path).unwrap(), encoded);
}
