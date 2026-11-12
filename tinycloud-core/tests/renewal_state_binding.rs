use serde_json::{json, Value};
use tinycloud_core::renewal::control::{bind_request, Operation};

fn vectors() -> Vec<Value> {
    serde_json::from_str(include_str!(
        "../../tinycloud-node-server/tests/fixtures/renewal-state-v1.json"
    ))
    .unwrap()
}

#[test]
fn frozen_signed_shapes_bind_stop_enable_and_owner_read() {
    let expected = [Operation::Stop, Operation::Enable, Operation::Read];
    for (vector, operation) in vectors().iter().zip(expected) {
        let (_, actual, generation) =
            bind_request(&vector["claims"]["att"], &vector["body"]).unwrap();
        assert_eq!(actual, operation);
        assert_eq!(generation, vector["body"]["expectedGeneration"].as_u64());
    }
}

#[test]
fn mutations_reject_unsigned_selection_and_malformed_signed_caveats() {
    let vector = &vectors()[0];
    let resource = vector["claims"]["att"]
        .as_object()
        .unwrap()
        .keys()
        .next()
        .unwrap();
    let action = vector["action"].as_str().unwrap();
    for caveats in [
        json!([]),
        json!([{}]),
        json!([{}, {}]),
        json!([{"expectedGeneration": 1}, {}]),
        json!([{"expectedGeneration": 1.0}]),
        json!([{"expectedGeneration": -1}]),
        json!([{"expectedGeneration": 9007199254740992u64}]),
        json!([{"expectedGeneration": 1, "other": 1}]),
        json!({"expectedGeneration": 1}),
    ] {
        let mut attenuation = vector["claims"]["att"].clone();
        attenuation[resource][action] = caveats;
        assert!(bind_request(&attenuation, &vector["body"]).is_err());
    }
    for body in [
        json!({"version": 1, "leaseCid": vector["body"]["leaseCid"], "expectedGeneration": 2}),
        json!({"version": 1, "leaseCid": vector["body"]["leaseCid"], "expectedGeneration": 1, "state": "active"}),
    ] {
        assert!(bind_request(&vector["claims"]["att"], &body).is_err());
    }
}

#[test]
fn owner_read_rejects_even_null_generation() {
    let vector = &vectors()[2];
    let mut body = vector["body"].clone();
    body["expectedGeneration"] = Value::Null;
    assert!(bind_request(&vector["claims"]["att"], &body).is_err());
}

#[tokio::test]
async fn frozen_authorizations_verify_and_retain_the_signed_caveat_shape() {
    use tinycloud_auth::authorization::{HeaderEncode, TinyCloudDelegation, TinyCloudInvocation};
    for vector in vectors() {
        // UCAN delegation/invocation share the existing signed encoding.
        let (decoded, _) =
            TinyCloudDelegation::decode(vector["authorization"].as_str().unwrap()).unwrap();
        let TinyCloudDelegation::Ucan(ucan) = decoded else {
            panic!("UCAN vector");
        };
        let ucan: TinyCloudInvocation = *ucan;
        tinycloud_core::did_resolution::verify_ucan_signature(&ucan)
            .await
            .unwrap();
        let attenuation = serde_json::to_value(&ucan.payload().attenuation).unwrap();
        assert_eq!(attenuation, vector["claims"]["att"]);
        bind_request(&attenuation, &vector["body"]).unwrap();
    }
}
