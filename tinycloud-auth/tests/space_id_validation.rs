use std::str::FromStr;
use tinycloud_auth::{
    resource::iri_string::types::UriStr,
    resource::{Name, ResourceId, SpaceId},
    ssi::dids::DIDBuf,
};

const OWNER: &str = "did:pkh:eip155:1:0x1111111111111111111111111111111111111111";

#[test]
fn rejects_names_through_public_entry_points() {
    let long = "a".repeat(129);
    for name in [
        "",
        ".",
        "..",
        "/",
        "a/b",
        "a\\b",
        "a:b",
        "a%2Fb",
        "OpenKey",
        "name\ncontrol",
        "a\0b",
        "é",
        "_a",
        "-a",
        &long,
    ] {
        assert!(Name::from_str(name).is_err(), "{name:?}");
        assert!(Name::try_from(name.to_owned()).is_err(), "{name:?}");
        assert!(serde_json::from_value::<Name>(serde_json::json!(name)).is_err());
        let id = format!("tinycloud:{}:{name}", &OWNER[4..]);
        assert!(id.parse::<SpaceId>().is_err(), "{name:?}");
        assert!(serde_json::from_value::<SpaceId>(serde_json::json!(id)).is_err());
        if let Ok(uri) = UriStr::new(&id) {
            assert!(SpaceId::try_from(uri).is_err(), "{name:?}");
        }
        // A slash starts the service/path in a ResourceId, rather than being a name.
        if name.contains('/') {
            continue;
        }
        let resource = format!("{id}/space");
        assert!(resource.parse::<ResourceId>().is_err(), "{name:?}");
        assert!(serde_json::from_value::<ResourceId>(serde_json::json!(resource)).is_err());
    }
}

#[test]
fn valid_names_roundtrip_and_constructors_agree() {
    for name in [
        "openkey".to_owned(),
        "secrets".into(),
        "a-b_2".into(),
        "0._-".into(),
        "a".repeat(128),
    ] {
        let did: DIDBuf = OWNER.parse().unwrap();
        let name: Name = name.parse().unwrap();
        let space = SpaceId::new(did.clone(), name.clone()).unwrap();
        assert_eq!(space, SpaceId::try_from((did, name)).unwrap());
        assert_eq!(space, space.to_string().parse().unwrap());
        assert_eq!(
            space,
            serde_json::from_str::<SpaceId>(&serde_json::to_string(&space).unwrap()).unwrap()
        );
    }
}

#[test]
fn unsafe_suffixes_rejected_before_storage() {
    for suffix in [
        "",
        ".",
        "..",
        "key:../other",
        "key:sub/other",
        "key:sub\\other",
        "key:control\0byte",
    ] {
        let owner = format!("did:{suffix}");
        if let Ok(did) = owner.parse::<DIDBuf>() {
            assert!(SpaceId::new(did.clone(), "safe".parse().unwrap()).is_err());
            assert!(SpaceId::try_from((did, "safe".parse().unwrap())).is_err());
        }
        let id = format!("tinycloud:{suffix}:safe");
        assert!(id.parse::<SpaceId>().is_err());
        assert!(serde_json::from_value::<SpaceId>(serde_json::json!(id)).is_err());
    }
}

#[test]
fn constructor_canonicalizes_owner_case() {
    let lower: DIDBuf = "did:pkh:eip155:1:0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
        .parse()
        .unwrap();
    let mixed: DIDBuf = "did:pkh:eip155:1:0xF39fd6e51aad88f6f4ce6ab8827279cfffb92266"
        .parse()
        .unwrap();
    let first = SpaceId::new(lower, "openkey".parse().unwrap()).unwrap();
    let second = SpaceId::new(mixed, "openkey".parse().unwrap()).unwrap();
    assert_eq!(first, second);
    assert_eq!(
        first.did().as_str(),
        "did:pkh:eip155:1:0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
    );
    assert_eq!(first, first.to_string().parse().unwrap());
}
