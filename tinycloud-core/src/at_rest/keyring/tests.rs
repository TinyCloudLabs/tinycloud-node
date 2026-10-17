use std::io::Read;
use std::sync::Arc;

use base64::Engine as _;
use sea_orm::{
    ColumnTrait, ConnectOptions, Database, DatabaseConnection, EntityTrait, IntoActiveModel,
    QueryFilter,
};
use sea_orm_migration::MigratorTrait;
use tinycloud_at_rest_escrow::{wrap_share, EscrowBundle, HolderRecipient, SharePayload};

use super::*;
use crate::at_rest::store::{MemoryMirror, MAX_MIRROR_OBJECT};
use crate::models::{at_rest_escrow, at_rest_key, space_data_key};

const ROOT: [u8; 64] = [7; 64];
const NEW_ROOT: [u8; 64] = [9; 64];

async fn db() -> DatabaseConnection {
    let mut options = ConnectOptions::new("sqlite::memory:".to_string());
    options.max_connections(1).sqlx_logging(false);
    let db = Database::connect(options).await.unwrap();
    crate::migrations::Migrator::up(&db, None).await.unwrap();
    db
}

struct Holders {
    ids: Vec<age::x25519::Identity>,
    recipients: Vec<HolderRecipient>,
}

fn holders() -> Holders {
    let ids: Vec<_> = (0..3).map(|_| age::x25519::Identity::generate()).collect();
    let recipients = ["sam", "hunter", "safe"]
        .iter()
        .zip(&ids)
        .map(|(h, id)| HolderRecipient {
            holder: h.to_string(),
            recipient: id.to_public().to_string(),
        })
        .collect();
    Holders { ids, recipients }
}

impl Holders {
    /// What holder `i` gets from `age -d`.
    fn decrypt(&self, bundle: &EscrowBundle, i: usize) -> SharePayload {
        let armored = &bundle.shares[i].ciphertext;
        let decryptor =
            age::Decryptor::new_buffered(age::armor::ArmoredReader::new(armored.as_bytes()))
                .unwrap();
        let mut reader = decryptor
            .decrypt(std::iter::once(&self.ids[i] as &dyn age::Identity))
            .unwrap();
        let mut plain = Vec::new();
        reader.read_to_end(&mut plain).unwrap();
        bundle.open_share(&plain).unwrap()
    }
}

fn config(h: &Holders, pinned: Option<Efp>) -> KeyringConfig {
    KeyringConfig {
        provision: true,
        holders: h.recipients.clone(),
        recipient_policy: RecipientPolicy::AllowSoftware,
        pinned_efp: pinned,
        app_id: Some("app".into()),
        compose_hash: Some("compose".into()),
        require_mirror: true,
        allow_resplit_before_verify: false,
    }
}

async fn open(
    db: &DatabaseConnection,
    mirror: &Arc<MemoryMirror>,
    root: &[u8],
    config: KeyringConfig,
) -> Result<AtRestKeyring, AtRestError> {
    AtRestKeyring::open(AtRestStore::new(db.clone()), mirror.clone(), root, config).await
}

/// Holder `i` wraps their share to the keyring's current recovery key.
async fn submit(k: &AtRestKeyring, h: &Holders, i: usize) -> Result<ShareOutcome, ShareRefusal> {
    let view = k.escrow_view().await.unwrap().unwrap();
    let share = h.decrypt(&view.bundle, i);
    let wrapped = wrap_share(&view.recovery_recipient, &share).unwrap();
    k.submit_share(wrapped.as_bytes()).await
}

#[tokio::test]
async fn provision_then_reopen_with_same_root_serves_the_same_keys() {
    let (db, mirror, h) = (db().await, Arc::new(MemoryMirror::default()), holders());
    let k = open(&db, &mirror, &ROOT, config(&h, None)).await.unwrap();
    assert_eq!(k.state(), KeyringState::Unlocked);
    let dek = k.current_key("space-a").await.unwrap();
    assert_eq!(dek.id(), DekId::new(1));
    let nk = k.object_name_key().unwrap();
    // Mirror holds the sealed ARK and the escrow bundle.
    let names = mirror.names();
    assert!(names.iter().any(|n| n.starts_with(ARK_MIRROR_PREFIX)));
    assert!(names.iter().any(|n| n.contains("/escrow-")));
    drop(k);

    let k = open(&db, &mirror, &ROOT, config(&h, None)).await.unwrap();
    assert_eq!(k.state(), KeyringState::Unlocked);
    assert_eq!(k.current_key("space-a").await.unwrap().bytes(), dek.bytes());
    assert_eq!(k.object_name_key().unwrap().bytes(), nk.bytes());
    assert_eq!(at_rest_key::Entity::find().all(&db).await.unwrap().len(), 1);
}

#[tokio::test]
async fn nothing_is_created_without_provisioning() {
    let (db, mirror) = (db().await, Arc::new(MemoryMirror::default()));
    let k = open(&db, &mirror, &ROOT, KeyringConfig::default())
        .await
        .unwrap();
    assert_eq!(k.state(), KeyringState::NotProvisioned);
    assert!(matches!(
        k.current_key("s").await,
        Err(DataKeyError::Locked)
    ));
    assert!(at_rest_key::Entity::find()
        .all(&db)
        .await
        .unwrap()
        .is_empty());
    assert!(mirror.names().is_empty());
}

#[tokio::test]
async fn data_keys_converge_are_bound_and_never_invented() {
    let (db, mirror, h) = (db().await, Arc::new(MemoryMirror::default()), holders());
    let k = Arc::new(open(&db, &mirror, &ROOT, config(&h, None)).await.unwrap());
    // A second keyring on the same database stands in for another process.
    let other = Arc::new(open(&db, &mirror, &ROOT, config(&h, None)).await.unwrap());
    let tasks: Vec<_> = (0..8)
        .map(|i| {
            let k = if i % 2 == 0 { k.clone() } else { other.clone() };
            tokio::spawn(async move { k.current_key("space-a").await.unwrap() })
        })
        .collect();
    let keys: Vec<DataKey> = futures::future::join_all(tasks)
        .await
        .into_iter()
        .map(|r| r.unwrap())
        .collect();
    assert!(keys
        .iter()
        .all(|key| key.id() == DekId::new(1) && key.bytes() == keys[0].bytes()));
    assert_eq!(
        space_data_key::Entity::find().all(&db).await.unwrap().len(),
        1
    );

    let b = k.current_key("space-b").await.unwrap();
    assert_ne!(b.bytes(), keys[0].bytes());
    assert!(matches!(
        k.key("space-a", DekId::new(2)).await,
        Err(DataKeyError::UnknownKey { dek_id }) if dek_id == DekId::new(2)
    ));
    assert!(matches!(
        k.key("space-a", DekId::new(u32::MAX)).await,
        Err(DataKeyError::UnknownKey { .. })
    ));

    // A wrapped DEK copied to another space fails authentication instead of
    // serving space-a's key for space-c.
    let row = space_data_key::Entity::find_by_id(("space-a".to_string(), 1))
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    AtRestStore::new(db.clone())
        .insert_dek(space_data_key::Model {
            space: "space-c".into(),
            ..row
        })
        .await
        .unwrap();
    let fresh = open(&db, &mirror, &ROOT, config(&h, None)).await.unwrap();
    assert!(matches!(
        fresh.key("space-c", DekId::new(1)).await,
        Err(DataKeyError::Backend(_))
    ));
}

#[tokio::test]
async fn new_root_boots_locked_and_two_shares_unlock_without_restart() {
    let (db, mirror, h) = (db().await, Arc::new(MemoryMirror::default()), holders());
    let k = open(&db, &mirror, &ROOT, config(&h, None)).await.unwrap();
    let dek = k.current_key("space-a").await.unwrap();
    let nk = k.object_name_key().unwrap();
    let efp = k.escrow_view().await.unwrap().unwrap().efp;
    drop(k);

    // New app id / KMS: a different root. Locked, not lost.
    let k = open(&db, &mirror, &NEW_ROOT, config(&h, Some(efp)))
        .await
        .unwrap();
    assert_eq!(k.state(), KeyringState::Locked);
    assert!(matches!(
        k.current_key("space-a").await,
        Err(DataKeyError::Locked)
    ));
    assert!(matches!(k.object_name_key(), Err(DataKeyError::Locked)));
    assert_eq!(k.gate(false).await, Err(GateRefusal::Locked));

    // One share does nothing.
    assert_eq!(
        submit(&k, &h, 2).await.unwrap(),
        ShareOutcome::Held {
            shares_held: vec![3]
        }
    );
    assert_eq!(k.state(), KeyringState::Locked);
    // A second distinct share recovers and reseals.
    assert_eq!(submit(&k, &h, 0).await.unwrap(), ShareOutcome::Unlocked);
    assert_eq!(k.state(), KeyringState::Unlocked);
    assert_eq!(
        k.key("space-a", DekId::new(1)).await.unwrap().bytes(),
        dek.bytes()
    );
    assert_eq!(k.object_name_key().unwrap().bytes(), nk.bytes());
    drop(k);

    // Resealed under the new root: it now boots unlocked; the old root is locked out.
    let k = open(&db, &mirror, &NEW_ROOT, config(&h, Some(efp)))
        .await
        .unwrap();
    assert_eq!(k.state(), KeyringState::Unlocked);
    assert_eq!(k.current_key("space-a").await.unwrap().bytes(), dek.bytes());
    let old = open(&db, &mirror, &ROOT, config(&h, Some(efp)))
        .await
        .unwrap();
    assert_eq!(old.state(), KeyringState::Locked);
}

#[tokio::test]
async fn locked_node_trusts_only_the_pinned_bundle() {
    let (db, mirror, h) = (db().await, Arc::new(MemoryMirror::default()), holders());
    let k = open(&db, &mirror, &ROOT, config(&h, None)).await.unwrap();
    let real = k.escrow_view().await.unwrap().unwrap();
    drop(k);

    // No pin: nothing to check shares against.
    let k = open(&db, &mirror, &NEW_ROOT, config(&h, None))
        .await
        .unwrap();
    assert!(k.escrow_view().await.unwrap().is_none());
    let share = h.decrypt(&real.bundle, 0);
    let wrapped = wrap_share(&k.intake.lock().await.identity.recipient(), &share).unwrap();
    assert!(matches!(
        k.submit_share(wrapped.as_bytes()).await,
        Err(ShareRefusal::NoBundle(_))
    ));

    // A pin that isn't the stored bundle (e.g. storage swapped the bundle).
    let k = open(&db, &mirror, &NEW_ROOT, config(&h, Some(Digest32([1; 32]))))
        .await
        .unwrap();
    assert!(k.escrow_view().await.unwrap().is_none());

    // Shares of a different ARK (another bundle) are refused before a slot.
    let k = open(&db, &mirror, &NEW_ROOT, config(&h, Some(real.efp)))
        .await
        .unwrap();
    let foreign = EscrowBundle::create(
        &Ark::generate(),
        ArkId::generate(),
        1,
        &h.recipients,
        RecipientPolicy::AllowSoftware,
    )
    .unwrap();
    let wrapped = wrap_share(
        &k.escrow_view().await.unwrap().unwrap().recovery_recipient,
        &h.decrypt(&foreign, 1),
    )
    .unwrap();
    assert!(matches!(
        k.submit_share(wrapped.as_bytes()).await,
        Err(ShareRefusal::Invalid(_))
    ));
    assert!(k
        .escrow_view()
        .await
        .unwrap()
        .unwrap()
        .shares_held
        .is_empty());
    // Junk and wrong-key age files too.
    assert!(k.submit_share(b"junk").await.is_err());
}

#[tokio::test]
async fn pitr_restore_without_ark_rows_recovers_from_the_mirror() {
    let (db, mirror, h) = (db().await, Arc::new(MemoryMirror::default()), holders());
    let k = open(&db, &mirror, &ROOT, config(&h, None)).await.unwrap();
    let dek = k.current_key("space-a").await.unwrap();
    drop(k);
    at_rest_key::Entity::delete_many().exec(&db).await.unwrap();

    let k = open(&db, &mirror, &ROOT, config(&h, None)).await.unwrap();
    assert_eq!(k.state(), KeyringState::Unlocked);
    assert_eq!(
        k.key("space-a", DekId::new(1)).await.unwrap().bytes(),
        dek.bytes()
    );
}

#[tokio::test]
async fn never_provisions_over_uncertainty() {
    let (db, mirror, h) = (db().await, Arc::new(MemoryMirror::default()), holders());
    let k = open(&db, &mirror, &ROOT, config(&h, None)).await.unwrap();
    k.current_key("space-a").await.unwrap();
    drop(k);
    at_rest_key::Entity::delete_many().exec(&db).await.unwrap();

    // Mirror unreachable: fail, don't make a fresh ARK.
    mirror.set_failing(true);
    assert!(matches!(
        open(&db, &mirror, &ROOT, config(&h, None)).await,
        Err(AtRestError::Mirror(_))
    ));
    // Mirror empty but data keys exist: inconsistent, don't make a fresh ARK.
    mirror.set_failing(false);
    mirror.clear();
    assert!(matches!(
        open(&db, &mirror, &ROOT, config(&h, None)).await,
        Err(AtRestError::Inconsistent(_))
    ));
    assert!(at_rest_key::Entity::find()
        .all(&db)
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn gate_requires_pinned_verified_escrow_for_the_configured_recipients() {
    let (db, mirror, h) = (db().await, Arc::new(MemoryMirror::default()), holders());
    let k = open(&db, &mirror, &ROOT, config(&h, None)).await.unwrap();
    let efp = k.escrow_view().await.unwrap().unwrap().efp;
    assert_eq!(
        k.gate(false).await,
        Err(GateRefusal::NotPinned {
            efp: efp.to_string()
        })
    );
    drop(k);

    let k = open(&db, &mirror, &ROOT, config(&h, Some(Digest32([2; 32]))))
        .await
        .unwrap();
    assert!(matches!(
        k.gate(false).await,
        Err(GateRefusal::PinMismatch { .. })
    ));
    drop(k);

    // Pinned but no ceremony yet.
    let k = open(&db, &mirror, &ROOT, config(&h, Some(efp)))
        .await
        .unwrap();
    assert_eq!(
        k.gate(false).await,
        Err(GateRefusal::NotVerified {
            efp: efp.to_string()
        })
    );

    // Ceremony test-unlock: two shares are held, the third verifies.
    assert_eq!(
        submit(&k, &h, 0).await.unwrap(),
        ShareOutcome::Held {
            shares_held: vec![1]
        }
    );
    assert_eq!(
        submit(&k, &h, 2).await.unwrap(),
        ShareOutcome::Held {
            shares_held: vec![1, 3]
        }
    );
    assert_eq!(
        submit(&k, &h, 1).await.unwrap(),
        ShareOutcome::Verified { efp }
    );
    assert_eq!(k.gate(false).await, Ok(GatePass::Verified { efp }));
    assert!(k.escrow_view().await.unwrap().unwrap().verified);
    assert_eq!(
        k.verification_record().await.unwrap().map(|r| r.efp),
        Some(efp)
    );
    let record = at_rest_escrow::Entity::find_by_id(efp.to_string())
        .one(&db)
        .await
        .unwrap()
        .unwrap()
        .record
        .unwrap();
    let parsed: VerificationRecord = serde_json::from_str(&record).unwrap();
    assert_eq!(parsed.app_id.as_deref(), Some("app"));
    drop(k);

    // A record edited in storage no longer verifies.
    let mut forged: serde_json::Value = serde_json::from_str(&record).unwrap();
    forged["verified_at"] = serde_json::json!("2030-01-01T00:00:00Z");
    AtRestStore::new(db.clone())
        .save_record(&efp.to_string(), forged.to_string())
        .await
        .unwrap();
    let k = open(&db, &mirror, &ROOT, config(&h, Some(efp)))
        .await
        .unwrap();
    assert!(matches!(
        k.gate(false).await,
        Err(GateRefusal::NotVerified { .. })
    ));
    // A record this node can't read (a newer format) is not "unverified":
    // the operator must fix the node, not re-run the ceremony.
    let mut newer: serde_json::Value = serde_json::from_str(&record).unwrap();
    newer["version"] = serde_json::json!(2);
    AtRestStore::new(db.clone())
        .save_record(&efp.to_string(), newer.to_string())
        .await
        .unwrap();
    assert!(matches!(
        k.gate(false).await,
        Err(GateRefusal::Unavailable(e)) if e.contains("version 2")
    ));
    AtRestStore::new(db.clone())
        .save_record(&efp.to_string(), record)
        .await
        .unwrap();
    assert_eq!(k.gate(false).await, Ok(GatePass::Verified { efp }));
    drop(k);

    // New recipients in config: the node never re-splits on its own, with
    // or without the pin. Nothing is written.
    let changed = holders();
    for pin in [None, Some(efp)] {
        assert!(matches!(
            open(&db, &mirror, &ROOT, config(&changed, pin)).await,
            Err(AtRestError::EscrowHoldersChanged)
        ));
    }
    let bundles = at_rest_escrow::Entity::find().all(&db).await.unwrap();
    assert_eq!(bundles.len(), 1);
}

#[tokio::test]
async fn two_nodes_with_different_holders_never_flip_the_escrow() {
    let (db, mirror) = (db().await, Arc::new(MemoryMirror::default()));
    let (ha, hb) = (holders(), holders());
    let a = open(&db, &mirror, &ROOT, config(&ha, None)).await.unwrap();
    let efp = a.escrow_view().await.unwrap().unwrap().efp;
    // A second node configured with other holders refuses to boot.
    assert!(matches!(
        open(&db, &mirror, &ROOT, config(&hb, None)).await,
        Err(AtRestError::EscrowHoldersChanged)
    ));
    // Read paths are read-only: any number of them change nothing.
    let escrow_objects = || {
        mirror
            .names()
            .iter()
            .filter(|n| n.contains("/escrow-"))
            .count()
    };
    let before = escrow_objects();
    for _ in 0..10 {
        assert_eq!(a.escrow_view().await.unwrap().unwrap().efp, efp);
        assert!(a.verification_record().await.unwrap().is_none());
        let _ = a.gate(false).await;
    }
    assert_eq!(
        at_rest_escrow::Entity::find().all(&db).await.unwrap().len(),
        1
    );
    assert_eq!(escrow_objects(), before);
}

/// Run the ceremony test-unlock on an unlocked keyring.
async fn verify_escrow(k: &AtRestKeyring, h: &Holders) -> Efp {
    for i in 0..3 {
        submit(k, h, i).await.unwrap();
    }
    let view = k.escrow_view().await.unwrap().unwrap();
    assert!(view.verified);
    view.efp
}

#[tokio::test]
async fn a_restore_before_the_escrow_or_record_needs_no_new_ceremony() {
    let (db, mirror, h) = (db().await, Arc::new(MemoryMirror::default()), holders());
    let k = open(&db, &mirror, &ROOT, config(&h, None)).await.unwrap();
    let efp = verify_escrow(&k, &h).await;
    drop(k);

    // Before the record: it comes back from the mirror (its MAC verifies).
    at_rest_escrow::Entity::update_many()
        .col_expr(
            at_rest_escrow::Column::Record,
            sea_orm::sea_query::Expr::value(Option::<String>::None),
        )
        .exec(&db)
        .await
        .unwrap();
    let k = open(&db, &mirror, &ROOT, config(&h, Some(efp)))
        .await
        .unwrap();
    assert_eq!(k.gate(false).await, Ok(GatePass::Verified { efp }));
    drop(k);

    // Before the escrow row, pinned and unpinned: the same bundle and its
    // record come back; no new split.
    for pin in [Some(efp), None] {
        at_rest_escrow::Entity::delete_many()
            .exec(&db)
            .await
            .unwrap();
        let k = open(&db, &mirror, &ROOT, config(&h, pin)).await.unwrap();
        let view = k.escrow_view().await.unwrap().unwrap();
        assert_eq!((view.efp, view.verified), (efp, true), "pin {pin:?}");
        assert_eq!(
            at_rest_escrow::Entity::find().all(&db).await.unwrap().len(),
            1
        );
    }

    // A forged record in the mirror proves nothing: unpinned, a new bundle.
    at_rest_escrow::Entity::delete_many()
        .exec(&db)
        .await
        .unwrap();
    let name = format!("{MIRROR_PREFIX}record-{efp}.json");
    let mut forged: serde_json::Value =
        serde_json::from_slice(&mirror.get(&name).await.unwrap().unwrap()).unwrap();
    forged["verified_at"] = serde_json::json!("2030-01-01T00:00:00Z");
    mirror
        .put(&name, serde_json::to_vec(&forged).unwrap())
        .await
        .unwrap();
    let k = open(&db, &mirror, &ROOT, config(&h, None)).await.unwrap();
    let view = k.escrow_view().await.unwrap().unwrap();
    assert_ne!(view.efp, efp);
    assert!(!view.verified);
}

#[tokio::test]
async fn a_mirrored_row_picked_for_its_chain_never_brings_its_seal() {
    let (db, mirror, h) = (db().await, Arc::new(MemoryMirror::default()), holders());
    let k = open(&db, &mirror, &ROOT, config(&h, None)).await.unwrap();
    k.rotate_ark().await.unwrap();
    drop(k);
    let gen1 = AtRestStore::new(db.clone()).keys().await.unwrap()[0].clone();
    // The database lost generation 1's chain; the mirror has it, next to
    // junk seal bytes.
    set_chain(&db, 1, None).await;
    let name = ark_mirror_name(1, &hex::encode(&gen1.ark_id));
    let mut obj: serde_json::Value =
        serde_json::from_slice(&mirror.get(&name).await.unwrap().unwrap()).unwrap();
    obj["sealed"] = serde_json::json!(base64::engine::general_purpose::STANDARD.encode([7; 60]));
    mirror
        .put(&name, serde_json::to_vec(&obj).unwrap())
        .await
        .unwrap();

    let k = open(&db, &mirror, &ROOT, config(&h, None)).await.unwrap();
    assert_eq!(k.state(), KeyringState::Unlocked);
    let rows = AtRestStore::new(db.clone()).keys().await.unwrap();
    assert_eq!(
        rows[0].sealed, gen1.sealed,
        "the database keeps its own seal"
    );
    assert_eq!(
        rows[0].chain, gen1.chain,
        "the authenticated chain is restored"
    );
}

#[tokio::test]
async fn a_stale_chain_on_the_newest_generation_is_cleared_not_a_permanent_conflict() {
    let (db, mirror, h) = (db().await, Arc::new(MemoryMirror::default()), holders());
    let k = open(&db, &mirror, &ROOT, config(&h, None)).await.unwrap();
    drop(k);
    set_chain(&db, 1, Some(vec![0x33; 60])).await;
    let k = open(&db, &mirror, &ROOT, config(&h, None)).await.unwrap();
    let rows = AtRestStore::new(db.clone()).keys().await.unwrap();
    assert_eq!(chain_of(&rows, 1), None);
    assert_eq!(k.rotate_ark().await.unwrap(), 2);

    // Garbage chained after boot: an explicit, retryable error, then success.
    set_chain(&db, 2, Some(vec![0x33; 60])).await;
    assert!(matches!(
        k.rotate_ark().await,
        Err(AtRestError::Inconsistent(why)) if why.contains("retry")
    ));
    assert_eq!(k.rotate_ark().await.unwrap(), 3);
}

#[tokio::test]
async fn software_holders_need_the_opt_in_to_escrow_and_to_pass_the_gate() {
    let (db, mirror, h) = (db().await, Arc::new(MemoryMirror::default()), holders());
    let hardware_only = |pinned| KeyringConfig {
        recipient_policy: RecipientPolicy::HardwareOnly,
        ..config(&h, pinned)
    };
    // Hardware-only config with X25519 holders: no escrow is made.
    assert!(matches!(
        open(&db, &mirror, &ROOT, hardware_only(None)).await,
        Err(AtRestError::Escrow(_))
    ));
    // Escrowed and verified under the opt-in...
    let k = open(&db, &mirror, &ROOT, config(&h, None)).await.unwrap();
    let efp = k.escrow_view().await.unwrap().unwrap().efp;
    drop(k);
    let k = open(&db, &mirror, &ROOT, config(&h, Some(efp)))
        .await
        .unwrap();
    for i in 0..3 {
        submit(&k, &h, i).await.unwrap();
    }
    assert_eq!(k.gate(false).await, Ok(GatePass::Verified { efp }));
    drop(k);
    // ...still doesn't open the gate once the opt-in is removed.
    let k = open(&db, &mirror, &ROOT, hardware_only(Some(efp)))
        .await
        .unwrap();
    assert_eq!(k.gate(false).await, Err(GateRefusal::SoftwareRecipients));
}

#[tokio::test]
async fn self_host_without_escrow_needs_the_explicit_acknowledgement() {
    let (db, mirror) = (db().await, Arc::new(MemoryMirror::default()));
    let config = KeyringConfig {
        provision: true,
        ..Default::default()
    };
    let k = open(&db, &mirror, &ROOT, config).await.unwrap();
    assert_eq!(k.gate(false).await, Err(GateRefusal::NoEscrow));
    assert_eq!(k.gate(true).await, Ok(GatePass::Unescrowed));
    assert!(k.escrow_view().await.unwrap().is_none());
    assert!(at_rest_escrow::Entity::find()
        .all(&db)
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn rotation_keeps_old_generations_and_survives_recovery() {
    let (db, mirror, h) = (db().await, Arc::new(MemoryMirror::default()), holders());
    let k = open(&db, &mirror, &ROOT, config(&h, None)).await.unwrap();
    let old = k.current_key("space-a").await.unwrap();
    let nk = k.object_name_key().unwrap();
    assert_eq!(k.rotate_ark().await.unwrap(), 2);
    // Old DEK still served; a new space wraps under generation 2; NK pinned to gen 1.
    assert_eq!(
        k.key("space-a", DekId::new(1)).await.unwrap().bytes(),
        old.bytes()
    );
    k.current_key("space-b").await.unwrap();
    let b_row = space_data_key::Entity::find_by_id(("space-b".to_string(), 1))
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(b_row.generation, 2);
    assert_eq!(k.object_name_key().unwrap().bytes(), nk.bytes());
    let view = k.escrow_view().await.unwrap().unwrap();
    assert_eq!(view.generation, 2);
    assert!(!view.verified);
    drop(k);

    // Escrow of generation 2 alone recovers both generations on a new root.
    let k = open(&db, &mirror, &NEW_ROOT, config(&h, Some(view.efp)))
        .await
        .unwrap();
    assert_eq!(k.state(), KeyringState::Locked);
    submit(&k, &h, 0).await.unwrap();
    assert_eq!(submit(&k, &h, 1).await.unwrap(), ShareOutcome::Unlocked);
    assert_eq!(
        k.key("space-a", DekId::new(1)).await.unwrap().bytes(),
        old.bytes()
    );
    assert_eq!(k.object_name_key().unwrap().bytes(), nk.bytes());
    assert_eq!(at_rest_key::Entity::find().all(&db).await.unwrap().len(), 2);
}

#[tokio::test]
async fn junk_never_spends_the_share_budget() {
    let (db, mirror, h) = (db().await, Arc::new(MemoryMirror::default()), holders());
    let k = open(&db, &mirror, &ROOT, config(&h, None)).await.unwrap();
    // Any amount of junk, or shares of another escrow, is refused but free.
    let foreign = EscrowBundle::create(
        &Ark::generate(),
        ArkId::generate(),
        1,
        &h.recipients,
        RecipientPolicy::AllowSoftware,
    )
    .unwrap();
    let recipient = k.escrow_view().await.unwrap().unwrap().recovery_recipient;
    for _ in 0..3 * SHARE_BURST {
        assert!(matches!(
            k.submit_share(b"junk").await,
            Err(ShareRefusal::Invalid(_))
        ));
        let wrapped = wrap_share(&recipient, &h.decrypt(&foreign, 0)).unwrap();
        assert!(matches!(
            k.submit_share(wrapped.as_bytes()).await,
            Err(ShareRefusal::Invalid(_))
        ));
    }
    // A genuine share still goes through after the junk...
    assert!(matches!(
        submit(&k, &h, 0).await,
        Ok(ShareOutcome::Held { .. })
    ));
    // ...and only genuine submissions count against the per-boot budget.
    for _ in 1..SHARE_BURST {
        submit(&k, &h, 0).await.unwrap();
    }
    assert!(matches!(
        submit(&k, &h, 0).await,
        Err(ShareRefusal::RateLimited)
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn postgres_concurrent_writers_converge_on_one_row_each() {
    let Some(pg) = crate::test_support::PostgresTestSchema::new(
        "postgres_concurrent_writers_converge_on_one_row_each",
    )
    .await
    else {
        return;
    };
    let (mirror, h) = (Arc::new(MemoryMirror::default()), holders());
    // Two processes booting at once against the same database (pool of 4).
    let (a, b) = tokio::join!(
        open(&pg.conn, &mirror, &ROOT, config(&h, None)),
        open(&pg.conn, &mirror, &ROOT, config(&h, None)),
    );
    let (a, b) = (Arc::new(a.unwrap()), Arc::new(b.unwrap()));
    assert_eq!(
        at_rest_key::Entity::find()
            .all(&pg.conn)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        a.object_name_key().unwrap().bytes(),
        b.object_name_key().unwrap().bytes()
    );

    let tasks: Vec<_> = (0..16)
        .map(|i| {
            let k = if i % 2 == 0 { a.clone() } else { b.clone() };
            tokio::spawn(async move { k.current_key(&format!("space-{}", i % 4)).await.unwrap() })
        })
        .collect();
    let keys: Vec<DataKey> = futures::future::join_all(tasks)
        .await
        .into_iter()
        .map(|r| r.unwrap())
        .collect();
    for (i, key) in keys.iter().enumerate() {
        assert_eq!(key.id(), DekId::new(1));
        assert_eq!(key.bytes(), keys[i % 4].bytes(), "space-{} diverged", i % 4);
    }
    assert_eq!(
        space_data_key::Entity::find()
            .all(&pg.conn)
            .await
            .unwrap()
            .len(),
        4
    );

    // Store conflicts keep the first row, deterministically, on PG too.
    store_conflicts_keep_the_first_row(&pg.conn).await;

    // Concurrent re-splits of one generation leave exactly one active bundle.
    let store = AtRestStore::new(pg.conn.clone());
    for round in 0..50 {
        let row = |n: u8| at_rest_escrow::Model {
            efp: format!("{round:04}-{n}"),
            generation: 1,
            bundle: "{}".into(),
            active: true,
            record: None,
            created_at: now_rfc3339(),
        };
        let (x, y) = tokio::join!(store.activate_escrow(row(1)), store.activate_escrow(row(2)));
        x.unwrap();
        y.unwrap();
        let active = at_rest_escrow::Entity::find()
            .all(&pg.conn)
            .await
            .unwrap()
            .into_iter()
            .filter(|b| b.generation == 1 && b.active)
            .count();
        assert_eq!(active, 1, "round {round}");
    }
}

/// Both conflict branches return `Ok` and keep the first row; a rotation
/// onto an existing generation writes nothing.
async fn store_conflicts_keep_the_first_row(db: &DatabaseConnection) {
    let store = AtRestStore::new(db.clone());
    let key = |ark_id: u8, generation: i32| at_rest_key::Model {
        generation,
        ark_id: vec![ark_id; 16],
        w_label: W_LABEL.into(),
        sealed: vec![ark_id; 60],
        chain: None,
        created_at: now_rfc3339(),
    };
    let gen1 = store.keys().await.unwrap()[0].clone();
    store.insert_key(key(0xee, 1)).await.unwrap();
    assert_eq!(store.keys().await.unwrap()[0], gen1);

    let dek = |wrapped: u8| space_data_key::Model {
        space: "conflict".into(),
        dek_id: 1,
        generation: 1,
        wrapped: vec![wrapped; 60],
        created_at: now_rfc3339(),
    };
    store.insert_dek(dek(1)).await.unwrap();
    store.insert_dek(dek(2)).await.unwrap();
    assert_eq!(
        store.dek("conflict", 1).await.unwrap().unwrap().wrapped,
        vec![1; 60]
    );

    // Generation 1 exists: rotating "to" it writes neither row nor chain.
    let before = store.keys().await.unwrap();
    assert!(!store.rotate(key(0xdd, 1), vec![1; 60]).await.unwrap());
    assert_eq!(store.keys().await.unwrap(), before);
}

#[tokio::test]
async fn sqlite_store_conflicts_keep_the_first_row() {
    let (db, mirror, h) = (db().await, Arc::new(MemoryMirror::default()), holders());
    open(&db, &mirror, &ROOT, config(&h, None)).await.unwrap();
    store_conflicts_keep_the_first_row(&db).await;
}

async fn set_chain(db: &DatabaseConnection, generation: i32, chain: Option<Vec<u8>>) {
    at_rest_key::Entity::update_many()
        .col_expr(at_rest_key::Column::Chain, chain.into())
        .filter(at_rest_key::Column::Generation.eq(generation))
        .exec(db)
        .await
        .unwrap();
}

fn chain_of(rows: &[at_rest_key::Model], generation: i32) -> Option<Vec<u8>> {
    rows.iter()
        .find(|r| r.generation == generation)
        .unwrap()
        .chain
        .clone()
}

#[tokio::test]
async fn a_missing_or_foreign_chain_is_rebuilt_under_the_same_root() {
    for broken in [None, Some(vec![0x5a; 60])] {
        let (db, mirror, h) = (db().await, Arc::new(MemoryMirror::default()), holders());
        let k = open(&db, &mirror, &ROOT, config(&h, None)).await.unwrap();
        let old = k.current_key("space-a").await.unwrap();
        k.rotate_ark().await.unwrap();
        let efp = k.escrow_view().await.unwrap().unwrap().efp;
        drop(k);
        // A crash or a stale writer left generation 1 without a usable
        // chain, and the mirror has no better copy.
        set_chain(&db, 1, broken.clone()).await;
        mirror.remove_prefix(ARK_MIRROR_PREFIX);

        let k = open(&db, &mirror, &ROOT, config(&h, None)).await.unwrap();
        assert_eq!(k.state(), KeyringState::Unlocked);
        let rows = AtRestStore::new(db.clone()).keys().await.unwrap();
        let rebuilt = chain_of(&rows, 1).expect("chain rebuilt");
        assert_ne!(Some(rebuilt), broken);
        drop(k);

        // The rebuilt chain is what recovery under a new root relies on.
        let k = open(&db, &mirror, &NEW_ROOT, config(&h, Some(efp)))
            .await
            .unwrap();
        submit(&k, &h, 0).await.unwrap();
        assert_eq!(submit(&k, &h, 2).await.unwrap(), ShareOutcome::Unlocked);
        assert_eq!(
            k.key("space-a", DekId::new(1)).await.unwrap().bytes(),
            old.bytes()
        );
    }
}

#[tokio::test]
async fn recovery_fails_loudly_on_a_broken_chain_or_missing_generation() {
    let (db, mirror, h) = (db().await, Arc::new(MemoryMirror::default()), holders());
    let k = open(&db, &mirror, &ROOT, config(&h, None)).await.unwrap();
    k.current_key("space-a").await.unwrap();
    k.rotate_ark().await.unwrap();
    let efp = k.escrow_view().await.unwrap().unwrap().efp;
    drop(k);
    set_chain(&db, 1, None).await;
    mirror.remove_prefix(ARK_MIRROR_PREFIX);

    // Under a new root nothing can rebuild the chain: two valid shares are
    // refused with the reason, and the node stays locked.
    let k = open(&db, &mirror, &NEW_ROOT, config(&h, Some(efp)))
        .await
        .unwrap();
    submit(&k, &h, 0).await.unwrap();
    assert!(matches!(
        submit(&k, &h, 1).await,
        Err(ShareRefusal::Keyring(AtRestError::Inconsistent(_)))
    ));
    assert_eq!(k.state(), KeyringState::Locked);

    // Generation 1 deleted after boot: an error, not a panic. The two
    // valid shares stay held, so any submission retries the unlock.
    at_rest_key::Entity::delete_by_id(1)
        .exec(&db)
        .await
        .unwrap();
    assert!(matches!(
        submit(&k, &h, 0).await,
        Err(ShareRefusal::Keyring(AtRestError::Inconsistent(_)))
    ));
    assert_eq!(k.state(), KeyringState::Locked);
}

#[tokio::test]
async fn a_stale_node_cannot_rotate_over_another_nodes_rotation() {
    let (db, mirror, h) = (db().await, Arc::new(MemoryMirror::default()), holders());
    let a = open(&db, &mirror, &ROOT, config(&h, None)).await.unwrap();
    let b = open(&db, &mirror, &ROOT, config(&h, None)).await.unwrap();
    let old = a.current_key("space-a").await.unwrap();
    assert_eq!(a.rotate_ark().await.unwrap(), 2);
    let chain = chain_of(&AtRestStore::new(db.clone()).keys().await.unwrap(), 1);

    // B still believes generation 1 is newest.
    assert!(matches!(
        b.rotate_ark().await,
        Err(AtRestError::Conflict(_))
    ));
    let rows = AtRestStore::new(db.clone()).keys().await.unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(chain_of(&rows, 1), chain, "A's chain is untouched");
    // B reloaded A's generation: new spaces wrap under generation 2.
    b.current_key("space-b").await.unwrap();
    assert_eq!(
        AtRestStore::new(db.clone())
            .dek("space-b", 1)
            .await
            .unwrap()
            .unwrap()
            .generation,
        2
    );
    assert_eq!(b.rotate_ark().await.unwrap(), 3);
    let efp = b.escrow_view().await.unwrap().unwrap().efp;
    drop((a, b));

    // Generation 3's escrow alone recovers every generation.
    let k = open(&db, &mirror, &NEW_ROOT, config(&h, Some(efp)))
        .await
        .unwrap();
    submit(&k, &h, 1).await.unwrap();
    assert_eq!(submit(&k, &h, 2).await.unwrap(), ShareOutcome::Unlocked);
    assert_eq!(
        k.key("space-a", DekId::new(1)).await.unwrap().bytes(),
        old.bytes()
    );
}

#[tokio::test]
async fn data_keys_survive_a_restore_to_before_they_were_created() {
    let (db, mirror, h) = (db().await, Arc::new(MemoryMirror::default()), holders());
    let k = open(&db, &mirror, &ROOT, config(&h, None)).await.unwrap();
    let a = k.current_key("space-a").await.unwrap();
    // Mirror names don't reveal the space.
    assert!(mirror.names().iter().all(|n| !n.contains("space-a")));
    drop(k);
    space_data_key::Entity::delete_many()
        .exec(&db)
        .await
        .unwrap();

    // The restored database lacks the row; objects sealed under it remain.
    let k = open(&db, &mirror, &ROOT, config(&h, None)).await.unwrap();
    assert_eq!(
        k.key("space-a", DekId::new(1)).await.unwrap().bytes(),
        a.bytes()
    );
    space_data_key::Entity::delete_many()
        .exec(&db)
        .await
        .unwrap();
    let k = open(&db, &mirror, &ROOT, config(&h, None)).await.unwrap();
    assert_eq!(k.current_key("space-a").await.unwrap().bytes(), a.bytes());
    drop(k);

    // A different DEK under the same id would strand every object sealed
    // under the mirrored one: refused, and the mirror is not overwritten.
    space_data_key::Entity::delete_many()
        .exec(&db)
        .await
        .unwrap();
    let keys = open(&db, &mirror, &ROOT, config(&h, None)).await.unwrap();
    let gen = &keys.keys().unwrap();
    let (g, newest) = gen.newest();
    let (wrapped, _) = new_dek(&newest.kek, "space-a", DekId::new(1), g, &newest.ark_id);
    AtRestStore::new(db.clone())
        .insert_dek(space_data_key::Model {
            space: "space-a".into(),
            dek_id: 1,
            generation: g as i32,
            wrapped,
            created_at: now_rfc3339(),
        })
        .await
        .unwrap();
    assert!(matches!(
        keys.current_key("space-a").await,
        Err(DataKeyError::Backend(_))
    ));
    space_data_key::Entity::delete_many()
        .exec(&db)
        .await
        .unwrap();
    let k = open(&db, &mirror, &ROOT, config(&h, None)).await.unwrap();
    assert_eq!(k.current_key("space-a").await.unwrap().bytes(), a.bytes());
}

/// TC-887 S3: inside `write_locked` (the invoke write lock and transaction)
/// the keyring never writes: a key that would need restoring or creating is
/// `NotPrepared`, with no row inserted. `prepare_read` restores it beforehand
/// (never creating one), after which lookups under the lock succeed.
#[tokio::test]
async fn under_the_write_lock_keys_are_only_looked_up() {
    use crate::at_rest::write_locked;
    let (db, mirror, h) = (db().await, Arc::new(MemoryMirror::default()), holders());
    let k = open(&db, &mirror, &ROOT, config(&h, None)).await.unwrap();
    let a = k.current_key("space-a").await.unwrap();
    drop(k);
    space_data_key::Entity::delete_many()
        .exec(&db)
        .await
        .unwrap();
    let rows = || async { space_data_key::Entity::find().all(&db).await.unwrap().len() };

    let k = open(&db, &mirror, &ROOT, config(&h, None)).await.unwrap();
    assert!(matches!(
        write_locked(k.key("space-a", DekId::new(1))).await,
        Err(DataKeyError::NotPrepared)
    ));
    assert!(matches!(
        write_locked(k.current_key("space-a")).await,
        Err(DataKeyError::NotPrepared)
    ));
    assert!(matches!(
        write_locked(k.current_key("space-new")).await,
        Err(DataKeyError::NotPrepared)
    ));
    assert_eq!(rows().await, 0, "nothing is written under the lock");

    // Reads never create a key: a space with no key stays without one.
    k.prepare_read("space-new").await.unwrap();
    assert_eq!(rows().await, 0);
    // The lost row comes back from the mirror before the lock.
    k.prepare_read("space-a").await.unwrap();
    assert_eq!(rows().await, 1);
    assert_eq!(
        write_locked(k.key("space-a", DekId::new(1)))
            .await
            .unwrap()
            .bytes(),
        a.bytes()
    );
}

#[tokio::test]
async fn escrow_rows_or_any_mirror_object_block_provisioning() {
    let (db, mirror, h) = (db().await, Arc::new(MemoryMirror::default()), holders());
    open(&db, &mirror, &ROOT, config(&h, None)).await.unwrap();
    at_rest_key::Entity::delete_many().exec(&db).await.unwrap();
    mirror.remove_prefix(ARK_MIRROR_PREFIX);
    // Only escrow rows and escrow mirror objects are left.
    assert!(matches!(
        open(&db, &mirror, &ROOT, config(&h, None)).await,
        Err(AtRestError::Inconsistent(_))
    ));
    at_rest_escrow::Entity::delete_many()
        .exec(&db)
        .await
        .unwrap();
    // Only a mirror object is left.
    assert!(matches!(
        open(&db, &mirror, &ROOT, config(&h, None)).await,
        Err(AtRestError::Inconsistent(_))
    ));
    assert!(at_rest_key::Entity::find()
        .all(&db)
        .await
        .unwrap()
        .is_empty());
}

/// Plant an unauthenticated ARK row in the mirror, as a bucket writer could.
async fn plant_ark(mirror: &MemoryMirror, generation: u32) {
    let ark_id = ArkId::generate();
    let forged = MirroredArk {
        version: 1,
        generation,
        ark_id: hex::encode(ark_id.0),
        w_label: W_LABEL.into(),
        sealed: base64::engine::general_purpose::STANDARD.encode([0x41; 60]),
        chain: Some(base64::engine::general_purpose::STANDARD.encode([0x42; 60])),
        created_at: now_rfc3339(),
    };
    mirror
        .put(
            &ark_mirror_name(generation, &hex::encode(ark_id.0)),
            serde_json::to_vec(&forged).unwrap(),
        )
        .await
        .unwrap();
}

/// Junk the parser must skip: not JSON, a newer format, and oversized.
async fn plant_junk(mirror: &MemoryMirror) {
    mirror
        .put(&format!("{ARK_MIRROR_PREFIX}zzz.json"), b"<html>".to_vec())
        .await
        .unwrap();
    let newer = serde_json::json!({"version": 2, "generation": 1});
    mirror
        .put(
            &ark_mirror_name(1, &"f".repeat(32)),
            serde_json::to_vec(&newer).unwrap(),
        )
        .await
        .unwrap();
    mirror
        .put(
            &ark_mirror_name(1, &"e".repeat(32)),
            vec![b' '; MAX_MIRROR_OBJECT + 1],
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn forged_gapped_or_junk_mirror_rows_never_lock_or_stop_a_healthy_node() {
    let (db, mirror, h) = (db().await, Arc::new(MemoryMirror::default()), holders());
    let k = open(&db, &mirror, &ROOT, config(&h, None)).await.unwrap();
    let dek = k.current_key("space-a").await.unwrap();
    let efp = k.escrow_view().await.unwrap().unwrap().efp;
    drop(k);
    plant_ark(&mirror, 2).await; // forged next generation
    plant_ark(&mirror, 4).await; // gap: no generation 3
    plant_junk(&mirror).await;

    for _ in 0..2 {
        let k = open(&db, &mirror, &ROOT, config(&h, None)).await.unwrap();
        assert_eq!(k.state(), KeyringState::Unlocked);
        assert_eq!(k.current_key("space-a").await.unwrap().bytes(), dek.bytes());
        let gens: Vec<i32> = AtRestStore::new(db.clone())
            .keys()
            .await
            .unwrap()
            .iter()
            .map(|r| r.generation)
            .collect();
        assert_eq!(gens, vec![1], "nothing unauthenticated was stored");
    }

    // A new root still waits for the real generation and recovers with it.
    let k = open(&db, &mirror, &NEW_ROOT, config(&h, Some(efp)))
        .await
        .unwrap();
    assert_eq!(k.state(), KeyringState::Locked);
    submit(&k, &h, 0).await.unwrap();
    assert_eq!(submit(&k, &h, 1).await.unwrap(), ShareOutcome::Unlocked);
    assert_eq!(
        k.key("space-a", DekId::new(1)).await.unwrap().bytes(),
        dek.bytes()
    );
}

#[tokio::test]
async fn an_empty_database_takes_back_only_authenticated_mirror_rows() {
    let (db, mirror, h) = (db().await, Arc::new(MemoryMirror::default()), holders());
    let k = open(&db, &mirror, &ROOT, config(&h, None)).await.unwrap();
    let dek = k.current_key("space-a").await.unwrap();
    k.rotate_ark().await.unwrap();
    let efp = k.escrow_view().await.unwrap().unwrap().efp;
    drop(k);
    plant_ark(&mirror, 3).await;
    plant_junk(&mirror).await;

    // A restore to before any key row, same root: generations 1 and 2 come
    // back (they authenticate); the forged generation 3 doesn't.
    at_rest_key::Entity::delete_many().exec(&db).await.unwrap();
    let k = open(&db, &mirror, &ROOT, config(&h, None)).await.unwrap();
    assert_eq!(k.state(), KeyringState::Unlocked);
    assert_eq!(
        k.key("space-a", DekId::new(1)).await.unwrap().bytes(),
        dek.bytes()
    );
    assert_eq!(at_rest_key::Entity::find().all(&db).await.unwrap().len(), 2);
    drop(k);

    // The same restore under a new root: nothing authenticates until the
    // pinned escrow's shares do; then the rows are stored, resealed.
    at_rest_key::Entity::delete_many().exec(&db).await.unwrap();
    let k = open(&db, &mirror, &NEW_ROOT, config(&h, Some(efp)))
        .await
        .unwrap();
    assert_eq!(k.state(), KeyringState::Locked);
    assert!(at_rest_key::Entity::find()
        .all(&db)
        .await
        .unwrap()
        .is_empty());
    submit(&k, &h, 2).await.unwrap();
    assert_eq!(submit(&k, &h, 0).await.unwrap(), ShareOutcome::Unlocked);
    assert_eq!(
        k.key("space-a", DekId::new(1)).await.unwrap().bytes(),
        dek.bytes()
    );
    assert_eq!(at_rest_key::Entity::find().all(&db).await.unwrap().len(), 2);
    drop(k);
    let k = open(&db, &mirror, &NEW_ROOT, config(&h, Some(efp)))
        .await
        .unwrap();
    assert_eq!(k.state(), KeyringState::Unlocked);

    // Only junk and no rows at all: fail closed, never provision over it.
    let (db, mirror) = (self::db().await, Arc::new(MemoryMirror::default()));
    plant_junk(&mirror).await;
    assert!(matches!(
        open(&db, &mirror, &ROOT, config(&h, None)).await,
        Err(AtRestError::Inconsistent(_))
    ));
    assert!(at_rest_key::Entity::find()
        .all(&db)
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn a_mirrored_data_key_for_another_space_is_never_stored() {
    let (db, mirror, h) = (db().await, Arc::new(MemoryMirror::default()), holders());
    let k = open(&db, &mirror, &ROOT, config(&h, None)).await.unwrap();
    let a = k.current_key("space-a").await.unwrap();
    // A bucket writer copies space-a's mirrored DEK to space-b's name.
    let keys = k.keys().unwrap();
    let a_name = dek_mirror_name(&keys.dek_tag.tag("space-a"), 1);
    let b_name = dek_mirror_name(&keys.dek_tag.tag("space-b"), 1);
    let copied = mirror.get(&a_name).await.unwrap().unwrap();
    mirror.put(&b_name, copied.clone()).await.unwrap();

    // It doesn't authenticate for space-b: never stored, never replaced,
    // and space-b fails closed rather than getting a new key over it.
    let unavailable = |r: Result<DataKey, DataKeyError>| {
        matches!(r, Err(DataKeyError::Backend(e))
            if matches!(e.downcast_ref::<AtRestError>(), Some(AtRestError::DekUnavailable(_))))
    };
    assert!(unavailable(k.key("space-b", DekId::new(1)).await));
    assert!(unavailable(k.current_key("space-b").await));
    assert!(AtRestStore::new(db.clone())
        .dek("space-b", 1)
        .await
        .unwrap()
        .is_none());
    assert_eq!(mirror.get(&b_name).await.unwrap().unwrap(), copied);
    assert_eq!(k.current_key("space-a").await.unwrap().bytes(), a.bytes());
}

/// The round-3 correctness probe D1: a restore before generation 2, plus
/// one failed read of the genuine generation-2 object at boot, used to
/// replace space-x's data key and overwrite its only copy.
#[tokio::test]
async fn a_mirrored_data_key_under_an_unloaded_generation_is_never_replaced() {
    let (db, mirror, h) = (db().await, Arc::new(MemoryMirror::default()), holders());
    let k = open(&db, &mirror, &ROOT, config(&h, None)).await.unwrap();
    k.rotate_ark().await.unwrap();
    let original = k.current_key("space-x").await.unwrap();
    let keys = k.keys().unwrap();
    let dek_name = dek_mirror_name(&keys.dek_tag.tag("space-x"), 1);
    let gen2 = AtRestStore::new(db.clone()).keys().await.unwrap()[1].clone();
    let gen2_name = ark_mirror_name(2, &hex::encode(&gen2.ark_id));
    drop((k, keys));
    let mirrored = mirror.get(&dek_name).await.unwrap().unwrap();

    // The restore: generation 2, its escrow and space-x's DEK row are gone.
    at_rest_key::Entity::delete_by_id(2)
        .exec(&db)
        .await
        .unwrap();
    at_rest_escrow::Entity::delete_many()
        .filter(at_rest_escrow::Column::Generation.eq(2))
        .exec(&db)
        .await
        .unwrap();
    space_data_key::Entity::delete_many()
        .exec(&db)
        .await
        .unwrap();
    // One boot where the genuine generation-2 object can't be read.
    mirror.set_unreadable(&gen2_name, true);
    let k = open(&db, &mirror, &ROOT, config(&h, None)).await.unwrap();
    assert_eq!(k.keys().unwrap().newest().0, 1);
    for _ in 0..2 {
        assert!(matches!(
            k.current_key("space-x").await,
            Err(DataKeyError::Backend(e))
                if matches!(e.downcast_ref::<AtRestError>(), Some(AtRestError::DekUnavailable(why)) if why.contains("hasn't loaded"))
        ));
    }
    assert_eq!(mirror.get(&dek_name).await.unwrap().unwrap(), mirrored);
    assert!(space_data_key::Entity::find()
        .all(&db)
        .await
        .unwrap()
        .is_empty());
    drop(k);

    // The object is readable again: generation 2 and the original key are back.
    mirror.set_unreadable(&gen2_name, false);
    let k = open(&db, &mirror, &ROOT, config(&h, None)).await.unwrap();
    assert_eq!(k.keys().unwrap().newest().0, 2);
    assert_eq!(
        k.current_key("space-x").await.unwrap().bytes(),
        original.bytes()
    );
}

#[tokio::test]
async fn a_wrong_holder_is_fixed_only_before_the_ceremony_and_with_a_fresh_root_key() {
    let (db, mirror, h) = (db().await, Arc::new(MemoryMirror::default()), holders());
    let wrong = open(&db, &mirror, &ROOT, config(&h, None)).await.unwrap();
    let old = wrong.escrow_view().await.unwrap().unwrap().bundle;
    drop(wrong);
    let old_keys = at_rest_key::Entity::find().all(&db).await.unwrap();
    let old_escrow = at_rest_escrow::Entity::find().all(&db).await.unwrap();
    let fixed = holders();
    let allow = |h: &Holders| KeyringConfig {
        allow_resplit_before_verify: true,
        ..config(h, None)
    };
    // Without the flag a holder change is refused, as before.
    assert!(matches!(
        open(&db, &mirror, &ROOT, config(&fixed, None)).await,
        Err(AtRestError::EscrowHoldersChanged)
    ));
    // With it, unverified and nothing sealed: a fresh ARK, split for the
    // new holders.
    let k = open(&db, &mirror, &ROOT, allow(&fixed)).await.unwrap();
    let new = k.escrow_view().await.unwrap().unwrap().bundle;
    assert_ne!(new.fingerprint(), old.fingerprint());
    assert_ne!(new.ark_id, old.ark_id);
    // The removed holder's old share, with any other old share, rebuilds
    // only the retired ARK, never the one now escrowed.
    let old_ark = old
        .recover(&h.decrypt(&old, 1), &h.decrypt(&old, 0))
        .unwrap();
    let new_ark = new
        .recover(&fixed.decrypt(&new, 0), &fixed.decrypt(&new, 2))
        .unwrap();
    assert_ne!(old_ark.expose(), new_ark.expose());
    // The old ARK's copy, bundle and record objects are gone from the mirror.
    let old_hex = hex::encode(old.ark_id.0);
    let names = mirror.list(MIRROR_PREFIX).await.unwrap();
    assert!(!names
        .iter()
        .any(|n| n.starts_with(ARK_MIRROR_PREFIX) && n.contains(&old_hex)));
    assert!(!names.contains(&escrow_mirror_name(&old.fingerprint().to_string())));
    drop(k);

    // A database restored to before the re-split never brings the old ARK
    // back: its rows are dropped and the fresh ARK comes from the mirror.
    at_rest_escrow::Entity::delete_many()
        .exec(&db)
        .await
        .unwrap();
    at_rest_key::Entity::delete_many().exec(&db).await.unwrap();
    at_rest_key::Entity::insert_many(old_keys.into_iter().map(IntoActiveModel::into_active_model))
        .exec(&db)
        .await
        .unwrap();
    at_rest_escrow::Entity::insert_many(
        old_escrow
            .into_iter()
            .map(IntoActiveModel::into_active_model),
    )
    .exec(&db)
    .await
    .unwrap();
    let k = open(&db, &mirror, &ROOT, config(&fixed, None))
        .await
        .unwrap();
    assert_eq!(
        k.escrow_view().await.unwrap().unwrap().bundle.ark_id,
        new.ark_id
    );
    assert!(at_rest_key::Entity::find()
        .all(&db)
        .await
        .unwrap()
        .iter()
        .all(|r| r.ark_id == new.ark_id.0));

    // Once verified, the flag no longer helps.
    verify_escrow(&k, &fixed).await;
    drop(k);
    assert!(matches!(
        open(&db, &mirror, &ROOT, allow(&h)).await,
        Err(AtRestError::EscrowHoldersChanged)
    ));
    // Nor when the database lost the record but the mirror still has it.
    at_rest_escrow::Entity::update_many()
        .col_expr(
            at_rest_escrow::Column::Record,
            sea_orm::sea_query::Expr::value(Option::<String>::None),
        )
        .exec(&db)
        .await
        .unwrap();
    assert!(matches!(
        open(&db, &mirror, &ROOT, allow(&h)).await,
        Err(AtRestError::EscrowHoldersChanged)
    ));

    // Unverified, but a data key exists (data may be sealed): refused,
    // also when only the mirror still has it.
    let (db, mirror) = (self::db().await, Arc::new(MemoryMirror::default()));
    let k = open(&db, &mirror, &ROOT, config(&h, None)).await.unwrap();
    k.current_key("space-a").await.unwrap();
    drop(k);
    assert!(matches!(
        open(&db, &mirror, &ROOT, allow(&fixed)).await,
        Err(AtRestError::EscrowHoldersChanged)
    ));
    space_data_key::Entity::delete_many()
        .exec(&db)
        .await
        .unwrap();
    assert!(matches!(
        open(&db, &mirror, &ROOT, allow(&fixed)).await,
        Err(AtRestError::EscrowHoldersChanged)
    ));
}

#[tokio::test]
async fn a_forged_retirement_marker_never_drops_a_live_root_key() {
    let (db, mirror, h) = (db().await, Arc::new(MemoryMirror::default()), holders());
    let k = open(&db, &mirror, &ROOT, config(&h, None)).await.unwrap();
    let bundle = k.escrow_view().await.unwrap().unwrap().bundle;
    drop(k);
    let id = hex::encode(bundle.ark_id.0);
    // A marker for the live ARK under another root's W, and junk.
    let forged = WrapKey::derive(&NEW_ROOT).retire_tag(&bundle.ark_id.0);
    mirror
        .put(
            &retired_mirror_name(&id),
            serde_json::to_vec(&MirroredRetired::new(id.clone(), &forged)).unwrap(),
        )
        .await
        .unwrap();
    mirror
        .put(&retired_mirror_name("junk"), b"not json".to_vec())
        .await
        .unwrap();
    let k = open(&db, &mirror, &ROOT, config(&h, None)).await.unwrap();
    assert_eq!(
        k.escrow_view().await.unwrap().unwrap().bundle.ark_id,
        bundle.ark_id
    );
}

#[tokio::test]
async fn a_pinned_escrow_is_never_re_split() {
    let (db, mirror, h) = (db().await, Arc::new(MemoryMirror::default()), holders());
    let k = open(&db, &mirror, &ROOT, config(&h, None)).await.unwrap();
    let efp = k.escrow_view().await.unwrap().unwrap().efp;
    drop(k);
    // Different recipients with the pin still set: refused, nothing written.
    let changed = holders();
    assert!(matches!(
        open(&db, &mirror, &ROOT, config(&changed, Some(efp))).await,
        Err(AtRestError::EscrowHoldersChanged)
    ));
    assert_eq!(
        at_rest_escrow::Entity::find().all(&db).await.unwrap().len(),
        1
    );
    // Pinned to a bundle for other holders, with the database's row gone:
    // still no split.
    at_rest_escrow::Entity::delete_many()
        .exec(&db)
        .await
        .unwrap();
    assert!(matches!(
        open(&db, &mirror, &ROOT, config(&changed, Some(efp))).await,
        Err(AtRestError::EscrowPinned)
    ));
    assert!(at_rest_escrow::Entity::find()
        .all(&db)
        .await
        .unwrap()
        .is_empty());
    // Pinned and the database lost the bundle: the pinned one comes back
    // from the mirror, no new split.
    at_rest_escrow::Entity::delete_many()
        .exec(&db)
        .await
        .unwrap();
    let k = open(&db, &mirror, &ROOT, config(&h, Some(efp)))
        .await
        .unwrap();
    assert_eq!(k.escrow_view().await.unwrap().unwrap().efp, efp);
    assert_eq!(
        at_rest_escrow::Entity::find().all(&db).await.unwrap().len(),
        1
    );
}

#[tokio::test]
async fn migration_down_refuses_to_drop_keys() {
    let (db, mirror, h) = (db().await, Arc::new(MemoryMirror::default()), holders());
    open(&db, &mirror, &ROOT, config(&h, None)).await.unwrap();
    assert!(crate::migrations::Migrator::down(&db, Some(1))
        .await
        .is_err());
    assert_eq!(at_rest_key::Entity::find().all(&db).await.unwrap().len(), 1);
    at_rest_escrow::Entity::delete_many()
        .exec(&db)
        .await
        .unwrap();
    at_rest_key::Entity::delete_many().exec(&db).await.unwrap();
    crate::migrations::Migrator::down(&db, Some(1))
        .await
        .unwrap();
    assert!(at_rest_key::Entity::find().all(&db).await.is_err());
}

#[tokio::test]
async fn unreadable_mirror_objects_never_stop_a_node_with_a_healthy_database() {
    let (db, mirror, h) = (db().await, Arc::new(MemoryMirror::default()), holders());
    let k = open(&db, &mirror, &ROOT, config(&h, None)).await.unwrap();
    let dek = k.current_key("space-a").await.unwrap();
    let efp = k.escrow_view().await.unwrap().unwrap().efp;
    drop(k);
    // Objects the real mirror can't read: odd names, a directory, a symlink.
    for name in [
        "ark-0000000002-x y.json",
        "ark-..json",
        "ark-0000000002-x+y.json",
        "ark-0000000002-d.json",
        "record-x y.json",
    ] {
        mirror.plant_unreadable(&format!("{MIRROR_PREFIX}{name}"));
    }
    for pin in [None, Some(efp)] {
        let k = open(&db, &mirror, &ROOT, config(&h, pin)).await.unwrap();
        assert_eq!(k.state(), KeyringState::Unlocked);
        assert_eq!(k.current_key("space-a").await.unwrap().bytes(), dek.bytes());
    }
    // A new root still boots locked and recovers.
    let k = open(&db, &mirror, &NEW_ROOT, config(&h, Some(efp)))
        .await
        .unwrap();
    submit(&k, &h, 0).await.unwrap();
    assert_eq!(submit(&k, &h, 1).await.unwrap(), ShareOutcome::Unlocked);
    drop(k);

    // With an empty database the mirror is all there is: an object that
    // can't be read stops the boot rather than guessing.
    at_rest_key::Entity::delete_many().exec(&db).await.unwrap();
    assert!(matches!(
        open(&db, &mirror, &NEW_ROOT, config(&h, Some(efp))).await,
        Err(AtRestError::Mirror(_))
    ));
}

#[tokio::test]
async fn a_mirror_that_cannot_be_written_only_matters_once_keys_may_seal() {
    let (db, mirror, h) = (db().await, Arc::new(MemoryMirror::default()), holders());
    open(&db, &mirror, &ROOT, config(&h, None)).await.unwrap();
    // The mirror lost its copies and can't take new ones.
    mirror.clear();
    mirror.set_read_only(true);
    let off = KeyringConfig {
        require_mirror: false,
        ..config(&h, None)
    };
    let k = open(&db, &mirror, &ROOT, off).await.unwrap();
    assert_eq!(k.state(), KeyringState::Unlocked);
    drop(k);
    assert!(matches!(
        open(&db, &mirror, &ROOT, config(&h, None)).await,
        Err(AtRestError::Mirror(_))
    ));
}
