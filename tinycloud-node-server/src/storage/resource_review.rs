//! Fresh review-ledger verification in the caller's acceptance transaction.
//! This adapter never creates a fence/job or enables a lifecycle route.
use super::purge_ledger::PurgeLedgerStore;
use std::io::{Error, ErrorKind};
use tinycloud_core::{
    resource_review::{self, ReviewExpectation, ReviewUse, ReviewVerifier, VerifiedDecision},
    sea_orm::DatabaseTransaction,
};

async fn revocations(ledger: &dyn PurgeLedgerStore) -> Result<Vec<Vec<u8>>, Error> {
    let paths = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        ledger.list_purge_records(),
    )
    .await
    .map_err(|_| Error::other("review revocation ledger unavailable"))??;
    let mut records = Vec::new();
    for path in paths {
        let Some(id) = path.strip_prefix("_purge-ledger/review-revocations/") else {
            continue;
        };
        if uuid::Uuid::parse_str(id).is_err() || id.contains('/') {
            return Err(Error::other("invalid review revocation record"));
        }
        let body = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            ledger.read_purge_record(&path),
        )
        .await
        .map_err(|_| Error::other("review revocation ledger unavailable"))??
        .ok_or_else(|| Error::other("missing review revocation record"))?;
        if body.len() > 65_536 {
            return Err(Error::other("invalid review revocation record"));
        }
        let parsed: serde_json::Value = serde_json::from_slice(&body)
            .map_err(|_| Error::other("invalid review revocation record"))?;
        if parsed
            .get("payload")
            .and_then(|p| p.get(3))
            .and_then(|v| v.as_str())
            != Some(id)
        {
            return Err(Error::other("review revocation path mismatch"));
        }
        records.push(body);
    }
    Ok(records)
}

/// Caller holds the acceptance locks before calling; no cached absence is used.
/// A decision field is a signed carrier, never an assertion of authority.
pub async fn verify_current(
    ledger: &dyn PurgeLedgerStore,
    verifier: &ReviewVerifier,
    raw: &[u8],
    expected: &ReviewExpectation<'_>,
    now: i64,
) -> Result<VerifiedDecision, Error> {
    let revocations = revocations(ledger).await?;
    verifier
        .verify_decision(raw, &revocations, expected, now)
        .map_err(|_| Error::other("review decision unavailable or refused"))
}

/// Publish authenticated immutable evidence, then consume once in the SAME TX
/// as the caller's fence/job/purging evidence. No acceptance ACK before commit.
#[allow(clippy::too_many_arguments)]
pub async fn record_and_consume(
    tx: &DatabaseTransaction,
    ledger: &dyn PurgeLedgerStore,
    verifier: &ReviewVerifier,
    raw: &[u8],
    expected: &ReviewExpectation<'_>,
    purge_id: &str,
    clock: &(dyn Fn() -> time::OffsetDateTime + Send + Sync),
) -> Result<ReviewUse, Error> {
    let now = clock();
    let proof = verify_current(ledger, verifier, raw, expected, now.unix_timestamp()).await?;
    let parsed: serde_json::Value = serde_json::from_slice(proof.authenticated_body())
        .map_err(|_| Error::other("invalid review decision"))?;
    let body = serde_json::to_vec(&parsed).map_err(|_| Error::other("invalid review decision"))?;
    let path = format!(
        "_purge-ledger/decisions/{}/{}/{}",
        expected.host_id,
        expected.target.0,
        proof.decision_id()
    );
    match tokio::time::timeout(
        std::time::Duration::from_secs(20),
        ledger.append_purge_record(&path, &body),
    )
    .await
    .map_err(|_| Error::other("review decision ledger unavailable"))?
    {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {
            let existing = tokio::time::timeout(
                std::time::Duration::from_secs(20),
                ledger.read_purge_record(&path),
            )
            .await
            .map_err(|_| Error::other("review decision ledger unavailable"))??
            .ok_or_else(|| Error::other("missing review decision evidence"))?;
            let verified =
                verify_current(ledger, verifier, &existing, expected, now.unix_timestamp()).await?;
            let other: serde_json::Value = serde_json::from_slice(verified.authenticated_body())
                .map_err(|_| Error::other("invalid review decision evidence"))?;
            if other != parsed {
                return Err(Error::other("conflicting review decision evidence"));
            }
        }
        Err(_) => return Err(Error::other("review decision ledger unavailable")),
    }
    // Re-read immediately before consumption as publication may have yielded
    // while an operator published a kill switch. Expiry is checked again too.
    let now = clock();
    let proof = verify_current(ledger, verifier, raw, expected, now.unix_timestamp()).await?;
    resource_review::consume(tx, &proof, purge_id, now)
        .await
        .map_err(|_| Error::other("review decision already consumed or unavailable"))
}
