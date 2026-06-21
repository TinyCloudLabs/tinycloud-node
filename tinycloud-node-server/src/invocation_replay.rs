use std::collections::HashMap;

use rocket::http::Status;
use time::{Duration, OffsetDateTime};
use tinycloud_core::{events::Invocation, hash::Hash};
use tokio::sync::Mutex;

const CLOCK_SKEW_SECONDS: i64 = 60;

#[derive(Debug, thiserror::Error)]
pub enum InvocationReplayError {
    #[error("duplicate invocation")]
    Duplicate,
}

#[derive(Default)]
pub struct InvocationReplayCache {
    seen: Mutex<HashMap<Hash, OffsetDateTime>>,
}

impl InvocationReplayCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn check_and_insert(
        &self,
        invocation: &Invocation,
    ) -> Result<(), InvocationReplayError> {
        let now = OffsetDateTime::now_utc();
        let key = invocation.content_hash();
        let expires_at = invocation_expires_at(invocation, now);
        self.check_and_insert_key(key, expires_at, now).await
    }

    async fn check_and_insert_key(
        &self,
        key: Hash,
        expires_at: OffsetDateTime,
        now: OffsetDateTime,
    ) -> Result<(), InvocationReplayError> {
        let mut seen = self.seen.lock().await;
        seen.retain(|_, expires_at| *expires_at > now);

        if seen.contains_key(&key) {
            return Err(InvocationReplayError::Duplicate);
        }

        seen.insert(key, expires_at);
        Ok(())
    }
}

impl From<InvocationReplayError> for (Status, String) {
    fn from(err: InvocationReplayError) -> Self {
        match err {
            InvocationReplayError::Duplicate => (Status::Conflict, err.to_string()),
        }
    }
}

fn invocation_expires_at(invocation: &Invocation, now: OffsetDateTime) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(
        invocation.0.invocation.payload().expiration.as_seconds() as i64 + CLOCK_SKEW_SECONDS,
    )
    .unwrap_or(now + Duration::seconds(CLOCK_SKEW_SECONDS))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tinycloud_core::hash::hash;

    #[tokio::test]
    async fn duplicate_key_is_rejected_until_entry_expires() {
        let cache = InvocationReplayCache::new();
        let key = hash(b"invocation");
        let now = OffsetDateTime::now_utc();

        assert!(cache
            .check_and_insert_key(key, now + Duration::seconds(60), now)
            .await
            .is_ok());
        assert!(matches!(
            cache
                .check_and_insert_key(key, now + Duration::seconds(60), now)
                .await,
            Err(InvocationReplayError::Duplicate)
        ));
        assert!(cache
            .check_and_insert_key(
                key,
                now + Duration::seconds(120),
                now + Duration::seconds(61)
            )
            .await
            .is_ok());
    }
}
