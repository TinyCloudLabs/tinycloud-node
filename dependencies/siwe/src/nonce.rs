use rand::distributions::Alphanumeric;
use rand::{Rng, thread_rng};

/// Generates a secure nonce.
pub fn generate_nonce() -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(17)
        .map(char::from)
        .collect()
}
