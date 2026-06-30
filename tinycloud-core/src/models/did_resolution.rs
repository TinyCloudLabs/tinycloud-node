use std::{env, time::Duration};

pub(crate) const DID_RESOLUTION_TIMEOUT_ENV: &str = "TINYCLOUD_DID_RESOLUTION_TIMEOUT_MS";
const DEFAULT_DID_RESOLUTION_TIMEOUT: Duration = Duration::from_secs(3);

pub(crate) fn did_resolution_timeout() -> Duration {
    env::var(DID_RESOLUTION_TIMEOUT_ENV)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .map(Duration::from_millis)
        .unwrap_or(DEFAULT_DID_RESOLUTION_TIMEOUT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn restore_env(previous: Option<std::ffi::OsString>) {
        match previous {
            Some(value) => env::set_var(DID_RESOLUTION_TIMEOUT_ENV, value),
            None => env::remove_var(DID_RESOLUTION_TIMEOUT_ENV),
        }
    }

    #[test]
    fn uses_default_timeout_when_env_is_missing() {
        let _guard = env_lock().lock().unwrap();
        let previous = env::var_os(DID_RESOLUTION_TIMEOUT_ENV);

        env::remove_var(DID_RESOLUTION_TIMEOUT_ENV);
        assert_eq!(did_resolution_timeout(), Duration::from_secs(3));

        restore_env(previous);
    }

    #[test]
    fn uses_timeout_from_env_milliseconds() {
        let _guard = env_lock().lock().unwrap();
        let previous = env::var_os(DID_RESOLUTION_TIMEOUT_ENV);

        env::set_var(DID_RESOLUTION_TIMEOUT_ENV, "1250");
        assert_eq!(did_resolution_timeout(), Duration::from_millis(1250));

        restore_env(previous);
    }

    #[test]
    fn invalid_env_uses_default_timeout() {
        let _guard = env_lock().lock().unwrap();
        let previous = env::var_os(DID_RESOLUTION_TIMEOUT_ENV);

        env::set_var(DID_RESOLUTION_TIMEOUT_ENV, "invalid");
        assert_eq!(did_resolution_timeout(), Duration::from_secs(3));

        env::set_var(DID_RESOLUTION_TIMEOUT_ENV, "0");
        assert_eq!(did_resolution_timeout(), Duration::from_secs(3));

        restore_env(previous);
    }
}
