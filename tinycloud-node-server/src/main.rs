fn main() {
    if let Err(e) = tinycloud::cli::run() {
        eprintln!("\n✗ tinycloud-node failed:\n");
        for cause in e.chain() {
            eprintln!("  {cause}");
        }
        std::process::exit(1);
    }
}

#[cfg(test)]
fn build_config_figment() -> rocket::figment::Figment {
    tinycloud::runtime::legacy_config_figment()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    struct EnvVarGuard {
        key: &'static str,
        previous: Option<String>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let previous = std::env::var(key).ok();
            std::env::set_var(key, value);
            Self { key, previous }
        }

        fn unset(key: &'static str) -> Self {
            let previous = std::env::var(key).ok();
            std::env::remove_var(key);
            Self { key, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match &self.previous {
                Some(value) => std::env::set_var(self.key, value),
                None => std::env::remove_var(self.key),
            }
        }
    }

    fn lock_env() -> std::sync::MutexGuard<'static, ()> {
        static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("env lock should not be poisoned")
    }

    fn clear_keys_env() -> (
        EnvVarGuard,
        EnvVarGuard,
        EnvVarGuard,
        EnvVarGuard,
        EnvVarGuard,
    ) {
        (
            EnvVarGuard::unset("TINYCLOUD_KEYS"),
            EnvVarGuard::unset("TINYCLOUD_KEYS_TYPE"),
            EnvVarGuard::unset("TINYCLOUD_KEYS__TYPE"),
            EnvVarGuard::unset("TINYCLOUD_KEYS_SECRET"),
            EnvVarGuard::unset("TINYCLOUD_KEYS__SECRET"),
        )
    }

    #[test]
    fn canonical_double_underscore_loads_hooks_max_ticket_ttl_seconds() {
        let _lock = lock_env();
        let _keys_env = clear_keys_env();
        let _legacy = EnvVarGuard::unset("TINYCLOUD_HOOKS_MAX_TICKET_TTL_SECONDS");
        let _canonical = EnvVarGuard::set("TINYCLOUD_HOOKS__MAX_TICKET_TTL_SECONDS", "777");

        let cfg = build_config_figment()
            .extract::<tinycloud::config::Config>()
            .expect("config should parse");

        assert_eq!(cfg.hooks.max_ticket_ttl_seconds, 777);
    }

    #[test]
    fn canonical_double_underscore_loads_storage_database() {
        let _lock = lock_env();
        let _keys_env = clear_keys_env();
        let _legacy = EnvVarGuard::unset("TINYCLOUD_STORAGE_DATABASE");
        let _canonical = EnvVarGuard::set(
            "TINYCLOUD_STORAGE__DATABASE",
            "sqlite:/tmp/canonical-storage.db",
        );

        let cfg = build_config_figment()
            .extract::<tinycloud::config::Config>()
            .expect("config should parse");

        assert_eq!(
            cfg.storage.database.as_deref(),
            Some("sqlite:/tmp/canonical-storage.db")
        );
    }

    #[test]
    fn telemetry_defaults_to_disabled() {
        let _lock = lock_env();
        let _keys_env = clear_keys_env();
        let _legacy = EnvVarGuard::unset("TINYCLOUD_TELEMETRY_ENABLED");
        let _canonical = EnvVarGuard::unset("TINYCLOUD_TELEMETRY__ENABLED");

        let cfg = build_config_figment()
            .extract::<tinycloud::config::Config>()
            .expect("config should parse");

        assert!(!cfg.telemetry.enabled);
    }

    #[test]
    fn canonical_double_underscore_loads_telemetry_enabled() {
        let _lock = lock_env();
        let _keys_env = clear_keys_env();
        let _legacy = EnvVarGuard::unset("TINYCLOUD_TELEMETRY_ENABLED");
        let _canonical = EnvVarGuard::set("TINYCLOUD_TELEMETRY__ENABLED", "true");

        let cfg = build_config_figment()
            .extract::<tinycloud::config::Config>()
            .expect("config should parse");

        assert!(cfg.telemetry.enabled);
    }

    #[test]
    fn canonical_double_underscore_wins_for_storage_database_when_both_are_set() {
        let _lock = lock_env();
        let _keys_env = clear_keys_env();
        let _legacy = EnvVarGuard::set("TINYCLOUD_STORAGE_DATABASE", "sqlite:/tmp/legacy.db");
        let _canonical =
            EnvVarGuard::set("TINYCLOUD_STORAGE__DATABASE", "sqlite:/tmp/canonical.db");

        let cfg = build_config_figment()
            .extract::<tinycloud::config::Config>()
            .expect("config should parse");

        assert_eq!(
            cfg.storage.database.as_deref(),
            Some("sqlite:/tmp/canonical.db")
        );
    }
}
