use hyper::{
    service::{make_service_fn, service_fn},
    Server,
};
use rocket::{
    figment::providers::{Env, Format, Serialized, Toml},
    tokio,
};
use tinycloud::{app, config, prometheus};

fn build_config_figment() -> rocket::figment::Figment {
    let config_file =
        std::env::var("TINYCLOUD_CONFIG_FILE").unwrap_or_else(|_| "tinycloud.toml".to_owned());
    rocket::figment::Figment::from(rocket::Config::default())
        .merge(Serialized::defaults(config::Config::default()))
        .merge(Toml::file(config_file).nested())
        // Legacy env style: single underscore as nesting separator.
        .merge(Env::prefixed("TINYCLOUD_").split("_").global())
        // Canonical env style: double underscore as nesting separator.
        // Loaded second so canonical values win when both are present.
        .merge(Env::prefixed("TINYCLOUD_").split("__").global())
        .merge(Env::prefixed("ROCKET_").global())
}

#[rocket::main]
async fn main() {
    let config = build_config_figment(); // That's just for easy access to ROCKET_LOG_LEVEL
    let tinycloud_config = config.extract::<config::Config>().unwrap();

    let rocket = match app(&config).await {
        Ok(r) => r.ignite().await.unwrap(),
        Err(e) => {
            eprintln!("\n✗ Failed to start tinycloud-node:\n");
            for cause in e.chain() {
                eprintln!("  {cause}");
            }
            eprintln!("\nCheck your tinycloud.toml or TINYCLOUD_ environment variables.");
            std::process::exit(1);
        }
    };

    if tinycloud_config.telemetry.enabled {
        let prom_addr = (rocket.config().address, tinycloud_config.prometheus.port).into();
        let prometheus = Server::bind(&prom_addr).serve(make_service_fn(|_| async {
            Ok::<_, hyper::Error>(service_fn(prometheus::serve_req))
        }));

        tokio::select! {
            r = rocket.launch() => {let _ = r.unwrap();},
            r = prometheus => r.unwrap()
        };
    } else {
        let _ = rocket.launch().await.unwrap();
    }
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

    #[test]
    fn canonical_double_underscore_loads_hooks_max_ticket_ttl_seconds() {
        let _lock = lock_env();
        let _legacy = EnvVarGuard::unset("TINYCLOUD_HOOKS_MAX_TICKET_TTL_SECONDS");
        let _canonical = EnvVarGuard::set("TINYCLOUD_HOOKS__MAX_TICKET_TTL_SECONDS", "777");

        let cfg = build_config_figment()
            .extract::<config::Config>()
            .expect("config should parse");

        assert_eq!(cfg.hooks.max_ticket_ttl_seconds, 777);
    }

    #[test]
    fn canonical_double_underscore_loads_storage_database() {
        let _lock = lock_env();
        let _legacy = EnvVarGuard::unset("TINYCLOUD_STORAGE_DATABASE");
        let _canonical = EnvVarGuard::set(
            "TINYCLOUD_STORAGE__DATABASE",
            "sqlite:/tmp/canonical-storage.db",
        );

        let cfg = build_config_figment()
            .extract::<config::Config>()
            .expect("config should parse");

        assert_eq!(
            cfg.storage.database.as_deref(),
            Some("sqlite:/tmp/canonical-storage.db")
        );
    }

    #[test]
    fn telemetry_defaults_to_disabled() {
        let _lock = lock_env();
        let _legacy = EnvVarGuard::unset("TINYCLOUD_TELEMETRY_ENABLED");
        let _canonical = EnvVarGuard::unset("TINYCLOUD_TELEMETRY__ENABLED");

        let cfg = build_config_figment()
            .extract::<config::Config>()
            .expect("config should parse");

        assert!(!cfg.telemetry.enabled);
    }

    #[test]
    fn canonical_double_underscore_loads_telemetry_enabled() {
        let _lock = lock_env();
        let _legacy = EnvVarGuard::unset("TINYCLOUD_TELEMETRY_ENABLED");
        let _canonical = EnvVarGuard::set("TINYCLOUD_TELEMETRY__ENABLED", "true");

        let cfg = build_config_figment()
            .extract::<config::Config>()
            .expect("config should parse");

        assert!(cfg.telemetry.enabled);
    }

    #[test]
    fn canonical_double_underscore_wins_for_storage_database_when_both_are_set() {
        let _lock = lock_env();
        let _legacy = EnvVarGuard::set("TINYCLOUD_STORAGE_DATABASE", "sqlite:/tmp/legacy.db");
        let _canonical =
            EnvVarGuard::set("TINYCLOUD_STORAGE__DATABASE", "sqlite:/tmp/canonical.db");

        let cfg = build_config_figment()
            .extract::<config::Config>()
            .expect("config should parse");

        assert_eq!(
            cfg.storage.database.as_deref(),
            Some("sqlite:/tmp/canonical.db")
        );
    }

    #[test]
    fn configured_toml_file_is_loaded_before_environment_overrides() {
        let _lock = lock_env();
        let file = tempfile::NamedTempFile::new().expect("temporary config");
        std::fs::write(
            file.path(),
            "[global.share_email]\nreadiness_max_age_seconds = 42\n",
        )
        .expect("write temporary config");
        let _config_file = EnvVarGuard::set(
            "TINYCLOUD_CONFIG_FILE",
            file.path().to_str().expect("temporary config path"),
        );
        let _readiness = EnvVarGuard::unset("TINYCLOUD_SHARE_EMAIL_READINESS_MAX_AGE_SECONDS");
        let _canonical_readiness =
            EnvVarGuard::unset("TINYCLOUD_SHARE_EMAIL__READINESS_MAX_AGE_SECONDS");

        let cfg = build_config_figment()
            .extract::<config::Config>()
            .expect("config should parse");

        assert_eq!(cfg.share_email.readiness_max_age_seconds, 42);
    }
}
