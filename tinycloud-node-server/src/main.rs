#[cfg(all(feature = "jemalloc", target_env = "musl"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use hyper::{
    service::{make_service_fn, service_fn},
    Server,
};
use rocket::{
    figment::providers::{Env, Format, Serialized, Toml},
    tokio,
};
use tinycloud::{app, config, prometheus, resolve_runtime_config};

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

/// Report panics off the main thread (request handlers and background tasks)
/// by location only. Their messages can format request data, and production
/// logs are public (TC-961). Startup panics on the main thread keep the
/// default report, which operators need to fix a bad configuration.
fn install_panic_hook() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let thread = std::thread::current();
        if thread.name() == Some("main") {
            default_hook(info);
            return;
        }
        let location = info
            .location()
            .map(|location| format!("{}:{}", location.file(), location.line()));
        eprintln!(
            "thread '{}' panicked at {}: <message withheld from the log>",
            thread.name().unwrap_or("<unnamed>"),
            location.as_deref().unwrap_or("<unknown>"),
        );
    }));
}

/// The server start path is only for the two invocations that exist outside
/// the CLI: no arguments (the container entrypoint, `cargo run`) and exactly
/// `--validate-config` (the deploy preflight). Every other argv goes to clap,
/// which also rejects anything it does not recognise instead of booting.
fn starts_server(args: &[std::ffi::OsString]) -> bool {
    match args {
        [] => true,
        [only] => only == "--validate-config",
        _ => false,
    }
}

fn main() {
    install_panic_hook();
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if !starts_server(&args) {
        if let Err(e) = tinycloud::cli::run() {
            eprintln!("\n✗ tinycloud-node failed:\n");
            for cause in e.chain() {
                eprintln!("  {cause}");
            }
            std::process::exit(1);
        }
        return;
    }
    // The runtime `#[rocket::main]` used to set up: worker and blocking
    // thread counts come from ROCKET_WORKERS / ROCKET_MAX_BLOCKING.
    rocket::execute(start_server());
}

async fn start_server() {
    let config = build_config_figment(); // That's just for easy access to ROCKET_LOG_LEVEL
    let tinycloud_config = config.extract::<config::Config>().unwrap();

    if std::env::args_os()
        .skip(1)
        .any(|arg| arg == "--validate-config")
    {
        match resolve_runtime_config(&tinycloud_config) {
            Ok(_) => {
                eprintln!("tinycloud-node runtime configuration is valid");
                return;
            }
            Err(error) => {
                eprintln!("tinycloud-node runtime configuration is invalid");
                for cause in error.chain() {
                    eprintln!("  {cause}");
                }
                std::process::exit(1);
            }
        }
    }

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
    fn did_resolution_defaults_off_and_canonical_env_enables_it() {
        let _lock = lock_env();
        let _network = EnvVarGuard::unset("TINYCLOUD_DID_RESOLUTION__NETWORK_METHODS");
        assert!(!config::Config::default().did_resolution.network_methods);
        assert!(
            !build_config_figment()
                .extract::<config::Config>()
                .unwrap()
                .did_resolution
                .network_methods
        );
        let _network = EnvVarGuard::set("TINYCLOUD_DID_RESOLUTION__NETWORK_METHODS", "true");
        assert!(
            build_config_figment()
                .extract::<config::Config>()
                .unwrap()
                .did_resolution
                .network_methods
        );
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
    fn epoch_head_backfill_enabled_reads_only_the_double_underscore_key() {
        let _lock = lock_env();
        let single = "TINYCLOUD_EPOCH_HEAD_BACKFILL_ENABLED";
        let double = "TINYCLOUD_EPOCH_HEAD_BACKFILL__ENABLED";
        let rate = "TINYCLOUD_EPOCH_HEAD_BACKFILL__SPACES_PER_SECOND";
        let extract = || {
            build_config_figment()
                .extract::<config::Config>()
                .expect("config should parse")
                .epoch_head_backfill
        };

        let _s = EnvVarGuard::unset(single);
        let _d = EnvVarGuard::unset(double);
        let _r = EnvVarGuard::unset(rate);
        assert!(extract().enabled, "backfill is on by default");

        // The production compose sets this key (TC-1274).
        let _d = EnvVarGuard::set(double, "false");
        assert!(!extract().enabled);
        drop(_d);

        // The trap: a single underscore is a silent no-op.
        let _s = EnvVarGuard::set(single, "false");
        assert!(
            extract().enabled,
            "single-underscore form must not disable it"
        );
        drop(_s);

        // The key the later ramp tunes.
        let _r = EnvVarGuard::set(rate, "7");
        assert_eq!(extract().spaces_per_second, 7);
    }

    #[test]
    fn sql_store_loads_from_the_double_underscore_keys() {
        let _lock = lock_env();
        let keys = [
            "TINYCLOUD_SQL_STORE__ENABLED",
            "TINYCLOUD_SQL_STORE__UPLOAD_INTERVAL_SECS",
            "TINYCLOUD_SQL_STORE__UPLOAD_BYTES",
            "TINYCLOUD_SQL_STORE__RETENTION__HISTORY_DAYS__FREE",
        ];
        let _unset: Vec<_> = keys.iter().map(|k| EnvVarGuard::unset(k)).collect();
        let extract = || {
            build_config_figment()
                .extract::<config::Config>()
                .expect("config should parse")
                .sql_store
        };
        let defaults = extract();
        assert!(!defaults.enabled);
        assert_eq!(defaults.upload_interval_secs, 60);

        let _e = EnvVarGuard::set(keys[0], "true");
        let _i = EnvVarGuard::set(keys[1], "15");
        let _b = EnvVarGuard::set(keys[2], "2 MiB");
        let _r = EnvVarGuard::set(keys[3], "7");
        let loaded = extract();
        assert!(loaded.enabled);
        assert_eq!(loaded.upload_interval_secs, 15);
        assert_eq!(loaded.upload_bytes, rocket::data::ByteUnit::Mebibyte(2));
        assert_eq!(loaded.retention.history_days.get("free"), Some(&7));
    }

    #[test]
    fn sql_durability_settings_default_and_take_env_overrides() {
        use tinycloud_core::sql::durability::Synchronous;
        let _lock = lock_env();
        let names = [
            "TINYCLOUD_STORAGE__SQL__SYNCHRONOUS",
            "TINYCLOUD_STORAGE_SQL_SYNCHRONOUS",
            "TINYCLOUD_STORAGE__SQL__MAX_DATABASE_BYTES",
            "TINYCLOUD_STORAGE__SQL__MIN_FREE_BYTES",
        ];
        let _unset: Vec<_> = names.iter().map(|name| EnvVarGuard::unset(name)).collect();
        let extract = || {
            build_config_figment()
                .extract::<config::Config>()
                .expect("config should parse")
                .storage
                .sql
        };

        let sql = extract();
        assert_eq!(sql.synchronous, Synchronous::Full, "full by default");
        assert_eq!(sql.max_database_bytes.as_u64(), 0, "no cap by default");
        assert_eq!(
            sql.min_free_bytes.as_u64(),
            0,
            "headroom check off by default"
        );
        let policy = sql.durability();
        assert_eq!(policy.synchronous, Synchronous::Full);
        assert_eq!(policy.max_database_bytes, 0);
        assert_eq!(policy.min_free_bytes, 0);

        let _canonical = EnvVarGuard::set("TINYCLOUD_STORAGE__SQL__SYNCHRONOUS", "normal");
        let _max = EnvVarGuard::set("TINYCLOUD_STORAGE__SQL__MAX_DATABASE_BYTES", "2 GiB");
        let _free = EnvVarGuard::set("TINYCLOUD_STORAGE__SQL__MIN_FREE_BYTES", "1 GiB");
        let sql = extract();
        assert_eq!(sql.synchronous, Synchronous::Normal);
        assert_eq!(sql.max_database_bytes.as_u64(), 2 << 30);
        assert_eq!(sql.min_free_bytes.as_u64(), 1 << 30);
        drop(_canonical);

        let _legacy = EnvVarGuard::set("TINYCLOUD_STORAGE_SQL_SYNCHRONOUS", "normal");
        assert_eq!(extract().synchronous, Synchronous::Normal);
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
