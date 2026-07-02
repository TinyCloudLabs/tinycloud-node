use anyhow::{Context, Result};
use hyper::{
    service::{make_service_fn, service_fn},
    Server,
};
use rocket::{
    figment::providers::{Env, Format, Serialized, Toml},
    tokio,
};
use std::path::{Path, PathBuf};

use crate::{app, config, node_control::paths::Profile, prometheus};

fn with_serve_env(figment: rocket::figment::Figment) -> rocket::figment::Figment {
    figment
        .merge(Env::prefixed("TINYCLOUD_").split("_").global())
        .merge(Env::prefixed("TINYCLOUD_").split("__").global())
        .merge(Env::prefixed("ROCKET_").global())
}

pub fn legacy_config_figment() -> rocket::figment::Figment {
    with_serve_env(
        rocket::figment::Figment::from(rocket::Config::default())
            .merge(Serialized::defaults(config::Config::default()))
            .merge(Toml::file("tinycloud.toml").nested()),
    )
}

pub fn serve_config_figment(base_config_path: &Path) -> Result<rocket::figment::Figment> {
    let mut base = rocket::figment::Figment::from(rocket::Config::default())
        .merge(Serialized::defaults(config::Config::default()));

    if base_config_path.exists() {
        base = base.merge(Toml::file(base_config_path).nested());
    }

    let mut resolved = with_serve_env(base.clone())
        .extract::<config::Config>()
        .with_context(|| {
            format!(
                "failed to load base config at {}",
                base_config_path.display()
            )
        })?;
    resolved.storage.resolve();
    let overlay_path = resolved
        .storage
        .datadir
        .join("runtime/config.override.toml");

    let mut figment = base;
    if overlay_path.exists() {
        figment = figment.merge(Toml::file(&overlay_path).nested());
    }

    Ok(with_serve_env(figment))
}

pub async fn launch_with_figment(figment: rocket::figment::Figment) -> Result<()> {
    let tinycloud_config = figment.extract::<config::Config>()?;
    let rocket = match app(&figment).await {
        Ok(r) => r.ignite().await?,
        Err(e) => {
            eprintln!("\n✗ Failed to start tinycloud-node:\n");
            for cause in e.chain() {
                eprintln!("  {cause}");
            }
            eprintln!("\nCheck your tinycloud.toml or TINYCLOUD_ environment variables.");
            std::process::exit(1);
        }
    };

    launch_rocket(
        rocket,
        tinycloud_config.telemetry.enabled,
        tinycloud_config.prometheus.port,
    )
    .await
}

async fn launch_rocket(
    rocket: rocket::Rocket<rocket::Ignite>,
    telemetry_enabled: bool,
    prometheus_port: u16,
) -> Result<()> {
    let shutdown = rocket.shutdown();

    tokio::spawn(async move {
        wait_for_shutdown_signal().await;
        shutdown.notify();
    });

    if telemetry_enabled {
        let prom_addr = (rocket.config().address, prometheus_port).into();
        let prometheus = Server::bind(&prom_addr).serve(make_service_fn(|_| async {
            Ok::<_, hyper::Error>(service_fn(prometheus::serve_req))
        }));

        tokio::select! {
            r = rocket.launch() => {
                r?;
            },
            r = prometheus => r?,
        };
    } else {
        rocket.launch().await?;
    }

    Ok(())
}

async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use rocket::tokio::signal::unix::{signal, SignalKind};
        let mut sigint = signal(SignalKind::interrupt()).expect("SIGINT handler should install");
        let mut sigterm = signal(SignalKind::terminate()).expect("SIGTERM handler should install");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = sigint.recv() => {},
            _ = sigterm.recv() => {},
        }
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

pub fn serve_profile_config_path(profile: Profile) -> PathBuf {
    profile.paths().config_path
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        env,
        ffi::OsString,
        fs,
        sync::{Mutex, OnceLock},
    };
    use tempfile::tempdir;

    struct EnvGuard {
        key: &'static str,
        previous: Option<OsString>,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: impl AsRef<std::ffi::OsStr>) -> Self {
            let previous = env::var_os(key);
            env::set_var(key, value);
            Self { key, previous }
        }

        fn unset(key: &'static str) -> Self {
            let previous = env::var_os(key);
            env::remove_var(key);
            Self { key, previous }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.previous {
                Some(value) => env::set_var(self.key, value),
                None => env::remove_var(self.key),
            }
        }
    }

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|err| err.into_inner())
    }

    #[test]
    fn serve_config_figment_uses_env_resolved_datadir_for_overlay() {
        let _lock = env_lock();
        let temp = tempdir().unwrap();
        let base = temp.path().join("base.toml");
        let base_data = temp.path().join("base-data");
        let override_data = temp.path().join("override-data");
        fs::create_dir_all(&base_data).unwrap();
        fs::create_dir_all(override_data.join("runtime")).unwrap();
        fs::write(
            &base,
            format!(
                "[global]\n\n[global.storage]\ndatadir = \"{}\"\n",
                base_data.display()
            ),
        )
        .unwrap();
        fs::write(
            override_data.join("runtime/config.override.toml"),
            "[global.telemetry]\nenabled = true\n",
        )
        .unwrap();
        let _storage_datadir = EnvGuard::set("TINYCLOUD_STORAGE_DATADIR", &override_data);
        let _storage_datadir_canonical = EnvGuard::unset("TINYCLOUD_STORAGE__DATADIR");
        let _telemetry_legacy = EnvGuard::unset("TINYCLOUD_TELEMETRY_ENABLED");
        let _telemetry_canonical = EnvGuard::unset("TINYCLOUD_TELEMETRY__ENABLED");
        let _rocket_address = EnvGuard::unset("ROCKET_ADDRESS");
        let _rocket_port = EnvGuard::unset("ROCKET_PORT");
        let _rocket_config = EnvGuard::unset("ROCKET_CONFIG");
        let _rocket_profile = EnvGuard::unset("ROCKET_PROFILE");

        let figment = serve_config_figment(&base).unwrap();
        let cfg = figment.extract::<config::Config>().unwrap();

        assert_eq!(cfg.storage.datadir, override_data);
        assert!(cfg.telemetry.enabled);
    }
}
