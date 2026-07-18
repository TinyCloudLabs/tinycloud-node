use anyhow::{Context, Result};
use hyper::{
    service::{make_service_fn, service_fn},
    Server,
};
use rocket::{
    figment::providers::{Env, Format, Serialized, Toml},
    tokio,
};
use std::{
    net::Ipv4Addr,
    path::{Path, PathBuf},
};
use tokio::sync::watch;

use crate::{
    app, config, link,
    node_control::{
        control::{self, ControlPlaneServer},
        paths::Profile,
    },
    prometheus,
};

fn with_serve_env(figment: rocket::figment::Figment) -> rocket::figment::Figment {
    figment
        .merge(Env::prefixed("TINYCLOUD_").split("_").global())
        .merge(Env::prefixed("TINYCLOUD_").split("__").global())
        .merge(Env::prefixed("ROCKET_").global())
}

fn spec_default_rocket_config() -> rocket::Config {
    rocket::Config {
        address: Ipv4Addr::LOCALHOST.into(),
        port: 8081,
        ..rocket::Config::default()
    }
}

pub fn legacy_config_figment() -> rocket::figment::Figment {
    with_serve_env(
        rocket::figment::Figment::from(spec_default_rocket_config())
            .merge(Serialized::defaults(config::Config::default()))
            .merge(Toml::file("tinycloud.toml").nested()),
    )
}

pub fn serve_config_figment(base_config_path: &Path) -> Result<rocket::figment::Figment> {
    let mut base = rocket::figment::Figment::from(spec_default_rocket_config())
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

pub async fn launch_with_figment(
    figment: rocket::figment::Figment,
    base_config_path: PathBuf,
) -> Result<()> {
    let mut tinycloud_config = figment.extract::<config::Config>()?;
    tinycloud_config.storage.resolve();
    let control = control::spawn_control_plane(
        &tinycloud_config,
        base_config_path,
        Profile::default_for_host(),
    )
    .await?;
    let rocket = match app(&figment, &tinycloud_config, Some(control.handle())).await {
        Ok(r) => r.ignite().await?,
        Err(e) => {
            eprintln!("\n✗ Failed to start tinycloud-node:\n");
            for cause in e.chain() {
                eprintln!("  {cause}");
            }
            eprintln!("\nCheck your tinycloud.toml or TINYCLOUD_ environment variables.");
            let _ = control.shutdown().await;
            std::process::exit(1);
        }
    };

    let public_api_port = rocket.config().port;
    launch_rocket(
        rocket,
        tinycloud_config.telemetry.enabled,
        tinycloud_config.prometheus.port,
        control,
        tinycloud_config.storage.datadir.clone(),
        public_api_port,
    )
    .await
}

async fn launch_rocket(
    rocket: rocket::Rocket<rocket::Ignite>,
    telemetry_enabled: bool,
    prometheus_port: u16,
    control: ControlPlaneServer,
    data_root: PathBuf,
    public_api_port: u16,
) -> Result<()> {
    let shutdown = rocket.shutdown();
    let control_for_signal = control.handle();
    let (link_shutdown_tx, link_shutdown_rx) = watch::channel(false);

    tokio::spawn(async move {
        wait_for_shutdown_signal(control_for_signal, shutdown).await;
    });

    // Spawn the LAN TLS terminator + auto-renew task if link is enabled.
    // Not enabled -> no listener bound, exactly as spec'd.
    let link_task = spawn_link_task(&data_root, public_api_port, link_shutdown_rx);

    let launch_result = if telemetry_enabled {
        let prom_addr = (rocket.config().address, prometheus_port).into();
        let prometheus = Server::bind(&prom_addr).serve(make_service_fn(|_| async {
            Ok::<_, hyper::Error>(service_fn(prometheus::serve_req))
        }));

        tokio::select! {
            r = rocket.launch() => r.context("rocket launch failed").map(|_| ()),
            r = prometheus => r.context("prometheus listener failed").map(|_| ()),
        }
    } else {
        rocket
            .launch()
            .await
            .context("rocket launch failed")
            .map(|_| ())
    };

    // Signal the link listener/renew task and let it drain.
    let _ = link_shutdown_tx.send(true);
    if let Some(handle) = link_task {
        let _ = handle.await;
    }

    control.shutdown().await?;
    launch_result?;

    Ok(())
}

fn spawn_link_task(
    data_root: &Path,
    public_api_port: u16,
    shutdown: watch::Receiver<bool>,
) -> Option<tokio::task::JoinHandle<()>> {
    let material = match link::commands::load_tls_material(data_root) {
        Ok(Some(material)) => material,
        Ok(None) => {
            tracing::info!("link is disabled: no state.json — LAN listener not started");
            return None;
        }
        Err(err) => {
            tracing::warn!(%err, "failed to load link state; LAN listener not started");
            return None;
        }
    };
    let (state, key_pem, cert_pem) = material;
    let bind = link::commands::effective_bind_address(&state);
    let bind_addr: std::net::SocketAddr = match bind.parse() {
        Ok(addr) => addr,
        Err(err) => {
            tracing::warn!(%err, %bind, "invalid link bind address; LAN listener not started");
            return None;
        }
    };
    let upstream_addr: std::net::SocketAddr = match format!("127.0.0.1:{public_api_port}").parse() {
        Ok(addr) => addr,
        Err(err) => {
            tracing::warn!(%err, "invalid loopback API address; LAN listener not started");
            return None;
        }
    };
    let server_config = match link::proxy::build_rustls_config(&key_pem, &cert_pem) {
        Ok(cfg) => cfg,
        Err(err) => {
            tracing::warn!(%err, "failed to build TLS config; LAN listener not started");
            return None;
        }
    };
    let listener_shutdown = shutdown.clone();
    let listener_task = tokio::spawn(async move {
        if let Err(err) =
            link::proxy::run(bind_addr, upstream_addr, server_config, listener_shutdown).await
        {
            tracing::error!(%err, "link LAN listener exited with error");
        }
    });

    // Auto-renew loop: daily wake-up, renew when <30d from expiry OR if the
    // LAN IP set changed. Runs in the background alongside the listener.
    let renew_data_root = data_root.to_path_buf();
    let renew_shutdown = shutdown.clone();
    tokio::spawn(async move {
        run_link_renew_loop(renew_data_root, renew_shutdown).await;
    });

    Some(listener_task)
}

async fn run_link_renew_loop(data_root: PathBuf, mut shutdown: watch::Receiver<bool>) {
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(24 * 60 * 60));
    // First tick fires immediately — skip that so we don't renew on boot.
    ticker.tick().await;
    loop {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() { break; }
            }
            _ = ticker.tick() => {
                let should_renew = should_renew_now(&data_root);
                if should_renew {
                    // Off the async runtime because commands::renew uses blocking reqwest.
                    let cloned = data_root.clone();
                    let _ = tokio::task::spawn_blocking(move || {
                        let paths = match crate::node_control::paths::Profile::discovery_order_for_host()
                            .into_iter()
                            .map(|p| p.paths())
                            .find(|p| p.data_root == cloned)
                        {
                            Some(paths) => paths,
                            None => crate::node_control::paths::Profile::default_for_host().paths(),
                        };
                        let config = match crate::runtime::serve_config_figment(&paths.config_path)
                            .and_then(|f| f.extract::<crate::config::Config>().map_err(Into::into))
                        {
                            Ok(cfg) => cfg,
                            Err(err) => {
                                tracing::warn!(%err, "failed to load config for auto-renew");
                                return;
                            }
                        };
                        if let Err(err) = crate::link::commands::renew(&cloned, Some(&config.keys)) {
                            tracing::warn!(%err, "link auto-renew failed");
                        } else {
                            tracing::info!("link auto-renew succeeded");
                        }
                    }).await;
                }
            }
        }
    }
}

fn should_renew_now(data_root: &Path) -> bool {
    // Load state — if it's gone, do nothing.
    let Ok(Some(state)) = link::commands::load_state(data_root) else {
        return false;
    };
    // Renew if IP set changed since last claim.
    let current_ips = match link::ip::discover_lan_ips() {
        Ok(ips) => link::ip::format_lan_ips(&ips),
        Err(_) => return false,
    };
    if current_ips != state.last_lan_ips {
        return true;
    }
    // Renew if within 30 days of cert notAfter.
    let Some(not_after) = state.cert_not_after.as_deref() else {
        return true;
    };
    match time::OffsetDateTime::parse(not_after, &time::format_description::well_known::Rfc3339) {
        Ok(expiry) => {
            let now = time::OffsetDateTime::now_utc();
            (expiry - now) < time::Duration::days(link::RENEW_WINDOW_DAYS)
        }
        Err(_) => true,
    }
}

async fn wait_for_shutdown_signal(
    control: control::ControlPlaneHandle,
    shutdown: rocket::Shutdown,
) {
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

    control.mark_stopping();
    shutdown.notify();
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
        path::{Path, PathBuf},
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

    struct CwdGuard {
        previous: PathBuf,
    }

    impl CwdGuard {
        fn set(dir: impl AsRef<Path>) -> Self {
            let previous = env::current_dir().unwrap();
            env::set_current_dir(dir).unwrap();
            Self { previous }
        }
    }

    impl Drop for CwdGuard {
        fn drop(&mut self) {
            env::set_current_dir(&self.previous).unwrap();
        }
    }

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        crate::test_support::env_lock()
    }

    fn clear_keys_env() -> (EnvGuard, EnvGuard, EnvGuard, EnvGuard, EnvGuard) {
        (
            EnvGuard::unset("TINYCLOUD_KEYS"),
            EnvGuard::unset("TINYCLOUD_KEYS_TYPE"),
            EnvGuard::unset("TINYCLOUD_KEYS__TYPE"),
            EnvGuard::unset("TINYCLOUD_KEYS_SECRET"),
            EnvGuard::unset("TINYCLOUD_KEYS__SECRET"),
        )
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
        let _keys_env = clear_keys_env();
        let _rocket_address = EnvGuard::unset("ROCKET_ADDRESS");
        let _rocket_port = EnvGuard::unset("ROCKET_PORT");
        let _rocket_config = EnvGuard::unset("ROCKET_CONFIG");
        let _rocket_profile = EnvGuard::unset("ROCKET_PROFILE");

        let figment = serve_config_figment(&base).unwrap();
        let cfg = figment.extract::<config::Config>().unwrap();

        assert_eq!(cfg.storage.datadir, override_data);
        assert!(cfg.telemetry.enabled);
    }

    #[test]
    fn serve_config_figment_defaults_to_spec_bind_without_config_file() {
        let _lock = env_lock();
        let temp = tempdir().unwrap();
        let missing_config = temp.path().join("tinycloud.toml");
        let _storage_datadir = EnvGuard::unset("TINYCLOUD_STORAGE_DATADIR");
        let _storage_datadir_canonical = EnvGuard::unset("TINYCLOUD_STORAGE__DATADIR");
        let _keys_env = clear_keys_env();
        let _address = EnvGuard::unset("TINYCLOUD_ADDRESS");
        let _port = EnvGuard::unset("TINYCLOUD_PORT");
        let _rocket_address = EnvGuard::unset("ROCKET_ADDRESS");
        let _rocket_port = EnvGuard::unset("ROCKET_PORT");
        let _rocket_config = EnvGuard::unset("ROCKET_CONFIG");
        let _rocket_profile = EnvGuard::unset("ROCKET_PROFILE");

        let figment = serve_config_figment(&missing_config).unwrap();
        let rocket_cfg = figment.extract::<rocket::Config>().unwrap();
        let cfg = figment.extract::<config::Config>().unwrap();

        assert_eq!(
            rocket_cfg.address,
            std::net::IpAddr::V4(Ipv4Addr::LOCALHOST)
        );
        assert_eq!(rocket_cfg.port, 8081);
        assert_eq!(cfg.keys, config::Keys::Auto);
    }

    #[test]
    fn legacy_config_figment_defaults_to_spec_bind_without_config_file() {
        let _lock = env_lock();
        let temp = tempdir().unwrap();
        let _cwd = CwdGuard::set(temp.path());
        let _storage_datadir = EnvGuard::unset("TINYCLOUD_STORAGE_DATADIR");
        let _storage_datadir_canonical = EnvGuard::unset("TINYCLOUD_STORAGE__DATADIR");
        let _keys_env = clear_keys_env();
        let _address = EnvGuard::unset("TINYCLOUD_ADDRESS");
        let _port = EnvGuard::unset("TINYCLOUD_PORT");
        let _rocket_address = EnvGuard::unset("ROCKET_ADDRESS");
        let _rocket_port = EnvGuard::unset("ROCKET_PORT");
        let _rocket_config = EnvGuard::unset("ROCKET_CONFIG");
        let _rocket_profile = EnvGuard::unset("ROCKET_PROFILE");

        let figment = legacy_config_figment();
        let rocket_cfg = figment.extract::<rocket::Config>().unwrap();
        let cfg = figment.extract::<config::Config>().unwrap();

        assert_eq!(
            rocket_cfg.address,
            std::net::IpAddr::V4(Ipv4Addr::LOCALHOST)
        );
        assert_eq!(rocket_cfg.port, 8081);
        assert_eq!(cfg.keys, config::Keys::Auto);
    }

    #[cfg(feature = "dstack")]
    #[test]
    fn serve_config_figment_loads_keys_type_from_env() {
        let _lock = env_lock();
        let temp = tempdir().unwrap();
        let missing_config = temp.path().join("tinycloud.toml");
        let data_root = temp.path().join("data");
        fs::create_dir_all(&data_root).unwrap();
        let _storage_datadir = EnvGuard::set("TINYCLOUD_STORAGE_DATADIR", &data_root);
        let _storage_datadir_canonical = EnvGuard::unset("TINYCLOUD_STORAGE__DATADIR");
        let _keys_env = clear_keys_env();
        let _keys_type = EnvGuard::set("TINYCLOUD_KEYS_TYPE", "Dstack");
        let _address = EnvGuard::unset("TINYCLOUD_ADDRESS");
        let _port = EnvGuard::unset("TINYCLOUD_PORT");
        let _rocket_address = EnvGuard::unset("ROCKET_ADDRESS");
        let _rocket_port = EnvGuard::unset("ROCKET_PORT");
        let _rocket_config = EnvGuard::unset("ROCKET_CONFIG");
        let _rocket_profile = EnvGuard::unset("ROCKET_PROFILE");

        let figment = serve_config_figment(&missing_config).unwrap();
        let cfg = figment.extract::<config::Config>().unwrap();

        assert_eq!(cfg.keys, config::Keys::Dstack);
    }

    #[cfg(feature = "dstack")]
    #[test]
    fn legacy_config_figment_loads_keys_type_from_env() {
        let _lock = env_lock();
        let temp = tempdir().unwrap();
        let _cwd = CwdGuard::set(temp.path());
        let _storage_datadir = EnvGuard::unset("TINYCLOUD_STORAGE_DATADIR");
        let _storage_datadir_canonical = EnvGuard::unset("TINYCLOUD_STORAGE__DATADIR");
        let _keys_env = clear_keys_env();
        let _keys_type = EnvGuard::set("TINYCLOUD_KEYS_TYPE", "Dstack");
        let _address = EnvGuard::unset("TINYCLOUD_ADDRESS");
        let _port = EnvGuard::unset("TINYCLOUD_PORT");
        let _rocket_address = EnvGuard::unset("ROCKET_ADDRESS");
        let _rocket_port = EnvGuard::unset("ROCKET_PORT");
        let _rocket_config = EnvGuard::unset("ROCKET_CONFIG");
        let _rocket_profile = EnvGuard::unset("ROCKET_PROFILE");

        let figment = legacy_config_figment();
        let cfg = figment.extract::<config::Config>().unwrap();

        assert_eq!(cfg.keys, config::Keys::Dstack);
    }
}
