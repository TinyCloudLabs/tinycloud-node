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

pub fn legacy_config_figment() -> rocket::figment::Figment {
    rocket::figment::Figment::from(rocket::Config::default())
        .merge(Serialized::defaults(config::Config::default()))
        .merge(Toml::file("tinycloud.toml").nested())
        // Legacy env style: single underscore as nesting separator.
        .merge(Env::prefixed("TINYCLOUD_").split("_").global())
        // Canonical env style: double underscore as nesting separator.
        // Loaded second so canonical values win when both are present.
        .merge(Env::prefixed("TINYCLOUD_").split("__").global())
        .merge(Env::prefixed("ROCKET_").global())
}

pub fn serve_config_figment(base_config_path: &Path) -> Result<rocket::figment::Figment> {
    let mut base = rocket::figment::Figment::from(rocket::Config::default())
        .merge(Serialized::defaults(config::Config::default()));

    if base_config_path.exists() {
        base = base.merge(Toml::file(base_config_path).nested());
    }

    let mut resolved = base.extract::<config::Config>().with_context(|| {
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

    Ok(figment
        .merge(Env::prefixed("TINYCLOUD_").split("_").global())
        .merge(Env::prefixed("TINYCLOUD_").split("__").global())
        .merge(Env::prefixed("ROCKET_").global()))
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
