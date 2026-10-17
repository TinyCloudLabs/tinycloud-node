//! Read-only policy witness inventory. No migrations, alias backfills, or
//! signed artifacts are written; success output contains only four counts.
//! Run with the same TINYCLOUD_CONFIG_FILE / TINYCLOUD_* settings as the node.
use rocket::figment::{
    providers::{Env, Format, Serialized, Toml},
    Figment,
};
use tinycloud::{config, resolve_keys};
use tinycloud_core::{
    encryption::ColumnEncryption,
    policy_witness::{dry_run_backfill, BackfillCounts},
    sea_orm::{ConnectOptions, ConnectionTrait, Database, DbBackend, Statement, TransactionTrait},
};

fn config() -> Result<config::Config, ()> {
    let config_file =
        std::env::var("TINYCLOUD_CONFIG_FILE").unwrap_or_else(|_| "tinycloud.toml".to_owned());
    let mut config = Figment::from(rocket::Config::default())
        .merge(Serialized::defaults(config::Config::default()))
        .merge(Toml::file(config_file).nested())
        .merge(Env::prefixed("TINYCLOUD_").split("_").global())
        .merge(Env::prefixed("TINYCLOUD_").split("__").global())
        .merge(Env::prefixed("ROCKET_").global())
        .extract::<config::Config>()
        .map_err(|_| ())?;
    config.storage.resolve();
    Ok(config)
}

fn readonly_url(url: &str) -> Result<String, ()> {
    if url.starts_with("sqlite:") {
        // A SQLite read-only open must not create a database (or be silently
        // overridden by caller-supplied URI mode parameters).
        if url.contains('?') || url.contains('#') || url.contains(":memory:") {
            return Err(());
        }
        Ok(format!("{url}?mode=ro"))
    } else if url.starts_with("postgres://")
        || url.starts_with("postgresql://")
        || url.starts_with("mysql://")
    {
        Ok(url.to_owned())
    } else {
        Err(())
    }
}

async fn dry_run() -> Result<BackfillCounts, ()> {
    let config = config()?;
    tinycloud_core::did_resolution::configure(
        tinycloud_core::did_resolution::DidResolutionPolicy {
            network_methods: config.did_resolution.network_methods,
        },
    );
    let key = resolve_keys(&config.keys).await.map_err(|_| ())?;
    // Exactly the node's delegation-column context; no key material is logged.
    let encryption = ColumnEncryption::new(key.derive_key(b"tinycloud/hooks/webhook-secrets"));
    let database = readonly_url(config.storage.database())?;
    let mut opts = ConnectOptions::new(database);
    opts.max_connections(1)
        .min_connections(1)
        .sqlx_logging(false);
    let conn = Database::connect(opts).await.map_err(|_| ())?;
    // The SQLite connection was opened with mode=ro above. MySQL's session
    // setting applies to BEGIN; verify the acquired transaction inherited it
    // before issuing any inventory query, including after a pool reconnect.
    let backend = conn.get_database_backend();
    match backend {
        DbBackend::MySql => {
            conn.execute_unprepared("SET SESSION TRANSACTION READ ONLY")
                .await
                .map_err(|_| ())?;
        }
        DbBackend::Sqlite => return scan_sqlite(&conn, &encryption).await,
        DbBackend::Postgres => (),
    }
    let tx = conn.begin().await.map_err(|_| ())?;
    match backend {
        DbBackend::Postgres => {
            tx.execute_unprepared("SET TRANSACTION READ ONLY")
                .await
                .map_err(|_| ())?;
        }
        DbBackend::MySql => {
            let row = tx
                .query_one(Statement::from_string(
                    backend,
                    "SELECT CAST(@@session.transaction_read_only AS SIGNED) AS read_only",
                ))
                .await
                .map_err(|_| ())?
                .ok_or(())?;
            if row.try_get::<i64>("", "read_only").map_err(|_| ())? != 1 {
                return Err(());
            }
        }
        DbBackend::Sqlite => return Err(()),
    }
    let counts = dry_run_backfill(&tx, Some(&encryption))
        .await
        .map_err(|_| ())?;
    tx.rollback().await.map_err(|_| ())?;
    Ok(counts)
}

async fn scan_sqlite(
    conn: &tinycloud_core::sea_orm::DatabaseConnection,
    encryption: &ColumnEncryption,
) -> Result<BackfillCounts, ()> {
    dry_run_backfill(conn, Some(encryption))
        .await
        .map_err(|_| ())
}

fn counts_json(counts: &BackfillCounts) -> String {
    let unresolved = counts
        .missing
        .saturating_add(counts.ambiguous)
        .saturating_add(counts.overflow);
    let ok = counts.policies.saturating_sub(unresolved);
    format!(
        "{{\"ok\":{ok},\"missing\":{},\"ambiguous\":{},\"overflow\":{}}}",
        counts.missing, counts.ambiguous, counts.overflow
    )
}

#[tokio::main]
async fn main() {
    match dry_run().await {
        Ok(counts) => println!("{}", counts_json(&counts)),
        Err(()) => {
            eprintln!("policy witness dry-run unavailable");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqlite_dry_run_forces_read_only_and_rejects_preexisting_modes() {
        assert_eq!(
            readonly_url("sqlite:./data/caps.db"),
            Ok("sqlite:./data/caps.db?mode=ro".into())
        );
        assert!(readonly_url("sqlite:./data/caps.db?mode=rwc").is_err());
        assert!(readonly_url("sqlite::memory:").is_err());
    }

    #[test]
    fn dry_run_output_contains_counts_only() {
        let counts = BackfillCounts {
            policies: 5,
            witnesses: 10,
            missing: 1,
            ambiguous: 1,
            overflow: 1,
        };
        assert_eq!(
            counts_json(&counts),
            r#"{"ok":2,"missing":1,"ambiguous":1,"overflow":1}"#
        );
    }
}
