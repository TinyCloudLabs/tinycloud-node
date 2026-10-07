//! Offline operator tool for the TC-780 SQL/DuckDB identity cutover.
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use tinycloud_core::{
    database_migration as migration,
    migrations::Migrator,
    sea_orm::{ConnectOptions, Database},
    sea_orm_migration::MigratorTrait,
};

#[derive(Parser)]
#[command(name = "tinycloud-sql-identity")]
struct Args {
    /// Data directory containing caps.db, sql/, and duckdb/. A copied
    /// production snapshot can be inspected without touching the live node.
    #[arg(long)]
    datadir: PathBuf,
    /// Override the metadata database URL (default: sqlite:<datadir>/caps.db).
    #[arg(long)]
    database: Option<String>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// JSON inventory and migration dry-run. This command never writes.
    Inventory,
    /// Preview classification and collisions on a copied data directory.
    DryRun,
    /// Checkpoint every local SQL/DuckDB cache after stopping the fenced node.
    Checkpoint,
    /// Persist the metadata fence. The server also honors this flag at runtime.
    Fence {
        #[arg(value_enum)]
        state: FenceState,
    },
    /// Quarantine every discovered artifact and alias uniquely attributed ones
    /// in one transaction. Run only after fencing, drain, and backup.
    Apply,
    /// Assign an ambiguous or unattributed artifact to one owner-approved path.
    #[command(alias = "resolve")]
    Set {
        service: String,
        space: String,
        physical: String,
        #[arg(long, conflicts_with = "pathless")]
        path: Option<String>,
        #[arg(long)]
        pathless: bool,
        #[arg(long)]
        authorized: bool,
    },
    /// Clear an alias, leaving its artifact quarantined.
    Clear {
        service: String,
        space: String,
        #[arg(long, conflicts_with = "pathless")]
        path: Option<String>,
        #[arg(long)]
        pathless: bool,
    },
    /// Show all aliases and unresolved inventory entries.
    Report,
    /// Read every aliased artifact offline and compare with a saved dry-run.
    Verify {
        #[arg(long)]
        baseline: PathBuf,
    },
}

#[derive(clap::ValueEnum, Clone)]
enum FenceState {
    On,
    Off,
}

fn requested_path(path: &Option<String>, pathless: bool) -> anyhow::Result<Option<&str>> {
    if path.is_none() && !pathless {
        anyhow::bail!("specify --path or --pathless");
    }
    Ok(path.as_deref())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let readonly = matches!(
        &args.command,
        Command::Inventory | Command::DryRun | Command::Report | Command::Verify { .. }
    );
    let url = args.database.unwrap_or_else(|| {
        format!(
            "sqlite:{}{}",
            args.datadir.join("caps.db").display(),
            if readonly { "?mode=ro" } else { "?mode=rw" }
        )
    });
    let conn = Database::connect(ConnectOptions::new(url)).await?;
    match args.command {
        Command::Inventory | Command::DryRun => {
            let items = migration::inventory(&conn, &args.datadir).await?;
            println!("{}", serde_json::to_string_pretty(&items)?);
            migration::validate_inventory(&items)?;
        }
        Command::Fence { state } => {
            Migrator::up(&conn, None).await?;
            migration::set_fence(&conn, matches!(state, FenceState::On)).await?;
            println!(
                "metadata fence {}",
                if matches!(state, FenceState::On) {
                    "on"
                } else {
                    "off"
                }
            );
        }
        Command::Checkpoint => {
            migration::require_fence(&conn).await?;
            let (sql, duckdb) = migration::checkpoint_cache(&args.datadir)?;
            println!("checkpointed {sql} SQL and {duckdb} DuckDB caches");
        }
        Command::Apply => {
            migration::require_fence(&conn).await?;
            let items = migration::apply(&conn, &args.datadir).await?;
            println!("{}", serde_json::to_string_pretty(&items)?);
        }
        Command::Set {
            service,
            space,
            physical,
            path,
            pathless,
            authorized,
        } => {
            anyhow::ensure!(
                authorized,
                "set requires owner/admin authorization (--authorized)"
            );
            migration::set_alias(
                &conn,
                &service,
                &space,
                requested_path(&path, pathless)?,
                &physical,
            )
            .await?;
            println!("alias set");
        }
        Command::Clear {
            service,
            space,
            path,
            pathless,
        } => {
            migration::clear_alias(&conn, &service, &space, requested_path(&path, pathless)?)
                .await?;
            println!("alias cleared");
        }
        Command::Report => {
            let items = migration::inventory(&conn, &args.datadir).await?;
            let aliases = migration::aliases(&conn).await?;
            let quarantined = migration::quarantined(&conn).await?;
            let unresolved: Vec<_> = items
                .iter()
                .filter(|item| {
                    !aliases.iter().any(|alias| {
                        alias.service == item.service
                            && alias.space == item.space
                            && alias.physical_name == item.physical_name
                    })
                })
                .cloned()
                .collect();
            let quarantine_rows: Vec<_> = quarantined.into_iter().map(|row| serde_json::json!({
                "service": row.service, "space": row.space, "physical_name": row.physical_name,
            })).collect();
            let aliases: Vec<_> = aliases
                .into_iter()
                .map(|a| {
                    serde_json::json!({
                        "service": a.service, "space": a.space, "path": a.path,
                        "logical_name": a.logical_name, "physical_name": a.physical_name,
                    })
                })
                .collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "inventory": items, "aliases": aliases,
                    "unresolved": unresolved, "quarantined": quarantine_rows,
                }))?
            );
        }
        Command::Verify { baseline } => {
            let before: Vec<migration::InventoryItem> =
                serde_json::from_slice(&std::fs::read(baseline)?)?;
            let current = migration::inventory(&conn, &args.datadir).await?;
            let aliases = migration::aliases(&conn).await?;
            let mut verified = Vec::new();
            for alias in aliases {
                let key = (&alias.service, &alias.space, &alias.physical_name);
                let expected = before
                    .iter()
                    .find(|item| (&item.service, &item.space, &item.physical_name) == key)
                    .ok_or_else(|| anyhow::anyhow!("alias missing from baseline: {key:?}"))?;
                let actual = current
                    .iter()
                    .find(|item| (&item.service, &item.space, &item.physical_name) == key)
                    .ok_or_else(|| anyhow::anyhow!("aliased artifact missing: {key:?}"))?;
                anyhow::ensure!(actual.durable, "aliased durable artifact missing: {key:?}");
                anyhow::ensure!(
                    expected.fingerprint.is_some(),
                    "baseline has no fingerprint: {key:?}"
                );
                anyhow::ensure!(
                    expected.fingerprint == actual.fingerprint,
                    "schema or row-count mismatch: {key:?}: expected {:?}, actual {:?}",
                    expected.fingerprint,
                    actual.fingerprint
                );
                verified.push(serde_json::json!({"service": alias.service, "space": alias.space,
                    "path": alias.path, "physical_name": alias.physical_name, "fingerprint": actual.fingerprint}));
            }
            println!("{}", serde_json::to_string_pretty(&verified)?);
        }
    }
    Ok(())
}
