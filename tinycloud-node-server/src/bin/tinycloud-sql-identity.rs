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
    Checkpoint {
        #[arg(long)]
        fence_confirmed: bool,
    },
    /// Quarantine every discovered artifact and alias uniquely attributed ones
    /// in one transaction. Run only after fencing, drain, and backup.
    Apply {
        #[arg(long)]
        fence_confirmed: bool,
    },
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
        #[arg(long)]
        fence_confirmed: bool,
    },
    /// Clear an alias, leaving its artifact quarantined.
    Clear {
        service: String,
        space: String,
        #[arg(long, conflicts_with = "pathless")]
        path: Option<String>,
        #[arg(long)]
        pathless: bool,
        #[arg(long)]
        fence_confirmed: bool,
    },
    /// Show all aliases and unresolved inventory entries.
    Report,
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
    if let Command::Checkpoint { fence_confirmed } = &args.command {
        anyhow::ensure!(
            *fence_confirmed,
            "stop the fenced node before checkpointing, then pass --fence-confirmed"
        );
        let (sql, duckdb) = migration::checkpoint_cache(&args.datadir)?;
        println!("checkpointed {sql} SQL and {duckdb} DuckDB caches");
        return Ok(());
    }
    let readonly = matches!(
        &args.command,
        Command::Inventory | Command::DryRun | Command::Report
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
        }
        Command::Checkpoint { .. } => unreachable!("checkpoint handled before metadata connection"),
        Command::Apply { fence_confirmed } => {
            anyhow::ensure!(
                fence_confirmed,
                "verify the running node returns 503 for SQL/DuckDB, then pass --fence-confirmed"
            );
            Migrator::up(&conn, None).await?;
            let items = migration::inventory(&conn, &args.datadir).await?;
            anyhow::ensure!(
                items.iter().all(|item| !item.collision),
                "collision in inventory; resolve before applying"
            );
            migration::apply_inventory(&conn, &items).await?;
            println!("{}", serde_json::to_string_pretty(&items)?);
        }
        Command::Set {
            service,
            space,
            physical,
            path,
            pathless,
            authorized,
            fence_confirmed,
        } => {
            anyhow::ensure!(authorized && fence_confirmed,
                "set requires owner/admin authorization and active fence (--authorized --fence-confirmed)");
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
            fence_confirmed,
        } => {
            anyhow::ensure!(
                fence_confirmed,
                "clear requires an active fence (--fence-confirmed)"
            );
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
    }
    Ok(())
}
