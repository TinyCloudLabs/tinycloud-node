use anyhow::{Context, Result};
use serde::{de::DeserializeOwned, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::{self, BufReader, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(clap::Args)]
pub struct Output {
    /// Create a new public JSON file exclusively; otherwise write JSON to stdout.
    #[arg(long)]
    output: Option<PathBuf>,
}

impl Output {
    pub fn write(&self, document: &impl Serialize) -> Result<()> {
        if let Some(path) = &self.output {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .context("creating exclusive output file")?;
            serde_json::to_writer(&mut file, document)?;
            file.write_all(b"\n")?;
            file.sync_all()?;
        } else {
            let mut stdout = io::stdout().lock();
            serde_json::to_writer(&mut stdout, document)?;
            stdout.write_all(b"\n")?;
            stdout.flush()?;
        }
        Ok(())
    }
}

pub fn read<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let file = File::open(path).context("opening public JSON input")?;
    serde_json::from_reader(BufReader::new(file)).context("reading public JSON input")
}

pub fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

pub fn finish(result: Result<()>) -> std::process::ExitCode {
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("root transfer failed: {error:#}");
            std::process::ExitCode::FAILURE
        }
    }
}
