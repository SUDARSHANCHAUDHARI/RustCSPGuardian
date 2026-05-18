mod cli;
mod error;
mod output;

use cspguard::report;
use cspguard::scanner;
use anyhow::Result;
use clap::Parser;
use cli::{Cli, Commands};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Check { url, json, html } => {
            let result = scanner::check_url(&url).await?;
            if json {
                output::json::print(&result)?;
            } else if let Some(path) = html {
                output::html::export(&[result], &path)?;
            } else {
                output::terminal::print(&result);
            }
        }
        Commands::Batch { file, json, html } => {
            let urls = std::fs::read_to_string(&file)?;
            let mut results = Vec::new();
            for url in urls.lines().filter(|l| !l.trim().is_empty()) {
                let result = scanner::check_url(url).await?;
                results.push(result);
            }
            if json {
                for r in &results {
                    output::json::print(r)?;
                }
            } else if let Some(path) = html {
                output::html::export(&results, &path)?;
            } else {
                for r in &results {
                    output::terminal::print(r);
                }
            }
        }
    }

    Ok(())
}
