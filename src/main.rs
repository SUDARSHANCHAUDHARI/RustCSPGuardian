mod cli;
mod error;
mod report;
mod scanner;
mod output;

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
        Commands::Check { url, json } => {
            let result = scanner::check_url(&url).await?;
            if json {
                output::json::print(&result)?;
            } else {
                output::terminal::print(&result);
            }
        }
        Commands::Batch { file, json } => {
            let urls = std::fs::read_to_string(&file)?;
            for url in urls.lines().filter(|l| !l.trim().is_empty()) {
                let result = scanner::check_url(url).await?;
                if json {
                    output::json::print(&result)?;
                } else {
                    output::terminal::print(&result);
                }
            }
        }
    }

    Ok(())
}
