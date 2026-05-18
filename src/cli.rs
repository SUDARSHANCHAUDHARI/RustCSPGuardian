use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "cspguard",
    about = "Check whether a website can be embedded in iframe-based digital signage environments",
    version
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Check a single URL
    Check {
        /// URL to check
        url: String,
        /// Output as JSON
        #[arg(long)]
        json: bool,
        /// Export HTML report to file
        #[arg(long)]
        html: Option<String>,
    },
    /// Check multiple URLs from a file (one per line)
    Batch {
        /// Path to file containing URLs
        file: String,
        /// Output as JSON
        #[arg(long)]
        json: bool,
        /// Export HTML report to file
        #[arg(long)]
        html: Option<String>,
    },
}
