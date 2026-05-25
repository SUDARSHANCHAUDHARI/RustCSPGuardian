use anyhow::Result;
use cspguard::report::ScanReport;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

fn history_path() -> Result<PathBuf> {
    let dir = dirs::home_dir()
        .ok_or_else(|| anyhow::anyhow!("Cannot find home directory"))?
        .join(".cspguard");
    fs::create_dir_all(&dir)?;
    Ok(dir.join("history.jsonl"))
}

pub fn save(report: &ScanReport) -> Result<()> {
    let path = history_path()?;
    let mut file = OpenOptions::new().create(true).append(true).open(&path)?;
    writeln!(file, "{}", serde_json::to_string(report)?)?;
    Ok(())
}

pub fn load(last: usize) -> Result<Vec<ScanReport>> {
    let path = history_path()?;
    if !path.exists() {
        return Ok(vec![]);
    }
    let file = fs::File::open(&path)?;
    let lines: Vec<String> = BufReader::new(file)
        .lines()
        .map_while(Result::ok)
        .filter(|l| !l.trim().is_empty())
        .collect();

    let reports: Vec<ScanReport> = lines
        .iter()
        .rev()
        .take(last)
        .rev()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();

    Ok(reports)
}
