use crate::report::ScanReport;
use anyhow::Result;

pub fn print(report: &ScanReport) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(report)?);
    Ok(())
}
