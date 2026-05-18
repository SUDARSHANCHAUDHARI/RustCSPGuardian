use anyhow::Result;
use crate::report::ScanReport;

pub fn print(report: &ScanReport) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(report)?);
    Ok(())
}
