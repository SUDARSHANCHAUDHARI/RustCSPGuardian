use colored::Colorize;
use crate::report::{EmbedResult, RiskLevel, ScanReport};

pub fn print(report: &ScanReport) {
    println!("\n{}", "CSP Guardian Report".bold().underline());
    println!("{} {}", "URL:".bold(), report.url);

    println!("\n{}", "Frame Policy:".bold());
    println!(
        "  {:<26} {}",
        "CSP frame-ancestors:",
        report.frame_policy.csp_frame_ancestors.as_deref().unwrap_or("missing").yellow()
    );
    println!(
        "  {:<26} {}",
        "X-Frame-Options:",
        report.frame_policy.x_frame_options.as_deref().unwrap_or("missing").yellow()
    );
    let result_colored = match report.frame_policy.result {
        EmbedResult::Allowed => report.frame_policy.result.to_string().green(),
        EmbedResult::Blocked => report.frame_policy.result.to_string().red(),
        EmbedResult::Unknown => report.frame_policy.result.to_string().yellow(),
    };
    println!("  {:<26} {}", "Result:", result_colored);

    println!("\n{}", "Security Headers:".bold());
    println!(
        "  {:<26} {}",
        "HSTS:",
        if report.security_headers.hsts { "present".green() } else { "missing".red() }
    );
    println!(
        "  {:<26} {}",
        "CSP:",
        report.security_headers.csp.as_deref().map(|_| "present".green()).unwrap_or("missing".red())
    );
    println!(
        "  {:<26} {}",
        "Referrer-Policy:",
        report.security_headers.referrer_policy.as_deref().map(|_| "present".green()).unwrap_or("missing".red())
    );
    println!(
        "  {:<26} {}",
        "Permissions-Policy:",
        report.security_headers.permissions_policy.as_deref().map(|_| "present".green()).unwrap_or("missing".red())
    );

    let risk_colored = match report.risk {
        RiskLevel::Low => report.risk.to_string().green(),
        RiskLevel::Medium => report.risk.to_string().yellow(),
        RiskLevel::High => report.risk.to_string().red(),
    };
    println!("\n{} {}", "Risk:".bold(), risk_colored);
    println!("\n{}", "Suggestion:".bold());
    println!("  {}", report.suggestion);
    println!();
}
