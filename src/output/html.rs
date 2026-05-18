use crate::report::{EmbedResult, RiskLevel, ScanReport};
use anyhow::Result;
use std::fs;

pub fn export(reports: &[ScanReport], path: &str) -> Result<()> {
    let body = reports
        .iter()
        .map(render_report)
        .collect::<Vec<_>>()
        .join("\n");
    let html = page(&body);
    fs::write(path, html)?;
    println!("HTML report saved to: {}", path);
    Ok(())
}

fn render_report(r: &ScanReport) -> String {
    let embed_badge = match r.frame_policy.result {
        EmbedResult::Allowed => badge("Allowed", "#22c55e"),
        EmbedResult::Blocked => badge("Blocked", "#ef4444"),
        EmbedResult::Unknown => badge("Unknown", "#f59e0b"),
    };

    let risk_color = match r.risk {
        RiskLevel::Low => "#22c55e",
        RiskLevel::Medium => "#f59e0b",
        RiskLevel::High => "#ef4444",
    };

    format!(
        r#"
<div class="card">
  <div class="card-header">
    <span class="url">{url}</span>
    {embed_badge}
  </div>

  <div class="section">
    <h3>Frame Policy</h3>
    <table>
      <tr><td>CSP frame-ancestors</td><td>{csp_fa}</td></tr>
      <tr><td>X-Frame-Options</td><td>{xfo}</td></tr>
    </table>
  </div>

  <div class="section">
    <h3>Security Headers</h3>
    <table>
      <tr><td>HSTS</td><td>{hsts}</td></tr>
      <tr><td>CSP</td><td>{csp}</td></tr>
      <tr><td>Referrer-Policy</td><td>{rp}</td></tr>
      <tr><td>Permissions-Policy</td><td>{pp}</td></tr>
    </table>
  </div>

  <div class="section">
    <h3>CORS</h3>
    <table>
      <tr><td>Access-Control-Allow-Origin</td><td>{cors_origin}</td></tr>
      <tr><td>Access-Control-Allow-Methods</td><td>{cors_methods}</td></tr>
    </table>
  </div>

  <div class="section">
    <h3>Mixed Content</h3>
    <table>
      <tr><td>Risk</td><td>{mixed}</td></tr>
    </table>
  </div>

  <div class="risk-bar" style="background:{risk_color}">
    Risk: {risk}
  </div>

  <div class="suggestion">💡 {suggestion}</div>
</div>
"#,
        url = r.url,
        embed_badge = embed_badge,
        csp_fa = r
            .frame_policy
            .csp_frame_ancestors
            .as_deref()
            .unwrap_or("missing"),
        xfo = r
            .frame_policy
            .x_frame_options
            .as_deref()
            .unwrap_or("missing"),
        hsts = present(r.security_headers.hsts),
        csp = option_present(r.security_headers.csp.as_deref()),
        rp = option_present(r.security_headers.referrer_policy.as_deref()),
        pp = option_present(r.security_headers.permissions_policy.as_deref()),
        cors_origin = r
            .security_headers
            .cors
            .allow_origin
            .as_deref()
            .unwrap_or("not set"),
        cors_methods = r
            .security_headers
            .cors
            .allow_methods
            .as_deref()
            .unwrap_or("not set"),
        mixed = if r.security_headers.mixed_content_risk {
            "⚠ Yes"
        } else {
            "No"
        },
        risk_color = risk_color,
        risk = r.risk,
        suggestion = r.suggestion,
    )
}

fn badge(label: &str, color: &str) -> String {
    format!(
        r#"<span class="badge" style="background:{}">{}</span>"#,
        color, label
    )
}

fn present(v: bool) -> &'static str {
    if v {
        "✅ present"
    } else {
        "❌ missing"
    }
}

fn option_present(v: Option<&str>) -> &'static str {
    if v.is_some() {
        "✅ present"
    } else {
        "❌ missing"
    }
}

fn page(body: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>CSP Guardian Report</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #0f172a; color: #e2e8f0; padding: 2rem; }}
    h1 {{ font-size: 1.5rem; margin-bottom: 1.5rem; color: #f8fafc; }}
    .card {{ background: #1e293b; border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; border: 1px solid #334155; }}
    .card-header {{ display: flex; align-items: center; gap: 1rem; margin-bottom: 1rem; flex-wrap: wrap; }}
    .url {{ font-size: 1rem; font-weight: 600; color: #94a3b8; word-break: break-all; }}
    .badge {{ padding: 0.25rem 0.75rem; border-radius: 999px; font-size: 0.8rem; font-weight: 700; color: white; }}
    .section {{ margin: 1rem 0; }}
    .section h3 {{ font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; color: #64748b; margin-bottom: 0.5rem; }}
    table {{ width: 100%; border-collapse: collapse; }}
    td {{ padding: 0.35rem 0.5rem; font-size: 0.875rem; border-bottom: 1px solid #334155; }}
    td:first-child {{ color: #94a3b8; width: 45%; }}
    .risk-bar {{ margin-top: 1rem; padding: 0.5rem 1rem; border-radius: 4px; font-weight: 700; font-size: 0.875rem; color: white; }}
    .suggestion {{ margin-top: 0.75rem; font-size: 0.875rem; color: #94a3b8; padding: 0.75rem; background: #0f172a; border-radius: 4px; }}
    .meta {{ font-size: 0.75rem; color: #475569; margin-bottom: 1rem; }}
  </style>
</head>
<body>
  <h1>🛡 CSP Guardian Report</h1>
  <p class="meta">Generated by cspguard — {date}</p>
  {body}
</body>
</html>"#,
        date = chrono_date(),
        body = body,
    )
}

fn chrono_date() -> String {
    // Simple date without chrono dependency
    chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
}
