use anyhow::Result;
use cspguard::report::{EmbedResult, RiskLevel, ScanReport};
use std::fs;

pub fn export(reports: &[ScanReport], path: &str) -> Result<()> {
    let summary = build_summary(reports);
    let body = reports
        .iter()
        .map(render_report)
        .collect::<Vec<_>>()
        .join("\n");
    let html = page(&summary, &body);
    fs::write(path, html)?;
    println!("HTML report saved to: {}", path);
    Ok(())
}

fn build_summary(reports: &[ScanReport]) -> String {
    let total = reports.len();
    let blocked = reports
        .iter()
        .filter(|r| r.frame_policy.result == EmbedResult::Blocked)
        .count();
    let allowed = reports
        .iter()
        .filter(|r| r.frame_policy.result == EmbedResult::Allowed)
        .count();
    let unknown = total - blocked - allowed;
    let high_risk = reports
        .iter()
        .filter(|r| matches!(r.risk, RiskLevel::High))
        .count();

    format!(
        r#"<div class="summary">
  <div class="summary-item"><span class="num">{total}</span><span class="lbl">Total</span></div>
  <div class="summary-item green"><span class="num">{allowed}</span><span class="lbl">Allowed</span></div>
  <div class="summary-item red"><span class="num">{blocked}</span><span class="lbl">Blocked</span></div>
  <div class="summary-item yellow"><span class="num">{unknown}</span><span class="lbl">Unknown</span></div>
  <div class="summary-item red"><span class="num">{high_risk}</span><span class="lbl">High Risk</span></div>
</div>"#
    )
}

fn render_report(r: &ScanReport) -> String {
    let embed_badge = match r.frame_policy.result {
        EmbedResult::Allowed => badge("Allowed", "#22c55e"),
        EmbedResult::Blocked => badge("Blocked", "#ef4444"),
        EmbedResult::Unknown => badge("Unknown", "#f59e0b"),
    };

    let (risk_color, risk_bg) = match r.risk {
        RiskLevel::Low => ("#22c55e", "#052e16"),
        RiskLevel::Medium => ("#f59e0b", "#1c1007"),
        RiskLevel::High => ("#ef4444", "#1f0707"),
    };

    let redirect_row = if let Some(final_url) = &r.final_url {
        format!(r#"<tr><td>Redirected to</td><td>{}</td></tr>"#, final_url)
    } else {
        String::new()
    };

    format!(
        r#"
<div class="card">
  <div class="card-header">
    <div>
      <span class="url">{url}</span>
      <span class="scanned-at">Scanned {scanned_at}</span>
    </div>
    {embed_badge}
  </div>

  {redirect_row_section}

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

  <div class="risk-bar" style="background:{risk_bg}; border-left: 4px solid {risk_color}; color:{risk_color}">
    Risk: {risk}
  </div>

  <div class="suggestion">💡 {suggestion}</div>
</div>
"#,
        url = r.url,
        scanned_at = r.scanned_at,
        embed_badge = embed_badge,
        redirect_row_section = if redirect_row.is_empty() {
            String::new()
        } else {
            format!(
                r#"<div class="section"><table>{}</table></div>"#,
                redirect_row
            )
        },
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
        risk_bg = risk_bg,
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

fn page(summary: &str, body: &str) -> String {
    let date = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>CSP Guardian Report</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #0f172a; color: #e2e8f0; padding: 2rem; max-width: 900px; margin: 0 auto; }}
    h1 {{ font-size: 1.5rem; margin-bottom: 0.25rem; color: #f8fafc; }}
    .meta {{ font-size: 0.75rem; color: #475569; margin-bottom: 1.5rem; }}
    .summary {{ display: flex; gap: 1rem; margin-bottom: 1.5rem; flex-wrap: wrap; }}
    .summary-item {{ background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 0.75rem 1.25rem; display: flex; flex-direction: column; align-items: center; min-width: 80px; }}
    .summary-item.green {{ border-color: #22c55e; }}
    .summary-item.red {{ border-color: #ef4444; }}
    .summary-item.yellow {{ border-color: #f59e0b; }}
    .num {{ font-size: 1.5rem; font-weight: 700; color: #f8fafc; }}
    .lbl {{ font-size: 0.7rem; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; }}
    .card {{ background: #1e293b; border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; border: 1px solid #334155; }}
    .card-header {{ display: flex; align-items: flex-start; justify-content: space-between; gap: 1rem; margin-bottom: 1rem; flex-wrap: wrap; }}
    .url {{ font-size: 1rem; font-weight: 600; color: #e2e8f0; word-break: break-all; }}
    .scanned-at {{ font-size: 0.7rem; color: #475569; margin-top: 0.25rem; display: block; }}
    .badge {{ padding: 0.25rem 0.75rem; border-radius: 999px; font-size: 0.8rem; font-weight: 700; color: white; white-space: nowrap; }}
    .section {{ margin: 1rem 0; }}
    .section h3 {{ font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; color: #64748b; margin-bottom: 0.5rem; }}
    table {{ width: 100%; border-collapse: collapse; }}
    td {{ padding: 0.35rem 0.5rem; font-size: 0.875rem; border-bottom: 1px solid #1e293b; }}
    td:first-child {{ color: #94a3b8; width: 45%; }}
    .risk-bar {{ margin-top: 1rem; padding: 0.6rem 1rem; border-radius: 4px; font-weight: 700; font-size: 0.875rem; }}
    .suggestion {{ margin-top: 0.75rem; font-size: 0.85rem; color: #94a3b8; padding: 0.75rem; background: #0f172a; border-radius: 4px; line-height: 1.5; }}
  </style>
</head>
<body>
  <h1>🛡 CSP Guardian Report</h1>
  <p class="meta">Generated {date} · cspguard v0.2.0</p>
  {summary}
  {body}
</body>
</html>"#,
        date = date,
        summary = summary,
        body = body,
    )
}
