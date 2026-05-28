mod headers;

use crate::report::{EmbedResult, FramePolicy, RiskLevel, ScanReport, SecurityHeaders};
use anyhow::Result;

pub async fn check_url(url: &str) -> Result<ScanReport> {
    let client = reqwest::Client::builder()
        .user_agent("cspguard/0.1.0")
        .timeout(std::time::Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::limited(10))
        .build()?;

    let response = client.get(url).send().await?;
    let final_url = response.url().to_string();
    let redirected = final_url != url;
    let hdrs = response.headers().clone();

    let csp = headers::get_header(&hdrs, "content-security-policy");
    let xfo = headers::get_header(&hdrs, "x-frame-options");
    let csp_frame_ancestors = headers::parse_csp_frame_ancestors(csp.as_deref());
    let embed_result = headers::evaluate_embed(&xfo, &csp_frame_ancestors);

    let frame_policy = FramePolicy {
        csp_frame_ancestors: csp_frame_ancestors.clone(),
        x_frame_options: xfo.clone(),
        result: embed_result,
    };

    let security_headers = SecurityHeaders {
        hsts: headers::has_header(&hdrs, "strict-transport-security"),
        csp: csp.clone(),
        referrer_policy: headers::get_header(&hdrs, "referrer-policy"),
        permissions_policy: headers::get_header(&hdrs, "permissions-policy"),
        cors: headers::evaluate_cors(&hdrs),
        mixed_content_risk: headers::evaluate_mixed_content(&final_url, &hdrs),
    };

    let risk = evaluate_risk(&frame_policy, &security_headers);
    let suggestion = build_suggestion(&frame_policy);
    let remediation_hints = build_remediation_hints(&frame_policy, &security_headers);

    Ok(ScanReport {
        url: url.to_string(),
        final_url: if redirected { Some(final_url) } else { None },
        scanned_at: chrono::Local::now().to_rfc3339(),
        frame_policy,
        security_headers,
        risk,
        suggestion,
        remediation_hints,
    })
}

fn evaluate_risk(frame: &FramePolicy, sec: &SecurityHeaders) -> RiskLevel {
    if frame.result == EmbedResult::Blocked {
        return RiskLevel::High;
    }
    let missing = [
        sec.referrer_policy.is_none(),
        sec.permissions_policy.is_none(),
        !sec.hsts,
    ]
    .iter()
    .filter(|&&x| x)
    .count();

    match missing {
        0 | 1 => RiskLevel::Low,
        _ => RiskLevel::Medium,
    }
}

fn build_suggestion(frame: &FramePolicy) -> String {
    match frame.result {
        EmbedResult::Blocked => {
            if let Some(xfo) = &frame.x_frame_options {
                format!(
                    "X-Frame-Options is {} — this site blocks iframe embedding. \
                    Ask the site owner to allow your domain via CSP frame-ancestors.",
                    xfo
                )
            } else {
                "CSP frame-ancestors blocks iframe embedding. \
                Contact the site owner to allow your domain."
                    .to_string()
            }
        }
        EmbedResult::Allowed => {
            "No iframe blocking policy detected. Site should be embeddable.".to_string()
        }
        EmbedResult::Unknown => {
            "No frame policy detected. Embedding may work but cannot be guaranteed.".to_string()
        }
    }
}

fn build_remediation_hints(frame: &FramePolicy, sec: &SecurityHeaders) -> Vec<String> {
    let mut hints = Vec::new();

    if let Some(xfo) = &frame.x_frame_options {
        let normalized = xfo.trim().to_ascii_uppercase();
        if normalized == "DENY" {
            hints.push(
                "Remove X-Frame-Options: DENY if iframe embedding is intentional.".to_string(),
            );
            hints.push(
                "Use Content-Security-Policy frame-ancestors to allow only trusted embedding origins."
                    .to_string(),
            );
        } else if normalized == "SAMEORIGIN" {
            hints.push(
                "Replace X-Frame-Options: SAMEORIGIN with CSP frame-ancestors when trusted external domains need to embed this page."
                    .to_string(),
            );
        } else {
            hints.push(format!(
                "Review X-Frame-Options: {xfo}; modern embed allowlists should use CSP frame-ancestors."
            ));
        }
    }

    if let Some(ancestors) = &frame.csp_frame_ancestors {
        let normalized = ancestors.to_ascii_lowercase();
        if normalized.contains("'none'") {
            hints.push(
                "Change Content-Security-Policy frame-ancestors from 'none' to the trusted embedding origin."
                    .to_string(),
            );
        } else if normalized.contains("'self'") {
            hints.push(
                "Add the trusted embedding origin to Content-Security-Policy frame-ancestors instead of only 'self'."
                    .to_string(),
            );
        }
    } else if frame.x_frame_options.is_none() {
        hints.push(
            "Add an explicit Content-Security-Policy frame-ancestors directive so embed behavior is predictable."
                .to_string(),
        );
    }

    if !sec.hsts {
        hints.push("Add Strict-Transport-Security for HTTPS-only deployments.".to_string());
    }
    if sec.referrer_policy.is_none() {
        hints.push("Add Referrer-Policy to reduce accidental URL data leakage.".to_string());
    }
    if sec.permissions_policy.is_none() {
        hints.push("Add Permissions-Policy to make browser feature access explicit.".to_string());
    }

    hints
}
