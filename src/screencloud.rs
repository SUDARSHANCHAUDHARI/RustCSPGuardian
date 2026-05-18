use crate::report::{EmbedResult, ScanReport};

pub struct ScreenCloudAdvice {
    pub verdict: String,
    pub reason: String,
    pub fix: Vec<String>,
    pub customer_message: String,
}

pub fn explain(report: &ScanReport) -> ScreenCloudAdvice {
    match report.frame_policy.result {
        EmbedResult::Blocked => blocked_advice(report),
        EmbedResult::Allowed => allowed_advice(report),
        EmbedResult::Unknown => unknown_advice(report),
    }
}

fn blocked_advice(report: &ScanReport) -> ScreenCloudAdvice {
    let mut fix = Vec::new();
    let reason;

    if let Some(xfo) = &report.frame_policy.x_frame_options {
        let upper = xfo.to_uppercase();
        if upper.contains("DENY") {
            reason = format!(
                "X-Frame-Options: DENY blocks all iframe embedding — including ScreenCloud players."
            );
            fix.push("Ask the site owner to change X-Frame-Options to ALLOWALL or remove it.".to_string());
            fix.push("Or add CSP: frame-ancestors 'self' https://screencloud.io".to_string());
        } else {
            reason = format!(
                "X-Frame-Options: SAMEORIGIN only allows embedding from the same domain. \
                ScreenCloud players are on a different domain so they are blocked."
            );
            fix.push("Ask the site owner to replace X-Frame-Options: SAMEORIGIN with:".to_string());
            fix.push("  Content-Security-Policy: frame-ancestors 'self' https://screencloud.io".to_string());
            fix.push("Or remove X-Frame-Options entirely if the site doesn't need it.".to_string());
        }
    } else if let Some(fa) = &report.frame_policy.csp_frame_ancestors {
        reason = format!(
            "CSP frame-ancestors policy ({}) blocks ScreenCloud from embedding this site.",
            fa
        );
        fix.push("Ask the site owner to update their CSP to include ScreenCloud's domain:".to_string());
        fix.push("  Content-Security-Policy: frame-ancestors 'self' https://screencloud.io https://*.screencloud.io".to_string());
    } else {
        reason = "Site is blocked from iframe embedding — exact policy unclear.".to_string();
        fix.push("Ask the site owner to explicitly allow iframe embedding for ScreenCloud.".to_string());
    }

    if report.security_headers.mixed_content_risk {
        fix.push("⚠ Site is served over HTTP — ScreenCloud players use HTTPS. Mixed content will cause additional issues.".to_string());
    }

    ScreenCloudAdvice {
        verdict: "❌ Will NOT embed in ScreenCloud".to_string(),
        reason,
        fix,
        customer_message: format!(
            "The website {} cannot be embedded in ScreenCloud due to its security policy. \
            Please contact the website owner and ask them to allow iframe embedding for screencloud.io.",
            report.url
        ),
    }
}

fn allowed_advice(report: &ScanReport) -> ScreenCloudAdvice {
    let mut notes = Vec::new();

    if report.security_headers.cors.is_wildcard {
        notes.push("CORS is set to wildcard (*) — this is permissive and should work fine.".to_string());
    }
    if report.security_headers.mixed_content_risk {
        notes.push("⚠ Site is on HTTP — may cause mixed content warnings inside ScreenCloud (HTTPS).".to_string());
    }
    if !report.security_headers.hsts {
        notes.push("HSTS is not set — consider asking the site owner to enable HTTPS enforcement.".to_string());
    }

    ScreenCloudAdvice {
        verdict: "✅ Should embed in ScreenCloud".to_string(),
        reason: "No iframe blocking policy detected. ScreenCloud players should be able to display this site.".to_string(),
        fix: notes,
        customer_message: format!(
            "The website {} appears to allow iframe embedding and should work in ScreenCloud. \
            If you experience issues, try refreshing the screen or checking your playlist settings.",
            report.url
        ),
    }
}

fn unknown_advice(report: &ScanReport) -> ScreenCloudAdvice {
    ScreenCloudAdvice {
        verdict: "⚠ Uncertain — test in ScreenCloud".to_string(),
        reason: "No explicit iframe policy found. The site may work in ScreenCloud but cannot be guaranteed.".to_string(),
        fix: vec![
            "Test by adding this URL to a ScreenCloud screen directly.".to_string(),
            "If it shows a blank screen, the site may be blocking iframes via JavaScript.".to_string(),
            format!("Try opening {} in a browser and checking the console for iframe errors.", report.url),
        ],
        customer_message: format!(
            "The website {} doesn't have an explicit iframe policy. \
            Please test it directly in ScreenCloud — it may work, but we cannot guarantee it.",
            report.url
        ),
    }
}
