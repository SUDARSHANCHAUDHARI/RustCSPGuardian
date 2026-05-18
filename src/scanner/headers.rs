use reqwest::header::HeaderMap;
use crate::report::{CorsPolicy, EmbedResult};

pub fn get_header(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

pub fn has_header(headers: &HeaderMap, name: &str) -> bool {
    headers.contains_key(name)
}

pub fn parse_csp_frame_ancestors(csp: Option<&str>) -> Option<String> {
    let csp = csp?;
    csp.split(';')
        .map(|d| d.trim())
        .find(|d| d.starts_with("frame-ancestors"))
        .map(|d| d.to_string())
}

pub fn evaluate_cors(headers: &HeaderMap) -> CorsPolicy {
    let allow_origin = get_header(headers, "access-control-allow-origin");
    let allow_methods = get_header(headers, "access-control-allow-methods");
    let is_wildcard = allow_origin.as_deref() == Some("*");
    CorsPolicy {
        allow_origin,
        allow_methods,
        is_wildcard,
    }
}

pub fn evaluate_mixed_content(url: &str, headers: &HeaderMap) -> bool {
    // Mixed content risk: site served over HTTP (not HTTPS) or CSP allows http:
    if url.starts_with("http://") {
        return true;
    }
    if let Some(csp) = get_header(headers, "content-security-policy") {
        if csp.contains("http:") && !csp.contains("https:") {
            return true;
        }
    }
    false
}

pub fn evaluate_embed(xfo: &Option<String>, frame_ancestors: &Option<String>) -> EmbedResult {
    if let Some(xfo_val) = xfo {
        let upper = xfo_val.to_uppercase();
        if upper.contains("DENY") || upper.contains("SAMEORIGIN") {
            return EmbedResult::Blocked;
        }
    }

    if let Some(fa) = frame_ancestors {
        if fa.contains("'none'") {
            return EmbedResult::Blocked;
        }
        if fa.contains("'self'") || fa.contains("*") || fa.len() > "frame-ancestors".len() + 2 {
            return EmbedResult::Allowed;
        }
        return EmbedResult::Blocked;
    }

    EmbedResult::Unknown
}
