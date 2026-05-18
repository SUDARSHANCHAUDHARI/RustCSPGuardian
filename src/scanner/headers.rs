use reqwest::header::HeaderMap;
use crate::report::EmbedResult;

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
