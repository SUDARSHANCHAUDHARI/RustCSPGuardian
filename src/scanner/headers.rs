use crate::report::{CorsPolicy, EmbedResult};
use reqwest::header::HeaderMap;

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

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

    fn headers_from(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (k, v) in pairs {
            map.insert(
                HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        map
    }

    #[test]
    fn parse_csp_frame_ancestors_extracts_directive() {
        let csp = "default-src 'self'; frame-ancestors 'none'; img-src *";
        assert_eq!(
            parse_csp_frame_ancestors(Some(csp)),
            Some("frame-ancestors 'none'".to_string())
        );
    }

    #[test]
    fn parse_csp_frame_ancestors_returns_none_when_missing() {
        assert!(parse_csp_frame_ancestors(Some("default-src 'self'")).is_none());
        assert!(parse_csp_frame_ancestors(None).is_none());
    }

    #[test]
    fn evaluate_embed_blocked_by_xfo_deny() {
        let headers = headers_from(&[("x-frame-options", "DENY")]);
        assert!(matches!(
            evaluate_embed(&get_header(&headers, "x-frame-options"), &None),
            EmbedResult::Blocked
        ));
    }

    #[test]
    fn evaluate_embed_blocked_by_frame_ancestors_none() {
        assert!(matches!(
            evaluate_embed(&None, &Some("frame-ancestors 'none'".to_string())),
            EmbedResult::Blocked
        ));
    }

    #[test]
    fn evaluate_embed_allowed_by_frame_ancestors_wildcard() {
        assert!(matches!(
            evaluate_embed(&None, &Some("frame-ancestors *".to_string())),
            EmbedResult::Allowed
        ));
    }

    #[test]
    fn evaluate_embed_unknown_when_no_headers() {
        assert!(matches!(evaluate_embed(&None, &None), EmbedResult::Unknown));
    }

    #[test]
    fn evaluate_cors_wildcard_detected() {
        let headers = headers_from(&[("access-control-allow-origin", "*")]);
        let cors = evaluate_cors(&headers);
        assert!(cors.is_wildcard);
    }

    #[test]
    fn evaluate_mixed_content_http_url_is_risky() {
        let headers = HeaderMap::new();
        assert!(evaluate_mixed_content("http://example.com", &headers));
    }

    #[test]
    fn evaluate_mixed_content_https_url_is_safe() {
        let headers = HeaderMap::new();
        assert!(!evaluate_mixed_content("https://example.com", &headers));
    }
}
