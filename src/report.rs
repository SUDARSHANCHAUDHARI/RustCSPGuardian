use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanReport {
    pub url: String,
    pub final_url: Option<String>,
    pub scanned_at: String,
    pub frame_policy: FramePolicy,
    pub security_headers: SecurityHeaders,
    pub risk: RiskLevel,
    pub suggestion: String,
    pub remediation_hints: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FramePolicy {
    pub csp_frame_ancestors: Option<String>,
    pub x_frame_options: Option<String>,
    pub result: EmbedResult,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SecurityHeaders {
    pub hsts: bool,
    pub csp: Option<String>,
    pub referrer_policy: Option<String>,
    pub permissions_policy: Option<String>,
    pub cors: CorsPolicy,
    pub mixed_content_risk: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CorsPolicy {
    pub allow_origin: Option<String>,
    pub allow_methods: Option<String>,
    pub is_wildcard: bool,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub enum EmbedResult {
    Allowed,
    Blocked,
    Unknown,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
}

impl std::fmt::Display for EmbedResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EmbedResult::Allowed => write!(f, "Allowed"),
            EmbedResult::Blocked => write!(f, "Blocked"),
            EmbedResult::Unknown => write!(f, "Unknown"),
        }
    }
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskLevel::Low => write!(f, "Low"),
            RiskLevel::Medium => write!(f, "Medium"),
            RiskLevel::High => write!(f, "High"),
        }
    }
}
