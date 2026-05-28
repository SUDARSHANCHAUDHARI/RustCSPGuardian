use assert_cmd::Command;
use cspguard::report::EmbedResult;
use cspguard::scanner::check_url;
use predicates::str::contains;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

#[test]
fn test_help() {
    Command::cargo_bin("cspguard")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(contains("Check whether a website"));
}

#[test]
fn test_check_subcommand_help() {
    Command::cargo_bin("cspguard")
        .unwrap()
        .args(["check", "--help"])
        .assert()
        .success()
        .stdout(contains("URL to check"));
}

#[test]
fn test_batch_subcommand_help() {
    Command::cargo_bin("cspguard")
        .unwrap()
        .args(["batch", "--help"])
        .assert()
        .success()
        .stdout(contains("one per line"));
}

// --- Scanner unit tests ---

#[tokio::test]
async fn test_xfo_deny_is_blocked() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).insert_header("x-frame-options", "DENY"))
        .mount(&server)
        .await;

    let result = check_url(&server.uri()).await.unwrap();
    assert!(matches!(result.frame_policy.result, EmbedResult::Blocked));
}

#[tokio::test]
async fn test_xfo_deny_includes_remediation_hints() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).insert_header("x-frame-options", "DENY"))
        .mount(&server)
        .await;

    let result = check_url(&server.uri()).await.unwrap();
    assert!(result
        .remediation_hints
        .iter()
        .any(|hint| hint.contains("Remove X-Frame-Options: DENY")));
    assert!(result
        .remediation_hints
        .iter()
        .any(|hint| hint.contains("Content-Security-Policy")));
}

#[tokio::test]
async fn test_xfo_sameorigin_is_blocked() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).insert_header("x-frame-options", "SAMEORIGIN"))
        .mount(&server)
        .await;

    let result = check_url(&server.uri()).await.unwrap();
    assert!(matches!(result.frame_policy.result, EmbedResult::Blocked));
}

#[tokio::test]
async fn test_csp_frame_ancestors_none_is_blocked() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-security-policy", "frame-ancestors 'none'"),
        )
        .mount(&server)
        .await;

    let result = check_url(&server.uri()).await.unwrap();
    assert!(matches!(result.frame_policy.result, EmbedResult::Blocked));
}

#[tokio::test]
async fn test_no_headers_is_unknown() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let result = check_url(&server.uri()).await.unwrap();
    assert!(matches!(result.frame_policy.result, EmbedResult::Unknown));
}

#[tokio::test]
async fn test_wildcard_cors_detected() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).insert_header("access-control-allow-origin", "*"))
        .mount(&server)
        .await;

    let result = check_url(&server.uri()).await.unwrap();
    assert!(result.security_headers.cors.is_wildcard);
}
