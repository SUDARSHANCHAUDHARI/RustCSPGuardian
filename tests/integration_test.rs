use assert_cmd::Command;
use predicates::str::contains;

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
