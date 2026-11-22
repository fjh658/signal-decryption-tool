//! Binary-level tests for `SignalDecryption` that need no OS key store.

use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_SignalDecryption");
const KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

#[test]
fn plaintext_key_is_printed_without_the_os_store() {
    let config = std::env::temp_dir().join(format!("decryption_plain_{}.json", std::process::id()));
    std::fs::write(&config, format!(r#"{{"key":"{KEY}"}}"#)).unwrap();
    let out = Command::new(BIN).args(["-c", config.to_str().unwrap(), "-p"]).output().expect("spawn");
    let _ = std::fs::remove_file(&config);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(stdout.contains(&format!("Decrypted key: {KEY}")), "{stdout}");
    assert!(stdout.contains("plaintext"), "-p should say there is no key material: {stdout}");
}

#[test]
fn never_launched_signal_is_explained() {
    let out = Command::new(BIN).args(["-c", "/nonexistent/Signal/config.json"]).output().expect("spawn");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success());
    assert!(stderr.contains("/nonexistent/Signal/config.json") && stderr.contains("start Signal"), "{stderr}");
}
