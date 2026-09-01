//! End-to-end tests that exercise the actual `plog` binary as a subprocess.
use std::io::Write;
use std::process::Command;

fn plog_bin() -> &'static str {
    env!("CARGO_BIN_EXE_plog")
}

fn write_file(dir: &std::path::Path, name: &str, content: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    let mut f = std::fs::File::create(&path).unwrap();
    f.write_all(content.as_bytes()).unwrap();
    path
}

#[test]
fn line_mode_decodes_each_matching_line() {
    let dir = tempfile::tempdir().unwrap();
    let ksy = write_file(dir.path(), "schema.ksy", "name: test\n");
    let log = write_file(
        dir.path(),
        "sample.log",
        "2024-01-01 PACKET: deadbeef\nnoise\n2024-01-01 PACKET: cafebabe\n",
    );

    let output = Command::new(plog_bin())
        .args([
            log.to_str().unwrap(),
            "--ksy",
            ksy.to_str().unwrap(),
            "--pattern",
            "PACKET: (?P<hex>[0-9a-fA-F ]+)",
            "--mode",
            "line",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("packet #0"));
    assert!(stdout.contains("raw: de ad be ef"));
    assert!(stdout.contains("packet #1"));
    assert!(stdout.contains("raw: ca fe ba be"));
}

#[test]
fn whole_mode_concatenates_into_single_packet() {
    let dir = tempfile::tempdir().unwrap();
    let ksy = write_file(dir.path(), "schema.ksy", "name: test\n");
    let log = write_file(
        dir.path(),
        "sample.log",
        "PACKET: deadbeef\nnoise\nPACKET: cafebabe\n",
    );

    let output = Command::new(plog_bin())
        .args([
            log.to_str().unwrap(),
            "--ksy",
            ksy.to_str().unwrap(),
            "--pattern",
            "PACKET: (?P<hex>[0-9a-fA-F ]+)",
            "--mode",
            "whole",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("packet #0"));
    assert!(stdout.contains("raw: de ad be ef ca fe ba be"));
    assert_eq!(stdout.matches("--- packet").count(), 1);
}

#[test]
fn binary_mode_decodes_raw_file_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let ksy = write_file(dir.path(), "schema.ksy", "name: test\n");
    let bin_path = dir.path().join("sample.bin");
    std::fs::write(&bin_path, [0xde, 0xad, 0xbe, 0xef]).unwrap();

    let output = Command::new(plog_bin())
        .args([bin_path.to_str().unwrap(), "--ksy", ksy.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("raw: de ad be ef"));
}

#[test]
fn auto_mode_detects_binary_without_flag() {
    let dir = tempfile::tempdir().unwrap();
    let ksy = write_file(dir.path(), "schema.ksy", "name: test\n");
    let bin_path = dir.path().join("sample.bin");
    std::fs::write(&bin_path, [0x00, 0xde, 0xad]).unwrap();

    let output = Command::new(plog_bin())
        .args([bin_path.to_str().unwrap(), "--ksy", ksy.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("raw: 00 de ad"));
}

#[test]
fn missing_ksy_file_fails_with_error() {
    let dir = tempfile::tempdir().unwrap();
    let log = write_file(dir.path(), "sample.log", "PACKET: deadbeef\n");

    let output = Command::new(plog_bin())
        .args([
            log.to_str().unwrap(),
            "--ksy",
            "does-not-exist.ksy",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("error"));
}

#[test]
fn missing_input_file_fails_with_error() {
    let dir = tempfile::tempdir().unwrap();
    let ksy = write_file(dir.path(), "schema.ksy", "name: test\n");

    let output = Command::new(plog_bin())
        .args(["does-not-exist.log", "--ksy", ksy.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("error"));
}
