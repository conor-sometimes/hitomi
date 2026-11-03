//! End-to-end test of the `hitomi scan` binary: a benign marker rule (never the EICAR string,
//! which is never committed to source) over a temp file, proving the CLI emits one `yara/1` line
//! per hit that parses with `yara-types`, and nothing for a clean file. The EICAR string itself is
//! exercised at runtime on hokkaido, not in committed source.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

/// A unique scratch directory under the system temp dir, removed on drop.
struct Scratch {
    dir: PathBuf,
}

impl Scratch {
    fn new(tag: &str) -> Scratch {
        let dir = std::env::temp_dir().join(format!(
            "hitomi-it-{}-{}-{tag}",
            std::process::id(),
            // a monotonic-ish suffix so repeated runs in one process never collide
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(dir.join("rules")).unwrap();
        Scratch { dir }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn write_marker_rule(scratch: &Scratch) {
    let rule = r#"rule it_marker : integration {
    meta:
        score = 42
        description = "integration-test marker"
    strings:
        $m = "hitomi-integration-marker"
    condition:
        $m
}
"#;
    fs::write(scratch.dir.join("rules/marker.yar"), rule).unwrap();
}

fn run_scan(scratch: &Scratch, target: &PathBuf) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_hitomi"))
        .arg("scan")
        .arg("--rules")
        .arg(scratch.dir.join("rules"))
        .arg(target)
        .output()
        .expect("the hitomi binary runs")
}

#[test]
fn scan_emits_one_parseable_line_per_hit() {
    let scratch = Scratch::new("hit");
    write_marker_rule(&scratch);

    let dirty = scratch.dir.join("dirty.bin");
    fs::write(&dirty, b"....hitomi-integration-marker....").unwrap();

    let out = run_scan(&scratch, &dirty);
    assert!(out.status.success(), "a match is not an error");
    let stdout = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 1, "one line per matching rule: {stdout:?}");

    let m = yara_types::parse(lines[0]).expect("the emitted line parses with yara-types");
    assert_eq!(m.schema, "yara/1");
    assert_eq!(m.kind, "match");
    assert_eq!(m.trigger, "scan");
    assert_eq!(m.process.pid, 0, "a manual scan has no fanotify pid");
    assert_eq!(m.rule.name, "it_marker");
    assert_eq!(m.rule.namespace, "default");
    assert_eq!(m.rule.score, Some(42));
    assert_eq!(m.rule.patterns, vec!["$m".to_string()]);
    assert_eq!(m.file.path, dirty.to_string_lossy());
    assert_eq!(m.file.size, 33);
    assert!(m.ruleset.starts_with("sha256:"));
    assert_eq!(m.file.hashes[0].algorithm, "SHA-256");
    assert_eq!(m.file.hashes[0].value.len(), 64);
    // render(parse(line)) must reproduce the line exactly: a stable wire fixpoint.
    assert_eq!(yara_types::render(&m), lines[0]);
}

#[test]
fn clean_file_emits_nothing_and_exits_zero() {
    let scratch = Scratch::new("clean");
    write_marker_rule(&scratch);

    let clean = scratch.dir.join("clean.txt");
    fs::write(&clean, b"nothing of interest here\n").unwrap();

    let out = run_scan(&scratch, &clean);
    assert!(out.status.success());
    assert!(out.stdout.is_empty(), "a clean file prints nothing");
}

#[test]
fn missing_rules_directory_is_an_error() {
    let out = Command::new(env!("CARGO_BIN_EXE_hitomi"))
        .arg("scan")
        .arg("--rules")
        .arg("/nonexistent/hitomi/rules")
        .arg("/etc/hostname")
        .output()
        .expect("the hitomi binary runs");
    assert!(!out.status.success(), "a bad rules dir is a non-zero exit");
}
