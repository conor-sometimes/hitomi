//! hitomi's scan engine: compile a directory of YARA rules with yara-x and scan a file's bytes for
//! matches, producing `yara/1` wire events (the [`yara_types`] schema).
//!
//! The engine is the sensor's one piece of untrusted-input handling: the bytes it scans are the
//! thing the box is defending against. It treats them as pure inert data -- yara-x only matches
//! patterns and evaluates module logic over the byte slice; the engine never executes, maps, or
//! shells out to anything derived from the scanned bytes, and the rule text is operator-supplied,
//! not attacker-supplied. yara-x is built with the `pulley` feature (see `Cargo.toml`), so rule
//! evaluation runs on the wasmtime Pulley bytecode interpreter and never maps a writable-then-
//! executable page; the sensor therefore runs under `MemoryDenyWriteExecute=yes` (design section
//! 2.2). A crafted file that trips a parser bug surfaces as a caught error from [`Engine::scan`],
//! never a crash of the process (design section 2.2's never-die argument); `fuzz/` proves it.
//!
//! This crate is the engine and the on-demand `scan` path only. The fanotify daemon, its cache,
//! queue and the kernel-facing `unsafe` land in a later step (design section 12 step 4); nothing
//! here is `unsafe`.

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use yara_x::MetaValue;

/// The engine identity stamped on every event's `engine` field. Kept in step with the `yara-x` pin
/// in `Cargo.toml`; a bump moves both.
pub const ENGINE: &str = "yara-x 1.22.1";

/// The trigger string the on-demand CLI stamps (design section 3.3: `sensor scan` is the
/// on-demand trigger). The daemon's fanotify triggers (`exec`, `close-write`) land in a later step.
pub const TRIGGER_SCAN: &str = "scan";

/// File extensions treated as YARA rule sources when loading a directory. A rule set is a
/// directory of files, never a file that reads other files: `include` is not used (design 2.3).
const RULE_EXTENSIONS: [&str; 2] = ["yar", "yara"];

/// A compiled rule set plus its identity, ready to scan many files. Build once, scan repeatedly:
/// compilation is the expensive step and the daemon holds one `Engine` for the process's life.
pub struct Engine {
    rules: yara_x::Rules,
    /// `sha256:<hex>` over the rule sources, the `ruleset` field on every event. A changed rule
    /// set changes this, which is also the verdict cache's rule-set key (design 7.1).
    ruleset_id: String,
    /// How many rule *files* were compiled (for the load report, not the wire).
    rule_files: usize,
}

impl Engine {
    /// Load and compile every `*.yar`/`*.yara` file in `rules_dir` (non-recursive, sorted by path
    /// for a deterministic rule-set hash). A compile error names the offending file and aborts the
    /// load -- rules are reported, never silently dropped (design 2.3). An empty directory is an
    /// error: a sensor with no rules is a misconfiguration, not a silent no-op.
    pub fn load(rules_dir: &Path) -> Result<Engine> {
        let mut paths: Vec<PathBuf> = Vec::new();
        for entry in fs::read_dir(rules_dir)
            .with_context(|| format!("reading rules directory {}", rules_dir.display()))?
        {
            let path = entry
                .with_context(|| format!("reading an entry of {}", rules_dir.display()))?
                .path();
            let is_rule = path
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| RULE_EXTENSIONS.contains(&e));
            if is_rule && path.is_file() {
                paths.push(path);
            }
        }
        paths.sort();
        if paths.is_empty() {
            bail!(
                "no YARA rule files (*.yar, *.yara) in {}",
                rules_dir.display()
            );
        }

        // Read all sources up front: the compiler borrows each source for the duration of the
        // build (for its error reports), so `from_sources` keeps them alive until after it.
        let mut sources: Vec<(String, String)> = Vec::with_capacity(paths.len());
        for path in &paths {
            let text = fs::read_to_string(path)
                .with_context(|| format!("reading rule file {}", path.display()))?;
            sources.push((path.to_string_lossy().into_owned(), text));
        }
        Engine::from_sources(sources)
    }

    /// Compile a rule set already in memory: pairs of `(origin, rule_text)` where `origin` is a
    /// name used in error reports and in the rule-set hash. The in-memory counterpart of
    /// [`Engine::load`] (which is this plus a directory read), shared by the daemon-less tests and
    /// the `fuzz_scan` target so they compile the same way the CLI does.
    pub fn from_sources(sources: Vec<(String, String)>) -> Result<Engine> {
        if sources.is_empty() {
            bail!("empty rule set: a sensor with no rules is a misconfiguration");
        }

        // Rule-set identity: sha256 over (origin, NUL, bytes, NUL) for each source in order.
        // Deterministic for a given set of sources and contents; `load` sorts by path first.
        let mut hasher = Sha256::new();
        for (origin, text) in &sources {
            hasher.update(origin.as_bytes());
            hasher.update([0u8]);
            hasher.update(text.as_bytes());
            hasher.update([0u8]);
        }
        let ruleset_id = format!("sha256:{}", hex(&hasher.finalize()));

        let mut compiler = yara_x::Compiler::new();
        // Community sets were written against YARA 4.x, which is more tolerant of regex syntax;
        // turn that tolerance on so they load (design 2.3). The sensor defines no external
        // variables, so a rule referencing one fails to compile loudly, which is correct.
        compiler.relaxed_re_syntax(true);
        for (origin, text) in &sources {
            let src = yara_x::SourceCode::from(text.as_str()).with_origin(origin.as_str());
            compiler
                .add_source(src)
                .with_context(|| format!("compiling rule source {origin}"))?;
        }
        let rules = compiler.build();

        Ok(Engine {
            rules,
            ruleset_id,
            rule_files: sources.len(),
        })
    }

    /// The `sha256:<hex>` identity of the loaded rule set.
    pub fn ruleset_id(&self) -> &str {
        &self.ruleset_id
    }

    /// How many rule files were compiled (load report only).
    pub fn rule_files(&self) -> usize {
        self.rule_files
    }

    /// Scan one file by path: read its bytes, hash them with SHA-256, and match the compiled rules
    /// against the exact bytes read (no mmap -- the engine reads the file itself, design 4.1). The
    /// hash is over the same buffer that is scanned, so the event's digest is of the bytes the
    /// verdict is about. A yara-x scan error (a timed-out or malformed input) is returned as an
    /// `Err`, never a panic.
    pub fn scan(&self, path: &Path) -> Result<ScanOutcome> {
        let data =
            fs::read(path).with_context(|| format!("reading file to scan {}", path.display()))?;
        self.scan_bytes(&data)
    }

    /// Scan an in-memory buffer. The byte-slice entry point the daemon (an fd read) and the fuzzer
    /// share; [`Engine::scan`] is this plus a file read.
    pub fn scan_bytes(&self, data: &[u8]) -> Result<ScanOutcome> {
        let sha256 = hex(&Sha256::digest(data));
        let mut scanner = yara_x::Scanner::new(&self.rules);
        let results = scanner
            .scan(data)
            .map_err(|e| anyhow::anyhow!("yara-x scan failed: {e}"))?;

        let mut hits = Vec::new();
        for rule in results.matching_rules() {
            let mut score = None;
            let mut description = None;
            for (key, value) in rule.metadata() {
                match (key, value) {
                    ("score", MetaValue::Integer(n)) => score = Some(n),
                    ("description", MetaValue::String(s)) => description = Some(s.to_string()),
                    _ => {}
                }
            }
            let tags = rule.tags().map(|t| t.identifier().to_string()).collect();
            // Only the patterns that actually matched, by identifier ($a, $s1): names, never the
            // matched bytes (design 4.3).
            let patterns = rule
                .patterns()
                .filter(|p| p.matches().len() > 0)
                .map(|p| p.identifier().to_string())
                .collect();
            hits.push(RuleHit {
                name: rule.identifier().to_string(),
                namespace: rule.namespace().to_string(),
                tags,
                score,
                description,
                patterns,
            });
        }

        Ok(ScanOutcome {
            size: data.len() as u64,
            sha256,
            hits,
        })
    }
}

/// The result of scanning one file: the size and SHA-256 of the scanned bytes, and the rules that
/// matched (empty when the file is clean).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanOutcome {
    pub size: u64,
    pub sha256: String,
    pub hits: Vec<RuleHit>,
}

/// One matching rule, reported as values (never the matched bytes or the rule text), ready to be
/// turned into a `yara/1` event line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleHit {
    pub name: String,
    pub namespace: String,
    pub tags: Vec<String>,
    pub score: Option<i64>,
    pub description: Option<String>,
    pub patterns: Vec<String>,
}

impl ScanOutcome {
    /// Build the `yara/1` wire events for this scan: one [`yara_types::Match`] per matching rule
    /// (none when the file is clean). `pid` is the process that touched the file (0 for a manual
    /// scan, which has no fanotify linkage); `path` is the scanned file; `trigger` is `scan` for
    /// the CLI; `ruleset` is the loaded set's [`Engine::ruleset_id`]. `now` is the scan time, taken
    /// once so every line of one scan shares a timestamp.
    pub fn to_events(
        &self,
        path: &str,
        pid: u32,
        trigger: &str,
        ruleset: &str,
        now: SystemTime,
    ) -> Vec<yara_types::Match> {
        let time = format_rfc3339_millis(now);
        self.hits
            .iter()
            .map(|hit| yara_types::Match {
                schema: yara_types::SCHEMA.to_string(),
                kind: "match".to_string(),
                time: time.clone(),
                trigger: trigger.to_string(),
                file: yara_types::File {
                    path: path.to_string(),
                    size: self.size,
                    hashes: vec![yara_types::Hash {
                        algorithm: "SHA-256".to_string(),
                        value: self.sha256.clone(),
                    }],
                },
                process: yara_types::Process { pid },
                rule: yara_types::Rule {
                    name: hit.name.clone(),
                    namespace: hit.namespace.clone(),
                    tags: hit.tags.clone(),
                    score: hit.score,
                    description: hit.description.clone(),
                    patterns: hit.patterns.clone(),
                },
                engine: ENGINE.to_string(),
                ruleset: ruleset.to_string(),
                truncated: false,
            })
            .collect()
    }
}

/// Lower-case hex of a byte slice (a SHA-256 digest is 32 bytes -> 64 chars).
fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Format a `SystemTime` as RFC3339 UTC with millisecond precision (`2026-11-03T04:12:03.418Z`),
/// the wire's `time` shape. std has no calendar, and the dependency policy adds no `time`/`chrono`
/// crate for this, so the civil date is computed directly.
fn format_rfc3339_millis(t: SystemTime) -> String {
    let dur = t.duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO);
    let secs = dur.as_secs() as i64;
    let millis = dur.subsec_millis();
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (hh, mm, ss) = (tod / 3600, (tod % 3600) / 60, tod % 60);
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}T{hh:02}:{mm:02}:{ss:02}.{millis:03}Z")
}

/// Convert a count of days since the Unix epoch to a `(year, month, day)` civil date (UTC).
/// Howard Hinnant's public-domain algorithm: http://howardhinnant.github.io/date_algorithms.html
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if month <= 2 { year + 1 } else { year }, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_is_lowercase_and_padded() {
        assert_eq!(hex(&[0x00, 0x0f, 0xff, 0xa5]), "000fffa5");
    }

    #[test]
    fn rfc3339_matches_the_wire_shape() {
        // 2026-11-03T04:12:03.418Z == 1793679123.418 since the epoch.
        let t = UNIX_EPOCH + Duration::new(1_793_679_123, 418_000_000);
        assert_eq!(format_rfc3339_millis(t), "2026-11-03T04:12:03.418Z");
    }

    #[test]
    fn civil_from_days_known_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(18_993), (2022, 1, 1));
    }

    #[test]
    fn events_are_empty_when_clean() {
        let clean = ScanOutcome {
            size: 10,
            sha256: "ab".to_string(),
            hits: vec![],
        };
        assert!(clean
            .to_events("/x", 0, TRIGGER_SCAN, "sha256:ab", SystemTime::now())
            .is_empty());
    }

    /// A benign marker rule (never the EICAR string, which is never committed to source): compile
    /// it, match a buffer that contains the marker, and confirm a clean buffer does not match. This
    /// exercises the whole value path (identifier, namespace, tags, score/description meta, matched
    /// pattern names) that the EICAR runtime proof checks end to end.
    #[test]
    fn engine_matches_marker_and_leaves_clean_bytes_alone() {
        let marker = "hitomi-engine-selftest-marker";
        let rule = format!(
            r#"rule hitomi_selftest : selftest synthetic {{
                   meta:
                       score = 50
                       description = "hitomi engine self-test marker"
                   strings:
                       $m = "{marker}"
                   condition:
                       $m
               }}"#
        );
        let engine = Engine::from_sources(vec![("selftest.yar".to_string(), rule)])
            .expect("the self-test rule compiles");
        assert!(engine.ruleset_id().starts_with("sha256:"));

        let dirty = format!("prefix {marker} suffix").into_bytes();
        let hits = engine.scan_bytes(&dirty).expect("scan succeeds").hits;
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].name, "hitomi_selftest");
        assert_eq!(hits[0].score, Some(50));
        assert_eq!(
            hits[0].description.as_deref(),
            Some("hitomi engine self-test marker")
        );
        assert_eq!(
            hits[0].tags,
            vec!["selftest".to_string(), "synthetic".to_string()]
        );
        assert_eq!(hits[0].patterns, vec!["$m".to_string()]);

        let clean = engine
            .scan_bytes(b"nothing to see here")
            .expect("scan succeeds");
        assert!(clean.hits.is_empty());
    }

    #[test]
    fn empty_rule_set_is_an_error() {
        assert!(Engine::from_sources(vec![]).is_err());
    }

    #[test]
    fn events_render_and_parse_back() {
        let outcome = ScanOutcome {
            size: 68,
            sha256: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f".to_string(),
            hits: vec![RuleHit {
                name: "eicar_test".to_string(),
                namespace: "default".to_string(),
                tags: vec!["test".to_string()],
                score: Some(50),
                description: Some("EICAR test string".to_string()),
                patterns: vec!["$eicar".to_string()],
            }],
        };
        let events = outcome.to_events(
            "/tmp/eicar",
            0,
            TRIGGER_SCAN,
            "sha256:deadbeef",
            SystemTime::now(),
        );
        assert_eq!(events.len(), 1);
        let line = yara_types::render(&events[0]);
        let parsed = yara_types::parse(&line).expect("the engine's own line parses");
        assert_eq!(parsed, events[0]);
        assert_eq!(parsed.rule.patterns, vec!["$eicar".to_string()]);
        assert_eq!(parsed.process.pid, 0);
        assert_eq!(parsed.trigger, "scan");
    }
}
