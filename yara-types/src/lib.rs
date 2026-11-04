//! The yara sensor's wire schema: the one `yara/1` match-line shape the sensor emits and banken
//! parses. This is the single source of truth for the bytes crossing the boundary, the counterpart
//! of mimi's `mimi-types` crate -- except the sensor is an ordinary std binary (no eBPF, no no_std
//! probe), so the type is a plain serde struct that renders and parses with `serde_json` rather
//! than a hand-rolled `#[repr(C)]` layout.
//!
//! The format is frozen by a shared golden fixture (`testdata/yara_event.golden.jsonl`) that is
//! byte-for-byte identical to banken's copy: the sensor asserts its render equals that file, and
//! banken asserts its parser reads exactly it, so the two repos cannot drift. `just contract`
//! checks it on both sides.
//!
//! The on-wire shape (design docs/design/yara-sensor.md section 5.1):
//!
//! ```json
//! {"schema":"yara/1","kind":"match","time":"...","trigger":"exec",
//!  "file":{"path":"...","size":48128,"hashes":[{"algorithm":"SHA-256","value":"..."}]},
//!  "process":{"pid":4242},
//!  "rule":{"name":"...","namespace":"forge-core","tags":["linux","miner"],
//!          "score":75,"description":"...","patterns":["$s1","$s4"]},
//!  "engine":"yara-x 1.22.1","ruleset":"sha256:...","truncated":false}
//! ```

use serde::{Deserialize, Serialize};

// The daemon's kernel-free logic, kept here (design 8.1) so it is unit-tested on the Mac with no
// syscalls: the verdict cache key and its bounded LRU, mountinfo parsing + filesystem
// classification, and path-prefix matching for the drop-zone and exclude filters.
pub mod cache;
pub mod mount;
pub mod prefix;

/// The wire schema version, emitted in every line. banken checks it and skips a line whose version
/// it does not know rather than misreading newer bytes, so the sensor and the brain can evolve
/// without silent drift (the same contract mimi's `SCHEMA` carries).
pub const SCHEMA: &str = "yara/1";

/// One `yara/1` match line: one rule that matched one scanned inode, with the pid that touched it.
///
/// Field order is the wire order, and `serde_json` serialises a struct in declaration order, so the
/// order here IS the golden's byte order -- do not reorder without regenerating the golden on both
/// sides.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Match {
    /// Always `yara/1` for this version. Stamped, checked by banken, never trusted for provenance
    /// (banken stamps `Source: "yara"` from the parser, never from the line).
    pub schema: String,
    /// `match` for every v1 line. A future `kind: "verdict"` (the CLI's clean/failed results) uses
    /// the same envelope; the daemon's stream carries matches only.
    pub kind: String,
    /// RFC3339 wall-clock time of the scan.
    pub time: String,
    /// What fired the scan: `exec` | `close-write` | `scan`.
    pub trigger: String,
    pub file: File,
    pub process: Process,
    pub rule: Rule,
    /// Engine identity, e.g. `yara-x 1.22.1`.
    pub engine: String,
    /// The rule-set identity the scan ran under, e.g. `sha256:...`.
    pub ruleset: String,
    /// True when more rules matched than `maxHitsPerFile` and were not emitted.
    pub truncated: bool,
}

/// The scanned file: the bytes that ran (exec) or were written (close-write).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct File {
    /// The path the fd resolved to (`readlink /proc/self/fd/N`); may end ` (deleted)`.
    pub path: String,
    /// Size of the bytes scanned.
    pub size: u64,
    /// Digests of the scanned bytes. SHA-256 in v1; a list so a second algorithm is additive.
    pub hashes: Vec<Hash>,
}

/// One digest of the scanned bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hash {
    /// OCSF algorithm name, e.g. `SHA-256`.
    pub algorithm: String,
    /// Lower-case hex digest.
    pub value: String,
}

/// The only process linkage fanotify gives: the TGID that executed or closed the file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Process {
    pub pid: u32,
}

/// The matching YARA rule, reported as values (never a dump of the rule text or the matched bytes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub name: String,
    pub namespace: String,
    pub tags: Vec<String>,
    /// The rule's `score` meta (Forge is 0-100), absent when the rule has no such meta.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub score: Option<i64>,
    /// The rule's `description` meta, absent when the rule has none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The identifiers of the patterns that matched (`$s1`, `$a`): names, never the matched bytes.
    pub patterns: Vec<String>,
}

/// Render one match line as the compact JSON that goes on the wire (and that the golden fixture
/// freezes). Infallible for any `Match` value -- every field is a plain type serde cannot refuse.
pub fn render(m: &Match) -> String {
    serde_json::to_string(m).expect("Match serialises to JSON: every field is a plain serde type")
}

/// Parse one `yara/1` line into a `Match`, or a serde error for malformed/short JSON. The caller
/// (and banken, on its own side) decides what to do with an unknown `schema`; this does not gate on
/// the version, so a reader can inspect `schema` and skip deliberately.
pub fn parse(line: &str) -> Result<Match, serde_json::Error> {
    serde_json::from_str(line)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The sample the golden fixture is rendered from: the design's section 5.1 example with a full
    /// concrete SHA-256 and rule-set digest. banken's parser is tested against a byte-for-byte copy
    /// of the same golden, so this sample IS the cross-repo contract.
    fn sample() -> Match {
        Match {
            schema: SCHEMA.to_string(),
            kind: "match".to_string(),
            time: "2026-11-03T04:12:03.418Z".to_string(),
            trigger: "exec".to_string(),
            file: File {
                path: "/tmp/.x/payload".to_string(),
                size: 48128,
                hashes: vec![Hash {
                    algorithm: "SHA-256".to_string(),
                    value: "9f2c3d4e5a6b7c8d9e0f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f"
                        .to_string(),
                }],
            },
            process: Process { pid: 4242 },
            rule: Rule {
                name: "MAL_Linux_XMRig_Jan24".to_string(),
                namespace: "forge-core".to_string(),
                tags: vec!["linux".to_string(), "miner".to_string()],
                score: Some(75),
                description: Some("XMRig miner, Linux build".to_string()),
                patterns: vec!["$s1".to_string(), "$s4".to_string()],
            },
            engine: "yara-x 1.22.1".to_string(),
            ruleset: "sha256:3b1e9f44a0c7d2e1b8f6a3049d5c7e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5"
                .to_string(),
            truncated: false,
        }
    }

    /// The shared contract: `render(sample)` must equal the golden byte for byte. banken tests the
    /// same file from its side (`just contract` there); the two repos' copies must stay identical,
    /// so a schema change has to move both halves of the family. This is `just contract`.
    #[test]
    fn golden_render_yara() {
        let fixture = include_str!("../../testdata/yara_event.golden.jsonl");
        assert_eq!(render(&sample()), fixture.trim_end());
    }

    /// Parsing the golden back yields the sample, and re-rendering it equals the golden: the wire
    /// type round-trips losslessly.
    #[test]
    fn golden_parse_round_trips() {
        let fixture = include_str!("../../testdata/yara_event.golden.jsonl");
        let parsed = parse(fixture.trim_end()).expect("golden parses");
        assert_eq!(parsed, sample());
        assert_eq!(render(&parsed), fixture.trim_end());
    }

    /// The optional meta (`score`, `description`) is omitted on the wire when absent, and parses
    /// back as `None` -- not as a zero or an empty string.
    #[test]
    fn optional_meta_is_omitted_when_absent() {
        let mut m = sample();
        m.rule.score = None;
        m.rule.description = None;
        let line = render(&m);
        assert!(!line.contains("\"score\""), "{line}");
        assert!(!line.contains("\"description\""), "{line}");
        let back = parse(&line).expect("parses without the optional meta");
        assert_eq!(back.rule.score, None);
        assert_eq!(back.rule.description, None);
    }

    /// A reader can see an unknown schema version and decide to skip it: the version is data on the
    /// parsed value, not a parse error (banken does the skipping on its side).
    #[test]
    fn unknown_schema_parses_so_a_reader_can_skip_it() {
        let mut m = sample();
        m.schema = "yara/99".to_string();
        let back = parse(&render(&m)).expect("an unknown-version line still parses structurally");
        assert_eq!(back.schema, "yara/99");
    }

    /// Malformed JSON is a reported error, never a panic.
    #[test]
    fn malformed_json_is_an_error_not_a_panic() {
        assert!(parse("{ not json").is_err());
        assert!(parse("").is_err());
        assert!(parse("{}").is_err());
    }
}
