//! `hitomi` -- the yara sensor's binary. In this step it is the on-demand scanner only:
//!
//! ```text
//! hitomi scan [--rules DIR] PATH...
//! ```
//!
//! It loads a directory of YARA rules once, scans each PATH, and prints one `yara/1` JSON line per
//! matching rule to stdout (the [`yara_types`] wire schema banken parses). A clean file prints
//! nothing. The exit code is 0 when every path scanned (matches or not) and non-zero only when a
//! path could not be read or the rules could not be compiled -- a match is a finding, not an error.
//!
//! The fanotify daemon (the `exec`/`close-write` triggers, the cache, the queue) is a later step
//! (design section 12 step 4); the rules directory here comes from `--rules`/`$HITOMI_RULES`, not
//! from the kernel. Nothing in this binary is `unsafe`, and it never executes or shells out to
//! anything derived from a scanned file: the bytes are inert data handed to the matcher.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::SystemTime;

use anyhow::{bail, Context, Result};
use hitomi::{Engine, TRIGGER_SCAN};

/// Environment fallback for the rules directory when `--rules` is not given.
const RULES_ENV: &str = "HITOMI_RULES";

const USAGE: &str = "usage: hitomi scan [--rules DIR] PATH...\n\
    \n\
    Scan each PATH with the YARA rules in DIR (or $HITOMI_RULES) and print one yara/1\n\
    JSON line per matching rule. A clean file prints nothing. Exit 0 unless a path\n\
    cannot be read or the rules cannot be compiled.";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            // One line per cause, no panic, no backtrace on the wire path.
            eprintln!("hitomi: {err:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = Command::parse(&args)?;
    match cmd {
        Command::Scan { rules_dir, paths } => scan(&rules_dir, &paths),
    }
}

/// The parsed command line. Only `scan` exists in this step; the enum is where `daemon` and
/// `--check` join later without reshaping `main`.
enum Command {
    Scan {
        rules_dir: PathBuf,
        paths: Vec<PathBuf>,
    },
}

impl Command {
    fn parse(args: &[String]) -> Result<Command> {
        match args.first().map(String::as_str) {
            Some("scan") => {
                let rest = &args[1..];
                let mut rules_dir: Option<PathBuf> = None;
                let mut paths: Vec<PathBuf> = Vec::new();
                let mut i = 0;
                while i < rest.len() {
                    match rest[i].as_str() {
                        "--rules" => {
                            i += 1;
                            let dir = rest.get(i).context("--rules needs a directory argument")?;
                            rules_dir = Some(PathBuf::from(dir));
                        }
                        "--" => {
                            // Everything after `--` is a path, even if it starts with a dash.
                            paths.extend(rest[i + 1..].iter().map(PathBuf::from));
                            break;
                        }
                        other if other.starts_with("--") => {
                            bail!("unknown flag {other}\n{USAGE}");
                        }
                        other => paths.push(PathBuf::from(other)),
                    }
                    i += 1;
                }
                let rules_dir = rules_dir
                    .or_else(|| std::env::var_os(RULES_ENV).map(PathBuf::from))
                    .with_context(|| {
                        format!("no rules directory: pass --rules DIR or set ${RULES_ENV}\n{USAGE}")
                    })?;
                if paths.is_empty() {
                    bail!("no files to scan\n{USAGE}");
                }
                Ok(Command::Scan { rules_dir, paths })
            }
            Some("-h") | Some("--help") | Some("help") => {
                println!("{USAGE}");
                std::process::exit(0);
            }
            Some(other) => bail!("unknown command {other}\n{USAGE}"),
            None => bail!("no command\n{USAGE}"),
        }
    }
}

fn scan(rules_dir: &Path, paths: &[PathBuf]) -> Result<()> {
    let engine = Engine::load(rules_dir)
        .with_context(|| format!("loading rules from {}", rules_dir.display()))?;
    let ruleset = engine.ruleset_id().to_string();

    // A manual scan has no fanotify process linkage, so the pid is 0 (design 5.3: the pid on an
    // event is the kernel-reported toucher; a manual scan has none). The daemon fills the real pid.
    const MANUAL_SCAN_PID: u32 = 0;

    let mut stdout = std::io::BufWriter::new(std::io::stdout().lock());
    for path in paths {
        let outcome = engine
            .scan(path)
            .with_context(|| format!("scanning {}", path.display()))?;
        let now = SystemTime::now();
        for event in outcome.to_events(
            &path.to_string_lossy(),
            MANUAL_SCAN_PID,
            TRIGGER_SCAN,
            &ruleset,
            now,
        ) {
            writeln!(stdout, "{}", yara_types::render(&event))
                .context("writing a match line to stdout")?;
        }
    }
    stdout.flush().context("flushing stdout")?;
    Ok(())
}
