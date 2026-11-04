//! `hitomi` -- the yara sensor's binary. Three modes over one engine:
//!
//! ```text
//! hitomi scan [--rules DIR] PATH...   # on-demand: scan each PATH, print one yara/1 line per hit
//! hitomi daemon [--rules DIR] [...]   # the fanotify sensor: watch execs + drop-zone writes (Linux)
//! hitomi --check [--rules DIR]        # preflight: rules compile, fanotify works, what it would mark
//! ```
//!
//! `scan` loads a directory of YARA rules once, scans each PATH, and prints one `yara/1` JSON line
//! per matching rule to stdout (the [`yara_types`] wire schema banken parses). A clean file prints
//! nothing; exit 0 unless a path cannot be read or the rules cannot be compiled -- a match is a
//! finding, not an error.
//!
//! `daemon` is the sensor proper (design 12 step 4): it subscribes to fanotify for `FAN_OPEN_EXEC`
//! and `FAN_CLOSE_WRITE`, scans the exact inode the kernel hands it, and appends `yara/1` lines to a
//! sink file banken tails. It is listener-only and Linux-only. `--check` is its preflight.
//!
//! All of this binary's `unsafe` is in `hitomi::fanotify`; `scan` and the engine use none. It never
//! executes or shells out to anything derived from a scanned file: the bytes are inert data handed
//! to the matcher.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::SystemTime;

use anyhow::{bail, Context, Result};
use hitomi::{Engine, TRIGGER_SCAN};

/// Environment fallback for the rules directory when `--rules` is not given.
const RULES_ENV: &str = "HITOMI_RULES";

const USAGE: &str = "usage:\n\
    \thitomi scan [--rules DIR] PATH...\n\
    \thitomi daemon [--rules DIR] [--sink FILE] [--max-bytes N] [--cache-entries N] \\\n\
    \t              [--drop-zone PREFIX]... [--exclude PREFIX]...\n\
    \thitomi --check [--rules DIR]\n\
    \n\
    scan    scan each PATH and print one yara/1 line per matching rule (clean prints nothing).\n\
    daemon  run the fanotify sensor: watch execs and drop-zone writes, append hits to the sink.\n\
    --check preflight: compile the rules, test fanotify_init, print the filesystems it would mark.\n\
    \n\
    The rules directory comes from --rules or $HITOMI_RULES. daemon and --check are Linux-only.";

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
    match Command::parse(&args)? {
        Command::Scan { rules_dir, paths } => scan(&rules_dir, &paths),
        Command::Daemon(opts) => daemon(opts),
        Command::Check { rules_dir } => check(&rules_dir),
    }
}

/// The parsed command line.
enum Command {
    Scan {
        rules_dir: PathBuf,
        paths: Vec<PathBuf>,
    },
    Daemon(DaemonOpts),
    Check {
        rules_dir: PathBuf,
    },
}

/// The flags of `hitomi daemon`, before defaults are applied (defaults live in `hitomi::daemon`).
struct DaemonOpts {
    rules_dir: PathBuf,
    sink: Option<PathBuf>,
    max_file_bytes: Option<u64>,
    cache_entries: Option<usize>,
    drop_zones: Vec<String>,
    excludes: Vec<String>,
}

impl Command {
    fn parse(args: &[String]) -> Result<Command> {
        match args.first().map(String::as_str) {
            Some("scan") => Self::parse_scan(&args[1..]),
            Some("daemon") => Self::parse_daemon(&args[1..]),
            Some("--check") | Some("check") => {
                let rules_dir = parse_rules_only(&args[1..])?;
                Ok(Command::Check { rules_dir })
            }
            Some("-h") | Some("--help") | Some("help") => {
                println!("{USAGE}");
                std::process::exit(0);
            }
            Some(other) => bail!("unknown command {other}\n{USAGE}"),
            None => bail!("no command\n{USAGE}"),
        }
    }

    fn parse_scan(rest: &[String]) -> Result<Command> {
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
                other if other.starts_with("--") => bail!("unknown flag {other}\n{USAGE}"),
                other => paths.push(PathBuf::from(other)),
            }
            i += 1;
        }
        let rules_dir = resolve_rules(rules_dir)?;
        if paths.is_empty() {
            bail!("no files to scan\n{USAGE}");
        }
        Ok(Command::Scan { rules_dir, paths })
    }

    fn parse_daemon(rest: &[String]) -> Result<Command> {
        let mut rules_dir: Option<PathBuf> = None;
        let mut sink: Option<PathBuf> = None;
        let mut max_file_bytes: Option<u64> = None;
        let mut cache_entries: Option<usize> = None;
        let mut drop_zones: Vec<String> = Vec::new();
        let mut excludes: Vec<String> = Vec::new();
        let mut i = 0;
        // Each flag takes one value; a repeated --drop-zone/--exclude accumulates. `take_value`
        // advances past the flag's argument and returns it, erroring if the flag ends the list.
        let take_value = |i: &mut usize| -> Result<String> {
            let flag = rest[*i].clone();
            *i += 1;
            rest.get(*i)
                .cloned()
                .with_context(|| format!("{flag} needs an argument\n{USAGE}"))
        };
        while i < rest.len() {
            match rest[i].as_str() {
                "--rules" => rules_dir = Some(PathBuf::from(take_value(&mut i)?)),
                "--sink" => sink = Some(PathBuf::from(take_value(&mut i)?)),
                "--max-bytes" => {
                    let v = take_value(&mut i)?;
                    max_file_bytes = Some(
                        v.parse()
                            .with_context(|| format!("--max-bytes {v:?} is not a number"))?,
                    );
                }
                "--cache-entries" => {
                    let v = take_value(&mut i)?;
                    cache_entries = Some(
                        v.parse()
                            .with_context(|| format!("--cache-entries {v:?} is not a number"))?,
                    );
                }
                "--drop-zone" => drop_zones.push(take_value(&mut i)?),
                "--exclude" => excludes.push(take_value(&mut i)?),
                other => bail!("unknown daemon flag {other}\n{USAGE}"),
            }
            i += 1;
        }
        Ok(Command::Daemon(DaemonOpts {
            rules_dir: resolve_rules(rules_dir)?,
            sink,
            max_file_bytes,
            cache_entries,
            drop_zones,
            excludes,
        }))
    }
}

/// Parse a flag list that accepts only an optional `--rules DIR` (used by `--check`).
fn parse_rules_only(rest: &[String]) -> Result<PathBuf> {
    let mut rules_dir: Option<PathBuf> = None;
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--rules" => {
                i += 1;
                rules_dir = Some(PathBuf::from(
                    rest.get(i).context("--rules needs a directory argument")?,
                ));
            }
            other => bail!("unknown flag {other}\n{USAGE}"),
        }
        i += 1;
    }
    resolve_rules(rules_dir)
}

/// Resolve the rules directory from the flag or the `$HITOMI_RULES` fallback.
fn resolve_rules(from_flag: Option<PathBuf>) -> Result<PathBuf> {
    from_flag
        .or_else(|| std::env::var_os(RULES_ENV).map(PathBuf::from))
        .with_context(|| {
            format!("no rules directory: pass --rules DIR or set ${RULES_ENV}\n{USAGE}")
        })
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

/// Run the fanotify daemon. Linux-only: fanotify is a Linux uapi, so on any other target this is a
/// clear error rather than a silent no-op (the daemon module itself is `cfg(target_os = "linux")`).
#[cfg(target_os = "linux")]
fn daemon(opts: DaemonOpts) -> Result<()> {
    use hitomi::daemon::{DaemonConfig, DEFAULT_MAX_FILE_BYTES, DEFAULT_SINK};
    use yara_types::cache::DEFAULT_CAPACITY;
    use yara_types::prefix::{DEFAULT_DROP_ZONES, DEFAULT_EXCLUDES};

    // Built-in defaults for anything a flag did not set (design 7.1/7.2/3.3). An empty --drop-zone
    // or --exclude list means "use the defaults"; passing any replaces the defaults for that list.
    let drop_zones = if opts.drop_zones.is_empty() {
        DEFAULT_DROP_ZONES.iter().map(|s| s.to_string()).collect()
    } else {
        opts.drop_zones
    };
    let mut exclude_prefixes: Vec<String> =
        DEFAULT_EXCLUDES.iter().map(|s| s.to_string()).collect();
    exclude_prefixes.extend(opts.excludes);

    let cfg = DaemonConfig {
        rules_dir: opts.rules_dir,
        sink: opts.sink.unwrap_or_else(|| PathBuf::from(DEFAULT_SINK)),
        max_file_bytes: opts.max_file_bytes.unwrap_or(DEFAULT_MAX_FILE_BYTES),
        drop_zones,
        exclude_prefixes,
        cache_entries: opts.cache_entries.unwrap_or(DEFAULT_CAPACITY),
    };
    hitomi::daemon::run(cfg)
}

#[cfg(not(target_os = "linux"))]
fn daemon(_opts: DaemonOpts) -> Result<()> {
    bail!("hitomi daemon is Linux-only (fanotify is a Linux uapi); build and run it on Linux");
}

/// Preflight (`--check`): rules compile, fanotify works, what would be marked. Linux-only, as above.
#[cfg(target_os = "linux")]
fn check(rules_dir: &Path) -> Result<()> {
    hitomi::daemon::check(rules_dir)
}

#[cfg(not(target_os = "linux"))]
fn check(_rules_dir: &Path) -> Result<()> {
    bail!("hitomi --check is Linux-only (it tests fanotify_init); build and run it on Linux");
}
