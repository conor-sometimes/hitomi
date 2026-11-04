//! The fanotify daemon: the reader loop of design section 4.1, the mountinfo marking of 3.4, the
//! verdict cache of 7.1, the bounded queue and scan bounds of 7.3, and the sink banken tails.
//!
//! Two threads. The **reader** does only cheap syscalls -- `poll`, `read`, `readlink`, `fstat`, a
//! cache lookup -- and hands a bounded queue the `(fd, path, pid, trigger)` of files that need
//! scanning; it never scans, so a slow scan never stalls the kernel's notification path. The
//! **scanner** (one thread in v1) reads each fd into a capped buffer, runs yara-x inside a
//! `catch_unwind` (a parser bug is a cached `failed`, never a crash -- the never-die contract,
//! design 2.2), writes one `yara/1` line per matching rule to the sink, and records the verdict.
//!
//! Every fanotify event holds an open fd until it is closed, so the queue depth is also a bound on
//! open fds: an exec storm overflows the bounded queue and the overflow is counted, not buffered
//! (design 4.1). A cache hit emits nothing (design 4.2): the "this inode is known" signal was sent
//! the first time it was scanned.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, TrySendError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use anyhow::{bail, Context, Result};

use crate::fanotify::{fstat_id, readlink_fd, Fanotify, FAN_CLOSE_WRITE, FAN_OPEN_EXEC};
use crate::{Engine, TRIGGER_CLOSE_WRITE, TRIGGER_EXEC};
use yara_types::cache::{CacheKey, Verdict, VerdictCache};
use yara_types::mount::{markable_superblocks, parse_mountinfo, unknown_fstypes};
use yara_types::prefix::is_under_any;

// ===== the named constants of design section 7.3 (each a sentence, no magic number) =====

/// Reader-to-scanner queue depth: at most this many event fds are in flight waiting to be scanned.
/// It bounds open fds and kernel-event backlog together; a burst past it is dropped and counted,
/// never buffered unboundedly (design 4.1, 7.3).
const QUEUE_DEPTH: usize = 256;
/// Per-scan wall-clock cap. A scan that exceeds it is `failed: timeout`, cached as failed so the one
/// pathological file is paid for once, not retried in a loop (design 7.3).
const SCAN_TIMEOUT: Duration = Duration::from_secs(10);
/// How many times one pattern may match before yara-x stops counting it, so a pattern that matches a
/// million times cannot blow up memory or time (design 7.3).
const MAX_MATCHES_PER_PATTERN: usize = 32;
/// How many matching rules one file may emit before the rest are dropped and the `truncated` flag is
/// set: a rule set that matches everything emits ten lines, not a flood (design 7.3).
const MAX_HITS_PER_FILE: usize = 10;
/// The same inode is not queued twice for a close-write within this window: a file written in
/// several open/write/close rounds (an editor saving) is scanned once (design 7.3).
const CLOSE_WRITE_DEBOUNCE: Duration = Duration::from_secs(2);
/// Bound on the debounce table so a long-lived daemon that sees many distinct inodes does not grow
/// it without limit; when it is exceeded, entries older than the window are pruned.
const DEBOUNCE_TABLE_SOFT_CAP: usize = 4096;
/// Poll wake interval: the reader wakes at least this often even with no events, so a shutdown
/// signal set between events is honoured promptly (design 3.2).
const POLL_TIMEOUT_MS: libc::c_int = 1000;
/// Reusable read buffer for a batch of fanotify event records (each record is 24 bytes under
/// FAN_CLASS_NOTIF with no FID info), so one `read` drains many events.
const EVENT_BUF_BYTES: usize = 64 * 1024;

/// The default per-file size cap (64 MiB, design 7.2): a larger file is skipped and counted, never
/// scanned partially (a "clean" verdict on a prefix is a false clean).
pub const DEFAULT_MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;

/// The default sink path; banken tails it as the `yara` source. Lives in the unit's `LogsDirectory`
/// (design 8.2).
pub const DEFAULT_SINK: &str = "/var/log/hitomi/hitomi.jsonl";

/// Everything the daemon needs to run, as the CLI assembles it from flags (with these defaults for
/// anything a flag does not set). Mirrors the module options of design 8.3.
pub struct DaemonConfig {
    pub rules_dir: PathBuf,
    pub sink: PathBuf,
    pub max_file_bytes: u64,
    /// Close-write is only reported under one of these prefixes (design 3.3). Empty means "use the
    /// built-in defaults"; the CLI fills that in.
    pub drop_zones: Vec<String>,
    /// Events under any of these prefixes are dropped before scanning (the sink dir is always added
    /// by the daemon, below).
    pub exclude_prefixes: Vec<String>,
    pub cache_entries: usize,
}

/// A unit of work handed from the reader to the scanner: the kernel's read-only fd of the inode, the
/// resolved path, the toucher's pid, which trigger fired, and the cache key the reader already
/// built. Dropping the job closes the fd (the `OwnedFd`).
struct ScanJob {
    fd: OwnedFd,
    path: String,
    pid: u32,
    trigger: &'static str,
    key: CacheKey,
}

/// The shutdown flag, set by the signal handler (SIGTERM/SIGINT) and read at the top of the reader
/// loop. A `static` because a signal handler can only touch `'static` state, and an atomic because
/// that is the one thing a handler may safely write.
static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_stop_signal(_sig: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

/// Install async-signal handlers for SIGTERM and SIGINT that flip [`STOP`], so the reader's next
/// `poll` wake tears the daemon down cleanly (draining the queue and joining the scanner).
fn install_signal_handlers() -> Result<()> {
    // SAFETY: a zeroed sigaction is a valid empty-mask action; we set only sa_sigaction to a real
    // extern "C" fn pointer. sigaction with a null oldact installs the handler and returns 0 or -1.
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = on_stop_signal as *const () as usize;
    for sig in [libc::SIGTERM, libc::SIGINT] {
        let rc = unsafe { libc::sigaction(sig, &action, std::ptr::null_mut()) };
        if rc < 0 {
            return Err(std::io::Error::last_os_error()).context("installing a signal handler");
        }
    }
    Ok(())
}

/// Running counters, reported to the journal on shutdown (design 3.2's "counted and reported like
/// mimi's ring-buffer drops"). Shared between the reader (overflow, dropped, skipped) and the
/// scanner (clean, hits, failures), so they are atomics behind an `Arc`.
#[derive(Default)]
struct Counters {
    overflow: AtomicU64,
    dropped_queue: AtomicU64,
    skipped_too_large: AtomicU64,
    stat_errors: AtomicU64,
    scanned_clean: AtomicU64,
    scanned_hits: AtomicU64,
    hit_lines_emitted: AtomicU64,
    scan_failed: AtomicU64,
    scan_panics: AtomicU64,
}

impl Counters {
    fn summary(&self) -> String {
        format!(
            "q_overflow={} dropped_queue_full={} skipped_too_large={} stat_errors={} \
             clean={} with_hits={} hit_lines={} scan_failed={} scan_panics={}",
            self.overflow.load(Ordering::Relaxed),
            self.dropped_queue.load(Ordering::Relaxed),
            self.skipped_too_large.load(Ordering::Relaxed),
            self.stat_errors.load(Ordering::Relaxed),
            self.scanned_clean.load(Ordering::Relaxed),
            self.scanned_hits.load(Ordering::Relaxed),
            self.hit_lines_emitted.load(Ordering::Relaxed),
            self.scan_failed.load(Ordering::Relaxed),
            self.scan_panics.load(Ordering::Relaxed),
        )
    }
}

/// Run the daemon until SIGTERM/SIGINT. Loads the rules, marks every markable superblock, and runs
/// the reader loop with one scanner thread.
pub fn run(mut cfg: DaemonConfig) -> Result<()> {
    install_signal_handlers()?;

    let engine = Engine::load(&cfg.rules_dir)
        .with_context(|| format!("loading rules from {}", cfg.rules_dir.display()))?;
    let ruleset = engine.ruleset_id().to_string();
    eprintln!(
        "hitomi: loaded {} rule file(s); engine {}; ruleset {}",
        engine.rule_files(),
        crate::ENGINE,
        ruleset
    );

    // Resolve the filesystems to mark (design 3.4): local on-disk superblocks only, one mark each.
    let mountinfo =
        std::fs::read_to_string("/proc/self/mountinfo").context("reading /proc/self/mountinfo")?;
    let mounts = parse_mountinfo(&mountinfo);
    for fstype in unknown_fstypes(&mounts) {
        eprintln!("hitomi: not marking unknown filesystem type {fstype:?} (add it to LOCAL_FSTYPES if on-disk)");
    }
    let marks = markable_superblocks(&mounts);

    // The sink's directory is always excluded and ignore-marked, so the sensor never scans or
    // reports its own output (belt: the reader also drops events whose pid is the sensor's own).
    let sink_dir = cfg
        .sink
        .parent()
        .map(|p| p.to_string_lossy().into_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "/".to_string());
    if !cfg.exclude_prefixes.iter().any(|p| p == &sink_dir) {
        cfg.exclude_prefixes.push(sink_dir.clone());
    }

    let fan = Fanotify::init().context("fanotify_init failed (the unit needs CAP_SYS_ADMIN)")?;
    let event_mask = FAN_OPEN_EXEC | FAN_CLOSE_WRITE;
    let mut marked = 0usize;
    for m in &marks {
        match fan.mark_filesystem(&m.mount_point, event_mask) {
            Ok(()) => {
                marked += 1;
                eprintln!(
                    "hitomi: marked {} ({}, dev {})",
                    m.mount_point, m.fstype, m.dev
                );
            }
            Err(e) => {
                eprintln!(
                    "hitomi: WARNING could not mark {} ({}): {e}",
                    m.mount_point, m.fstype
                );
            }
        }
    }
    if marked == 0 {
        bail!(
            "no filesystems could be marked ({} candidate superblock(s)); refusing to run blind",
            marks.len()
        );
    }
    // Suppress close-write notifications for our own sink directory.
    if let Err(e) = fan.mark_ignore(&sink_dir, FAN_CLOSE_WRITE) {
        eprintln!("hitomi: WARNING could not ignore-mark the sink dir {sink_dir}: {e}");
    }

    // Open (create/append) the sink before the first scan can produce a line.
    if let Some(dir) = cfg.sink.parent() {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("creating the sink directory {}", dir.display()))?;
    }
    let sink_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&cfg.sink)
        .with_context(|| format!("opening the sink {}", cfg.sink.display()))?;
    eprintln!("hitomi: sink {}", cfg.sink.display());

    let cache = Arc::new(Mutex::new(VerdictCache::new(cfg.cache_entries)));
    let counters = Arc::new(Counters::default());
    let max_file_bytes = cfg.max_file_bytes;

    // The scanner thread owns the engine (the only scanner in v1) and the sink (the only writer).
    let (tx, rx) = sync_channel::<ScanJob>(QUEUE_DEPTH);
    let scanner = {
        let cache = Arc::clone(&cache);
        let counters = Arc::clone(&counters);
        let ruleset = ruleset.clone();
        std::thread::Builder::new()
            .name("hitomi-scan".to_string())
            .spawn(move || {
                scanner_loop(
                    engine,
                    ruleset,
                    max_file_bytes,
                    rx,
                    cache,
                    counters,
                    sink_file,
                )
            })
            .context("spawning the scanner thread")?
    };

    // ===== the reader loop (design 4.1) =====
    let self_pid = std::process::id();
    let mut buf = vec![0u8; EVENT_BUF_BYTES];
    let mut debounce: HashMap<(u64, u64), Instant> = HashMap::new();
    eprintln!("hitomi: watching {marked} filesystem(s); ready");

    while !STOP.load(Ordering::SeqCst) {
        match fan.poll(POLL_TIMEOUT_MS) {
            Ok(false) => continue, // timeout or an interrupting signal: re-check STOP
            Ok(true) => {}
            Err(e) => {
                eprintln!("hitomi: WARNING poll failed: {e}");
                continue;
            }
        }
        let events = match fan.read_events(&mut buf) {
            Ok(evs) => evs,
            Err(e) => {
                eprintln!("hitomi: WARNING reading events failed: {e}");
                continue;
            }
        };
        for ev in events {
            if ev.overflow {
                counters.overflow.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            let fd = match ev.fd {
                Some(fd) => fd,
                None => continue,
            };
            // Drop our own activity (belt-and-braces with the sink ignore-mark).
            if ev.pid == self_pid {
                continue;
            }
            let raw = fd.as_raw_fd();
            let path = match readlink_fd(raw) {
                Ok(p) => p,
                Err(_) => {
                    // The fd vanished (a racing unlink) before we could name it: nothing to do.
                    continue;
                }
            };
            if is_under_any(&path, &cfg.exclude_prefixes) {
                continue;
            }
            let trigger = if ev.mask & FAN_OPEN_EXEC != 0 {
                TRIGGER_EXEC
            } else {
                TRIGGER_CLOSE_WRITE
            };
            // Close-write is a cost control, not a security boundary: only bother under a drop zone.
            if trigger == TRIGGER_CLOSE_WRITE && !is_under_any(&path, &cfg.drop_zones) {
                continue;
            }
            let st = match fstat_id(raw) {
                Ok(st) => st,
                Err(_) => {
                    counters.stat_errors.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
            };
            if !st.is_regular {
                continue;
            }
            if st.size > max_file_bytes {
                counters.skipped_too_large.fetch_add(1, Ordering::Relaxed);
                // Cache the skip so the size cap is paid once per inode (design 7.1/7.2).
                cache.lock().expect("cache mutex").insert(
                    CacheKey::new(
                        st.dev,
                        st.ino,
                        st.size,
                        st.ctime_sec,
                        st.ctime_nsec,
                        &ruleset,
                    ),
                    Verdict::Skipped("too large".to_string()),
                );
                continue;
            }
            let key = CacheKey::new(
                st.dev,
                st.ino,
                st.size,
                st.ctime_sec,
                st.ctime_nsec,
                &ruleset,
            );
            // A file already scanned under this rule set is not scanned again, and a hit emits
            // nothing a second time (design 4.2).
            if cache.lock().expect("cache mutex").get(&key).is_some() {
                continue;
            }
            // Close-write debounce: the same inode is not re-queued within the window.
            if trigger == TRIGGER_CLOSE_WRITE {
                let now = Instant::now();
                if let Some(prev) = debounce.get(&(st.dev, st.ino)) {
                    if now.duration_since(*prev) < CLOSE_WRITE_DEBOUNCE {
                        continue;
                    }
                }
                debounce.insert((st.dev, st.ino), now);
                if debounce.len() > DEBOUNCE_TABLE_SOFT_CAP {
                    debounce.retain(|_, t| now.duration_since(*t) < CLOSE_WRITE_DEBOUNCE);
                }
            }
            let job = ScanJob {
                fd,
                path,
                pid: ev.pid,
                trigger,
                key,
            };
            match tx.try_send(job) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => {
                    counters.dropped_queue.fetch_add(1, Ordering::Relaxed);
                    // job (and its fd) is dropped here: the fd closes, no leak under a storm.
                }
                Err(TrySendError::Disconnected(_)) => {
                    // The scanner died; nothing more can be scanned.
                    eprintln!("hitomi: scanner thread gone; stopping reader");
                    STOP.store(true, Ordering::SeqCst);
                    break;
                }
            }
        }
    }

    // Shut down: dropping the sender lets the scanner drain the queue and exit.
    drop(tx);
    if let Err(e) = scanner.join() {
        eprintln!("hitomi: scanner thread panicked on shutdown: {e:?}");
    }
    eprintln!("hitomi: stopped; counters {}", counters.summary());
    Ok(())
}

/// `hitomi --check`: a preflight, no marking and no loop (design 12 step 4 / 8.4 Y1). It confirms
/// the rules compile, that `fanotify_init` succeeds (so `CAP_SYS_ADMIN` and the kernel API are
/// present), and prints the superblocks it *would* mark and any unknown filesystem types. It exits
/// non-zero (an `Err`) on any problem: no loadable rules, no fanotify, or no markable filesystem.
pub fn check(rules_dir: &std::path::Path) -> Result<()> {
    let engine = Engine::load(rules_dir)
        .with_context(|| format!("loading rules from {}", rules_dir.display()))?;
    println!(
        "rules: {} file(s) compiled; engine {}; ruleset {}",
        engine.rule_files(),
        crate::ENGINE,
        engine.ruleset_id()
    );

    // Can we open a notification group at all? (CAP_SYS_ADMIN, kernel support.) Drop it at once --
    // --check marks nothing.
    let fan = Fanotify::init()
        .context("fanotify_init failed (needs CAP_SYS_ADMIN and a kernel with fanotify)")?;
    drop(fan);
    println!("fanotify_init: ok (FAN_CLASS_NOTIF, listener-only)");

    let mountinfo =
        std::fs::read_to_string("/proc/self/mountinfo").context("reading /proc/self/mountinfo")?;
    let mounts = parse_mountinfo(&mountinfo);
    let marks = markable_superblocks(&mounts);
    println!("markable superblocks: {}", marks.len());
    for m in &marks {
        println!(
            "  would mark {} ({}, dev {})",
            m.mount_point, m.fstype, m.dev
        );
    }
    let unknown = unknown_fstypes(&mounts);
    if !unknown.is_empty() {
        println!(
            "unknown filesystem types (not marked): {}",
            unknown.join(", ")
        );
    }
    if marks.is_empty() {
        bail!("no markable local filesystems found: the daemon would have nothing to watch");
    }
    println!("hitomi --check: OK");
    Ok(())
}

/// The scanner thread body: read each fd into a capped buffer, scan under the bounds, emit one line
/// per matching rule to the sink, record the verdict. A read error, a scan error, or a panic all
/// become a cached `Failed` -- the daemon never dies on a hostile file (design 2.2).
fn scanner_loop(
    engine: Engine,
    ruleset: String,
    max_file_bytes: u64,
    rx: std::sync::mpsc::Receiver<ScanJob>,
    cache: Arc<Mutex<VerdictCache>>,
    counters: Arc<Counters>,
    sink_file: File,
) {
    let mut sink = BufWriter::new(sink_file);
    while let Ok(job) = rx.recv() {
        let ScanJob {
            fd,
            path,
            pid,
            trigger,
            key,
        } = job;

        // Read the fd ourselves, capped at max_file_bytes (design 4.1: no mmap -- a writer
        // truncating the file mid-scan would SIGBUS an mmap; a bounded read cannot).
        let mut file = File::from(fd);
        let mut bytes = Vec::new();
        let read_result = (&mut file).take(max_file_bytes).read_to_end(&mut bytes);

        let verdict = match read_result {
            Err(e) => {
                counters.scan_failed.fetch_add(1, Ordering::Relaxed);
                Verdict::Failed(format!("read: {e}"))
            }
            Ok(_) => {
                // never-die: a panic inside yara-x is caught and turned into a cached failure, not a
                // SIGSEGV/abort of the process (design 2.2).
                let scanned = catch_unwind(AssertUnwindSafe(|| {
                    engine.scan_bytes_bounded(
                        &bytes,
                        Some(SCAN_TIMEOUT),
                        Some(MAX_MATCHES_PER_PATTERN),
                    )
                }));
                match scanned {
                    Ok(Ok(outcome)) if outcome.hits.is_empty() => {
                        counters.scanned_clean.fetch_add(1, Ordering::Relaxed);
                        Verdict::Clean
                    }
                    Ok(Ok(outcome)) => {
                        let names: Vec<String> =
                            outcome.hits.iter().map(|h| h.name.clone()).collect();
                        let now = SystemTime::now();
                        let mut events = outcome.to_events(&path, pid, trigger, &ruleset, now);
                        let truncated = events.len() > MAX_HITS_PER_FILE;
                        events.truncate(MAX_HITS_PER_FILE);
                        if truncated {
                            for e in &mut events {
                                e.truncated = true;
                            }
                        }
                        for e in &events {
                            if writeln!(sink, "{}", yara_types::render(e)).is_err() {
                                counters.scan_failed.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        // Flush so banken sees the line promptly; the sink is a durable append file.
                        let _ = sink.flush();
                        counters.scanned_hits.fetch_add(1, Ordering::Relaxed);
                        counters
                            .hit_lines_emitted
                            .fetch_add(events.len() as u64, Ordering::Relaxed);
                        Verdict::Hits(names)
                    }
                    Ok(Err(e)) => {
                        counters.scan_failed.fetch_add(1, Ordering::Relaxed);
                        Verdict::Failed(format!("{e:#}"))
                    }
                    Err(_) => {
                        counters.scan_panics.fetch_add(1, Ordering::Relaxed);
                        Verdict::Failed("scan panicked".to_string())
                    }
                }
            }
        };
        cache.lock().expect("cache mutex").insert(key, verdict);
        // `file` (the fd) is dropped here, closing the kernel-handed descriptor.
    }
}
