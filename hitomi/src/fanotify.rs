//! The fanotify FFI: the three syscalls (`fanotify_init`, `fanotify_mark`, `read`) and the handful
//! of struct/stat/readlink calls the daemon needs to be told "a file was executed" or "a file was
//! written and closed" and handed an open read-only fd of that exact inode (design section 3.2).
//!
//! This is the only `unsafe` in the sensor: the engine deferred all of it here (lib.rs). Every
//! `unsafe` block is as small as the call it wraps and carries a `// SAFETY:` note. The crate adds
//! no `nix`/`fanotify` wrapper crate for this -- fanotify is a stable uapi and ~40 lines of it, so a
//! freeloader tree is not worth the audit surface (design 8.1); it uses `libc` only (already in
//! yara-x's tree) for the raw declarations.
//!
//! # The listener charter, in the one file that could break it
//!
//! The sensor is a listener, never an enforcer: a dead, slow, or full sensor must never delay an
//! exec by a nanosecond, because the kernel is never waiting for it to answer (design 3.2). That is
//! enforced here by what this module *refuses to name*. It uses `FAN_CLASS_NOTIF` (value 0), the
//! notification class that cannot veto an open. It deliberately does NOT define the permission
//! classes nor any permission mask -- the "`_PERM`"-suffixed open/access masks and the content
//! classes exist precisely to let a listener block an open, which is what a blocking antivirus
//! does. Their absence is the written counterpart of mimi's ban on `bpf_send_signal`, and the build
//! gate greps the source for those tokens (outside this explaining comment) and fails the build if
//! they appear. This comment is allowed to spell them out; no line of code may use them.

use std::ffi::CString;
use std::io;
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use libc::{c_char, c_int, c_uint, c_void};

// ===== fanotify_init flags =====

/// The notification class: the kernel notifies, it never waits for a verdict. This is the whole
/// listener charter in one constant (see the module docs). Its value is 0: it is the default and
/// the only class this sensor will ever use.
pub const FAN_CLASS_NOTIF: c_uint = 0x0000_0000;
/// Close the fanotify group fd on exec.
pub const FAN_CLOEXEC: c_uint = 0x0000_0001;
/// Make the group fd non-blocking, so `read` returns `EAGAIN` on an empty queue and the daemon
/// drives it with `poll` (so a shutdown signal is honoured between events, design 3.2).
pub const FAN_NONBLOCK: c_uint = 0x0000_0002;

// ===== event masks =====

/// A file was executed (`execve`/`execveat`/`uselib`, or a `#!` script opened by the kernel for its
/// interpreter). Linux 5.0+.
pub const FAN_OPEN_EXEC: u64 = 0x0000_1000;
/// A file open for writing was closed: a dropper that finished landing, an upload, a written
/// script. Filtered to the drop zones in userspace (design 3.3).
pub const FAN_CLOSE_WRITE: u64 = 0x0000_0008;
/// Set on a synthetic record when the bounded kernel queue overflowed and events were lost; the
/// daemon counts it and journals it, like mimi's ring-buffer drops (design 3.2).
pub const FAN_Q_OVERFLOW: u64 = 0x0000_4000;

// ===== fanotify_mark flags =====

/// Add the given mask to a mark (as opposed to removing or flushing).
pub const FAN_MARK_ADD: c_uint = 0x0000_0001;
/// Mark the whole superblock, so events arrive for accesses through any mount of that filesystem
/// from any mount namespace (Linux 4.20+). This is what lets a read-only bind mount of `/home`
/// inside the unit's sandbox mark the host's real `/home` (design 3.2, 8.2); a per-mount mark would
/// see only the unit's private vfsmount.
pub const FAN_MARK_FILESYSTEM: c_uint = 0x0000_0100;
/// The mark carries an *ignore* mask: events in this mask are suppressed. Used on the sensor's own
/// sink directory so it never reports its own writes (design 3.2).
pub const FAN_MARK_IGNORED_MASK: c_uint = 0x0000_0020;
/// Keep the ignore mark across modifications of the marked object (so the sink-dir ignore survives
/// the sink file being rewritten).
pub const FAN_MARK_IGNORED_SURV_MODIFY: c_uint = 0x0000_0040;

/// The fanotify metadata version this code understands (`FANOTIFY_METADATA_VERSION`); a record with
/// any other version is skipped rather than misread (its fd, if any, is closed).
const FANOTIFY_METADATA_VERSION: u8 = 3;
/// The sentinel `fd` value on a metadata record that carries no file descriptor (e.g. an overflow
/// record): `FAN_NOFD`.
const FAN_NOFD: c_int = -1;

/// An open fanotify notification group. Owns the group fd (closed on drop); marking and reading go
/// through it.
pub struct Fanotify {
    fd: OwnedFd,
}

impl Fanotify {
    /// `fanotify_init(FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_NONBLOCK, O_RDONLY | O_CLOEXEC |
    /// O_NOATIME)` (design 3.2). The event fds the kernel hands over are opened read-only and
    /// `O_NOATIME` so scanning never touches access times. Needs `CAP_SYS_ADMIN`.
    pub fn init() -> io::Result<Fanotify> {
        let event_f_flags = (libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOATIME) as c_uint;
        // SAFETY: fanotify_init takes two scalar flag words and no memory arguments; we pass only
        // constants and check the return for the documented -1 error.
        let fd = unsafe {
            libc::fanotify_init(FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_NONBLOCK, event_f_flags)
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fd is a fresh, valid, owned descriptor just returned by fanotify_init; wrapping it
        // in OwnedFd transfers ownership so it is closed exactly once, on drop.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        Ok(Fanotify { fd })
    }

    /// Mark a superblock (via one of its mount points) for the given event mask, for the whole
    /// filesystem (`FAN_MARK_ADD | FAN_MARK_FILESYSTEM`).
    pub fn mark_filesystem(&self, mount_point: &str, mask: u64) -> io::Result<()> {
        self.mark(FAN_MARK_ADD | FAN_MARK_FILESYSTEM, mask, mount_point)
    }

    /// Add an ignore mark on a path (the sink directory), surviving modification, so events in the
    /// mask there are suppressed (design 3.2).
    pub fn mark_ignore(&self, path: &str, mask: u64) -> io::Result<()> {
        self.mark(
            FAN_MARK_ADD | FAN_MARK_IGNORED_MASK | FAN_MARK_IGNORED_SURV_MODIFY,
            mask,
            path,
        )
    }

    fn mark(&self, flags: c_uint, mask: u64, path: &str) -> io::Result<()> {
        let c_path = CString::new(path).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "mark path contains a NUL byte")
        })?;
        // SAFETY: self.fd is a live fanotify group fd; c_path is a valid NUL-terminated string that
        // outlives the call; AT_FDCWD plus an absolute path is the documented dir-relative form. The
        // return is checked for -1.
        let rc = unsafe {
            libc::fanotify_mark(
                self.fd.as_raw_fd(),
                flags,
                mask,
                libc::AT_FDCWD,
                c_path.as_ptr(),
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Wait up to `timeout_ms` for an event to be readable. Returns `Ok(true)` when the group fd is
    /// readable, `Ok(false)` on a timeout or an interrupting signal (so the caller re-checks its
    /// shutdown flag between events, design 3.2).
    pub fn poll(&self, timeout_ms: c_int) -> io::Result<bool> {
        let mut pfd = libc::pollfd {
            fd: self.fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: &mut pfd points at a single valid pollfd; the count (1) matches; timeout is in ms.
        let rc = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
        if rc < 0 {
            let err = io::Error::last_os_error();
            // An interrupting signal is how SIGTERM reaches the poll loop; it is not a failure.
            if err.raw_os_error() == Some(libc::EINTR) {
                return Ok(false);
            }
            return Err(err);
        }
        Ok(rc > 0 && (pfd.revents & libc::POLLIN) != 0)
    }

    /// Read a batch of events into the caller's reusable buffer and parse them. Returns an empty
    /// vector on `EAGAIN` (nothing queued) or `EINTR` (a signal); any other read error is returned.
    /// Each returned [`Event`] owns its kernel fd (closed when the `Event` is dropped), except an
    /// overflow record, which carries none.
    pub fn read_events(&self, buf: &mut [u8]) -> io::Result<Vec<Event>> {
        // SAFETY: buf is a valid writable slice of buf.len() bytes; read writes at most that many
        // and returns the count or -1. The fd is the live group fd.
        let n = unsafe {
            libc::read(
                self.fd.as_raw_fd(),
                buf.as_mut_ptr() as *mut c_void,
                buf.len(),
            )
        };
        if n < 0 {
            let err = io::Error::last_os_error();
            if matches!(err.raw_os_error(), Some(libc::EAGAIN) | Some(libc::EINTR)) {
                return Ok(Vec::new());
            }
            return Err(err);
        }
        let n = n as usize;
        let meta_size = mem::size_of::<libc::fanotify_event_metadata>();
        let mut events = Vec::new();
        let mut off = 0usize;
        while off + meta_size <= n {
            // SAFETY: the window off..off+meta_size lies within the n bytes read; read_unaligned
            // copies out the plain-old-data metadata struct without assuming the buffer's alignment.
            let meta: libc::fanotify_event_metadata = unsafe {
                std::ptr::read_unaligned(buf[off..].as_ptr() as *const libc::fanotify_event_metadata)
            };
            let len = meta.event_len as usize;
            // A record shorter than the header or running past the read is malformed: stop parsing
            // this batch rather than walk off the end.
            if len < meta_size || off + len > n {
                break;
            }
            if meta.vers != FANOTIFY_METADATA_VERSION {
                // A version we do not understand: do not interpret it, but do not leak its fd.
                if meta.fd >= 0 {
                    // SAFETY: meta.fd is a valid descriptor the kernel opened for us; closing it
                    // once is correct since we take no OwnedFd for it.
                    unsafe { libc::close(meta.fd) };
                }
                off += len;
                continue;
            }
            if meta.mask & FAN_Q_OVERFLOW != 0 {
                events.push(Event {
                    mask: meta.mask,
                    pid: meta.pid as u32,
                    fd: None,
                    overflow: true,
                });
            } else if meta.fd == FAN_NOFD {
                // No fd and not an overflow: nothing to scan, nothing to close.
            } else {
                // SAFETY: meta.fd is a valid, owned descriptor the kernel opened for this listener;
                // taking an OwnedFd transfers ownership so it is closed exactly once (when the Event
                // or the ScanJob built from it is dropped).
                let owned = unsafe { OwnedFd::from_raw_fd(meta.fd) };
                events.push(Event {
                    mask: meta.mask,
                    pid: meta.pid as u32,
                    fd: Some(owned),
                    overflow: false,
                });
            }
            off += len;
        }
        Ok(events)
    }
}

/// One parsed fanotify event: the mask (which trigger), the TGID that touched the file, and the
/// kernel-opened read-only fd of the exact inode (absent on an overflow record).
pub struct Event {
    pub mask: u64,
    pub pid: u32,
    pub fd: Option<OwnedFd>,
    pub overflow: bool,
}

/// The inode facts the daemon needs from one `fstat` of an event fd: the cache-key identity, the
/// size (for the cap), and whether it is a regular file (design 4.1).
pub struct FileId {
    pub dev: u64,
    pub ino: u64,
    pub size: u64,
    pub ctime_sec: i64,
    pub ctime_nsec: i64,
    pub is_regular: bool,
}

/// `fstat` an event fd into the [`FileId`] the pipeline uses for the regular-file check, the size
/// cap and the verdict-cache key (design 4.1, 7.1).
pub fn fstat_id(fd: RawFd) -> io::Result<FileId> {
    // SAFETY: a zeroed stat is a valid (empty) buffer for fstat to fill; fstat writes it and returns
    // 0 or -1, which we check before reading any field.
    let mut st: libc::stat = unsafe { mem::zeroed() };
    let rc = unsafe { libc::fstat(fd, &mut st) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(FileId {
        dev: st.st_dev as u64,
        ino: st.st_ino as u64,
        size: st.st_size.max(0) as u64,
        ctime_sec: st.st_ctime as i64,
        ctime_nsec: st.st_ctime_nsec as i64,
        is_regular: (st.st_mode & libc::S_IFMT) == libc::S_IFREG,
    })
}

/// Resolve an event fd to a path via `readlink(/proc/self/fd/N)` (design 3.2). The result may end in
/// `" (deleted)"`, which is itself a finding and is kept verbatim. A non-UTF-8 path is rendered
/// lossily rather than dropped (a path is still a path for the report).
pub fn readlink_fd(fd: RawFd) -> io::Result<String> {
    let link = CString::new(format!("/proc/self/fd/{fd}"))
        .expect("a /proc/self/fd path never contains a NUL byte");
    let mut buf = vec![0u8; 4096];
    // SAFETY: link is a valid NUL-terminated C string; buf is writable for buf.len() bytes; readlink
    // writes at most that many and returns the count or -1 (it does not NUL-terminate).
    let n = unsafe { libc::readlink(link.as_ptr(), buf.as_mut_ptr() as *mut c_char, buf.len()) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    buf.truncate(n as usize);
    Ok(String::from_utf8_lossy(&buf).into_owned())
}
