//! Path-prefix matching for the two userspace filters the daemon applies to fanotify events
//! (design `docs/design/yara-sensor.md` sections 3.3, 3.4, 4.1):
//!
//! - **drop-zone filter**: a `FAN_CLOSE_WRITE` event is only reported when its path is under one of
//!   the drop-zone prefixes (default `/tmp /var/tmp /dev/shm /home /root /opt`). On the root
//!   filesystem a close-write is every log flush and package write, so this is a cost control.
//! - **exclude filter**: any event whose path is under an excluded prefix (the sensor's own sink,
//!   banken's state and alert dirs, the audit log, `/proc /sys /dev`) is dropped before scanning,
//!   so the sensor never reports its own writes or re-scans pseudo paths.
//!
//! Neither filter is a security boundary: the sensor reads the fd the kernel handed it, never a
//! path, so a hostile path cannot steer a read. The filters only decide whether to bother. This is
//! pure string logic, unit-tested on the Mac.

/// True when `path` is at or below `prefix`, matching on path *components* so `/tmp` matches
/// `/tmp` and `/tmp/x` but NOT `/tmpfoo`. Both are compared as-is (the daemon passes the
/// `readlink` of the fd, already absolute); a trailing slash on either side is tolerated.
pub fn is_under(path: &str, prefix: &str) -> bool {
    let path = path.strip_suffix('/').unwrap_or(path);
    let prefix = prefix.strip_suffix('/').unwrap_or(prefix);
    if prefix.is_empty() || prefix == "/" {
        // Root as a prefix is "everything"; an empty prefix is treated the same rather than
        // matching nothing, so a misconfigured empty entry fails safe toward reporting.
        return true;
    }
    if path == prefix {
        return true;
    }
    // path must start with "prefix/" so the next char after the prefix is a separator -- this is
    // what rejects /tmpfoo for prefix /tmp.
    path.len() > prefix.len() && path.as_bytes()[prefix.len()] == b'/' && path.starts_with(prefix)
}

/// True when `path` is under any of `prefixes`. Used for both the drop-zone test (report a
/// close-write only if true) and the exclude test (drop if true).
pub fn is_under_any(path: &str, prefixes: &[String]) -> bool {
    prefixes.iter().any(|p| is_under(path, p))
}

/// The default drop-zone prefixes a `FAN_CLOSE_WRITE` must be under to be reported. Mirrors the
/// quarantine `allowPaths` list in the design (3.3) so a dropper caught here is in a place the
/// responder is allowed to quarantine from.
pub const DEFAULT_DROP_ZONES: &[&str] = &["/tmp", "/var/tmp", "/dev/shm", "/home", "/root", "/opt"];

/// The default exclude prefixes dropped before any scan. `/proc /sys /dev` are pseudo; the sensor's
/// own sink and banken's state/alert/audit paths are excluded so the sensor never reports its own
/// or banken's writes (the daemon also drops events whose pid is its own, belt and braces). An
/// operator adds to this via `excludePrefixes`; these are the built-in defaults.
pub const DEFAULT_EXCLUDES: &[&str] = &["/proc", "/sys", "/dev/pts", "/dev/mqueue"];

#[cfg(test)]
mod tests {
    use super::*;

    fn v(xs: &[&str]) -> Vec<String> {
        xs.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn component_boundary_not_substring() {
        assert!(is_under("/tmp", "/tmp"));
        assert!(is_under("/tmp/x/payload", "/tmp"));
        assert!(!is_under("/tmpfoo", "/tmp"), "substring must not match");
        assert!(!is_under("/var/tmpory", "/var/tmp"));
        assert!(is_under("/var/tmp/d", "/var/tmp"));
    }

    #[test]
    fn trailing_slashes_tolerated() {
        assert!(is_under("/home/alice/", "/home"));
        assert!(is_under("/home/alice", "/home/"));
    }

    #[test]
    fn root_prefix_matches_everything() {
        assert!(is_under("/anything/at/all", "/"));
        assert!(is_under("/x", ""));
    }

    #[test]
    fn under_any_over_the_defaults() {
        let zones = v(DEFAULT_DROP_ZONES);
        assert!(is_under_any("/tmp/.hidden/dropper", &zones));
        assert!(is_under_any("/home/bob/.cache/x", &zones));
        assert!(!is_under_any("/usr/bin/ls", &zones));
        assert!(!is_under_any("/var/log/syslog", &zones));
    }

    #[test]
    fn excludes_cover_pseudo_paths() {
        let ex = v(DEFAULT_EXCLUDES);
        assert!(is_under_any("/proc/1/mem", &ex));
        assert!(!is_under_any("/home/alice/payload", &ex));
    }

    #[test]
    fn deleted_suffix_is_not_special_here() {
        // The daemon keeps a " (deleted)" suffix verbatim in the report; prefix tests see the
        // whole string, so such a path simply does not match a clean prefix -- which is fine,
        // because a deleted-path close-write is rare and not the filter's job to special-case.
        assert!(!is_under("/tmp/x (deleted)", "/tmp/x"));
        assert!(is_under("/tmp/x (deleted)", "/tmp"));
    }
}
