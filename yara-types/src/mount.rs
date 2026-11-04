//! Parsing `/proc/self/mountinfo` and classifying filesystems, so the daemon knows which
//! superblocks to mark with fanotify (design `docs/design/yara-sensor.md` section 3.4).
//!
//! This is pure string + table logic with no syscalls, so it is unit-tested on the Mac against a
//! captured `mountinfo` sample. The daemon reads the real file and feeds its contents here; the
//! classification lists below are the single source of truth for "local, on-disk" versus
//! "pseudo or network".

use std::collections::BTreeSet;

/// On-disk, local filesystem types the sensor marks. A scan read of one of these is a local disk
/// read, never a network round trip. Keep this list and [`PSEUDO_FSTYPES`]/[`NETWORK_FSTYPES`] the
/// one place the policy lives; a type in none of the three lists is treated as non-local (not
/// marked) and named in the daemon's start-up report so an unknown type is visible, never silently
/// skipped or silently scanned.
pub const LOCAL_FSTYPES: &[&str] = &[
    "ext2", "ext3", "ext4", "xfs", "btrfs", "f2fs", "reiserfs", "jfs", "nilfs2", "bcachefs",
    "tmpfs", "ramfs", "zfs", "overlay", "vfat", "exfat", "ntfs", "ntfs3",
];

/// Pseudo filesystems: kernel-synthetic, nothing on disk to scan. Never marked. Listed so an
/// expected pseudo type is classified, not reported as unknown.
pub const PSEUDO_FSTYPES: &[&str] = &[
    "proc", "sysfs", "cgroup", "cgroup2", "devtmpfs", "devpts", "mqueue", "hugetlbfs", "bpf",
    "tracefs", "debugfs", "securityfs", "pstore", "configfs", "fusectl", "binfmt_misc",
    "autofs", "rpc_pipefs", "efivarfs", "selinuxfs",
];

/// Network filesystems: a scan read is a network round trip and a hung server would hang the
/// scanner thread, so these are never marked (design 3.4). `fuse.*` is matched by prefix in
/// [`is_network_fstype`], not listed here.
pub const NETWORK_FSTYPES: &[&str] = &[
    "nfs", "nfs4", "cifs", "smb3", "9p", "ceph", "glusterfs", "afs", "ncpfs", "fuseblk",
];

/// True for a network filesystem type, including any `fuse.*` backend (sshfs, s3fs, a userspace
/// driver whose latency and failure modes the scanner must not inherit).
pub fn is_network_fstype(fstype: &str) -> bool {
    fstype == "fuse"
        || fstype.starts_with("fuse.")
        || NETWORK_FSTYPES.contains(&fstype)
}

/// True for a local, on-disk filesystem the sensor marks. A network type is never local even if it
/// somehow appeared in both lists: network wins, because the cost of marking a hung NFS mount is
/// worse than the cost of missing one.
pub fn is_local_fstype(fstype: &str) -> bool {
    !is_network_fstype(fstype) && LOCAL_FSTYPES.contains(&fstype)
}

/// One mount, parsed from a `mountinfo` line: the fields the daemon needs to mark a superblock
/// once. `dev` is the `major:minor` of the mount's superblock (field 3 of `mountinfo`); two mounts
/// of the same filesystem share it, which is how [`markable_superblocks`] dedups to one mark per
/// filesystem (fanotify `FAN_MARK_FILESYSTEM` marks the superblock, not the mount).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mount {
    /// `major:minor` of the superblock (mountinfo field 3), e.g. `"8:1"`.
    pub dev: String,
    /// Where it is mounted (mountinfo field 5), e.g. `"/home"`.
    pub mount_point: String,
    /// Filesystem type (the field after the ` - ` separator), e.g. `"ext4"`.
    pub fstype: String,
}

/// Parse the contents of `/proc/self/mountinfo` into mounts. Unparseable lines are skipped (a
/// forward-compatible `mountinfo` could add fields, but the ones used here are at fixed positions
/// before, and immediately after, the mandatory ` - ` separator). The `mountinfo` format:
///
/// ```text
/// 36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext4 /dev/sda1 rw,errors=continue
/// (1)(2) (3)   (4)   (5)      (6)      (7..)   -  (fstype)(source)  (super opts)
/// ```
///
/// Field 3 is the superblock `major:minor`; field 5 is the mount point; the field right after the
/// `-` separator is the filesystem type. Optional fields (7..) are variable in count, which is why
/// the separator exists and why the type is read relative to it, not by a fixed index.
pub fn parse_mountinfo(contents: &str) -> Vec<Mount> {
    let mut mounts = Vec::new();
    for line in contents.lines() {
        if let Some(mount) = parse_line(line) {
            mounts.push(mount);
        }
    }
    mounts
}

fn parse_line(line: &str) -> Option<Mount> {
    // Split at the mandatory " - " separator: everything before it has the fixed-position fields
    // 1..6 then the variable optional fields; everything after is (fstype, source, superopts).
    let (before, after) = line.split_once(" - ")?;
    let pre: Vec<&str> = before.split_whitespace().collect();
    // Need at least fields 1..5 (indices 0..4): id, parent, dev, root, mountpoint.
    let dev = pre.get(2)?;
    let mount_point = pre.get(4)?;
    let fstype = after.split_whitespace().next()?;
    Some(Mount {
        dev: (*dev).to_string(),
        mount_point: unescape_mountinfo(mount_point),
        fstype: fstype.to_string(),
    })
}

/// `mountinfo` escapes space, tab, newline and backslash in paths as octal `\040 \011 \012 \134`.
/// A mount point with a space would otherwise split wrong downstream; decode it so the path the
/// daemon marks is the real one.
fn unescape_mountinfo(field: &str) -> String {
    if !field.contains('\\') {
        return field.to_string();
    }
    let bytes = field.as_bytes();
    let mut out = String::with_capacity(field.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 3 < bytes.len() {
            let oct = &field[i + 1..i + 4];
            if let Ok(code) = u8::from_str_radix(oct, 8) {
                out.push(code as char);
                i += 4;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

/// The distinct local superblocks to mark, one `Mount` per `dev`, in first-seen order. Network and
/// pseudo filesystems are dropped; a non-local type the lists do not know is also dropped (and the
/// daemon reports it from [`unknown_fstypes`]). Deduping by `dev` is the point: `FAN_MARK_FILESYSTEM`
/// marks the superblock, so marking `/` and a bind mount of `/home` on the same `ext4` twice is
/// redundant.
pub fn markable_superblocks(mounts: &[Mount]) -> Vec<Mount> {
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut out = Vec::new();
    for m in mounts {
        if is_local_fstype(&m.fstype) && seen.insert(m.dev.as_str()) {
            out.push(m.clone());
        }
    }
    out
}

/// Filesystem types present in the mounts that are in none of the three classification lists, so
/// the daemon can report "not marking <type> at <mount>: unknown filesystem type" at start-up. An
/// unknown type is never marked (it falls through [`is_local_fstype`]); surfacing it is how a new
/// on-disk type gets added to [`LOCAL_FSTYPES`] rather than being missed in silence.
pub fn unknown_fstypes(mounts: &[Mount]) -> Vec<String> {
    let mut out = BTreeSet::new();
    for m in mounts {
        if !is_local_fstype(&m.fstype)
            && !is_network_fstype(&m.fstype)
            && !PSEUDO_FSTYPES.contains(&m.fstype.as_str())
        {
            out.insert(m.fstype.clone());
        }
    }
    out.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // A captured slice of a real /proc/self/mountinfo: root ext4, two tmpfs, a bind mount of the
    // same ext4 superblock as /, a pseudo fs, an NFS mount, a fuse mount, and a path with a space.
    const SAMPLE: &str = "\
23 28 0:22 / /proc rw,nosuid,nodev,noexec,relatime shared:14 - proc proc rw
24 28 0:23 / /sys rw,nosuid,nodev,noexec,relatime shared:7 - sysfs sysfs rw
28 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw,errors=remount-ro
30 28 0:26 / /run rw,nosuid,nodev shared:5 - tmpfs tmpfs rw,size=1638400k
48 28 0:26 / /dev/shm rw,nosuid,nodev shared:6 - tmpfs tmpfs rw
52 28 8:1 /home /home rw,relatime shared:1 - ext4 /dev/sda1 rw,errors=remount-ro
61 28 0:52 / /srv/nfs rw,relatime shared:9 - nfs4 server:/export rw
70 28 0:60 / /mnt/sshfs rw,nosuid,nodev,relatime - fuse.sshfs user@host:/ rw
80 28 8:2 / /mnt/my\\040disk rw,relatime - ext4 /dev/sdb1 rw";

    #[test]
    fn parses_dev_mountpoint_and_fstype() {
        let m = parse_mountinfo(SAMPLE);
        let root = m.iter().find(|x| x.mount_point == "/").unwrap();
        assert_eq!(root.dev, "8:1");
        assert_eq!(root.fstype, "ext4");
        let shm = m.iter().find(|x| x.mount_point == "/dev/shm").unwrap();
        assert_eq!(shm.fstype, "tmpfs");
    }

    #[test]
    fn decodes_escaped_mount_point() {
        let m = parse_mountinfo(SAMPLE);
        assert!(
            m.iter().any(|x| x.mount_point == "/mnt/my disk"),
            "octal \\040 should decode to a space"
        );
    }

    #[test]
    fn classifies_fstypes() {
        assert!(is_local_fstype("ext4"));
        assert!(is_local_fstype("tmpfs"));
        assert!(!is_local_fstype("proc"));
        assert!(!is_local_fstype("nfs4"));
        assert!(is_network_fstype("nfs4"));
        assert!(is_network_fstype("fuse.sshfs"));
        assert!(is_network_fstype("fuse"));
        assert!(!is_network_fstype("ext4"));
    }

    #[test]
    fn markable_dedups_by_superblock_and_drops_nonlocal() {
        let marks = markable_superblocks(&parse_mountinfo(SAMPLE));
        let devs: Vec<&str> = marks.iter().map(|m| m.dev.as_str()).collect();
        // 8:1 appears twice (/ and /home) -> one mark. tmpfs 0:26 twice (/run, /dev/shm) -> one.
        // 8:2 once. proc/sysfs/nfs/fuse dropped.
        assert_eq!(devs, vec!["8:1", "0:26", "8:2"]);
    }

    #[test]
    fn unknown_type_is_surfaced_not_marked() {
        let line = "90 28 9:9 / /weird rw - wibblefs /dev/x rw";
        let mounts = parse_mountinfo(line);
        assert!(markable_superblocks(&mounts).is_empty());
        assert_eq!(unknown_fstypes(&mounts), vec!["wibblefs".to_string()]);
    }
}
