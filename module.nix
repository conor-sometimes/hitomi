# NixOS module: hitomi, the YARA content-scanner sensor. A long-running listener (like mimi): it
# subscribes to fanotify for "a file was executed" and "a file under a drop zone was written and
# closed", scans the exact inode the kernel hands it, and appends one `yara/1` line per rule hit to
# a sink file banken tails. It NEVER blocks, kills, or modifies -- it is a listener, never an
# enforcer (design docs/design/yara-sensor.md section 3.2, and the listener-charter build gate).
#
#   imports = [ hitomi.nixosModules.default ];   # flake
#   imports = [ "${hitomi}/module.nix" ];         # or a pinned checkout
#   services.hitomi.enable = true;
#   services.hitomi.rules  = ./my-rules;          # a directory of *.yar / *.yara files
#
# Usually you turn this on through banken's one switch (services.banken.hitomi.enable, a later step)
# rather than directly; that switch wires banken to the sink.
#
# The unit mirrors mimi's hardening, with the three differences fanotify forces, each one named in
# design 8.2: PrivateTmp=false and ProtectHome=read-only (a FAN_MARK_FILESYSTEM mark must name the
# host's real /tmp and /home SUPERBLOCKS, which a private tmpfs or an empty-tmpfs ProtectHome would
# hide), and a single capability, CAP_SYS_ADMIN, which fanotify_init and FAN_MARK_FILESYSTEM need.
{ config, lib, pkgs, ... }:

let
  cfg = config.services.hitomi;

  # Assemble the daemon argv from the options. --drop-zone/--exclude repeat; the daemon adds its own
  # built-in excludes (and the sink dir) on top of whatever --exclude passes.
  dropZoneArgs = lib.concatMap (p: [ "--drop-zone" p ]) cfg.dropZones;
  excludeArgs = lib.concatMap (p: [ "--exclude" p ]) cfg.excludePrefixes;
  # NOTE: interpolate cfg.rules ("${...}"), never `toString` it. toString strips the Nix string
  # context, so the rules store path would not be registered as a dependency and would be ABSENT
  # from a closure that only sees it as a bare argument string (e.g. inside a VM/remote host) --
  # exactly the "rules directory: No such file or directory" crash-loop that bit the first VM run.
  rulesArg = "${cfg.rules}";
  daemonArgs = [
    "daemon"
    "--rules" rulesArg
    "--sink" cfg.sink
    "--max-bytes" (toString cfg.maxFileBytes)
    "--cache-entries" (toString cfg.cacheEntries)
  ] ++ dropZoneArgs ++ excludeArgs;
in
{
  options.services.hitomi = {
    enable = lib.mkEnableOption "the hitomi YARA content-scanner sensor (listener-only)";

    package = lib.mkOption {
      type = lib.types.package;
      description = ''
        The hitomi package (the daemon binary). The flake's nixosModule defaults it to the flake's
        own hermetically-built hitomi; override to pin your own.
      '';
    };

    rules = lib.mkOption {
      type = lib.types.path;
      description = ''
        A directory of YARA rule files (*.yar, *.yara). The daemon compiles them once at start under
        yara-x (Pulley, no JIT). A rule set is a directory of files, never a file that reads other
        files (include is not used). There is no default: a sensor with no rules is a
        misconfiguration, so you must set this.
      '';
    };

    sink = lib.mkOption {
      type = lib.types.str;
      default = "/var/log/hitomi/hitomi.jsonl";
      description = ''
        File hitomi appends its yara/1 match stream to, for banken to tail. A durable append file in
        the unit's LogsDirectory (owned by the DynamicUser, UMask 0077). The daemon ignore-marks its
        own sink directory so it never reports its own writes.
      '';
    };

    maxFileBytes = lib.mkOption {
      type = lib.types.ints.positive;
      default = 64 * 1024 * 1024;
      description = ''
        Per-file size cap (design 7.2). A larger file is skipped and counted, never scanned
        partially -- a "clean" verdict on the first N bytes of a huge file is a false clean.
      '';
    };

    cacheEntries = lib.mkOption {
      type = lib.types.ints.positive;
      default = 65536;
      description = ''
        Verdict-cache capacity (design 7.1): a file already scanned under the current rule set is
        not scanned again, keyed on (dev, ino, size, ctime, rulesetHash). A few MB at this size.
      '';
    };

    dropZones = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ "/tmp" "/var/tmp" "/dev/shm" "/home" "/root" "/opt" ];
      description = ''
        A FAN_CLOSE_WRITE event is only scanned when the written file is under one of these prefixes
        (design 3.3). On the root filesystem a close-write is every log flush and package write, so
        this is a cost control, not a security boundary (the daemon reads the fd the kernel handed
        it, never a path). Mirrors the quarantine allowPaths list.
      '';
    };

    excludePrefixes = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = ''
        Extra path prefixes to drop before scanning, ADDED to the daemon's built-in excludes
        (/proc, /sys, /dev/pts, /dev/mqueue) and its own sink directory. Use it to exclude, say,
        /nix/store or a noisy build tree.
      '';
    };

    cpuQuota = lib.mkOption {
      type = lib.types.str;
      default = "50%";
      description = "CPUQuota for the unit (design 7.4): the single scanner thread cannot take more than one core, and the quota caps it below that.";
    };

    memoryMax = lib.mkOption {
      type = lib.types.str;
      default = "512M";
      description = "MemoryMax for the unit (design 7.4): the belt. One scan buffer is at most maxFileBytes; the cache a few MB; wasmtime reserves 16 MB per module.";
    };

    nice = lib.mkOption {
      type = lib.types.int;
      default = 10;
      description = "Nice for the unit (design 7.4): the content scanner yields to real work.";
    };
  };

  config = lib.mkIf cfg.enable {
    systemd.services.hitomi = {
      description = "hitomi: YARA content-scanner sensor for banken (listener-only)";
      documentation = [ "https://github.com/conor-sometimes/hitomi" ];
      wantedBy = [ "multi-user.target" ];
      # Start after local filesystems are mounted so the mark list at start covers them (a filesystem
      # mounted later is picked up on a SIGHUP / restart, design 3.4).
      after = [ "local-fs.target" ];
      serviceConfig = {
        Type = "exec";
        # Preflight before the real run: rules compile, fanotify_init works (CAP_SYS_ADMIN present),
        # and there is something markable. A failed --check fails the unit with a clear journal line
        # rather than a daemon that marks nothing and sits idle.
        ExecStartPre = "${lib.getExe cfg.package} --check --rules ${rulesArg}";
        ExecStart = "${lib.getExe cfg.package} ${lib.escapeShellArgs daemonArgs}";
        # Matches go to the --sink file (the daemon opens it itself, as mimi does -- StandardOutput=
        # append: fails under DynamicUser). Status, the mark list, and the shutdown counters go to
        # stderr; route both streams to the journal so a failure (a missing capability, an unmarkable
        # fs) shows in `journalctl -u hitomi`.
        StandardOutput = "journal";
        StandardError = "journal";
        LogsDirectory = lib.mkIf (lib.hasPrefix "/var/log/hitomi" cfg.sink) "hitomi";
        ReadWritePaths = lib.optional (!lib.hasPrefix "/var/log/hitomi" cfg.sink) (builtins.dirOf cfg.sink);
        Restart = "on-failure";
        RestartSec = 2;

        # The one capability (design 8.2): fanotify_init and FAN_MARK_FILESYSTEM need CAP_SYS_ADMIN;
        # the fds the kernel hands over need nothing else, and the rules directory is world-readable.
        DynamicUser = true;
        AmbientCapabilities = [ "CAP_SYS_ADMIN" ];
        CapabilityBoundingSet = [ "CAP_SYS_ADMIN" ];

        NoNewPrivileges = true;
        # strict: / and /usr stay read-only bind mounts of the REAL superblocks, so a
        # FAN_MARK_FILESYSTEM mark on them names the real filesystem (design 8.2). The sensor opens
        # no path to write; it reads the fds the kernel opened.
        ProtectSystem = "strict";
        # read-only (NOT true): `true` would replace /home with an empty tmpfs whose superblock is
        # not the host's; `read-only` bind-mounts the real /home, same superblock, markable.
        ProtectHome = "read-only";
        # false (NOT true): PrivateTmp would give the unit its own tmpfs, so a mark would name the
        # private /tmp, not the host's. The sensor writes nothing under /tmp (its sink is the
        # LogsDirectory), so the shared-/tmp risks do not apply to it (design 8.2).
        PrivateTmp = false;
        PrivateDevices = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        ProtectControlGroups = true;
        ProtectClock = true;
        ProtectHostname = true;
        # invisible: the sensor reads only /proc/self/fd/* and /proc/self/mountinfo, never another
        # process's /proc (it does not do the pid->exec join; that is banken's, design 5.3).
        ProtectProc = "invisible";
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
        # The pulley engine evaluates rules on a bytecode interpreter -- no JIT, no writable-then-
        # executable page -- so this holds (design 2.2). The VM test proves rule compile + scan work
        # under it.
        MemoryDenyWriteExecute = true;
        RestrictAddressFamilies = [ "AF_UNIX" ];
        IPAddressDeny = "any";
        SystemCallArchitectures = "native";
        # fanotify_init/fanotify_mark are named explicitly, not assumed to be in @system-service
        # (design 8.2).
        SystemCallFilter = [ "@system-service" "fanotify_init" "fanotify_mark" ];
        SystemCallErrorNumber = "EPERM";
        UMask = "0077";

        # Not melting the box (design 7.4): the scanner, not the kernel, is the cost.
        CPUQuota = cfg.cpuQuota;
        MemoryMax = cfg.memoryMax;
        Nice = cfg.nice;
        IOSchedulingClass = "best-effort";
        IOSchedulingPriority = 7;
        # Under memory pressure the content scanner should go before the exec sensor and banken
        # itself, but the box must not casually reap it (design 8.2).
        OOMScoreAdjust = -500;
      };
    };
  };
}
