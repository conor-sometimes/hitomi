# Runtime test of the hitomi NixOS unit: a VM with services.hitomi.enable = true and an EICAR rule
# in the rules dir. It is the listener proof under the real hardened unit (design 8.4 Y3-Y5, build
# sequence step 4):
#
#   (a) exec   -- a canary binary that contains the EICAR marker is executed; a yara/1 line with
#                 trigger "exec" and the matching rule lands in the sink.
#   (b) write  -- an EICAR file written into a drop zone (/tmp) and never executed is scanned; a
#                 yara/1 line with trigger "close-write" lands.
#   (c) clean  -- a clean exec produces nothing.
#   (d) W^X    -- the unit is up under MemoryDenyWriteExecute=yes: yara-x compiled the rules and
#                 scanned under Pulley (no JIT) without a writable-then-executable page faulting.
#   (Y5)       -- the canary ran (exit 0) and is byte-for-byte unchanged: the sensor never blocked
#                 or modified it. A listener, not an enforcer.
#
# The real EICAR string is assembled only HERE, at test time, from a base64 blob (so this source
# file never contains the literal AV test string, which would trip any other AV on the box and is
# never committed). The committed rule (testdata/rules/eicar.yar) matches a SUBSTRING of EICAR, not
# the full string, so the rule file is not itself a hit.
#
#   nix build .#checks.x86_64-linux.vm-hitomi -L    (needs KVM; runs on hokkaido)
# hitomiPackage overrides the service package; the musl check passes the fully-static build to prove
# the STATIC binary marks and scans too. null keeps the module default (gnu).
{ pkgs, hitomiModule, hitomiPackage ? null, name ? "hitomi-unit" }:
pkgs.testers.runNixOSTest {
  inherit name;

  nodes.machine = { lib, ... }: {
    imports = [ hitomiModule ];
    services.hitomi.enable = true;
    # The committed EICAR rule set (matches the EICAR substring, not the full string).
    services.hitomi.rules = ../testdata/rules;
    services.hitomi.package = lib.mkIf (hitomiPackage != null) hitomiPackage;
    # yara-x compiles rules through wasmtime (Pulley); give the guest headroom.
    virtualisation.memorySize = 2048;
  };

  testScript = ''
    import json

    # The EICAR standard antivirus test string, base64-encoded so this test's SOURCE never holds the
    # literal string. Decoded only inside the guest. It contains the substring the committed rule
    # matches.
    EICAR_B64 = "WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo="

    SINK = "/var/log/hitomi/hitomi.jsonl"

    def sink_lines():
        out = machine.succeed(f"cat {SINK} 2>/dev/null || true")
        return [json.loads(l) for l in out.splitlines() if l.strip()]

    machine.wait_for_unit("multi-user.target")

    # The hardened unit starts...
    machine.wait_for_unit("hitomi.service")

    # ...and STAYS up -- not crash-looping. A W^X fault at rule-compile under Pulley, a missing
    # CAP_SYS_ADMIN, or an unmarkable filesystem would restart it on-failure. On trouble, dump the
    # journal so the real cause is in the test log.
    machine.sleep(3)
    status = machine.execute("systemctl is-active hitomi.service")[1].strip()
    if status != "active":
        print(machine.execute("journalctl -u hitomi.service --no-pager | tail -60")[1])
        print(machine.execute("systemctl show hitomi.service -p NRestarts -p ExecMainStatus")[1])
    assert status == "active", f"hitomi.service not active: {status!r}"
    restarts = int(machine.succeed("systemctl show -p NRestarts --value hitomi.service").strip() or "0")
    assert restarts == 0, f"hitomi.service restarted {restarts} times (crash-loop)"

    # (d) The unit really is under MemoryDenyWriteExecute, and the sensor compiled + is scanning
    # under it (proven by the hits below): the Pulley no-JIT proof.
    mdwe = machine.succeed("systemctl show -p MemoryDenyWriteExecute --value hitomi.service").strip()
    assert mdwe == "yes", f"MemoryDenyWriteExecute is {mdwe!r}, expected yes"

    # The daemon marked its filesystems and is ready; its mark list is on the journal.
    machine.wait_until_succeeds("journalctl -u hitomi.service --no-pager | grep -q 'watching'")
    print(machine.execute("journalctl -u hitomi.service --no-pager | grep -E 'marked|watching|ruleset'")[1])

    # The sink exists once the daemon has opened it.
    machine.wait_for_file(SINK)

    # Record systemd-analyze security for the PR / doc (not asserted: the hardening set is fixed in
    # module.nix; this is the number design 8.2 asks to record).
    print("=== systemd-analyze security hitomi.service ===")
    print(machine.execute("systemd-analyze security hitomi.service --no-pager")[1])

    with subtest("(b) a drop-zone write of an EICAR file is scanned as close-write"):
        # Writing /tmp/eicar.bin closes a write fd under /tmp (a drop zone) -> FAN_CLOSE_WRITE.
        machine.succeed(f"echo {EICAR_B64} | base64 -d > /tmp/eicar.bin")
        machine.succeed("test -s /tmp/eicar.bin")
        machine.wait_until_succeeds(
            "grep -q '\"trigger\":\"close-write\"' " + SINK, timeout=30
        )
        cw = [e for e in sink_lines()
              if e.get("trigger") == "close-write" and e.get("file", {}).get("path") == "/tmp/eicar.bin"]
        assert cw, f"no close-write yara/1 line for /tmp/eicar.bin; sink={sink_lines()}"
        ev = cw[0]
        assert ev["schema"] == "yara/1" and ev["kind"] == "match", ev
        assert ev["rule"]["name"] == "eicar", ev
        assert ev["file"]["hashes"][0]["algorithm"] == "SHA-256", ev
        # the reported hash is of the bytes scanned
        want = machine.succeed("sha256sum /tmp/eicar.bin | cut -d' ' -f1").strip()
        assert ev["file"]["hashes"][0]["value"] == want, (ev["file"]["hashes"][0]["value"], want)

    with subtest("(a) an exec of an EICAR canary is scanned as exec, and is NOT blocked (Y5)"):
        # Build the canary on /srv -- a real local filesystem that is NOT a drop zone, so the writes
        # that build it are not scanned (close-write is drop-zone-only), leaving the EXEC the first
        # scan of the final bytes (a close-write scan would cache the inode and the exec would be a
        # cache hit that emits nothing, design 4.2). Appending EICAR to a copy of bash leaves it a
        # runnable ELF (trailing bytes are ignored by the loader) that now contains the marker.
        machine.succeed("mkdir -p /srv")
        machine.succeed("cp \"$(command -v bash)\" /srv/ycanary")
        machine.succeed(f"echo {EICAR_B64} | base64 -d >> /srv/ycanary")
        before = machine.succeed("sha256sum /srv/ycanary | cut -d' ' -f1").strip()
        # Run it: a listener must not delay or block the exec.
        machine.succeed("/srv/ycanary -c 'exit 0'")
        machine.wait_until_succeeds(
            "grep -q '\"trigger\":\"exec\"' " + SINK, timeout=30
        )
        ex = [e for e in sink_lines()
              if e.get("trigger") == "exec" and e.get("file", {}).get("path") == "/srv/ycanary"]
        assert ex, f"no exec yara/1 line for /srv/ycanary; sink={sink_lines()}"
        ev = ex[0]
        assert ev["rule"]["name"] == "eicar", ev
        assert ev["process"]["pid"] > 0, ev  # exec carries the toucher's pid (design 5.3)
        # Y5: the canary was not modified by the sensor (listener, not enforcer).
        after = machine.succeed("sha256sum /srv/ycanary | cut -d' ' -f1").strip()
        assert before == after, f"canary changed under the sensor ({before} -> {after}): not a listener!"
        # And it still runs with exit 0 (unaffected).
        machine.succeed("/srv/ycanary -c 'exit 0'")

    with subtest("(c) a clean exec produces no yara/1 line"):
        machine.succeed("cp \"$(command -v bash)\" /srv/yclean")
        machine.succeed("/srv/yclean -c 'exit 0'")
        machine.sleep(3)  # give the scanner time to (not) emit
        clean = [e for e in sink_lines() if e.get("file", {}).get("path") == "/srv/yclean"]
        assert not clean, f"a clean binary produced a yara/1 line: {clean}"

    print("HITOMI UNIT PASS: unit up under MemoryDenyWriteExecute; exec + close-write EICAR hits in the sink; clean exec silent; canary unblocked and unchanged")
  '';
}
