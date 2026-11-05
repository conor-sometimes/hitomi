# hitomi's cross-distro accuracy matrix, as a consumer of mayfly
# (github.com/conor-sometimes/mayfly). It installs the shipped fully-static musl
# binary with hitomi's own rules and EICAR accuracy suite, and asserts 100% true
# positives / 0% false positives on each real vendor distro. mayfly does the
# booting, provisioning, and teardown; nothing in the engine names hitomi.
#
# Returns the mkMatrix result (apps, checks, readme) for flake.nix to splice in.
# `nix run .#matrix` runs the lot; `nix run .#distro-ubuntu-2404` runs one.
{ pkgs, lib, mayfly, self }:
let
  system = pkgs.stdenv.hostPlatform.system;
  # hitomi ships its rules and its suite under testdata/. Carry each as a tar the
  # guest extracts (the engine stages single files; setup.sh unpacks).
  rulesTar = pkgs.runCommand "hitomi-rules.tar" { } "tar -C ${self}/testdata -cf $out rules";
  suiteTar = pkgs.runCommand "hitomi-suite.tar" { } "tar -C ${self}/testdata -cf $out suite";
in
mayfly.lib.mkMatrix {
  inherit pkgs;

  distros = {
    ubuntu-2404.enable = true;
    ubuntu-2204.enable = true;
    debian-13.enable = true;
    fedora-44.enable = true;
    rocky-9.enable = true;
    alma-10.enable = true;
    amazonlinux-2023.enable = true;
    opensuse-leap-16.enable = true;
  };

  # A wide matrix on one host: boot one distro at a time. Drop this (or set
  # "auto") on a big host.
  concurrency = 1;

  install = {
    binary = "${self.packages.${system}.hitomi-musl}/bin/hitomi";
    files = {
      "/opt/hitomi/rules.tar" = rulesTar;
      "/opt/hitomi/suite.tar" = suiteTar;
    };
    setup = ./setup.sh; # unpacks the tars into /etc/hitomi/rules and /opt/suite
  };

  # Exit 0 on 100% TP / 0% FP; any miss or false positive fails the distro.
  test = ./run-suite.sh;
}
