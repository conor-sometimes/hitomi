{
  # The yara sensor's build. Unlike mimi there is no three-way LLVM coherence to freeze: the sensor
  # is an ordinary stable-Rust crate (no eBPF, no `-Z build-std`, no bpf-linker), so this flake is
  # mostly mimi's with the nightly/bpf machinery removed.
  #
  #   * fenix provides a reproducible STABLE toolchain (from its own lock), with rust-src/clippy/
  #     rustfmt, so `nix develop` and the hermetic build agree on the compiler.
  #   * crane builds the workspace hermetically, so a later `services.<sensor>.package` has a
  #     default and the one-switch deploys with nothing built by hand (the mimi shape).
  #
  # `nix develop` gives the toolchain a shell (where `just`, `cargo test`, `just contract` run);
  # `nix build .#yara-types` builds and tests the wire-types crate. There is no nix on the Mac --
  # this is built and tested on hokkaido, like mimi.
  description = "the yara sensor (name TBD): a listener-only YARA content scanner, sibling of mimi";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    crane.url = "github:ipetkov/crane";
  };

  outputs =
    { self, nixpkgs, fenix, crane }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f system);

      perSystem =
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};

          # The stable toolchain, resolved reproducibly by fenix (no date/sha needed: `stable` is a
          # fixed attr from fenix's own lock). rust-src is harmless here and ready for the engine
          # crate's needs later.
          toolchain = fenix.packages.${system}.stable.withComponents [
            "cargo"
            "rustc"
            "rust-src"
            "rustfmt"
            "clippy"
          ];

          # The same stable toolchain plus the musl target's std, combined into one sysroot, so
          # `cargo build --target x86_64-unknown-linux-musl` can produce the fully-static binary
          # that ships to non-NixOS distros as copy-and-run (design 8.1). yara-x + wasmtime (pulley,
          # pure-Rust interpreter) are ordinary Rust, so the musl target needs no extra C toolchain:
          # Rust links a self-contained musl. This is a separate shell, not the default, so the gate
          # stays a plain host build.
          muslToolchain = fenix.packages.${system}.combine [
            toolchain
            fenix.packages.${system}.targets."x86_64-unknown-linux-musl".stable.rust-std
          ];

          craneLib = (crane.mkLib pkgs).overrideToolchain (_: toolchain);

          # The wire-types crate, built and unit-tested hermetically. The only step-1 artifact.
          # Its test asserts against the shared golden via `include_str!("../../testdata/...")`, so
          # the golden compiles into the test binary: the sandboxed source must keep testdata/
          # alongside the Cargo sources cleanCargoSource would keep. A plain cleanCargoSource drops
          # testdata/ and the hermetic checkPhase then fails to read the golden (CI, not the local
          # `nix develop` gate where the whole tree is present).
          yaraTypesSrc = pkgs.lib.cleanSourceWith {
            name = "source";
            src = ./.;
            filter = path: type:
              (pkgs.lib.hasInfix "/testdata/" path) || (craneLib.filterCargoSources path type);
          };
          yaraTypesPackage = craneLib.buildPackage {
            pname = "yara-types";
            version = "0.1.0";
            src = yaraTypesSrc;
            strictDeps = true;
            cargoExtraArgs = "--package yara-types";
            doCheck = true;
          };
        in
        {
          inherit pkgs toolchain muslToolchain yaraTypesPackage;
        };
    in
    {
      packages = forAllSystems (
        system:
        let
          s = perSystem system;
        in
        {
          yara-types = s.yaraTypesPackage;
          default = s.yaraTypesPackage;
        }
      );

      devShells = forAllSystems (
        system:
        let
          s = perSystem system;
        in
        {
          default = s.pkgs.mkShell {
            # The toolchain plus the gate's tools, so `nix develop -c just` runs the whole gate
            # (fmt-check, clippy, test, deny). cargo-fuzz is deliberately not here: the fuzz
            # campaign needs a nightly rustc (sanitizer + coverage instrumentation), so it runs in
            # its own nightly shell, not this stable one (see the justfile `fuzz` recipe).
            packages = [
              s.toolchain
              s.pkgs.just
              s.pkgs.cargo-deny
            ];
          };

          # The fully-static musl build shell: `nix develop .#musl -c cargo build --release
          # --target x86_64-unknown-linux-musl -p hitomi` produces the copy-and-run binary for any
          # Linux distro (design 8.1). No musl C toolchain is needed -- the tree is pure Rust and
          # Rust links a self-contained musl.
          musl = s.pkgs.mkShell {
            packages = [ s.muslToolchain ];
          };
        }
      );
    };
}
