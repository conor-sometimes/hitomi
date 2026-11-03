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

          craneLib = (crane.mkLib pkgs).overrideToolchain (_: toolchain);

          # The wire-types crate, built and unit-tested hermetically. The only step-1 artifact.
          yaraTypesPackage = craneLib.buildPackage {
            pname = "yara-types";
            version = "0.1.0";
            src = craneLib.cleanCargoSource ./.;
            strictDeps = true;
            cargoExtraArgs = "--package yara-types";
            doCheck = true;
          };
        in
        {
          inherit pkgs toolchain yaraTypesPackage;
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
            packages = [ s.toolchain ];
          };
        }
      );
    };
}
