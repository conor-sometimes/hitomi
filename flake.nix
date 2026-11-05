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

    # mayfly: the cross-distro test harness, consumed for the distro accuracy
    # matrix (tests/distros/matrix.nix). Its nixpkgs follows ours.
    mayfly.url = "github:conor-sometimes/mayfly";
    mayfly.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    { self, nixpkgs, fenix, crane, mayfly }:
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
          # The same crane with the musl sysroot, for the fully-static ship binary below.
          craneLibMusl = (crane.mkLib pkgs).overrideToolchain (_: muslToolchain);

          # The whole workspace's cargo source (both crates). doCheck is off for the binary builds
          # (the gate's `cargo test` and the hermetic yara-types check cover tests); yara-x's
          # include_str of testdata is #[cfg(test)]-only, so a non-test build needs no testdata/.
          workspaceSrc = craneLib.cleanCargoSource ./.;

          # The hitomi daemon+CLI binary. yara-x (Pulley) + wasmtime are ordinary Rust, so this is a
          # plain crane build -- no bpf-linker, no build-std, none of mimi's toolchain machinery.
          # Dependencies are compiled once and reused between the gnu and musl builds.
          hitomiArgs = {
            pname = "hitomi";
            version = "0.1.0";
            src = workspaceSrc;
            strictDeps = true;
            cargoExtraArgs = "--package hitomi";
            doCheck = false;
            meta.mainProgram = "hitomi";
            # yara-x's build.rs regenerates its protobuf module code and, when it does, copies the
            # result INTO its own source tree (src/modules/protos/generated). In a Nix sandbox the
            # vendored crate source is read-only, so that copy panics with EACCES. yara-x ships the
            # generated files and provides exactly one escape hatch for a read-only source tree --
            # the DOCS_RS env var (named for docs.rs, whose FS is also read-only): with it set,
            # build.rs skips regeneration and uses the committed generated code, which is correct for
            # a pinned version. This is the single reason it is set.
            DOCS_RS = "1";
          };
          hitomiDeps = craneLib.buildDepsOnly hitomiArgs;
          hitomiPackage = craneLib.buildPackage (hitomiArgs // { cargoArtifacts = hitomiDeps; });

          # The fully-static musl ship binary (design 8.1): the sensor's own code has no
          # proc-macro-forces-dynamic problem, and yara-x + wasmtime's Pulley interpreter are pure
          # Rust, so Rust links a self-contained musl -- no musl C toolchain. A VM check boots this
          # STATIC binary to prove it marks + scans just like the gnu one.
          hitomiMuslArgs = hitomiArgs // {
            pname = "hitomi-musl";
            CARGO_BUILD_TARGET = "x86_64-unknown-linux-musl";
          };
          hitomiMuslDeps = craneLibMusl.buildDepsOnly hitomiMuslArgs;
          hitomiMuslPackage =
            craneLibMusl.buildPackage (hitomiMuslArgs // { cargoArtifacts = hitomiMuslDeps; });

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
          inherit pkgs toolchain muslToolchain yaraTypesPackage hitomiPackage hitomiMuslPackage;
        };
    in
    {
      # services.hitomi: the sensor as a hardened systemd service (module.nix). Usually turned on via
      # banken's one switch (a later step); import this alongside banken's module. The nixosModule
      # defaults services.hitomi.package to this flake's own hitomi build, so the switch deploys
      # turnkey (overridable with a plain mkForce/assignment).
      nixosModules.default =
        { pkgs, lib, ... }:
        {
          imports = [ ./module.nix ];
          config.services.hitomi.package =
            lib.mkDefault self.packages.${pkgs.stdenv.hostPlatform.system}.hitomi;
        };
      nixosModules.hitomi = self.nixosModules.default;

      packages = forAllSystems (
        system:
        let
          s = perSystem system;
        in
        {
          yara-types = s.yaraTypesPackage;
          hitomi = s.hitomiPackage;
          hitomi-musl = s.hitomiMuslPackage;
          default = s.hitomiPackage;
        }
      );

      # Runtime VM tests (x86_64-linux only: runNixOSTest needs a KVM builder of the test's system).
      #   vm-hitomi      -- the hardened unit starts and stays up under MemoryDenyWriteExecute, an
      #                     exec of an EICAR canary and a drop-zone write each produce a yara/1 line,
      #                     a clean exec produces nothing, and the canary is never blocked (design
      #                     8.4 Y3-Y5). The listener proof under the real unit.
      #   vm-hitomi-musl -- the same, forcing the fully-static musl binary as the package.
      checks = nixpkgs.lib.genAttrs [ "x86_64-linux" ] (
        system:
        let
          s = perSystem system;
          args = {
            pkgs = s.pkgs;
            hitomiModule = self.nixosModules.default;
          };
        in
        {
          vm-hitomi = import ./tests/yara-switch.nix args;
          vm-hitomi-musl = import ./tests/yara-switch.nix (
            args
            // {
              name = "hitomi-unit-musl";
              hitomiPackage = s.hitomiMuslPackage;
            }
          );
        }
      );

      # Cross-distro accuracy matrix (tests/distros/matrix.nix): the shipped musl
      # binary's EICAR suite on each real vendor distro, via mayfly. x86_64-linux
      # only (needs a KVM host). `nix run .#matrix`, or `.#distro-ubuntu-2404`
      # for one.
      apps.x86_64-linux = (import ./tests/distros/matrix.nix {
        pkgs = nixpkgs.legacyPackages.x86_64-linux;
        lib = nixpkgs.lib;
        inherit mayfly self;
      }).apps;

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
