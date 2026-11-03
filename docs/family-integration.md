# Family integration plan

banken, mimi, hitomi. The goal: every seam between them frictionless. Smooth as butter.

Three pieces:

- **banken** - the brain. Go. Parses, matches, decides, responds.
- **mimi** - the ears. Rust, eBPF. What a process did.
- **hitomi** - the eyes. Rust, YARA. What a file is.

They meet at seven seams. Each should be frictionless.

## The seams

| Seam | Today | Butter | How |
| --- | --- | --- | --- |
| **Data** (sensor to banken) | One Event schema. mimi emits OCSF, hitomi emits `yara/1`. Both golden-pinned. | Zero drift, ever. | Keep the shared goldens. CI both sides on every change. |
| **Build** (source to binary) | banken is static Go. mimi/hitomi are dynamic, plus a libs bundle. | Three static binaries. | musl target for mimi and hitomi. |
| **Install** (binary to a host) | NixOS is first-class. Everyone else builds by hand. | Copy-and-run on any distro. One Nix option. | Ship the static binaries as release downloads. A suite flake for Nix. |
| **Config** (turning it on) | banken has a NixOS option and a CLI flag. Sensors are wired ad hoc. | One switch per sensor, same shape. | `services.banken.sensors.{mimi,hitomi}.enable`. The module composes them. |
| **Run** (detect, decide, respond) | Sensors feed banken. It correlates by hash and path. One response spine. | Signals fuse into one verdict. Enforce off by default. | The drop-zone-exec correlation. `enforceSources` per sensor. |
| **Test** (proving it) | The matrix proves banken + mimi + Sysmon. Goldens keep the contracts in sync. | Every integration is a green check. | A hitomi column, after the matrix review. Cross-repo CI. |
| **Release** (shipping updates) | Three independent repos. | A version bump is one lock change. | Flake inputs, pinned. Dependabot. A suite flake tracks all three. |

## Order of work

Highest payoff first.

1. **Fix the matrix.** Fable is reviewing the attribution method now. Deterministic attribution unblocks reliable testing for the whole family. Everything downstream leans on it.
2. **Static binaries.** Prove mimi and hitomi on musl. This is the install story for the hundreds of non-NixOS distros. (Needs a build host.)
3. **One config switch per sensor.** Fold mimi and hitomi into `services.banken.sensors.*`. Same shape both ways: option and CLI.
4. **hitomi to parity.** Engine, then daemon, then the matrix column. Then it stands beside mimi.
5. **Suite flake and releases.** One `banken-suite` flake, three pinned inputs. One command installs the family. Releases attach the three static binaries.

## The one rule

Loose coupling is what keeps it smooth.

The three stay separate repos. They are joined only by the Event contract and pinned flake inputs. No submodules. No repo reaching into another.

That is what lets any one of them move without breaking the others. It is also what makes "smooth as butter" survive growth.
