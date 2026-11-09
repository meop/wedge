# AGENTS.md

## After every code change

Run all four — do not skip any:

```sh
cargo build --release
cargo test
cargo fmt
cargo clippy -- -D warnings
```

## Comments

No comment explains why code does what it does where a unit test can show it: the test is the explanation, and it
fails when the reasoning stops holding. A comment is only for what no test can show.

## Keeping this file current

Update this file whenever a binary or source file is added, removed or renamed,
the trailer format changes, or a convention changes — do not wait to be asked.
If you notice a discrepancy between this file and the code, fix the file
immediately.

Update `README.md` when user-visible behavior changes: a binary's arguments,
what a release ships, or how a shim resolves its target.

## Cross-compile

All targets build natively — no cross-compilation tooling required.

```sh
cargo build --release --target aarch64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
cargo build --release --target aarch64-apple-darwin
cargo build --release --target aarch64-pc-windows-msvc
cargo build --release --target x86_64-pc-windows-msvc
```

Add a target with `rustup target add <target>` before building for it.

## Publishing

To cut a release: bump `version` in `Cargo.toml` and push to `main`.

The CI pipeline (`.github/workflows/pipeline.yaml`) runs: Version check (skips
the rest if `v<version>` already exists) → Validate (fmt + clippy) and Test (`cargo test` for every
release target, each on a runner of its own platform and architecture) →
Build for every target → Publish, which signs `SHA256SUMS`, creates a
GPG-signed tag `v<version>` and publishes the archives to a public GitHub
release. Requires the `GPG_PRIVATE_KEY` and `GPG_PASSPHRASE` repository
secrets. Never create the tag by hand.

ghpm and goup take wedge's latest release, through golie, checked against the
release's signed checksums when it is fetched. A new release reaches them at
`ghpm pull` and `goup refresh`, and reaches a shim when it is stamped again
(`ghpm renew`, `goup install --reinstall`).

## Project structure

- `src/lib.rs` — shim runtime: reads the embedded trailer and runs the target as a child it waits for, under the
  shim's name when it is the target's
- `src/pointer.rs` — pointer files: a regular file where a stamped path has a directory, naming it relative to its own
- `src/data.rs` — binary trailer format (append/read the embedded path and arguments: at end of exe, or in a Mach-O
  right before the code signature), `%NAME%` expansion
- `src/macho.rs` — on macOS, a shim's own identity: the Mach-O UUID and signing identifier derived from its path, the
  trailer placed before the code signature, and the ad-hoc signature (a CodeDirectory of SHA-256 page hashes) that
  covers both
- `src/sha256.rs` — SHA-256, for the code signature's page hashes and the derived UUID
- `src/windows_pe.rs` — Windows PE subsystem detection (GUI vs Console), of the program an App Execution Alias starts
  when the source is one (an MSIX package's command on PATH, which Windows will not open as a file)
- `src/platform/` — platform dispatch for `spawn_target` and `alert` (unix: a child under the shim's argv[0] when it
  names the target, signals sent to the shim passed on, ^C left to the target, the shim dying of the target's signal,
  and on Linux the target killed with the shim; windows: CreateProcessW with the shim's own first word when it names
  the target and raw arguments as the command line, in a kill-on-close job the target's children break away from,
  Ctrl+C left to the target, a GUI shim's errors in a message box)
- `src/bin/wedge.rs` — console shim entry point
- `src/bin/wedge-gui.rs` — GUI subsystem shim entry point
- `tests/windows.rs` — on Windows, a shim stamped through a pointer, a symlink, a junction or an App Execution Alias:
  the template mallet picks for each, and the shim running it
- `tests/unix.rs` — the unix runtime against a real stamped shim: parent, exit code, signals, ^C, a killed shim, and
  a shim stamped through a pointer or a link, or to a dangling one
- `src/bin/mallet.rs` — stamper tool: copies shim template and embeds target path (on macOS, with the shim's own
  identity and signature), staged beside the shim and moved
  over it (on Windows a running shim is moved aside first, and the next stamp deletes it)

## Testing on a real host

CI runs the tests for every release target, on its own platform and architecture. On a Windows machine of your own, run `cargo test` in its desktop
session, not an ssh login: rustup's `cargo` and `rustc` proxies cannot start in an ssh login (os error 448).

## Conventions

- Three binaries in one crate: `wedge`, `wedge-gui`, `mallet`
- All three compile on every platform; only Windows releases package `wedge-gui`
  (the `#![cfg_attr(windows, windows_subsystem = "windows")]` attribute is a no-op on Unix)
- `mallet` selects the GUI or console shim template based on PE subsystem of the source binary
- Trailer format: `[path bytes][u32 path_len LE][b"SHIM"]` appended to the exe; with stamped arguments
  `[path\0arg\0...][u32 len LE][b"SHM2"]`. A shim stamped without arguments is byte for byte what it was before
  arguments existed
- The only dependencies are `windows-sys` on Windows and `libc` on unix: hand-declared FFI was fine for one call, not
  for CreateProcessW and job objects, nor for sigaction and prctl
- `%NAME%` is expanded on Windows only, when the shim runs; mallet expands it too, but only to read the PE subsystem
- Version is in `Cargo.toml`; CI creates a signed tag on version bump
