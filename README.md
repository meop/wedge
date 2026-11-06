# wedge

Shim executables that run a real binary from where it is unpacked, under their own name. A shim is a thin wedge; `mallet` drives one in: it stamps a copy of a template with the target path, stored in the shim itself.

## Binaries

| Binary | Platforms | Purpose |
|--------|-----------|---------|
| `wedge` | all | Console shim — reads the embedded path, runs the target and waits for it |
| `wedge-gui` | Windows | GUI subsystem shim — same as `wedge` but suppresses the console window |
| `mallet` | all | Stamper tool — copies a shim template and embeds a target path into it |

## How it works

1. `mallet --source-path <target> --target-path <output>` copies the appropriate `wedge` template and appends the target path as a small binary trailer.
2. When the output executable is run, it reads the trailer, resolves the target path, and runs it as a child it waits for — passing all arguments through.

The shim never becomes the target, on any platform: it stays the process that was started, at the path it was stamped
to, with the bytes it was stamped with. So what knows a program by its process — macOS's privacy permissions, a
service manager, a firewall rule — keeps knowing the shim across upgrades of the target behind it, as long as the shim
is not restamped.

The target runs under the shim's name: whatever reads its command line (`ps`, Task Manager, a terminal multiplexer
saving its session) sees the shim, as it would through a symlink, rather than the versioned path behind it, which a
later upgrade may remove. The target's own path to itself (`/proc/self/exe`, `GetModuleFileName`) stays the real one,
so a tool that finds its files from where it sits still finds them. A shim named other than its target
(`mise@2026.4.11` for `mise`) runs it under the target's path.

`--arg <value>` (repeatable) stamps arguments the target always gets first, before the shim's own:
`mallet --source-path pwsh.exe --target-path shell.exe --arg -nol` runs `pwsh.exe -nol <args>`.

A component of the stamped path may be a pointer file: a regular file where a directory would be, naming that
directory relative to its own. `mallet --source-path ~/.ghpm/extract/fzf/latest/fzf` with `latest` holding `0.74.5`
runs `~/.ghpm/extract/fzf/0.74.5/fzf`, and rewriting `latest` moves every shim stamped through it to another version
without stamping them again. A file that names no directory there is not a pointer. A pointer file is read the same by every process,
elevated or not, where Windows does not let an elevated process follow a link a user made.

A relative `--source-path` is made absolute from where `mallet` runs. A link in it (a symlink, or on Windows a
junction) is kept as given, not resolved, so the shim runs whatever the link names when it runs. `mallet` stamps the shim beside `--target-path` and
moves it into place, so it can replace a shim that is running, and nothing ever runs one half written.

On Windows, `%NAME%` in the stamped path and arguments is the environment variable NAME when the shim runs (one left
unset stays as written), so one machine-wide shim can run each user's own copy of a tool:
`--source-path '%USERPROFILE%\.ghpm\bin\pwsh.exe'`.

On Windows, `mallet` inspects the PE subsystem of the target to decide whether to use the console or GUI shim template.
A target that is an App Execution Alias, as an MSIX package puts on `PATH` (winget's `pwsh`, `wt`), is read through to
the program it starts. An alias whose program is gone, as Windows leaves some behind after an update, is not stamped.
A GUI shim that cannot run its target says why in a message box. A batch file is not a target.

### Per platform

The outcome is the same everywhere; how the shim gets there is each platform's own.

|                                  | Linux and macOS                   | Windows                                                     |
| -------------------------------- | --------------------------------- | ----------------------------------------------------------- |
| the shim process                 | starts the target and waits for it | starts the target and waits for it                         |
| the target's command line        | the shim's name, then arguments   | the shim's first word as it was started, then arguments     |
| the shim's own arguments         | passed as the shim got them       | passed as the shim's raw command line had them, unparsed    |
| Ctrl+C                           | left to the target; the shim waits it out | console events left to the target; the shim waits it out |
| a signal sent to the shim alone  | HUP, TERM, USR1, USR2 passed on   | —                                                           |
| exit code                        | the target's, or the shim dies of the signal that ended it | the target's, passed on by the shim |
| the shim is killed               | Linux: the target ends with it; macOS: the target goes on | the target ends with it (a job object) |
| what the target starts           | outlives it, as it would          | outlives it: it breaks away from the job                    |
| `%NAME%` in the stamped path     | taken as written                  | expanded when the shim runs                                 |
| replacing a running shim         | a rename over it                  | it is moved aside, and deleted by the next stamp            |

## Building

```sh
cargo build --release
```

Produces `target/release/wedge`, `target/release/wedge-gui`, and `target/release/mallet`.

## Cross-compile

Releases are built for Linux and Windows on x86_64 and arm64, and macOS on arm64.

Add the target with `rustup target add <target>` then build:

```sh
cargo build --release --target aarch64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
cargo build --release --target aarch64-apple-darwin
cargo build --release --target aarch64-pc-windows-msvc
cargo build --release --target x86_64-pc-windows-msvc
```

## Verifying releases

Every release archive contains `LICENSE`. Verify the signed checksum
manifest with the public release key before checking downloaded artifacts:

```sh
gpg --verify SHA256SUMS.sig SHA256SUMS
sha256sum --ignore-missing --check SHA256SUMS
```

## License

[MIT](LICENSE)
