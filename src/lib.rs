pub mod data;
mod platform;
pub mod pointer;
pub mod windows_pe;

pub fn run() -> ! {
    run_reporting(|e| eprintln!("shim: {e}"))
}

pub fn run_gui() -> ! {
    run_reporting(|e| platform::alert(&format!("shim: {e}")))
}

fn run_reporting(report: impl Fn(&str)) -> ! {
    match try_run() {
        Ok(code) => std::process::exit(code as i32),
        Err(e) => {
            report(&e.to_string());
            std::process::exit(1);
        }
    }
}

fn try_run() -> Result<u32, Box<dyn std::error::Error>> {
    let t = data::Trailer::read_from_self()
        .ok_or("no shim data — use mallet to stamp a source path")?;
    let source_path = pointer::resolve(std::path::Path::new(&expand_env(
        &t.source_path.to_string_lossy(),
    )));
    if !source_path.exists() {
        return Err(format!("source not found: {}", source_path.display()).into());
    }
    let stamped: Vec<std::ffi::OsString> = t.args.iter().map(|a| expand_env(a).into()).collect();
    let as_shim = std::env::args_os()
        .next()
        .is_some_and(|arg0| named_for(&arg0, &source_path));
    platform::spawn_target(&source_path, &stamped, as_shim)
}

/// whether the shim, started as `arg0`, carries the target's own name, so the target can run under it
pub fn named_for(arg0: &std::ffi::OsStr, target: &std::path::Path) -> bool {
    let (Some(shim), Some(target)) = (std::path::Path::new(arg0).file_name(), target.file_name())
    else {
        return false;
    };
    let (shim, target) = (shim.to_string_lossy(), target.to_string_lossy());
    if cfg!(windows) {
        let bare = |s: &str| {
            let s = s.to_lowercase();
            s.strip_suffix(".exe").map(str::to_string).unwrap_or(s)
        };
        bare(&shim) == bare(&target)
    } else {
        shim.strip_prefix('-').unwrap_or(&shim) == target
    }
}

/// on windows a stamped `%NAME%` is the environment's NAME when the shim runs, so one shim serves every user (a
/// machine-wide shell set to `%USERPROFILE%\...`); a unix path is taken as written
pub fn expand_env(s: &str) -> String {
    if cfg!(windows) {
        data::expand(s, |k| std::env::var(k).ok())
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;
    use std::path::Path;

    fn named(arg0: &str, target: &str) -> bool {
        named_for(OsStr::new(arg0), Path::new(target))
    }

    #[test]
    fn a_shim_named_as_its_target_runs_it_under_its_own_name() {
        assert!(named("claude", "/x/claude/2.1.304/claude"));
        assert!(named(
            "/home/u/.ghpm/bin/claude",
            "/x/claude/2.1.304/claude"
        ));
    }

    #[test]
    fn a_pinned_or_renamed_shim_does_not() {
        // mise run as `mise@2026.4.11` looks for a tool of that name on PATH, finds the shim, and runs it again
        assert!(!named(
            "mise@2026.4.11",
            "/x/mise@2026.4.11/2026.4.11/mise/bin/mise"
        ));
        assert!(!named("go1.26", "/x/go/1.26.0/bin/go"));
        assert!(!named("", "/x/claude"));
    }

    #[cfg(unix)]
    #[test]
    fn a_login_shell_keeps_its_dash() {
        assert!(named("-nu", "/x/nu/0.108.0/nu"));
        assert!(!named("-nu", "/x/nu/0.108.0/-nux"));
    }

    #[cfg(unix)]
    #[test]
    fn unix_names_are_exact() {
        assert!(!named("Claude", "/x/claude"));
        assert!(!named("claude.exe", "/x/claude"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_names_ignore_case_and_exe() {
        assert!(named("claude", r"C:\x\claude.exe"));
        assert!(named(r"C:\u\.ghpm\bin\CLAUDE.EXE", r"C:\x\claude.exe"));
        assert!(!named("mise@2026.4.11.exe", r"C:\x\mise.exe"));
        assert!(!named("mise@2026.4.11", r"C:\x\mise.exe"));
    }
}
