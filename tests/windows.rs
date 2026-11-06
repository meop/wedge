#![cfg(windows)]

use std::os::windows::fs::{symlink_dir, symlink_file};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("wedge-test-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn system(program: &str) -> PathBuf {
    PathBuf::from(std::env::var("SystemRoot").unwrap())
        .join("System32")
        .join(program)
}

fn stamp(source: &Path, shim: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_mallet"))
        .arg("--source-path")
        .arg(source)
        .arg("--target-path")
        .arg(shim)
        .output()
        .unwrap()
}

fn stamped(source: &Path, shim: &Path) -> PathBuf {
    let out = stamp(source, shim);
    assert!(
        out.status.success(),
        "{}: {}",
        source.display(),
        String::from_utf8_lossy(&out.stderr)
    );
    shim.to_path_buf()
}

/// which of the two shim templates the shim was stamped from
fn template(shim: &Path) -> &'static str {
    let bytes = std::fs::read(shim).unwrap();
    for (name, path) in [
        ("console", env!("CARGO_BIN_EXE_wedge")),
        ("gui", env!("CARGO_BIN_EXE_wedge-gui")),
    ] {
        let t = std::fs::read(path).unwrap();
        if bytes.len() > t.len() && bytes.starts_with(&t) {
            return name;
        }
    }
    panic!("{} is neither template", shim.display())
}

fn says_hostname(shim: &Path) -> bool {
    let out = Command::new(shim).output().unwrap();
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .eq_ignore_ascii_case(&std::env::var("COMPUTERNAME").unwrap())
}

/// a symlink, which Windows lets only an elevated process or Developer Mode make. CI's runner is elevated, so there
/// they are always made; elsewhere the cases that need one are left out, saying so
fn symlinked(made: std::io::Result<()>) -> bool {
    const ERROR_PRIVILEGE_NOT_HELD: i32 = 1314;
    match made {
        Ok(()) => true,
        Err(e)
            if e.raw_os_error() == Some(ERROR_PRIVILEGE_NOT_HELD)
                && std::env::var_os("CI").is_none() =>
        {
            eprintln!(
                "symlink cases left out: this account cannot make symlinks (no Developer Mode, not elevated)"
            );
            false
        }
        Err(e) => panic!("{e}"),
    }
}

fn junction(link: &Path, target: &Path) {
    let status = Command::new("cmd")
        .args(["/c", "mklink", "/J"])
        .arg(link)
        .arg(target)
        .output()
        .unwrap()
        .status;
    assert!(status.success(), "mklink /J {}", link.display());
}

#[test]
fn a_shim_stamped_through_a_pointer_runs_what_the_pointer_names_now() {
    let dir = scratch("pointer");
    for (version, program) in [("1", "cmd.exe"), ("2", "hostname.exe")] {
        std::fs::create_dir_all(dir.join(version)).unwrap();
        std::fs::copy(system(program), dir.join(version).join("tool.exe")).unwrap();
    }
    let latest = dir.join("latest");
    std::fs::write(&latest, "1").unwrap();
    let shim = stamped(&latest.join("tool.exe"), &dir.join("shimmed.exe"));
    let bytes = std::fs::read(&shim).unwrap();

    let out = Command::new(&shim)
        .args(["/c", "echo", "one"])
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "one");
    std::fs::write(&latest, "2").unwrap();
    assert!(says_hostname(&shim), "the shim did not follow the pointer");
    assert_eq!(std::fs::read(&shim).unwrap(), bytes, "the shim changed");
}

#[test]
fn a_shim_stamped_through_a_link_takes_the_template_of_the_program_it_names_and_runs_it() {
    let dir = scratch("link");
    let real = dir.join("real");
    std::fs::create_dir_all(&real).unwrap();
    std::fs::copy(system("hostname.exe"), real.join("console.exe")).unwrap();
    // a gui program, stamped but never started
    std::fs::copy(env!("CARGO_BIN_EXE_wedge-gui"), real.join("gui.exe")).unwrap();
    junction(&dir.join("junction"), &real);
    let mut sources = vec![
        (dir.join("junction").join("console.exe"), "console"),
        (dir.join("junction").join("gui.exe"), "gui"),
    ];
    if symlinked(symlink_file(
        real.join("console.exe"),
        dir.join("console.exe"),
    )) {
        symlink_file(real.join("console.exe"), dir.join("renamed.exe")).unwrap();
        symlink_file(real.join("gui.exe"), dir.join("gui.exe")).unwrap();
        symlink_dir(&real, dir.join("dirlink")).unwrap();
        sources.extend([
            (dir.join("console.exe"), "console"),
            (dir.join("renamed.exe"), "console"),
            (dir.join("gui.exe"), "gui"),
            (dir.join("dirlink").join("console.exe"), "console"),
        ]);
    }
    let bin = dir.join("bin");
    std::fs::create_dir_all(&bin).unwrap();

    for (i, (source, kind)) in sources.iter().enumerate() {
        let shim = stamped(source, &bin.join(format!("{i}.exe")));
        assert_eq!(template(&shim), *kind, "{}", source.display());
        if *kind == "console" {
            assert!(says_hostname(&shim), "{} did not run", source.display());
        }
    }
}

#[test]
fn a_link_to_nothing_is_not_stamped() {
    let dir = scratch("dangling");
    junction(&dir.join("junction"), &dir.join("missing"));
    let shim = dir.join("shimmed.exe");

    let out = stamp(&dir.join("junction").join("tool.exe"), &shim);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).starts_with("mallet:"));
    assert!(!shim.exists());
}

#[test]
fn a_shim_stamped_to_an_app_execution_alias_takes_the_template_of_the_program_it_starts() {
    let dir = scratch("alias");
    let aliases =
        PathBuf::from(std::env::var("LOCALAPPDATA").unwrap()).join(r"Microsoft\WindowsApps");
    let found: Vec<PathBuf> = std::fs::read_dir(&aliases)
        .map(|entries| {
            entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|x| x.eq_ignore_ascii_case("exe")))
                .collect()
        })
        .unwrap_or_default();
    assert!(
        !found.is_empty(),
        "no App Execution Alias in {}",
        aliases.display()
    );

    let mut stamped_any = false;
    for (i, alias) in found.iter().enumerate() {
        let shim = dir.join(format!("{i}.exe"));
        let out = stamp(alias, &shim);
        if !out.status.success() {
            // windows leaves aliases behind that name a program an update removed
            let said = String::from_utf8_lossy(&out.stderr);
            assert!(
                said.contains("is an alias for"),
                "{}: {said}",
                alias.display()
            );
            continue;
        }
        stamped_any = true;
        let expected = match alias
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_lowercase()
            .as_str()
        {
            "winget.exe" | "python.exe" | "python3.exe" => Some("console"),
            "notepad.exe" | "mspaint.exe" | "wt.exe" => Some("gui"),
            _ => None,
        };
        if let Some(kind) = expected {
            assert_eq!(template(&shim), kind, "{}", alias.display());
        }
    }
    assert!(stamped_any, "no alias in {} was stamped", aliases.display());
}
