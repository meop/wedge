#![cfg(unix)]

use std::os::unix::fs::symlink;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn shim(dir: &Path, script: &str) -> PathBuf {
    shim_named(dir, "shimmed", script)
}

fn shim_named(dir: &Path, name: &str, script: &str) -> PathBuf {
    let shim = dir.join(name);
    let status = Command::new(env!("CARGO_BIN_EXE_mallet"))
        .args(["--source-path", "/bin/sh", "--target-path"])
        .arg(&shim)
        .args(["--arg", "-c", "--arg", script, "--arg", "sh"])
        .status()
        .unwrap();
    assert!(status.success());
    shim
}

fn stamped(source: &Path, shim: &Path) -> PathBuf {
    let status = Command::new(env!("CARGO_BIN_EXE_mallet"))
        .arg("--source-path")
        .arg(source)
        .arg("--target-path")
        .arg(shim)
        .status()
        .unwrap();
    assert!(status.success());
    shim.to_path_buf()
}

fn tool(path: &Path, says: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, format!("#!/bin/sh\necho {says}\n")).unwrap();
    std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
}

fn ran(shim: &Path) -> String {
    String::from_utf8(Command::new(shim).output().unwrap().stdout).unwrap()
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("wedge-test-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[cfg(target_os = "linux")]
fn alive(pid: i32) -> bool {
    unsafe { libc::kill(pid, 0) == 0 }
}

fn wait_for(what: impl Fn() -> bool) -> bool {
    let end = Instant::now() + Duration::from_secs(5);
    while Instant::now() < end {
        if what() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

#[test]
fn the_shim_is_the_targets_parent_and_exits_with_its_code() {
    let dir = scratch("code");
    let child = Command::new(shim(&dir, r#"echo "$PPID $0 $*"; exit 7"#))
        .args(["a b", "c"])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let shim_pid = child.id().to_string();
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(7));
    let said = String::from_utf8(out.stdout).unwrap();
    assert_eq!(
        said.split_whitespace().next(),
        Some(shim_pid.as_str()),
        "the target is not the shim's child: {said}"
    );
    assert!(said.trim_end().ends_with("sh a b c"), "{said}");
}

#[test]
fn a_signal_sent_to_the_shim_reaches_the_target() {
    let dir = scratch("term");
    let mut child = Command::new(shim(
        &dir,
        "trap 'exit 42' TERM; while :; do sleep 0.05; done",
    ))
    .stdout(Stdio::null())
    .spawn()
    .unwrap();
    std::thread::sleep(Duration::from_millis(300));
    unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
    assert_eq!(child.wait().unwrap().code(), Some(42));
}

#[test]
fn the_shim_dies_of_the_signal_that_ended_the_target() {
    let dir = scratch("killed");
    let status = Command::new(shim(&dir, "kill -KILL $$")).status().unwrap();
    assert_eq!(status.signal(), Some(libc::SIGKILL));
}

#[test]
fn ctrl_c_is_left_to_the_target_and_the_shim_waits_for_it() {
    let dir = scratch("int");
    let pids = dir.join("pids");
    let script = format!(
        "trap 'echo saw >> {p}; exit 3' INT; echo $$ > {p}.target; while :; do sleep 0.05; done",
        p = pids.display()
    );
    let mut child = Command::new(shim(&dir, &script)).spawn().unwrap();
    assert!(wait_for(|| pids.with_extension("target").exists()));
    std::thread::sleep(Duration::from_millis(100));
    let target: i32 = std::fs::read_to_string(pids.with_extension("target"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    // a terminal's ^C goes to the shim and the target alike
    unsafe {
        libc::kill(child.id() as i32, libc::SIGINT);
        libc::kill(target, libc::SIGINT);
    }
    assert_eq!(child.wait().unwrap().code(), Some(3));
    assert_eq!(std::fs::read_to_string(&pids).unwrap(), "saw\n");
}

#[cfg(target_os = "linux")]
#[test]
fn the_target_ends_with_a_shim_that_is_killed() {
    let dir = scratch("orphan");
    let pid_file = dir.join("target");
    let script = format!(
        "echo $$ > {}; while :; do sleep 0.05; done",
        pid_file.display()
    );
    let mut child = Command::new(shim(&dir, &script)).spawn().unwrap();
    assert!(wait_for(|| pid_file.exists()));
    std::thread::sleep(Duration::from_millis(100));
    let target: i32 = std::fs::read_to_string(&pid_file)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    unsafe { libc::kill(child.id() as i32, libc::SIGKILL) };
    child.wait().unwrap();
    assert!(wait_for(|| !alive(target)), "the target outlived its shim");
}

#[test]
fn a_shim_stamped_through_a_pointer_runs_what_the_pointer_names_now() {
    let dir = scratch("pointer");
    for version in ["1", "2"] {
        tool(&dir.join(version).join("tool"), version);
    }
    let latest = dir.join("latest");
    std::fs::write(&latest, "1").unwrap();
    let shim = stamped(&latest.join("tool"), &dir.join("shimmed"));
    let bytes = std::fs::read(&shim).unwrap();

    assert_eq!(ran(&shim), "1\n");
    std::fs::write(&latest, "2").unwrap();
    assert_eq!(ran(&shim), "2\n");
    assert_eq!(std::fs::read(&shim).unwrap(), bytes, "the shim changed");
}

#[test]
fn a_shim_stamped_through_a_link_runs_what_the_link_names_now() {
    let dir = scratch("link");
    for version in ["1", "2"] {
        tool(&dir.join(version).join("tool"), version);
    }
    let point = |version: &str| {
        for link in ["tool", "latest"] {
            let _ = std::fs::remove_file(dir.join(link));
        }
        symlink(format!("{version}/tool"), dir.join("tool")).unwrap();
        symlink(version, dir.join("latest")).unwrap();
    };
    point("1");
    let bin = dir.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let shims = [
        stamped(&dir.join("tool"), &bin.join("tool")),
        stamped(&dir.join("tool"), &bin.join("renamed")),
        stamped(&dir.join("latest").join("tool"), &bin.join("in-dir")),
    ];

    for shim in &shims {
        assert_eq!(ran(shim), "1\n", "{}", shim.display());
    }
    point("2");
    for shim in &shims {
        assert_eq!(ran(shim), "2\n", "{}", shim.display());
    }
}

#[test]
fn a_shim_stamped_to_a_dangling_link_says_its_source_is_missing() {
    let dir = scratch("dangling");
    symlink("missing", dir.join("tool")).unwrap();
    let shim = stamped(&dir.join("tool"), &dir.join("shimmed"));

    let out = Command::new(&shim).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    let said = String::from_utf8(out.stderr).unwrap();
    assert!(said.contains("source not found"), "{said}");
}

#[test]
fn the_target_runs_under_the_shims_name_only_when_it_is_its_own() {
    let dir = scratch("arg0");
    let arg0 = |name: &str| {
        let out = Command::new(shim_named(&dir, name, "ps -o args= -p $$; true"))
            .output()
            .unwrap();
        let said = String::from_utf8(out.stdout).unwrap();
        said.split_whitespace().next().unwrap().to_string()
    };
    assert_eq!(arg0("sh"), dir.join("sh").display().to_string());
    assert_eq!(arg0("sh@5"), "/bin/sh");
}
