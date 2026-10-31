use std::ffi::OsString;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicI32, Ordering};

static TARGET: AtomicI32 = AtomicI32::new(0);
static PENDING: AtomicI32 = AtomicI32::new(0);

const PASSED: [libc::c_int; 4] = [libc::SIGHUP, libc::SIGTERM, libc::SIGUSR1, libc::SIGUSR2];
const LEFT: [libc::c_int; 2] = [libc::SIGINT, libc::SIGQUIT];

extern "C" fn pass_on(signal: libc::c_int) {
    match TARGET.load(Ordering::SeqCst) {
        0 => PENDING.store(signal, Ordering::SeqCst),
        pid => unsafe {
            libc::kill(pid, signal);
        },
    }
}

extern "C" fn leave(_: libc::c_int) {}

fn handle(signal: libc::c_int, handler: extern "C" fn(libc::c_int)) {
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = handler as libc::sighandler_t;
        action.sa_flags = libc::SA_RESTART;
        libc::sigemptyset(&mut action.sa_mask);
        libc::sigaction(signal, &action, std::ptr::null_mut());
    }
}

pub fn spawn_target(
    target: &Path,
    stamped: &[OsString],
    as_shim: bool,
) -> Result<u32, Box<dyn std::error::Error>> {
    for signal in PASSED {
        handle(signal, pass_on);
    }
    for signal in LEFT {
        handle(signal, leave);
    }

    let mut cmd = Command::new(target);
    // the target runs under the shim's name, as through a symlink, so whatever reads its argv (ps, a terminal
    // multiplexer saving the session) sees `claude` rather than the versioned path behind it
    let mut own = std::env::args_os();
    if let Some(arg0) = own.next().filter(|_| as_shim) {
        cmd.arg0(arg0);
    }
    cmd.args(stamped).args(own);
    #[cfg(target_os = "linux")]
    {
        let shim = std::process::id() as libc::pid_t;
        unsafe {
            cmd.pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                // the shim may have died before prctl, which would then never fire
                if libc::getppid() != shim {
                    libc::_exit(1);
                }
                Ok(())
            });
        }
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("cannot run {}: {e}", target.display()))?;

    TARGET.store(child.id() as i32, Ordering::SeqCst);
    let pending = PENDING.swap(0, Ordering::SeqCst);
    if pending != 0 {
        unsafe { libc::kill(child.id() as i32, pending) };
    }

    let status = child.wait()?;
    if let Some(signal) = status.signal() {
        die_of(signal);
    }
    Ok(status.code().unwrap_or(1) as u32)
}

fn die_of(signal: libc::c_int) {
    unsafe {
        libc::signal(signal, libc::SIG_DFL);
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, signal);
        libc::sigprocmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
        libc::raise(signal);
    }
}

pub fn alert(message: &str) {
    eprintln!("{message}");
}
