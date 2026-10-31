use std::ffi::{OsStr, OsString};
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicPtr, Ordering};

use windows_sys::Win32::Foundation::{
    CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::System::Console::{
    CTRL_CLOSE_EVENT, CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT, GetStdHandle, STD_ERROR_HANDLE,
    STD_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, SetConsoleCtrlHandler,
};
use windows_sys::Win32::System::Environment::GetCommandLineW;
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectExtendedLimitInformation, SetInformationJobObject,
};
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, CreateProcessW, GetCurrentProcess, GetExitCodeProcess, INFINITE,
    PROCESS_INFORMATION, ResumeThread, STARTF_USESTDHANDLES, STARTUPINFOW, WaitForSingleObject,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{MB_ICONERROR, MB_OK, MessageBoxW};

static TARGET: AtomicPtr<core::ffi::c_void> = AtomicPtr::new(null_mut());

/// the console's Ctrl+C and Ctrl+Break reach the target too, which decides what they mean; the shim waits for it
unsafe extern "system" fn leave_to_target(event: u32) -> i32 {
    if matches!(
        event,
        CTRL_CLOSE_EVENT | CTRL_LOGOFF_EVENT | CTRL_SHUTDOWN_EVENT
    ) {
        let target = TARGET.load(Ordering::Acquire);
        if !target.is_null() {
            unsafe { WaitForSingleObject(target, INFINITE) };
        }
    }
    1
}

pub fn spawn_target(
    target: &Path,
    stamped: &[OsString],
    as_shim: bool,
) -> Result<u32, Box<dyn std::error::Error>> {
    // a handler routine, not SetConsoleCtrlHandler(NULL, TRUE): that would be inherited, and the target would ignore
    // Ctrl+C as well
    unsafe { SetConsoleCtrlHandler(Some(leave_to_target), 1) };

    let mut application = wide(target.as_os_str());
    application.push(0);
    let mut command_line = command_line(
        &own_command_line(),
        (!as_shim).then_some(target.as_os_str()),
        stamped,
    );
    command_line.push(0);

    let std_handles = [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE].map(inheritable);
    let mut startup: STARTUPINFOW = unsafe { std::mem::zeroed() };
    startup.cb = size_of::<STARTUPINFOW>() as u32;
    startup.dwFlags = STARTF_USESTDHANDLES;
    [startup.hStdInput, startup.hStdOutput, startup.hStdError] = std_handles;

    let mut process: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    let created = unsafe {
        CreateProcessW(
            application.as_ptr(),
            command_line.as_mut_ptr(),
            null(),
            null(),
            1,
            CREATE_SUSPENDED,
            null(),
            null(),
            &startup,
            &mut process,
        )
    };
    let error = std::io::Error::last_os_error();
    for h in std_handles.into_iter().filter(|h| !h.is_null()) {
        unsafe { CloseHandle(h) };
    }
    if created == 0 {
        return Err(format!("cannot run {}: {error}", target.display()).into());
    }

    let _job = kill_with_shim(process.hProcess);
    TARGET.store(process.hProcess, Ordering::Release);
    unsafe {
        ResumeThread(process.hThread);
        CloseHandle(process.hThread);
        WaitForSingleObject(process.hProcess, INFINITE);
    }
    let mut code = 1;
    unsafe { GetExitCodeProcess(process.hProcess, &mut code) };
    Ok(code)
}

fn kill_with_shim(process: HANDLE) -> Option<HANDLE> {
    unsafe {
        let job = CreateJobObjectW(null(), null());
        if job.is_null() {
            return None;
        }
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
        limits.BasicLimitInformation.LimitFlags =
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK;
        let set = SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            (&raw const limits).cast(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        );
        if set == 0 || AssignProcessToJobObject(job, process) == 0 {
            CloseHandle(job);
            return None;
        }
        Some(job)
    }
}

fn inheritable(which: STD_HANDLE) -> HANDLE {
    unsafe {
        let h = GetStdHandle(which);
        if h.is_null() || h == INVALID_HANDLE_VALUE {
            return null_mut();
        }
        let mut copy = null_mut();
        let me = GetCurrentProcess();
        if DuplicateHandle(me, h, me, &mut copy, 0, 1, DUPLICATE_SAME_ACCESS) == 0 {
            return null_mut();
        }
        copy
    }
}

fn own_command_line() -> Vec<u16> {
    unsafe {
        let p = GetCommandLineW();
        let len = (0..).take_while(|&i| *p.add(i) != 0).count();
        std::slice::from_raw_parts(p, len).to_vec()
    }
}

fn command_line(own: &[u16], target: Option<&OsStr>, stamped: &[OsString]) -> Vec<u16> {
    let (first, rest) = own.split_at(first_word_len(own));
    let mut line = Vec::new();
    match target {
        Some(target) => quote(target, &mut line),
        None => line.extend_from_slice(first),
    }
    for arg in stamped {
        line.push(b' ' as u16);
        quote(arg, &mut line);
    }
    if !rest.is_empty() {
        if !matches!(rest[0], 0x20 | 0x09) {
            line.push(b' ' as u16);
        }
        line.extend_from_slice(rest);
    }
    line
}

fn first_word_len(line: &[u16]) -> usize {
    if line.first() == Some(&(b'"' as u16)) {
        match line[1..].iter().position(|&c| c == b'"' as u16) {
            Some(close) => close + 2,
            None => line.len(),
        }
    } else {
        line.iter()
            .position(|&c| matches!(c, 0x20 | 0x09))
            .unwrap_or(line.len())
    }
}

fn quote(arg: &OsStr, out: &mut Vec<u16>) {
    let arg = wide(arg);
    let bare = !arg.is_empty()
        && !arg
            .iter()
            .any(|&c| matches!(c, 0x20 | 0x09 | 0x0a | 0x0b | 0x22));
    if bare {
        out.extend_from_slice(&arg);
        return;
    }
    out.push(b'"' as u16);
    let mut backslashes = 0;
    for &c in &arg {
        if c == b'\\' as u16 {
            backslashes += 1;
        } else {
            if c == b'"' as u16 {
                out.extend(std::iter::repeat_n(b'\\' as u16, backslashes + 1));
            }
            backslashes = 0;
        }
        out.push(c);
    }
    out.extend(std::iter::repeat_n(b'\\' as u16, backslashes));
    out.push(b'"' as u16);
}

fn wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide().collect()
}

pub fn alert(message: &str) {
    let mut text = wide(OsStr::new(message));
    text.push(0);
    let mut caption = wide(OsStr::new("shim"));
    caption.push(0);
    unsafe {
        MessageBoxW(
            null_mut(),
            text.as_ptr(),
            caption.as_ptr(),
            MB_OK | MB_ICONERROR,
        )
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::ffi::OsStringExt;

    fn line(own: &str, stamped: &[&str]) -> String {
        let own = wide(OsStr::new(own));
        let stamped: Vec<OsString> = stamped.iter().map(OsString::from).collect();
        OsString::from_wide(&command_line(&own, None, &stamped))
            .into_string()
            .unwrap()
    }

    #[test]
    fn the_first_word_stays_and_stamped_arguments_follow_it() {
        assert_eq!(line("claude", &[]), "claude");
        assert_eq!(line("claude --resume x", &[]), "claude --resume x");
        assert_eq!(
            line(r#""C:\Users\u\.ghpm\bin\shell.exe" -c "a  b""#, &["-nol"]),
            r#""C:\Users\u\.ghpm\bin\shell.exe" -nol -c "a  b""#
        );
        assert_eq!(line(r#""a b"x"#, &[]), r#""a b" x"#);
        assert_eq!(line("claude\targ", &["s"]), "claude s\targ");
        assert_eq!(
            line(r#""no closing quote"#, &["s"]),
            r#""no closing quote s"#
        );
    }

    #[test]
    fn a_shim_not_named_for_its_target_starts_it_as_the_target() {
        let own = wide(OsStr::new(r#""C:\u\bin\mise@2026.4.11.exe" ls -c "a  b""#));
        let target = OsStr::new(r"C:\x\mise@2026.4.11\2026.4.11\mise\bin\mise.exe");
        assert_eq!(
            OsString::from_wide(&command_line(&own, Some(target), &[]))
                .into_string()
                .unwrap(),
            r#"C:\x\mise@2026.4.11\2026.4.11\mise\bin\mise.exe ls -c "a  b""#
        );
    }

    #[test]
    fn stamped_arguments_are_quoted_as_the_runtime_reads_them() {
        assert_eq!(
            line("x", &["", "a b", r#"say "hi""#, r"C:\my dir\", r"a\\b"]),
            r#"x "" "a b" "say \"hi\"" "C:\my dir\\" a\\b"#
        );
    }
}
