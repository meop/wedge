use std::fs;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

pub enum Subsystem {
    Gui,
    Console,
    Unknown(u16),
}

/// The subsystem of the program at path, or of the program an App Execution Alias there starts: what an MSIX package
/// puts on PATH, as winget's pwsh does, is one, and Windows refuses to open it as a file.
pub fn detect(path: &Path) -> io::Result<Subsystem> {
    match fs::File::open(path) {
        Ok(f) => detect_file(f),
        Err(e) if is_cant_access(&e) => match alias_target(path) {
            Some(target) => detect_file(fs::File::open(&target).map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!(
                        "{} is an alias for {}: {e}",
                        path.display(),
                        target.display()
                    ),
                )
            })?),
            None => Err(e),
        },
        Err(e) => Err(e),
    }
}

#[cfg(windows)]
fn is_cant_access(e: &io::Error) -> bool {
    e.raw_os_error() == Some(windows_sys::Win32::Foundation::ERROR_CANT_ACCESS_FILE as i32)
}

#[cfg(not(windows))]
fn is_cant_access(_: &io::Error) -> bool {
    false
}

#[cfg(windows)]
fn alias_target(path: &Path) -> Option<PathBuf> {
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    };
    use windows_sys::Win32::System::IO::DeviceIoControl;
    use windows_sys::Win32::System::Ioctl::FSCTL_GET_REPARSE_POINT;

    let f = fs::OpenOptions::new()
        .access_mode(0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
        .ok()?;
    let mut data = vec![0u8; 16 * 1024];
    let mut len = 0u32;
    let ok = unsafe {
        DeviceIoControl(
            f.as_raw_handle(),
            FSCTL_GET_REPARSE_POINT,
            std::ptr::null(),
            0,
            data.as_mut_ptr().cast(),
            data.len() as u32,
            &mut len,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return None;
    }
    alias_target_in(&data[..len as usize])
}

#[cfg(not(windows))]
fn alias_target(_: &Path) -> Option<PathBuf> {
    None
}

/// The program an App Execution Alias's reparse data names: after the tag, its length and a version, the strings
/// package family name, app id and target path, each UTF-16 and NUL-terminated.
#[cfg(any(windows, test))]
fn alias_target_in(data: &[u8]) -> Option<PathBuf> {
    const IO_REPARSE_TAG_APPEXECLINK: u32 = 0x8000_001B;
    if u32::from_le_bytes(data.get(0..4)?.try_into().ok()?) != IO_REPARSE_TAG_APPEXECLINK {
        return None;
    }
    let units: Vec<u16> = data
        .get(12..)?
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    let mut strings = units.split(|&u| u == 0);
    let target = String::from_utf16(strings.nth(2)?).ok()?;
    (!target.is_empty()).then(|| PathBuf::from(target))
}

fn detect_file(mut f: fs::File) -> io::Result<Subsystem> {
    let mut dos = [0u8; 64];
    f.read_exact(&mut dos)?;
    if &dos[0..2] != b"MZ" {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "not a PE file"));
    }
    let e_lfanew = u32::from_le_bytes(dos[0x3C..0x40].try_into().unwrap()) as u64;

    f.seek(SeekFrom::Start(e_lfanew))?;
    let mut pe = [0u8; 94];
    f.read_exact(&mut pe)?;
    if &pe[0..4] != b"PE\0\0" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "PE signature missing",
        ));
    }

    let subsystem = u16::from_le_bytes(pe[92..94].try_into().unwrap());
    Ok(match subsystem {
        2 => Subsystem::Gui,
        3 => Subsystem::Console,
        n => Subsystem::Unknown(n),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alias_data(tag: u32, strings: &[&str]) -> Vec<u8> {
        let mut body = 3u32.to_le_bytes().to_vec();
        for s in strings {
            for u in s.encode_utf16().chain([0]) {
                body.extend(u.to_le_bytes());
            }
        }
        let mut data = tag.to_le_bytes().to_vec();
        data.extend((body.len() as u16).to_le_bytes());
        data.extend([0, 0]);
        data.extend(body);
        data
    }

    #[test]
    fn an_alias_names_the_program_it_starts_third() {
        let pwsh = r"C:\Program Files\WindowsApps\Microsoft.PowerShell_7.6.9.0_x64__8wekyb3d8bbwe\pwsh.exe";
        let data = alias_data(
            0x8000_001B,
            &[
                "Microsoft.PowerShell_8wekyb3d8bbwe",
                "Microsoft.PowerShell_8wekyb3d8bbwe!App",
                pwsh,
                "0",
            ],
        );
        assert_eq!(alias_target_in(&data), Some(PathBuf::from(pwsh)));
    }

    #[test]
    fn other_reparse_data_names_no_program() {
        let symlink = alias_data(0xA000_000C, &["a", "b", r"C:\c.exe", "0"]);
        let short = alias_data(0x8000_001B, &["a", "b"]);
        let empty = alias_data(0x8000_001B, &["a", "b", "", "0"]);
        for data in [&symlink[..], &short[..], &empty[..], &short[..6]] {
            assert_eq!(alias_target_in(data), None);
        }
    }
}
