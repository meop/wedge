use std::io::{self, Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::{fs, path::Path};

/// a trailer of the source path alone
const MAGIC: &[u8; 4] = b"SHIM";
/// a trailer of the source path and the arguments it always gets first, NUL separated
const MAGIC_ARGS: &[u8; 4] = b"SHM2";

pub struct Trailer {
    pub source_path: PathBuf,
    pub args: Vec<String>,
}

impl Trailer {
    pub fn read_from_self() -> Option<Self> {
        Self::read_from(&std::env::current_exe().ok()?)
    }

    /// the trailer at the end of the file, or, in a Mach-O mallet signed, right before the code signature
    pub fn read_from(path: &Path) -> Option<Self> {
        let mut f = fs::File::open(path).ok()?;
        let file_len = f.seek(SeekFrom::End(0)).ok()?;
        Self::read_ending_at(&mut f, file_len).or_else(|| {
            let end = signature_offset(&mut f)?;
            Self::read_ending_at(&mut f, end as u64)
        })
    }

    fn read_ending_at(f: &mut fs::File, end: u64) -> Option<Self> {
        f.seek(SeekFrom::Start(end.checked_sub(8)?)).ok()?;
        let mut tail = [0u8; 8];
        f.read_exact(&mut tail).ok()?;

        let magic = &tail[4..8];
        if magic != MAGIC && magic != MAGIC_ARGS {
            return None;
        }
        let path_len = u32::from_le_bytes(tail[0..4].try_into().unwrap()) as u64;
        f.seek(SeekFrom::Start(end.checked_sub(8 + path_len)?))
            .ok()?;
        let mut buf = vec![0u8; path_len as usize];
        f.read_exact(&mut buf).ok()?;

        Self::decode(magic, buf)
    }

    fn decode(magic: &[u8], payload: Vec<u8>) -> Option<Self> {
        let s = String::from_utf8(payload).ok()?;
        if magic == MAGIC {
            return Some(Trailer {
                source_path: PathBuf::from(s),
                args: Vec::new(),
            });
        }
        let mut parts = s.split('\0').map(String::from);
        Some(Trailer {
            source_path: PathBuf::from(parts.next()?),
            args: parts.collect(),
        })
    }

    /// with no arguments the trailer is the path-only one, byte for byte as before arguments existed
    pub fn append_to(
        source_path: &Path,
        args: &[String],
        dest: &mut impl io::Write,
    ) -> io::Result<()> {
        let s = source_path.to_str().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "source path is not valid UTF-8")
        })?;
        if args.iter().any(|a| a.contains('\0')) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "an argument contains NUL",
            ));
        }
        let (payload, magic) = if args.is_empty() {
            (s.to_string(), MAGIC)
        } else {
            (
                std::iter::once(s)
                    .chain(args.iter().map(String::as_str))
                    .collect::<Vec<_>>()
                    .join("\0"),
                MAGIC_ARGS,
            )
        };
        let bytes = payload.as_bytes();
        let len = bytes.len() as u32;
        dest.write_all(bytes)?;
        dest.write_all(&len.to_le_bytes())?;
        dest.write_all(magic)?;
        Ok(())
    }
}

/// where a Mach-O's code signature starts, read from its header and load commands
fn signature_offset(f: &mut fs::File) -> Option<usize> {
    f.seek(SeekFrom::Start(0)).ok()?;
    let mut head = [0u8; 32];
    f.read_exact(&mut head).ok()?;
    if !crate::macho::is_macho(&head) {
        return None;
    }
    let cmds_len = u32::from_le_bytes(head[20..24].try_into().unwrap()) as usize;
    let mut header = head.to_vec();
    header.resize(32 + cmds_len, 0);
    f.read_exact(&mut header[32..]).ok()?;
    crate::macho::code_signature_offset(&header)
}

/// `%NAME%` replaced by what `lookup` has for NAME; a name it has nothing for is left as written, as Windows'
/// ExpandEnvironmentStrings leaves one
pub fn expand(s: &str, lookup: impl Fn(&str) -> Option<String>) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        match after.find('%') {
            Some(end) if end > 0 => match lookup(&after[..end]) {
                Some(value) => {
                    out.push_str(&value);
                    rest = &after[end + 1..];
                }
                // the closing % may open the next name
                None => {
                    out.push('%');
                    out.push_str(&after[..end]);
                    rest = &after[end..];
                }
            },
            _ => {
                out.push('%');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trailer(path: &str, args: &[&str]) -> Vec<u8> {
        let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
        let mut out = Vec::new();
        Trailer::append_to(Path::new(path), &args, &mut out).unwrap();
        out
    }

    fn read(bytes: &[u8]) -> Trailer {
        let (head, tail) = bytes.split_at(bytes.len() - 8);
        let len = u32::from_le_bytes(tail[0..4].try_into().unwrap()) as usize;
        assert_eq!(len, head.len());
        Trailer::decode(&tail[4..8], head.to_vec()).unwrap()
    }

    #[test]
    fn a_path_alone_is_the_original_trailer() {
        let bytes = trailer(r"C:\a\pwsh.exe", &[]);
        let mut expected = br"C:\a\pwsh.exe".to_vec();
        expected.extend(13u32.to_le_bytes());
        expected.extend(b"SHIM");
        assert_eq!(bytes, expected);
        let t = read(&bytes);
        assert_eq!(
            (t.source_path, t.args.len()),
            (PathBuf::from(r"C:\a\pwsh.exe"), 0)
        );
    }

    #[test]
    fn arguments_come_back_in_order() {
        let t = read(&trailer(
            r"%USERPROFILE%\.ghpm\bin\pwsh.exe",
            &["-nol", "", "a b"],
        ));
        assert_eq!(
            t.source_path,
            PathBuf::from(r"%USERPROFILE%\.ghpm\bin\pwsh.exe")
        );
        assert_eq!(t.args, ["-nol", "", "a b"]);
    }

    #[test]
    fn expand_replaces_known_names_and_keeps_the_rest() {
        let lookup = |k: &str| (k == "USERPROFILE").then(|| r"C:\Users\u".to_string());
        assert_eq!(
            expand(r"%USERPROFILE%\.ghpm\bin\pwsh.exe", lookup),
            r"C:\Users\u\.ghpm\bin\pwsh.exe"
        );
        assert_eq!(expand("100% %NOPE% %%", lookup), "100% %NOPE% %%");
        assert_eq!(expand("%NOPE%USERPROFILE%", lookup), r"%NOPEC:\Users\u");
        assert_eq!(expand("no names", lookup), "no names");
    }
}
