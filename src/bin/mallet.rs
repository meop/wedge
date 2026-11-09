use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use wedge::data::Trailer;
#[cfg(windows)]
use wedge::windows_pe;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.get(1).map(|s| s.as_str()) == Some("--version") {
        println!("{}", env!("CARGO_PKG_VERSION"));
        return;
    }
    if let Err(e) = run() {
        eprintln!("mallet: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let (source_path, target_path, stamped_args) = parse_args()?;
    let source_path = absolute_source(source_path)?;
    let resolved = wedge::pointer::resolve(&PathBuf::from(wedge::expand_env(
        &source_path.to_string_lossy(),
    )));
    let template = select_template(&resolved)?;
    stamp(&template, &source_path, &target_path, &stamped_args)
}

fn absolute_source(source_path: PathBuf) -> std::io::Result<PathBuf> {
    if source_path.to_string_lossy().starts_with('%') {
        Ok(source_path)
    } else {
        std::path::absolute(&source_path)
    }
}

fn stamp(
    template: &Path,
    source_path: &Path,
    target_path: &Path,
    stamped_args: &[String],
) -> Result<(), Box<dyn Error>> {
    let name = target_path
        .file_name()
        .ok_or("--target-path has no file name")?
        .to_string_lossy()
        .into_owned();
    let staged = target_path.with_file_name(format!(".{name}.{}.new", std::process::id()));
    let stamped = (|| -> Result<(), Box<dyn Error>> {
        let mut trailer = Vec::new();
        Trailer::append_to(source_path, stamped_args, &mut trailer)?;
        write_shim(template, &trailer, &staged, target_path, &name)?;
        replace(&staged, target_path, &name)
    })();
    if stamped.is_err() {
        let _ = fs::remove_file(&staged);
    }
    stamped
}

/// on macOS a Mach-O template gets an identity of its own, from where the shim lives: a UUID and a signing
/// identifier no other shim has, the same at every restamp whatever wedge it comes from, and an ad-hoc signature, as
/// the linker signed the template, that covers the trailer too. anything else is the template, byte for byte, with
/// the trailer after it
fn write_shim(
    template: &Path,
    trailer: &[u8],
    staged: &Path,
    target_path: &Path,
    name: &str,
) -> Result<(), Box<dyn Error>> {
    let mut bytes = fs::read(template)?;
    if cfg!(target_os = "macos") && wedge::macho::is_macho(&bytes) {
        let key = std::path::absolute(target_path)?;
        bytes = wedge::macho::restamp(&bytes, &key.to_string_lossy(), name, trailer)?;
    } else {
        bytes.extend_from_slice(trailer);
    }
    fs::write(staged, bytes)?;
    fs::set_permissions(staged, fs::metadata(template)?.permissions())?;
    Ok(())
}

fn replace(staged: &Path, target: &Path, name: &str) -> Result<(), Box<dyn Error>> {
    let aside = |n: &str| n.starts_with(&format!(".{name}.")) && n.ends_with(".old");
    if let Some(dir) = target.parent().filter(|d| !d.as_os_str().is_empty()) {
        for entry in fs::read_dir(dir)?.flatten() {
            if aside(&entry.file_name().to_string_lossy()) {
                let _ = fs::remove_file(entry.path());
            }
        }
    }

    match fs::rename(staged, target) {
        Ok(()) => return Ok(()),
        Err(e) if !target.exists() => return Err(e.into()),
        Err(_) => {}
    }
    let old = target.with_file_name(format!(".{name}.{}.old", std::process::id()));
    fs::rename(target, &old)?;
    if let Err(e) = fs::rename(staged, target) {
        let _ = fs::rename(&old, target);
        return Err(e.into());
    }
    let _ = fs::remove_file(&old);
    Ok(())
}

fn parse_args() -> Result<(PathBuf, PathBuf, Vec<String>), Box<dyn Error>> {
    let mut source: Option<PathBuf> = None;
    let mut target: Option<PathBuf> = None;
    let mut stamped_args = Vec::new();

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--source-path" => {
                source = Some(PathBuf::from(
                    args.next().ok_or("--source-path requires a value")?,
                ));
            }
            "--target-path" => {
                target = Some(PathBuf::from(
                    args.next().ok_or("--target-path requires a value")?,
                ));
            }
            "--arg" => {
                stamped_args.push(args.next().ok_or("--arg requires a value")?);
            }
            other => return Err(format!("unknown argument: {other}").into()),
        }
    }

    let source = source.ok_or("--source-path is required")?;
    let target = target.ok_or("--target-path is required")?;
    Ok((source, target, stamped_args))
}

fn select_template(source_path: &Path) -> Result<PathBuf, Box<dyn Error>> {
    let shim_dir = env::current_exe()?
        .parent()
        .ok_or("cannot locate mallet exe dir")?
        .to_path_buf();

    #[cfg(windows)]
    {
        let use_gui = matches!(windows_pe::detect(source_path)?, windows_pe::Subsystem::Gui);
        let name = if use_gui {
            "wedge-gui.exe"
        } else {
            "wedge.exe"
        };
        Ok(shim_dir.join(name))
    }

    #[cfg(unix)]
    {
        let _ = source_path;
        Ok(shim_dir.join("wedge"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Dir(PathBuf);

    impl Dir {
        fn new(name: &str) -> Self {
            let dir = env::temp_dir().join(format!("mallet-{name}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            Dir(dir)
        }

        fn names(&self) -> Vec<String> {
            let mut names: Vec<String> = fs::read_dir(&self.0)
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            names.sort();
            names
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_relative_source_is_made_absolute_and_a_named_one_is_kept() {
        let relative = absolute_source(PathBuf::from("bin/tool")).unwrap();
        assert_eq!(relative, env::current_dir().unwrap().join("bin/tool"));
        let named = PathBuf::from(r"%USERPROFILE%\.ghpm\bin\pwsh.exe");
        assert_eq!(absolute_source(named.clone()).unwrap(), named);
    }

    #[test]
    fn a_stamp_is_the_template_and_its_trailer() {
        let dir = Dir::new("fresh");
        let template = dir.0.join("template");
        fs::write(&template, b"template").unwrap();
        let shim = dir.0.join("shim");
        stamp(&template, Path::new("/opt/tool"), &shim, &["-a".into()]).unwrap();

        assert!(fs::read(&shim).unwrap().starts_with(b"template"));
        let t = Trailer::read_from(&shim).unwrap();
        assert_eq!(
            (t.source_path, t.args),
            (PathBuf::from("/opt/tool"), vec!["-a".to_string()])
        );
        assert_eq!(dir.names(), ["shim", "template"]);
    }

    #[test]
    fn a_stamp_replaces_the_shim_and_what_an_earlier_one_moved_aside() {
        let dir = Dir::new("replace");
        let template = dir.0.join("template");
        fs::write(&template, b"template").unwrap();
        let shim = dir.0.join("shim");
        fs::write(&shim, b"the old shim").unwrap();
        fs::write(dir.0.join(".shim.1.old"), b"moved aside").unwrap();
        fs::write(dir.0.join(".other.1.old"), b"another shim's").unwrap();
        stamp(&template, Path::new("/opt/tool"), &shim, &[]).unwrap();

        assert_eq!(
            Trailer::read_from(&shim).unwrap().source_path,
            PathBuf::from("/opt/tool")
        );
        assert_eq!(dir.names(), [".other.1.old", "shim", "template"]);
    }

    #[test]
    fn a_failed_stamp_leaves_nothing_behind() {
        let dir = Dir::new("failed");
        let shim = dir.0.join("shim");
        fs::write(&shim, b"the old shim").unwrap();
        assert!(
            stamp(
                &dir.0.join("no-template"),
                Path::new("/opt/tool"),
                &shim,
                &[]
            )
            .is_err()
        );

        assert_eq!(fs::read(&shim).unwrap(), b"the old shim");
        assert_eq!(dir.names(), ["shim"]);
    }
}
