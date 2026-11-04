//! Shows a file or folder in the file manager, or starts Task Manager, Registry
//! Editor or the browser. These only open windows: nothing is changed. Best
//! effort: the caller shows the error and carries on.

use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::i18n::{Text, msg};

#[derive(Debug, Clone)]
pub enum Target {
    /// The file manager at the parent folder, with this file or folder selected.
    Reveal(PathBuf),
    TaskManager,
    RegistryEditor,
    Link(String),
}

/// Runs on a worker thread: on Linux and macOS it waits for the opener to exit.
pub fn open(target: &Target) -> Result<(), Text> {
    match target {
        Target::Reveal(path) => match existing(path) {
            Some(p) if p == *path => reveal(&p),
            // Gone since the scan: show the nearest folder that is still there.
            Some(p) => folder(&p),
            None => Err(msg("open.gone").arg("path", path.display().to_string())),
        },
        Target::TaskManager => program("System32\\Taskmgr.exe"),
        Target::RegistryEditor => program("regedit.exe"),
        Target::Link(url) => link(url),
    }
}

/// An error of the system, in its own words.
fn os_error(err: io::Error) -> Text {
    Text::Raw(err.to_string())
}

fn existing(path: &Path) -> Option<PathBuf> {
    path.ancestors().find(|p| p.exists()).map(Path::to_path_buf)
}

/// A program of the Windows folder by full path. A bare name would also find a
/// copy next to this tool, which users run from Downloads.
#[cfg(windows)]
fn windows_dir(rel: &str) -> PathBuf {
    let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
    Path::new(&root).join(rel)
}

#[cfg(windows)]
fn reveal(path: &Path) -> Result<(), Text> {
    use std::os::windows::process::CommandExt;
    // explorer reads "/select," and the quoted path as one argument; the standard
    // quoting would wrap the whole argument in quotes. Windows paths cannot hold '"'.
    Command::new(windows_dir("explorer.exe")).raw_arg(format!("/select,\"{}\"", plain(path))).spawn().map(drop).map_err(os_error)
}

/// Quoted by hand: explorer splits its command line at commas, and the standard
/// quoting only quotes an argument with a space or a tab.
#[cfg(windows)]
fn folder(path: &Path) -> Result<(), Text> {
    use std::os::windows::process::CommandExt;
    Command::new(windows_dir("explorer.exe")).raw_arg(format!("\"{}\"", plain(path))).spawn().map(drop).map_err(os_error)
}

/// Explorer does not take the \\?\ paths that canonicalize returns.
#[cfg(windows)]
fn plain(path: &Path) -> String {
    let s = path.display().to_string();
    match s.strip_prefix(r"\\?\UNC\") {
        Some(rest) => format!(r"\\{rest}"),
        None => s.strip_prefix(r"\\?\").unwrap_or(&s).to_string(),
    }
}

/// Task Manager and Registry Editor ask for administrator rights, which
/// CreateProcess cannot start (error 740); ShellExecute shows the prompt.
#[cfg(windows)]
fn program(rel: &str) -> Result<(), Text> {
    shell_execute(&windows_dir(rel).to_string_lossy())
}

#[cfg(windows)]
fn link(url: &str) -> Result<(), Text> {
    shell_execute(url)
}

#[cfg(windows)]
fn shell_execute(file: &str) -> Result<(), Text> {
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
    let wide = |s: &str| s.encode_utf16().chain([0]).collect::<Vec<u16>>();
    let (verb, file) = (wide("open"), wide(file));
    // SAFETY: both strings are NUL-terminated and outlive the call; the other pointers may be null.
    let code = unsafe {
        ShellExecuteW(std::ptr::null_mut(), verb.as_ptr(), file.as_ptr(), std::ptr::null(), std::ptr::null(), SW_SHOWNORMAL)
    } as isize;
    // Values above 32 mean success; the others are error codes.
    if code > 32 { Ok(()) } else { Err(msg("open.shell_execute").arg("code", code.to_string())) }
}

#[cfg(target_os = "macos")]
fn reveal(path: &Path) -> Result<(), Text> {
    run(Command::new("open").arg("-R").arg(path))
}

#[cfg(target_os = "macos")]
fn folder(path: &Path) -> Result<(), Text> {
    run(Command::new("open").arg(path))
}

#[cfg(target_os = "macos")]
fn link(url: &str) -> Result<(), Text> {
    run(Command::new("open").arg(url))
}

/// The freedesktop file manager interface selects the item (Dolphin, Nautilus,
/// Nemo, Thunar and others). Without it, the parent folder opens.
#[cfg(all(unix, not(target_os = "macos")))]
fn reveal(path: &Path) -> Result<(), Text> {
    let uri = file_uri(path);
    let shown = if let Some(gdbus) = in_path("gdbus") {
        // The URI is percent-encoded, so it holds no quote that would end the GVariant string.
        let array = format!("['{uri}']");
        let call = ["call", "--session", "--timeout=10", "--dest", "org.freedesktop.FileManager1"];
        let method = ["--object-path", "/org/freedesktop/FileManager1", "--method", "org.freedesktop.FileManager1.ShowItems"];
        run(Command::new(gdbus).args(call).args(method).arg(array).arg("''")).is_ok()
    } else if let Some(busctl) = in_path("busctl") {
        let call = ["--user", "--timeout=10", "call", "org.freedesktop.FileManager1", "/org/freedesktop/FileManager1"];
        run(Command::new(busctl).args(call).args(["org.freedesktop.FileManager1", "ShowItems", "ass", "1"]).arg(&uri).arg("")).is_ok()
    } else {
        false
    };
    if shown { Ok(()) } else { folder(path.parent().unwrap_or(path)) }
}

#[cfg(all(unix, not(target_os = "macos")))]
fn folder(path: &Path) -> Result<(), Text> {
    run(Command::new("xdg-open").arg(path))
}

#[cfg(all(unix, not(target_os = "macos")))]
fn link(url: &str) -> Result<(), Text> {
    run(Command::new("xdg-open").arg(url))
}

#[cfg(not(windows))]
fn program(rel: &str) -> Result<(), Text> {
    Err(msg("open.windows_only").arg("program", rel))
}

/// Waits for an opener (they exit once the window is up) and checks its exit status.
#[cfg(unix)]
fn run(command: &mut Command) -> Result<(), Text> {
    use std::process::Stdio;
    let status = command.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).status().map_err(os_error)?;
    if status.success() { Ok(()) } else { Err(msg("open.failed").arg("status", status.to_string())) }
}

#[cfg(all(unix, not(target_os = "macos")))]
fn in_path(name: &str) -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?).map(|d| d.join(name)).find(|p| p.is_file())
}

/// file:// URI with every byte outside the unreserved set and '/' percent-encoded.
#[cfg(all(unix, not(target_os = "macos")))]
fn file_uri(path: &Path) -> String {
    use std::os::unix::ffi::OsStrExt;
    let mut uri = String::from("file://");
    for &b in path.as_os_str().as_bytes() {
        if b.is_ascii_alphanumeric() || b"-._~/".contains(&b) {
            uri.push(b as char);
        } else {
            uri.push_str(&format!("%{b:02X}"));
        }
    }
    uri
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn file_uris_are_encoded() {
        assert_eq!(file_uri(Path::new("/home/a/My Games/it's [1]%")), "file:///home/a/My%20Games/it%27s%20%5B1%5D%25");
        assert_eq!(file_uri(Path::new("/tmp/é")), "file:///tmp/%C3%A9");
    }

    #[test]
    fn missing_paths_fall_back_to_a_parent() {
        let dir = std::env::temp_dir();
        assert_eq!(existing(&dir.join("nikke-check-test-missing/a/b")), Some(dir));
    }
}
