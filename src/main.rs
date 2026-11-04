#![cfg_attr(windows, windows_subsystem = "windows")]

mod exposure;
mod guide;
mod hsts;
mod i18n;
mod ldb;
mod locate;
mod open;
mod redact;
mod report;
mod scan;
mod timeline;
mod ui;

use std::ffi::OsString;
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use crate::i18n::{Lang, Text, msg};

fn main() -> ExitCode {
    quiet_drive_errors();
    let mut args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let lang = match take_lang(&mut args) {
        Ok(lang) => lang.unwrap_or_else(Lang::detect),
        Err(err) => {
            attach_console();
            eprintln!("{}", err.render(Lang::detect()));
            return ExitCode::from(4);
        }
    };
    let usage = || msg("cli.usage").arg("codes", Lang::codes()).render(lang);
    let Some(first) = args.first() else {
        return window(None, lang);
    };
    match first.to_str() {
        Some("--help" | "-h") => {
            attach_console();
            print!("{}", usage());
            ExitCode::SUCCESS
        }
        Some("--cli") => {
            attach_console();
            cli(&args[1..], lang)
        }
        // Items dropped on the .exe in Explorer arrive here with no console to print to,
        // so the window opens and says what is wrong with a path that is not a folder.
        // shortcut: only the first dropped item is scanned, take a list if users drop several.
        arg if !arg.is_some_and(|a| a.starts_with('-')) => {
            let path = PathBuf::from(first);
            window(Some(std::path::absolute(&path).unwrap_or(path)), lang)
        }
        _ => {
            attach_console();
            let unknown = msg("cli.unknown_argument").arg("arg", first.to_string_lossy().into_owned());
            eprintln!("{}\n\n{}", unknown.render(lang), usage());
            ExitCode::from(4)
        }
    }
}

/// Takes every `--lang CODE` out of `args`; the last one counts. Without one,
/// the window and the report use the system language.
fn take_lang(args: &mut Vec<OsString>) -> Result<Option<Lang>, Text> {
    let mut lang = None;
    while let Some(i) = args.iter().position(|a| a == "--lang") {
        args.remove(i);
        if i == args.len() {
            return Err(msg("cli.lang_missing").arg("codes", Lang::codes()));
        }
        let code = args.remove(i).to_string_lossy().into_owned();
        match Lang::from_code(&code) {
            Some(l) => lang = Some(l),
            None => return Err(msg("cli.lang_unknown").arg("code", code).arg("codes", Lang::codes())),
        }
    }
    Ok(lang)
}

fn window(folder: Option<PathBuf>, lang: Lang) -> ExitCode {
    skip_opengl();
    match run_window(folder, lang) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{}", msg("cli.window_failed").arg("error", err.as_str()).render(lang));
            error_box(&err, lang);
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(windows))]
fn run_window(folder: Option<PathBuf>, lang: Lang) -> Result<(), String> {
    ui::run(folder, lang).map_err(|e| e.to_string())
}

/// The Windows build has no console, so a panic would close the window without
/// a word. The hook keeps the panic message for the error box.
#[cfg(windows)]
fn run_window(folder: Option<PathBuf>, lang: Lang) -> Result<(), String> {
    use std::sync::{Arc, Mutex};
    let message = Arc::new(Mutex::new(String::new()));
    let kept = message.clone();
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if let Ok(mut m) = kept.lock() {
            *m = info.to_string();
        }
        default(info);
    }));
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| ui::run(folder, lang)))
        .map_err(|_| message.lock().map(|m| m.clone()).unwrap_or_default())?
        .map_err(|e| e.to_string())
}

/// Says what went wrong when the window cannot open, and how to get the report anyway.
#[cfg(windows)]
fn error_box(err: &str, lang: Lang) {
    use windows_sys::Win32::UI::WindowsAndMessaging::{MB_ICONERROR, MB_OK, MessageBoxW};
    let text = msg("cli.error_box").arg("error", err).arg("command", guide::powershell_cli("")).render(lang);
    let wide = |s: &str| s.encode_utf16().chain([0]).collect::<Vec<u16>>();
    let (text, title) = (wide(&text), wide(report::APP_NAME));
    // SAFETY: both strings are NUL-terminated and outlive the call; no owner window.
    unsafe {
        MessageBoxW(std::ptr::null_mut(), text.as_ptr(), title.as_ptr(), MB_OK | MB_ICONERROR);
    }
}

#[cfg(not(windows))]
fn error_box(_: &str, _: Lang) {}

/// The absolute path of a folder argument, or exit code 4.
fn folder(path: &OsString, lang: Lang) -> Result<PathBuf, ExitCode> {
    let path = PathBuf::from(path);
    let shown = path.display().to_string();
    match std::path::absolute(&path) {
        Ok(full) if full.is_dir() => {
            // A folder that cannot be listed would otherwise read as "NIKKE not found".
            if let Err(err) = std::fs::read_dir(&full) {
                eprintln!("{}", msg("cli.cannot_read_folder").arg("path", shown).arg("error", err.to_string()).render(lang));
                return Err(ExitCode::from(4));
            }
            Ok(full)
        }
        _ => {
            eprintln!("{}", msg("cli.not_a_folder").arg("path", shown).render(lang));
            Err(ExitCode::from(4))
        }
    }
}

fn cli(args: &[OsString], lang: Lang) -> ExitCode {
    let redact = args.iter().any(|a| a == "--redact");
    let full = args.iter().any(|a| a == "--full");
    let mut folders = Vec::new();
    for path in args.iter().filter(|a| *a != "--redact" && *a != "--full") {
        match folder(path, lang) {
            Ok(full) => folders.push(full),
            Err(code) => return code,
        }
    }
    let progress = locate::Progress::default();
    let result = if folders.is_empty() {
        scan::scan_computer(full, &progress)
    } else {
        scan::scan_folders(&folders, &progress)
    };
    let mut text = report::render(&result, lang);
    if redact {
        text = redact::Secrets::of(&result).apply(&text);
    }
    let mut stdout = std::io::stdout().lock();
    let _ = stdout.write_all(text.as_bytes());
    let _ = stdout.flush();
    ExitCode::from(result.verdict.exit_code())
}

/// The Windows build is a GUI program; reuse the console it was started from.
#[cfg(windows)]
fn attach_console() {
    use windows_sys::Win32::System::Console::{ATTACH_PARENT_PROCESS, AttachConsole};
    // SAFETY: plain Win32 call with a constant argument; failure only means no console.
    unsafe {
        AttachConsole(ATTACH_PARENT_PROCESS);
    }
}

#[cfg(not(windows))]
fn attach_console() {}

/// Stops Windows from showing "There is no disk in the drive" boxes when the
/// scan probes empty card readers and optical drives.
#[cfg(windows)]
fn quiet_drive_errors() {
    use windows_sys::Win32::System::Diagnostics::Debug::{SEM_FAILCRITICALERRORS, SEM_NOOPENFILEERRORBOX, SetErrorMode};
    // SAFETY: plain Win32 call with constant flags.
    unsafe {
        SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOOPENFILEERRORBOX);
    }
}

#[cfg(not(windows))]
fn quiet_drive_errors() {}

/// AMD's OpenGL driver (atio6axx.dll) can crash the process while wgpu probes its
/// backends, so on Windows the window uses DirectX 12 or Vulkan unless WGPU_BACKEND is set.
/// With neither, iced falls back to its software renderer.
#[cfg(windows)]
fn skip_opengl() {
    if std::env::var_os("WGPU_BACKEND").is_none() {
        // SAFETY: runs before the window starts any thread, so nothing reads the environment concurrently.
        unsafe { std::env::set_var("WGPU_BACKEND", "dx12,vulkan") };
    }
}

#[cfg(not(windows))]
fn skip_opengl() {}
