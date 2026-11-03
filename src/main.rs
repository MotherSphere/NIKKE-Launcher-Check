#![cfg_attr(windows, windows_subsystem = "windows")]

mod locate;
mod report;
mod scan;
mod ui;

use std::ffi::OsString;
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "\
NIKKE Launcher Check: looks for traces of the November 2026 NIKKE PC launcher compromise.
Read-only. No network access.

Usage:
  nikke-check                  Open the window
  nikke-check PATH             Open the window and scan this folder
  nikke-check --cli            Scan this computer and print a report
  nikke-check --cli PATH...    Scan only these folders and print a report
  nikke-check --help           Show this help

Exit codes (--cli):
  0  no traces found
  1  exposed (warnings only)
  2  infected (critical traces)
  3  no NIKKE install or launcher data found
  4  invalid arguments, or a folder that cannot be read
";

fn main() -> ExitCode {
    quiet_drive_errors();
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let Some(first) = args.first() else {
        return window(None);
    };
    attach_console();
    match first.to_str() {
        Some("--help" | "-h") => {
            print!("{USAGE}");
            ExitCode::SUCCESS
        }
        Some("--cli") => cli(&args[1..]),
        // One folder: dropping a folder on the .exe in Explorer starts it this way.
        arg if args.len() == 1 && !arg.is_some_and(|a| a.starts_with('-')) => match folder(first) {
            Ok(folder) => window(Some(folder)),
            Err(code) => code,
        },
        _ => {
            eprintln!("Unknown argument: {}\n\n{USAGE}", first.to_string_lossy());
            ExitCode::from(4)
        }
    }
}

fn window(folder: Option<PathBuf>) -> ExitCode {
    match ui::run(folder) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("Could not open the window: {err}");
            ExitCode::FAILURE
        }
    }
}

/// The absolute path of a folder argument, or exit code 4.
fn folder(path: &OsString) -> Result<PathBuf, ExitCode> {
    let path = PathBuf::from(path);
    match std::path::absolute(&path) {
        Ok(full) if full.is_dir() => {
            // A folder that cannot be listed would otherwise read as "NIKKE not found".
            if let Err(err) = std::fs::read_dir(&full) {
                eprintln!("Cannot read folder {}: {err}", path.display());
                return Err(ExitCode::from(4));
            }
            Ok(full)
        }
        _ => {
            eprintln!("Not a folder: {}", path.display());
            Err(ExitCode::from(4))
        }
    }
}

fn cli(paths: &[OsString]) -> ExitCode {
    let mut folders = Vec::new();
    for path in paths {
        match folder(path) {
            Ok(full) => folders.push(full),
            Err(code) => return code,
        }
    }
    let progress = locate::Progress::default();
    let result = if folders.is_empty() {
        scan::scan_computer(&progress)
    } else {
        scan::scan_folders(&folders, &progress)
    };
    let mut stdout = std::io::stdout().lock();
    let _ = stdout.write_all(report::render(&result).as_bytes());
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
