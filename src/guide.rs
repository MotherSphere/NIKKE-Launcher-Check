//! The result in plain words, for the window and the report: four answers
//! ("What happened") and the steps to take ("What to do"), built only from
//! what the scan found.

use std::path::{Path, PathBuf};

use crate::exposure::Exposure;
use crate::locate::TargetKind;
use crate::report;
use crate::scan::{self, ATTACKER_IPS, CLSID, Finding, FindingKind as K, ScanResult, Verdict};
use crate::timeline::{AgentRun, KNOWN_BUILDS, PayloadBuild, RunKind};

/// How an answer reads for the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    Bad,
    Unsure,
    Good,
}

#[derive(Debug, Clone)]
pub struct Answer {
    pub question: &'static str,
    pub reply: &'static str,
    pub tone: Tone,
    pub lines: Vec<String>,
    /// The agent's logged runs, one line each (first answer only).
    pub runs: Vec<String>,
}

/// Kinds that show the agent itself reached this computer.
const RAN: [K; 11] = [
    K::AgentRan,
    K::AgentState,
    K::PayloadDownloaded,
    K::PayloadFile,
    K::AgentServerContacted,
    K::TempFile,
    K::ChromeDll,
    K::RegistryKey,
    K::RegistryLeftover,
    K::LegacyDll,
    K::DllLoaded,
];
const PERSISTENCE: [K; 5] = [K::ChromeDll, K::RegistryKey, K::RegistryLeftover, K::LegacyDll, K::DllLoaded];
const CACHE_TRACES: [K; 4] = [K::AgentState, K::AgentServerContacted, K::LoaderCached, K::LauncherContacted];

fn findings(r: &ScanResult) -> impl Iterator<Item = &Finding> {
    r.groups.iter().flat_map(|g| &g.findings)
}

fn of<'a>(r: &'a ScanResult, kinds: &'a [K]) -> impl Iterator<Item = &'a Finding> {
    findings(r).filter(|f| kinds.contains(&f.kind))
}

fn any(r: &ScanResult, kinds: &[K]) -> bool {
    of(r, kinds).next().is_some()
}

fn push_new(lines: &mut Vec<String>, line: String) {
    if !lines.contains(&line) {
        lines.push(line);
    }
}

fn has_target(r: &ScanResult, kind: TargetKind) -> bool {
    r.targets.iter().any(|t| t.kind == kind)
}

pub fn answers(r: &ScanResult) -> [Answer; 4] {
    [did_it_run(r), still_active(r), to_clean(r), protected(r)]
}

fn answer(question: &'static str, reply: &'static str, tone: Tone, lines: Vec<String>) -> Answer {
    Answer { question, reply, tone, lines, runs: Vec::new() }
}

fn did_it_run(r: &ScanResult) -> Answer {
    const Q: &str = "Did the malware run on this computer?";
    let mut lines = Vec::new();
    if any(r, &RAN) {
        for f in of(r, &RAN) {
            push_new(&mut lines, format!("{}.", f.title));
        }
        let mut a = answer(Q, "Yes", Tone::Bad, lines);
        a.runs = r.runs.iter().map(run_line).collect();
        return a;
    }
    let loader = any(r, &[K::LoaderCached, K::LauncherContacted]);
    if r.verdict == Verdict::NotFound {
        lines.push("No NIKKE install or launcher data was found, so there was nothing to check.".into());
        return answer(Q, "Cannot tell", Tone::Unsure, lines);
    }
    if r.verdict == Verdict::Infected {
        for f in findings(r).filter(|f| f.severity == scan::Severity::Critical) {
            push_new(&mut lines, format!("{}.", f.title));
        }
        lines.push("No log shows the agent itself starting, but logs can be deleted or cut.".into());
        return answer(Q, "Cannot tell", Tone::Unsure, lines);
    }
    if loader {
        lines.push("The launcher loaded the malicious script, but no trace of the agent was found.".into());
        lines.push("The agent was sent only on some launches, from October 23, 2026 at the latest. If the launcher was open on or after that date, act as if it ran.".into());
    } else {
        lines.push("No trace of the malicious script or the agent was found.".into());
    }
    if !has_target(r, TargetKind::InstallDir) {
        lines.push("The NIKKE install folder was not found, so debug.log and the download logs were not checked.".into());
    }
    let gaps = any(r, &[K::Coverage]);
    if gaps {
        lines.push("Part of this scan could not be done. See \"What this scan could not check\" in Details.".into());
    }
    // A quick scan can miss an old install deeper down, so its "No" is not a clean result.
    if let Some(depth) = r.stats.depth_limit {
        lines.push(format!("This was a quick scan, which opens folders only {depth} levels deep. The full scan also checks deeper folders."));
    }
    if !loader {
        lines.push("Finding nothing is not proof that the computer is clean.".into());
    }
    let unsure = loader || gaps || r.stats.depth_limit.is_some();
    answer(Q, "No", if unsure { Tone::Unsure } else { Tone::Good }, lines)
}

/// One logged step of an agent run. "Hide my info" replaces the computer name
/// in the copied or saved report.
pub fn run_line(run: &AgentRun) -> String {
    let time = run.time.as_deref().unwrap_or("time not logged");
    let what = match run.kind {
        RunKind::Downloaded => match &run.file {
            Some(file) => format!("the launcher downloaded the agent and saved it as {file}"),
            None => "the launcher downloaded the agent".into(),
        },
        RunKind::Adopted => "the agent started for the first time on this computer and created its ID".into(),
        RunKind::Resumed => "the agent started again with the ID it saved".into(),
        RunKind::Started => match &run.host {
            Some(host) => format!("the agent sent the computer name {host} to the attacker"),
            None => "the agent sent the computer name to the attacker".into(),
        },
    };
    let source = run.source.file_name().map(|n| format!(" (from {})", n.to_string_lossy())).unwrap_or_default();
    format!("{time}: {what}{source}")
}

fn still_active(r: &ScanResult) -> Answer {
    const Q: &str = "Is anything still active?";
    let mut lines = Vec::new();
    for f in findings(r) {
        let line = match f.kind {
            K::LauncherRunning => "The NIKKE launcher is running now. While it runs, the attacker can send it commands.".to_string(),
            K::DllLoaded => format!("The malware's DLL is loaded now in {}.", program_names(f).join(", ")),
            K::RegistryKey => "The registry key that makes the browser load the malware's DLL is set.".to_string(),
            K::ChromeDll | K::LegacyDll => format!("{}.", f.title),
            _ => continue,
        };
        push_new(&mut lines, line);
    }
    if lines.is_empty() {
        lines.push("The launcher is not running, and no DLL is installed or set to load.".into());
        return answer(Q, "No", Tone::Good, lines);
    }
    answer(Q, "Yes", Tone::Bad, lines)
}

fn to_clean(r: &ScanResult) -> Answer {
    const Q: &str = "Is there something to clean up?";
    let mut lines = Vec::new();
    for f in findings(r) {
        let line = match f.kind {
            K::ChromeDll => format!("The {} DLL folder: {}", browser(f), dll_folder(f).display()),
            K::RegistryKey => format!("The HKCU registry key {CLSID}."),
            K::RegistryLeftover => format!("The empty HKCU registry key {CLSID}, left after the malware cleared the DLL path from it."),
            K::LegacyDll => format!("Older DLL files in {}", shown(f.path.as_deref())),
            K::TempFile => format!("k2f files in {}", shown(f.path.as_deref().and_then(Path::parent))),
            _ => continue,
        };
        push_new(&mut lines, line);
    }
    for c in caches(r).iter().filter(|c| c.traces) {
        push_new(&mut lines, format!("The launcher cache, which holds traces of the malware: {}", c.tbs.display()));
    }
    if !lines.is_empty() {
        return answer(Q, "Yes", Tone::Bad, lines);
    }
    if has_target(r, TargetKind::LauncherData) {
        lines.push("No file left by the malware was found. Delete the launcher cache (tbs_cache) anyway before you open the launcher again: it can still hold the malicious script from before the fix.".into());
    } else {
        lines.push("Nothing left by the malware was found.".into());
    }
    answer(Q, "No", Tone::Good, lines)
}

fn ip_line() -> String {
    format!(
        "The hosts file cannot block IP addresses, and this scan cannot check a firewall. Block {} and {} in your firewall or router.",
        ATTACKER_IPS[0], ATTACKER_IPS[1]
    )
}

fn protected(r: &ScanResult) -> Answer {
    const Q: &str = "Are you protected for next time?";
    let Some(h) = &r.hosts else {
        return answer(Q, "Cannot tell", Tone::Unsure, vec!["The hosts file was not checked.".into(), ip_line()]);
    };
    let mut lines: Vec<String> = h.note.iter().map(|n| n.to_string()).collect();
    lines.extend(h.domains.iter().map(|(d, b)| format!("{d}: {} in the hosts file.", report::block_state(*b))));
    lines.push(ip_line());
    let blocked = h.domains.iter().filter(|(_, b)| *b == Some(true)).count();
    let (reply, tone) = if h.domains.iter().any(|(_, b)| b.is_none()) {
        ("Cannot tell", Tone::Unsure)
    } else if blocked == h.domains.len() {
        ("Yes", Tone::Good)
    } else if blocked > 0 {
        ("Partly", Tone::Unsure)
    } else {
        ("No", Tone::Bad)
    };
    answer(Q, reply, tone, lines)
}

/// "6ae90538-3214f, uploaded ..., 205,135 bytes, one of the 5 known builds."
pub fn build_line(b: &PayloadBuild) -> String {
    let mut s = b.etag.clone().unwrap_or_else(|| "No ETag".into());
    match (&b.uploaded, &b.last_modified) {
        (Some(t), _) => s += &format!(", uploaded {t}"),
        (None, Some(t)) => s += &format!(", last modified {t}"),
        _ => {}
    }
    if let Some(size) = b.size {
        s += &format!(", {} bytes", report::thousands(size));
    }
    s += &if b.known {
        format!(", one of the {} known builds.", KNOWN_BUILDS.len())
    } else {
        format!(". It is not one of the {} known builds.", KNOWN_BUILDS.len())
    };
    if let Some(t) = &b.time {
        s += &format!(" The launcher received it {t}.");
    }
    s
}

// ------------------------------------------------------------------ steps

#[derive(Debug, Clone)]
pub struct Step {
    pub title: String,
    pub parts: Vec<Part>,
}

#[derive(Debug, Clone)]
pub enum Part {
    Text(String),
    /// One line of a list.
    Item(String),
    /// Text to copy or type exactly: a path, a registry key, a command.
    Code(String),
    /// Buttons in the window. The report prints only a `Reveal` path that no `Code` part shows.
    Actions(Vec<Action>),
}

#[derive(Debug, Clone)]
pub enum Action {
    /// Shows this file or folder selected in the file manager.
    Reveal(PathBuf),
    Copy(&'static str, String),
    TaskManager,
    RegistryEditor,
    SaveReport,
    CopyReport,
    ScanFolder,
    FullScan,
}

fn text(s: impl Into<String>) -> Part {
    Part::Text(s.into())
}

fn step(title: impl Into<String>, parts: Vec<Part>) -> Step {
    Step { title: title.into(), parts }
}

/// The launcher runs or a program has the DLL loaded: the window opens on the steps.
pub fn act_now(r: &ScanResult) -> bool {
    any(r, &[K::LauncherRunning, K::DllLoaded])
}

pub fn steps(r: &ScanResult) -> Vec<Step> {
    let found = r.verdict != Verdict::NotFound;
    // Scanning the install reads debug.log, which can turn the result into Infected.
    let rescan = found && !has_target(r, TargetKind::InstallDir);
    let mut out = Vec::new();
    if !found {
        out.push(scan_folder_step(r));
    }
    if act_now(r) {
        out.push(close_step(r));
    }
    if matches!(r.verdict, Verdict::Infected | Verdict::Exposed) {
        // Before the DLL step: its restart closes this window.
        out.push(save_step(r, restart_first(r)));
    }
    // After a quick scan without proof of the agent, the full scan is the next check.
    let quick_unsure = matches!(r.verdict, Verdict::NoTraces | Verdict::Exposed) && r.stats.depth_limit.is_some();
    if rescan && r.verdict != Verdict::Infected {
        out.push(scan_folder_step(r));
    } else if quick_unsure {
        out.push(step("Run the full scan", full_scan_parts(r)));
    }
    if any(r, &PERSISTENCE) {
        out.push(dll_step(r));
    }
    if found {
        out.push(cache_step(r));
        out.push(password_step(r));
    }
    out.push(block_step(r));
    if rescan && r.verdict == Verdict::Infected {
        out.push(scan_folder_step(r));
    }
    out.push(wait_step(r.verdict == Verdict::Infected && any(r, &RAN)));
    out
}

/// The PowerShell command that runs this program with `--cli`, from the folder
/// that holds it. A browser saves a second download as "<name> (1).exe".
pub fn powershell_cli(args: &str) -> String {
    let exe = std::env::current_exe()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .unwrap_or_else(|| "nikke-check-windows-x86_64.exe".into());
    ps_command(&exe, args)
}

fn ps_command(exe: &str, args: &str) -> String {
    format!("& '.\\{}' --cli{args} | Out-Host", exe.replace('\'', "''"))
}

fn scan_folder_step(r: &ScanResult) -> Step {
    const INTRO: &str = "If NIKKE is installed somewhere this scan did not look, such as another drive, scan that folder";
    let mut parts = if cfg!(windows) {
        let cmd = powershell_cli(r" 'D:\Games\NIKKE'");
        vec![
            text(format!("{INTRO} with \"Scan a folder...\". In PowerShell, from the folder that holds this program, this command scans it too. Put your NIKKE folder in place of D:\\Games\\NIKKE.")),
            Part::Code(cmd.clone()),
            Part::Actions(vec![Action::ScanFolder, Action::Copy("Copy command", cmd)]),
        ]
    } else {
        vec![
            text(format!("{INTRO}: \"Scan a folder...\" in the window, or nikke-check --cli <folder> in a terminal.")),
            Part::Actions(vec![Action::ScanFolder]),
        ]
    };
    parts.extend(full_scan_parts(r));
    step("Scan the folder where NIKKE is installed", parts)
}

/// After a quick scan: what the full scan adds, its button and its command.
fn full_scan_parts(r: &ScanResult) -> Vec<Part> {
    let Some(depth) = r.stats.depth_limit else {
        return Vec::new();
    };
    let mut parts = vec![text(format!("This was a quick scan, which opens folders only {depth} levels deep. If you do not know where NIKKE is, or an older copy may be deeper, the full scan opens every folder on every local drive. It can take a long time on large drives."))];
    if cfg!(windows) {
        let cmd = powershell_cli(" --full");
        parts.push(text("In PowerShell, from the folder that holds this program:"));
        parts.push(Part::Code(cmd.clone()));
        parts.push(Part::Actions(vec![Action::FullScan, Action::Copy("Copy command", cmd)]));
    } else {
        parts.push(text("In a terminal: nikke-check --cli --full"));
        parts.push(Part::Actions(vec![Action::FullScan]));
    }
    parts
}

fn close_step(r: &ScanResult) -> Step {
    let mut parts = Vec::new();
    let mut programs = Vec::new();
    if any(r, &[K::LauncherRunning]) {
        parts.push(text("The NIKKE launcher is running. While it runs, the attacker can send commands to this computer. Close it now and disconnect this computer from the network."));
        programs.push("nikke_launcher.exe".to_string());
    }
    let mut explorer = false;
    for f in of(r, &[K::DllLoaded]) {
        let names = program_names(f);
        let (has, them) = if names.len() == 1 { ("has", "it") } else { ("have", "them") };
        parts.push(text(format!("{} {has} the malware's DLL loaded. Close {them} if you can. The restart in a later step unloads the DLL from every program.", names.join(", "))));
        for name in names {
            if name.eq_ignore_ascii_case("explorer.exe") {
                explorer = true;
            } else {
                push_new(&mut programs, name);
            }
        }
    }
    if explorer {
        parts.push(text("Do not end explorer.exe: it runs the taskbar and the desktop. The restart unloads the DLL from it."));
    }
    if !programs.is_empty() {
        parts.push(text(format!("Programs to end: {}.", programs.join(", "))));
    }
    if cfg!(windows) {
        if !programs.is_empty() {
            parts.push(text("If a program does not close, open Task Manager (Ctrl+Shift+Esc), find it on the Details tab, select it and click End task."));
            parts.push(Part::Actions(vec![Action::TaskManager]));
        }
    } else {
        let cmd = "pkill -f nikke_launcher.exe";
        parts.push(text("If the launcher does not close, run this command in a terminal:"));
        parts.push(Part::Code(cmd.into()));
        parts.push(Part::Actions(vec![Action::Copy("Copy command", cmd.into())]));
    }
    let title = if any(r, &[K::LauncherRunning]) { "Close the launcher" } else { "Close the programs that run the malware" };
    step(title, parts)
}

fn save_step(r: &ScanResult, restart: bool) -> Step {
    let mut why = String::new();
    if any(r, &[K::AgentState]) {
        why += " Deleting tbs_cache also deletes the k2f.agent.state trace.";
    } else if caches(r).iter().any(|c| c.traces) {
        why += " Deleting tbs_cache also deletes the traces this scan found in it.";
    }
    if restart {
        why += " The restart in the next step closes this window.";
    }
    step(
        "Save the report before you delete anything",
        vec![
            text(format!("The report is the record of what this scan found.{why}")),
            text("Turn on \"Hide my info\" (--redact on the command line) before you share it: it replaces your computer name, user names, agent ID and home folder in the copied or saved report. The window still shows them."),
            Part::Actions(vec![Action::SaveReport, Action::CopyReport]),
        ],
    )
}

/// The browser name from a ChromeDll title ("Edge persistence is installed").
fn browser(f: &Finding) -> &str {
    f.title.strip_suffix(" persistence is installed").unwrap_or("Chrome")
}

/// The folder to delete for a ChromeDll finding: the 64-hex folder that holds the DLL.
fn dll_folder(f: &Finding) -> PathBuf {
    let Some(open) = f.open_path.as_deref().or(f.path.as_deref()) else {
        return PathBuf::new();
    };
    let is_dll = open.file_name().is_some_and(|n| n.eq_ignore_ascii_case("platform_experience_helper.dll"));
    match open.parent() {
        Some(parent) if is_dll && parent.file_name().is_some_and(|n| is_hex64(&n.to_string_lossy())) => parent.to_path_buf(),
        _ => open.to_path_buf(),
    }
}

fn is_hex64(name: &str) -> bool {
    name.len() == 64 && name.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Outside Windows, the files of `f` are in a Wine prefix or on a Windows drive
/// seen from this system.
fn in_prefix(r: &ScanResult, f: &Finding) -> bool {
    f.path.as_deref().is_some_and(|p| {
        r.targets.iter().any(|t| t.kind == TargetKind::WinePrefix && p.starts_with(&t.path))
            || p.components().any(|c| c.as_os_str().eq_ignore_ascii_case("drive_c"))
    })
}

/// On Windows, the files can be deleted only after a restart while the key is
/// set or a program has the DLL loaded: Windows keeps a loaded DLL locked.
fn restart_first(r: &ScanResult) -> bool {
    cfg!(windows) && (any(r, &[K::DllLoaded]) || (any(r, &[K::RegistryKey]) && any(r, &[K::ChromeDll, K::LegacyDll])))
}

/// `'text'` for a POSIX shell.
fn sh_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// The Steam game ID of a Proton prefix (`compatdata/<id>/pfx`).
fn steam_game_id(prefix: &Path) -> Option<String> {
    let parts: Vec<String> = prefix.components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect();
    parts
        .windows(3)
        .find(|w| w[0] == "compatdata" && w[2] == "pfx" && !w[1].is_empty() && w[1].bytes().all(|b| b.is_ascii_digit()))
        .map(|w| w[1].clone())
}

fn dll_step(r: &ScanResult) -> Step {
    let mut browsers: Vec<&str> = Vec::new();
    for f in of(r, &[K::ChromeDll]) {
        if !browsers.contains(&browser(f)) {
            browsers.push(browser(f));
        }
    }
    if browsers.is_empty() {
        browsers.push("Chrome");
    }
    let keys: Vec<String> = of(r, &[K::RegistryKey, K::RegistryLeftover])
        .filter_map(|f| f.copy_text.as_deref())
        .flat_map(|t| t.lines().map(str::to_string).collect::<Vec<_>>())
        .fold(Vec::new(), |mut v, k| {
            push_new(&mut v, k);
            v
        });
    let leftover = any(r, &[K::RegistryLeftover]);
    let (dll, legacy, loaded) = (any(r, &[K::ChromeDll]), any(r, &[K::LegacyDll]), any(r, &[K::DllLoaded]));
    let files = dll || legacy || loaded;
    let restart = restart_first(r);
    let wine = !cfg!(windows) && of(r, &PERSISTENCE).any(|f| in_prefix(r, f));
    let drive = !cfg!(windows) && of(r, &[K::ChromeDll, K::LegacyDll]).any(|f| !in_prefix(r, f));
    let mut parts = Vec::new();
    let mut n = 0;
    let mut num = |s: &str| {
        n += 1;
        text(format!("{n}. {s}"))
    };
    if cfg!(windows) {
        if any(r, &[K::RegistryKey]) || loaded {
            let why = if loaded { "a program has the DLL loaded now" } else { "while the key is set, the browser loads the DLL each time it starts" };
            parts.push(text(format!("Keep this computer offline until this step is done: {why}.")));
        }
        if restart && !keys.is_empty() {
            parts.push(text("Do these in this order. Windows keeps the DLL locked until it restarts, so the registry key goes first."));
        }
        if !keys.is_empty() {
            parts.push(num("Delete the registry key. Open Registry Editor (press Win+R, type regedit and press Enter), paste the key path below into the address bar at the top and press Enter. Right-click the selected key in the left pane and choose Delete."));
            for (i, key) in keys.iter().enumerate() {
                parts.push(Part::Code(key.clone()));
                let mut actions = vec![Action::Copy("Copy key path", key.clone())];
                if i == 0 {
                    actions.push(Action::RegistryEditor);
                }
                parts.push(Part::Actions(actions));
            }
            if leftover {
                parts.push(text("An empty key is a leftover: the malware removed the DLL path but kept the key. Delete it the same way."));
            }
        }
        if restart {
            parts.push(num("Restart Windows. Then open this tool again and scan: it shows what is left to delete."));
        }
    } else {
        if wine {
            let what = if files { "These files are" } else { "The key is" };
            parts.push(text(format!("{what} inside a Wine prefix. Close the launcher and every other program of that prefix first.")));
        }
        if drive {
            parts.push(text("These files are on a Windows drive seen from this system. That Windows is not running, so the DLL is not locked and you can delete it from here. If this system cannot delete files on that drive (Windows Fast Startup leaves it read-only), do this step from that Windows instead: delete the key, restart, then delete the files."));
        }
    }
    let delete = if restart { "After the restart, delete" } else { "Delete" };
    let in_use = if cfg!(windows) && !restart { " If Windows says the file is in use, restart Windows and delete it again." } else { "" };
    if dll {
        parts.push(num(&format!("{delete} the DLL folder below, the one named with 64 hex characters. Leave the rest of the PlatformExperienceHelper folder alone: Chrome keeps its own platform_experience_helper.exe and LoadFeatures there.{in_use}")));
        for f in of(r, &[K::ChromeDll]) {
            let folder = dll_folder(f);
            parts.push(Part::Code(folder.display().to_string()));
            parts.push(Part::Actions(vec![Action::Reveal(folder)]));
        }
    }
    if legacy {
        parts.push(num(&format!("In the folder below, {} only platform_experience_helper.dll, platform_experience_helper.dll.old and old-clsid.txt, the ones that are there. Keep platform_experience_helper.exe: it belongs to Chrome.{in_use}", delete.to_lowercase())));
        for f in of(r, &[K::LegacyDll]) {
            parts.push(Part::Code(shown(f.path.as_deref())));
            parts.extend(f.open_path.clone().map(|p| Part::Actions(vec![Action::Reveal(p)])));
        }
    }
    // The files can be gone while a program still has the DLL loaded.
    if loaded && !dll && !legacy {
        parts.push(num(&format!("{delete} the DLL file below.{in_use}")));
        for f in of(r, &[K::DllLoaded]) {
            parts.push(Part::Code(shown(f.open_path.as_deref())));
            parts.extend(f.open_path.clone().map(|p| Part::Actions(vec![Action::Reveal(p)])));
        }
    }
    if wine && !keys.is_empty() {
        parts.push(num(&format!("Delete the registry key in the prefix's user.reg file. Open Wine's regedit in that prefix with the command below, go to HKEY_CURRENT_USER\\Software\\Classes\\CLSID and delete the {CLSID} key.")));
        for f in of(r, &[K::RegistryKey, K::RegistryLeftover]) {
            let Some(reg) = f.path.as_deref() else {
                continue;
            };
            let prefix = reg.parent().unwrap_or(reg);
            let cmd = format!("WINEPREFIX={} wine regedit", sh_quote(&prefix.display().to_string()));
            parts.push(Part::Code(cmd.clone()));
            parts.push(Part::Actions(vec![Action::Copy("Copy command", cmd), Action::Reveal(reg.to_path_buf())]));
            if let Some(id) = steam_game_id(prefix) {
                let cmd = format!("protontricks -c 'wine regedit' {id}");
                parts.push(text("Without Wine installed, as on a Steam Deck, protontricks opens regedit in this Proton prefix:"));
                parts.push(Part::Code(cmd.clone()));
                parts.push(Part::Actions(vec![Action::Copy("Copy command", cmd)]));
            }
        }
    }
    if drive {
        parts.push(num("Start that Windows and delete the registry key below, and the WOW6432Node copy if it is there: this scan could not read that Windows' registry. Open Registry Editor (press Win+R, type regedit and press Enter), paste the key path into the address bar at the top and press Enter. Right-click the selected key in the left pane and choose Delete."));
        for key in scan::CLSID_KEYS {
            parts.push(Part::Code(key.into()));
            parts.push(Part::Actions(vec![Action::Copy("Copy key path", key.into())]));
        }
    }
    let defender = if cfg!(windows) || drive {
        " Microsoft Defender did not detect this DLL on one infected computer, so a clean antivirus scan does not show that it is gone."
    } else {
        ""
    };
    parts.push(text(format!("Scan again afterwards: these findings should be gone.{defender}")));
    let title = if files {
        format!("Remove the {} DLL", browsers.join(" and "))
    } else if leftover && !any(r, &[K::RegistryKey]) {
        "Delete the leftover registry key".into()
    } else {
        "Delete the registry key".into()
    };
    step(title, parts)
}

/// A launcher data folder and its browser cache.
struct Cache {
    tbs: PathBuf,
    traces: bool,
}

fn caches(r: &ScanResult) -> Vec<Cache> {
    r.targets
        .iter()
        .filter(|t| t.kind == TargetKind::LauncherData)
        .map(|t| Cache {
            tbs: t.path.join("tbs_cache"),
            traces: r
                .groups
                .iter()
                .filter(|g| g.path.as_deref() == Some(t.path.as_path()))
                .flat_map(|g| &g.findings)
                .any(|f| CACHE_TRACES.contains(&f.kind)),
        })
        .collect()
}

fn cache_step(r: &ScanResult) -> Step {
    let mut parts = vec![text("Close the launcher first. Then delete the tbs_cache folder, the cache of the launcher's built-in browser. It can still hold the malicious script from before the fix, and the launcher would load it again.")];
    let caches = caches(r);
    if caches.is_empty() {
        parts.push(text("This scan found no launcher data folder. It is %APPDATA%\\nikke_launcher\\tbs_cache on Windows (nikke_launcher_hmt for the HMT launcher), or drive_c/users/<user>/AppData/Roaming/nikke_launcher/tbs_cache inside the Proton or Wine prefix."));
    }
    for c in caches {
        parts.push(Part::Code(c.tbs.display().to_string()));
        parts.push(Part::Actions(vec![Action::Reveal(c.tbs)]));
    }
    step("Clear the launcher cache", parts)
}

/// The accounts and secrets to change, from what the agent could read.
pub fn password_list(r: &ScanResult) -> Vec<String> {
    let none = Exposure::default();
    let e = r.exposure.as_ref().unwrap_or(&none);
    let mut out = vec!["Your NIKKE / Level Infinite account first, then email, Discord and banking.".to_string()];
    let mut browsers: Vec<(&str, Vec<&str>)> = Vec::new();
    for l in &e.logins {
        match browsers.iter_mut().find(|(b, _)| *b == l.browser) {
            Some((_, profiles)) => profiles.push(&l.profile),
            None => browsers.push((l.browser, vec![&l.profile])),
        }
    }
    if browsers.is_empty() {
        out.push("Every password saved in your browsers.".into());
    }
    for (b, profiles) in browsers {
        let label = if profiles.len() == 1 { "profile" } else { "profiles" };
        out.push(format!("Every password saved in {b} ({label} {}).", profiles.join(", ")));
    }
    out.push("Log out of every session on those services. The agent can collect browser cookies, and a stolen cookie works without the password.".into());
    if e.wallets.is_empty() {
        out.push("If you hold cryptocurrency, move it to a new wallet with a new seed phrase created on the other device.".into());
    }
    for w in &e.wallets {
        out.push(format!("{} in {} (profile {}): move the funds to a new wallet with a new seed phrase, created on the other device.", w.name, w.browser, w.profile));
    }
    if e.secrets.is_empty() {
        out.push("Revoke the API tokens and SSH keys stored on this computer.".into());
    }
    for s in &e.secrets {
        out.push(format!("Revoke and replace: {}, {}.", s.what, s.path.display()));
    }
    if !e.wallets.is_empty() || !e.secrets.is_empty() {
        out.push("Any other password, API token, SSH key or wallet stored on this computer.".into());
    }
    if cfg!(unix) && has_target(r, TargetKind::WinePrefix) {
        out.push("Under Wine, the agent could read your whole home folder through the Z: drive, and the environment variables of the launcher process, not only the Wine prefix.".into());
    }
    out.extend(home_note(r).map(str::to_string));
    out
}

/// A folder scan that found a Wine prefix also checks this computer's home
/// folder, but the prefix may have been copied from another computer.
pub fn home_note(r: &ScanResult) -> Option<&'static str> {
    (cfg!(unix) && r.scope != scan::COMPUTER_SCOPE && r.exposure.is_some() && has_target(r, TargetKind::WinePrefix)).then_some(
        "This computer's home folder was checked because a Wine prefix was found. If the scanned prefix ran on another computer, check that computer instead.",
    )
}

fn password_step(r: &ScanResult) -> Step {
    let intro = match r.verdict {
        Verdict::Infected => "Use a phone or another computer that never ran the NIKKE launcher. While the agent ran, its commands could read this computer's files and browser data. Change or replace these:",
        Verdict::Exposed => "The agent was sent from October 23, 2026 at the latest, and only on some launches. If the launcher was open on or after that date, act as if it ran: from a phone or another computer that never ran the launcher, change or replace these:",
        _ => {
            return step(
                "Change your NIKKE password if the launcher was open on or after October 23",
                vec![text("If the launcher was open on or after October 23, 2026, change your NIKKE / Level Infinite password anyway, from a phone or another computer that never ran the launcher.")],
            );
        }
    };
    let list = password_list(r);
    let mut parts = vec![text(intro)];
    parts.extend(list.iter().cloned().map(Part::Item));
    if r.exposure.as_ref().is_some_and(|e| !e.logins.is_empty() || !e.wallets.is_empty() || !e.secrets.is_empty()) {
        parts.push(text("This scan only checked that these files exist. It did not open them."));
    }
    parts.push(Part::Actions(vec![Action::Copy("Copy this list", list.join("\n"))]));
    step("Change your passwords from another device", parts)
}

fn block_step(r: &ScanResult) -> Step {
    let lines = match &r.hosts {
        Some(h) => report::block_lines(h),
        None => scan::DOMAINS.iter().map(|d| format!("0.0.0.0 {d}")).collect(),
    };
    let mut parts = Vec::new();
    let title = if lines.is_empty() {
        parts.push(text("Your hosts file blocks the three domains."));
        "Block the attacker's IP addresses"
    } else {
        if cfg!(windows) {
            let hosts = scan::hosts_path().display().to_string();
            parts.push(text("Open the Start menu, type Notepad, right-click it and choose \"Run as administrator\". In Notepad, choose File > Open, paste the hosts file path below into the File name box and press Enter."));
            parts.push(Part::Code(hosts.clone()));
            parts.push(Part::Actions(vec![Action::Copy("Copy hosts path", hosts)]));
            parts.push(text("Paste these lines at the end of the file and save:"));
            parts.push(Part::Code(lines.join("\n")));
            parts.push(Part::Actions(vec![Action::Copy("Copy these lines", lines.join("\n"))]));
        } else {
            let cmd = format!("printf '\\n{}\\n' | sudo tee -a /etc/hosts", lines.join("\\n"));
            let deck = if cfg!(target_os = "macos") { "" } else { " On a Steam Deck, set a password with passwd first if you never did." };
            parts.push(text(format!("Run this command in a terminal. It adds the lines to /etc/hosts and asks for your password.{deck}")));
            parts.push(Part::Code(cmd.clone()));
            parts.push(Part::Actions(vec![Action::Copy("Copy command", cmd)]));
        }
        parts.push(text("Scan again afterwards: Protection, in Details, then shows each domain as blocked."));
        "Block the domains"
    };
    let [a, b] = ATTACKER_IPS;
    parts.push(text(format!("The hosts file cannot block IP addresses. Block {a} and {b} in your firewall or router.")));
    if cfg!(windows) {
        let cmd = format!("New-NetFirewallRule -DisplayName \"Block NIKKE malware servers\" -Direction Outbound -RemoteAddress {a},{b} -Action Block");
        parts.push(text("To add a Windows firewall rule, right-click the Start button, choose Terminal (Admin) or Windows PowerShell (Admin), and run:"));
        parts.push(Part::Code(cmd.clone()));
        parts.push(Part::Actions(vec![Action::Copy("Copy command", cmd)]));
    } else if cfg!(target_os = "macos") {
        parts.push(text("On macOS, block them in your router's settings."));
    } else {
        let cmd = format!("sudo ufw deny out to {a} && sudo ufw deny out to {b}");
        parts.push(text("With ufw, run this command. The rules block nothing while ufw is off: sudo ufw status must show \"Status: active\", and sudo ufw enable turns it on. Without ufw, block them in your router's settings."));
        parts.push(Part::Code(cmd.clone()));
        parts.push(Part::Actions(vec![Action::Copy("Copy command", cmd)]));
    }
    step(title, parts)
}

fn wait_step(agent_ran: bool) -> Step {
    let mut parts = vec![text("Some of Level Infinite's servers still sent the malicious file on November 3, 2026. A launch before the fix can load the script again.")];
    if agent_ran {
        parts.push(text("The agent could run any command, so reinstalling the operating system is the safest way to be sure this computer is clean."));
    }
    step("Do not open the launcher until Level Infinite confirms a fix", parts)
}

fn shown(path: Option<&Path>) -> String {
    path.map(|p| p.display().to_string()).unwrap_or_default()
}

/// Program names from DllLoaded evidence ("PID 12: chrome.exe (C:\...) has ... loaded").
fn program_names(f: &Finding) -> Vec<String> {
    let mut names: Vec<String> = f
        .evidence
        .iter()
        .filter_map(|e| e.strip_prefix("PID ")?.split_once(": ")?.1.split(" (").next().map(str::to_string))
        .collect();
    names.sort();
    names.dedup();
    names
}

// ---------------------------------------------------------------- details

/// The groups of the Details tab, in order. Exposure comes after `Signs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Section {
    Proof,
    Cleanup,
    Signs,
    Info,
    Coverage,
}

impl Section {
    pub const ALL: [Section; 5] = [Section::Proof, Section::Cleanup, Section::Signs, Section::Info, Section::Coverage];

    pub fn of(kind: K) -> Self {
        match kind {
            K::AgentRan | K::PayloadDownloaded | K::PayloadFile | K::AgentState | K::AgentServerContacted => Section::Proof,
            K::ChromeDll | K::RegistryKey | K::RegistryLeftover | K::LegacyDll | K::DllLoaded | K::TempFile | K::LauncherRunning => {
                Section::Cleanup
            }
            K::LoaderCached | K::LauncherContacted => Section::Signs,
            K::Coverage => Section::Coverage,
            K::Info => Section::Info,
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Section::Proof => "Proof the malware ran",
            Section::Cleanup => "Things to clean up",
            Section::Signs => "Signs of exposure",
            Section::Info => "Information",
            Section::Coverage => "What this scan could not check",
        }
    }
}

pub const EXPOSURE_TITLE: &str = "Your data the malware could reach";

/// One line on what a finding means for the user.
pub fn meaning(kind: K) -> &'static str {
    match kind {
        K::AgentRan => "The agent ran inside the launcher. While the launcher was open, the attacker could control this computer.",
        K::PayloadDownloaded => "The launcher received the agent from the attacker's server.",
        K::PayloadFile => "A copy of the agent is still in the launcher's log folder.",
        K::AgentState => "The agent saved its ID in the launcher's browser storage, so it ran at least once.",
        K::AgentServerContacted => "The launcher reached the server that sends the agent, so it got as far as asking for the agent.",
        K::LoaderCached => "The malicious script ran in the launcher. This alone does not show that the agent was sent.",
        K::LauncherContacted => "The launcher contacted the attacker's domain.",
        K::ChromeDll => "The browser loads this DLL when it starts, so the malware can run again without the launcher. The malware creates Chrome's folder even when Chrome is not installed.",
        K::RegistryKey => "This key makes the browser load the malware's DLL.",
        K::RegistryLeftover => "The DLL path was removed from this key, but the key is still there. Delete it.",
        K::LegacyDll => "An earlier version of the agent put its DLL here.",
        K::DllLoaded => "These programs run the malware's DLL now. Windows keeps it loaded until they exit or Windows restarts.",
        K::TempFile => "The agent wrote these files while it collected browser credentials or screenshots.",
        K::LauncherRunning => "While the launcher runs, the attacker can send it commands.",
        K::Coverage => "Part of this scan could not be done. The text above says what to do.",
        K::Info => "Context only. It does not change the verdict.",
    }
}

/// The exposure lists of the Details tab: (heading, [(what, path)]).
pub fn exposure_lists(e: &Exposure) -> [(&'static str, Vec<(String, PathBuf)>); 3] {
    [
        (
            "Saved passwords",
            e.logins.iter().map(|l| (format!("{}, profile {} ({})", l.browser, l.profile, l.files.join(", ")), l.path.clone())).collect(),
        ),
        (
            "Wallet extensions",
            e.wallets.iter().map(|w| (format!("{} ({}) in {}, profile {}", w.name, w.id, w.browser, w.profile), w.path.clone())).collect(),
        ),
        ("Secret files", e.secrets.iter().map(|s| (s.what.to_string(), s.path.clone())).collect()),
    ]
}

pub const EXPOSURE_NOTE: &str = "This scan only checked that these files exist. It did not open them. While the agent ran, its commands could read them.";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::locate::{Target, WalkStats};
    use crate::scan::{Group, HostsStatus, Severity};

    fn finding(kind: K, severity: Severity, title: &str) -> Finding {
        Finding {
            kind,
            severity,
            title: title.into(),
            detail: String::new(),
            path: None,
            open_path: None,
            copy_text: None,
            evidence: Vec::new(),
            time: None,
        }
    }

    fn result(verdict: Verdict, findings: Vec<Finding>, targets: Vec<(TargetKind, &str)>) -> ScanResult {
        ScanResult {
            scope: "test".into(),
            started: "2026-11-04 10:00:00 UTC".into(),
            verdict,
            targets: targets.into_iter().map(|(kind, p)| Target { kind, path: PathBuf::from(p), host: false }).collect(),
            groups: vec![Group { label: "Launcher data".into(), path: Some(PathBuf::from("/d/nikke_launcher")), findings }],
            hosts: Some(HostsStatus {
                path: PathBuf::from("/etc/hosts"),
                note: None,
                domains: vec![("insightjs.com", Some(true)), ("analytics.insightjs.com", Some(false)), ("insightjs.org", Some(false))],
            }),
            stats: WalkStats::default(),
            seconds: 0.0,
            runs: Vec::new(),
            builds: Vec::new(),
            exposure: None,
        }
    }

    fn titles(r: &ScanResult) -> Vec<String> {
        steps(r).into_iter().map(|s| s.title).collect()
    }

    #[test]
    fn steps_follow_the_findings() {
        let mut dll = finding(K::ChromeDll, Severity::Critical, "Edge persistence is installed");
        let hash = "a".repeat(64);
        dll.path = Some(PathBuf::from("/p/PlatformExperienceHelper"));
        dll.open_path = Some(PathBuf::from(format!("/p/PlatformExperienceHelper/{hash}/platform_experience_helper.dll")));
        let mut loaded = finding(K::DllLoaded, Severity::Critical, "The persistence DLL is loaded now");
        loaded.evidence = vec!["PID 9: msedge.exe (C:\\e\\msedge.exe) has C:\\x.dll loaded".into(), "PID 4: explorer.exe (C:\\explorer.exe) has C:\\x.dll loaded".into()];
        let infected = result(
            Verdict::Infected,
            vec![dll, loaded, finding(K::AgentState, Severity::Critical, "Agent state")],
            vec![(TargetKind::InstallDir, "/n"), (TargetKind::LauncherData, "/d/nikke_launcher")],
        );
        assert_eq!(
            titles(&infected),
            [
                "Close the programs that run the malware",
                "Save the report before you delete anything",
                "Remove the Edge DLL",
                "Clear the launcher cache",
                "Change your passwords from another device",
                "Block the domains",
                "Do not open the launcher until Level Infinite confirms a fix",
            ]
        );
        let all = steps(&infected);
        let codes: Vec<&str> = all.iter().flat_map(|s| &s.parts).filter_map(|p| if let Part::Code(c) = p { Some(c.as_str()) } else { None }).collect();
        assert!(codes.contains(&format!("/p/PlatformExperienceHelper/{hash}").as_str()), "{codes:?}");
        let cache = Path::new("/d/nikke_launcher").join("tbs_cache").display().to_string();
        assert!(codes.contains(&cache.as_str()), "{codes:?}");
        let close = format!("{:?}", all[0].parts);
        assert!(close.contains("Programs to end: msedge.exe.") && close.contains("Do not end explorer.exe"), "{close}");
        let [ran, active, clean, protect] = answers(&infected);
        assert_eq!((ran.reply, active.reply, clean.reply, protect.reply), ("Yes", "Yes", "Yes", "Partly"));
        assert!(clean.lines.iter().any(|l| l.contains("tbs_cache")), "{:?}", clean.lines);

        // A quick scan's "No" is unsure, and its steps offer the full scan.
        let mut quick_clean = result(Verdict::NoTraces, vec![], vec![(TargetKind::InstallDir, "/n"), (TargetKind::LauncherData, "/d/nikke_launcher")]);
        quick_clean.stats.depth_limit = Some(5);
        let [ran, ..] = answers(&quick_clean);
        assert_eq!((ran.reply, ran.tone), ("No", Tone::Unsure));
        assert_eq!(titles(&quick_clean)[0], "Run the full scan");

        let clean_scan = result(Verdict::NoTraces, vec![], vec![(TargetKind::InstallDir, "/n"), (TargetKind::LauncherData, "/d/nikke_launcher")]);
        assert_eq!(
            titles(&clean_scan),
            [
                "Clear the launcher cache",
                "Change your NIKKE password if the launcher was open on or after October 23",
                "Block the domains",
                "Do not open the launcher until Level Infinite confirms a fix",
            ]
        );
        let [ran, active, clean, _] = answers(&clean_scan);
        assert_eq!((ran.reply, active.reply, clean.reply), ("No", "No", "No"));
        assert_eq!(ran.tone, Tone::Good);

        let exposed = result(Verdict::Exposed, vec![finding(K::LoaderCached, Severity::Warning, "Loader")], vec![(TargetKind::LauncherData, "/d/nikke_launcher")]);
        let t = titles(&exposed);
        // Scanning the install can change the result, so it comes before the cleanup.
        assert_eq!(t[..3], ["Save the report before you delete anything", "Scan the folder where NIKKE is installed", "Clear the launcher cache"]);
        assert!(t.contains(&"Change your passwords from another device".to_string()));
        let ran = &answers(&exposed)[0];
        assert_eq!(ran.reply, "No");
        assert!(!ran.lines.iter().any(|l| l.starts_with("Finding nothing")), "{:?}", ran.lines);

        let none = result(Verdict::NotFound, vec![], vec![]);
        assert_eq!(titles(&none)[0], "Scan the folder where NIKKE is installed");
        assert_eq!(answers(&none)[0].reply, "Cannot tell");
        // Only a quick scan offers the full scan.
        let offers_full = |r: &ScanResult| {
            steps(r)[0].parts.iter().any(|p| matches!(p, Part::Actions(a) if a.iter().any(|a| matches!(a, Action::FullScan))))
        };
        let mut quick = result(Verdict::NotFound, vec![], vec![]);
        quick.stats.depth_limit = Some(5);
        assert!(offers_full(&quick) && !offers_full(&none));

        // A part of the scan that failed makes "No" unsure.
        let gap = result(
            Verdict::NoTraces,
            vec![finding(K::Coverage, Severity::Info, "debug.log could not be read")],
            vec![(TargetKind::InstallDir, "/n")],
        );
        assert_eq!(answers(&gap)[0].tone, Tone::Unsure);
    }

    fn texts(s: &Step) -> String {
        s.parts.iter().map(|p| format!("{p:?}\n")).collect()
    }

    #[cfg(not(windows))]
    fn dll_at(title: &str, path: &str) -> Finding {
        let mut f = finding(K::ChromeDll, Severity::Critical, title);
        f.path = Some(PathBuf::from(path));
        f.open_path = Some(PathBuf::from(format!("{path}/{}/platform_experience_helper.dll", "b".repeat(64))));
        f
    }

    #[cfg(not(windows))]
    #[test]
    fn dll_step_outside_windows() {
        // Two profiles of a Windows drive mounted under Linux: no prefix, and the key is in that Windows.
        let a = "/mnt/win/Users/A/AppData/Local/Google/Chrome/User Data/PlatformExperienceHelper";
        let e = "/mnt/win/Users/A/AppData/Local/Microsoft/Edge/User Data/PlatformExperienceHelper";
        let b = "/mnt/win/Users/B/AppData/Local/Google/Chrome/User Data/PlatformExperienceHelper";
        let found = vec![
            dll_at("Chrome persistence is installed", a),
            dll_at("Edge persistence is installed", e),
            dll_at("Chrome persistence is installed", b),
        ];
        let drive = result(Verdict::Infected, found, vec![(TargetKind::UserProfile, "/mnt/win/Users/A")]);
        let step = dll_step(&drive);
        assert_eq!(step.title, "Remove the Chrome and Edge DLL");
        let t = texts(&step);
        assert!(t.contains("on a Windows drive seen from this system") && !t.contains("Wine prefix"), "{t}");
        // Debug output doubles the backslashes.
        assert!(scan::CLSID_KEYS.iter().all(|k| t.contains(&format!("Code({k:?})"))), "{t}");
        assert!(t.contains("1. Delete the DLL folder below, the one named with 64 hex characters"), "{t}");
        assert!(t.contains("2. Start that Windows and delete the registry key"), "{t}");
        assert!(!t.contains("Restart Windows."), "{t}");

        // A Proton prefix with only the empty key the malware's uninstall leaves.
        let pfx = "/s/steamapps/compatdata/123/pfx";
        let mut key = finding(K::RegistryLeftover, Severity::Critical, "Registry leftover of the persistence (HKCU CLSID)");
        key.path = Some(PathBuf::from(format!("{pfx}/user.reg")));
        key.copy_text = Some(scan::CLSID_KEYS[0].into());
        let wine = result(Verdict::Infected, vec![key], vec![(TargetKind::WinePrefix, pfx)]);
        let step = dll_step(&wine);
        assert_eq!(step.title, "Delete the leftover registry key");
        let t = texts(&step);
        assert!(t.contains("The key is inside a Wine prefix") && !t.contains("Windows drive"), "{t}");
        assert!(t.contains("WINEPREFIX='/s/steamapps/compatdata/123/pfx' wine regedit"), "{t}");
        assert!(t.contains("protontricks -c 'wine regedit' 123"), "{t}");
        assert!(!t.contains("Defender"), "{t}");
        let [_, active, clean, _] = answers(&wine);
        assert_eq!(active.reply, "No");
        assert!(clean.lines[0].contains("left after the malware cleared the DLL path"), "{:?}", clean.lines);

        // Only the files of the older version: no 64-hex folder to point at.
        let mut legacy = finding(K::LegacyDll, Severity::Critical, "Files of an older Chrome persistence are installed");
        legacy.path = Some(PathBuf::from(format!("{pfx}/drive_c/Program Files/Google/Chrome/Application/PlatformExperienceHelper")));
        let step = dll_step(&result(Verdict::Infected, vec![legacy], vec![(TargetKind::WinePrefix, pfx)]));
        let t = texts(&step);
        assert!(!t.contains("64 hex") && t.contains("1. In the folder below, delete only platform_experience_helper.dll"), "{t}");
    }

    #[test]
    fn password_list_keeps_the_general_lines() {
        use crate::exposure::SecretFile;
        let mut r = result(Verdict::Infected, vec![finding(K::AgentRan, Severity::Critical, "The malware agent ran")], vec![(TargetKind::InstallDir, "/n")]);
        let step = password_step(&r);
        assert!(!texts(&step).contains("only checked that these files exist"), "{}", texts(&step));
        r.exposure = Some(Exposure { secrets: vec![SecretFile { what: "npm token", path: PathBuf::from("/h/.npmrc") }], ..Exposure::default() });
        let list = password_list(&r);
        assert!(list.iter().any(|l| l == "Revoke and replace: npm token, /h/.npmrc."), "{list:?}");
        assert!(list.iter().any(|l| l.starts_with("Any other password, API token, SSH key or wallet")), "{list:?}");
        assert!(texts(&password_step(&r)).contains("only checked that these files exist"));
    }

    #[test]
    fn powershell_names_are_quoted() {
        assert_eq!(ps_command("nikke-check-windows-x86_64 (1).exe", ""), r"& '.\nikke-check-windows-x86_64 (1).exe' --cli | Out-Host");
        assert_eq!(ps_command("it's.exe", " 'D:\\x'"), r"& '.\it''s.exe' --cli 'D:\x' | Out-Host");
    }

    #[test]
    fn run_lines() {
        let run = AgentRun { kind: RunKind::Started, time: Some("11-03 01:47:36".into()), agent_id: None, host: Some("COLONY".into()), file: None, source: PathBuf::new() };
        assert_eq!(run_line(&run), "11-03 01:47:36: the agent sent the computer name COLONY to the attacker");
        let run = AgentRun { source: PathBuf::from("/n/debug.log"), host: None, ..run };
        assert_eq!(run_line(&run), "11-03 01:47:36: the agent sent the computer name to the attacker (from debug.log)");
    }
}
