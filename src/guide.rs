//! The result in plain words, for the window and the report: four answers
//! ("What happened") and the steps to take ("What to do"), built only from
//! what the scan found, in the language asked for.

use std::path::{Path, PathBuf};

use crate::exposure::Exposure;
use crate::i18n::{Lang, Text, msg, tr};
use crate::locate::TargetKind;
use crate::report;
use crate::scan::{self, ATTACKER_IPS, Finding, FindingKind as K, ScanResult, Verdict};
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
const RAN: [K; 11] = scan::AGENT_SIGNS;
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

/// Sentences of the catalog, one after the other.
// shortcut: joined with a space in every language, add a separator text if CJK translators ask.
fn sentences(lang: Lang, keys: &[&'static str]) -> String {
    keys.iter().map(|k| tr(lang, k)).collect::<Vec<_>>().join(" ")
}

/// "A and B and C".
fn and(lang: Lang, items: &[String]) -> String {
    let mut items = items.iter();
    let first = items.next().cloned().unwrap_or_default();
    items.fold(first, |a, b| msg("common.and").arg("a", a).arg("b", b.as_str()).render(lang))
}

/// A finding title as one reason of an answer: "The malware agent ran."
fn title_line(f: &Finding, lang: Lang) -> String {
    msg("answer.finding").arg("title", f.title.clone()).render(lang)
}

pub fn answers(r: &ScanResult, lang: Lang) -> [Answer; 4] {
    [did_it_run(r, lang), still_active(r, lang), to_clean(r, lang), protected(r, lang)]
}

fn answer(question: &'static str, reply: &'static str, tone: Tone, lines: Vec<String>) -> Answer {
    Answer { question, reply, tone, lines, runs: Vec::new() }
}

fn did_it_run(r: &ScanResult, lang: Lang) -> Answer {
    let t = |key| tr(lang, key);
    let q = t("answer.ran.question");
    let mut lines = Vec::new();
    if any(r, &RAN) {
        for f in of(r, &RAN) {
            push_new(&mut lines, title_line(f, lang));
        }
        let mut a = answer(q, t("answer.yes"), Tone::Bad, lines);
        a.runs = r.runs.iter().map(|run| run_line(run, lang)).collect();
        return a;
    }
    let loader = any(r, &[K::LoaderCached, K::LauncherContacted]);
    if r.verdict == Verdict::NotFound {
        lines.push(t("answer.ran.nothing_checked").into());
        return answer(q, t("answer.cannot_tell"), Tone::Unsure, lines);
    }
    if r.verdict == Verdict::Infected {
        for f in findings(r).filter(|f| f.severity == scan::Severity::Critical) {
            push_new(&mut lines, title_line(f, lang));
        }
        lines.push(t("answer.ran.no_agent_log").into());
        return answer(q, t("answer.cannot_tell"), Tone::Unsure, lines);
    }
    if loader {
        lines.push(t("answer.ran.loader").into());
        lines.push(t("answer.ran.act_as_if").into());
    } else {
        lines.push(t("answer.ran.nothing").into());
    }
    if !has_target(r, TargetKind::InstallDir) {
        lines.push(t("answer.ran.no_install").into());
    }
    let gaps = any(r, &[K::Coverage]);
    if gaps {
        lines.push(t("answer.ran.gaps").into());
    }
    // A quick scan can miss an old install deeper down, so its "No" is not a clean result.
    if let Some(depth) = r.stats.depth_limit {
        lines.push(msg("answer.ran.quick").arg("depth", depth.to_string()).render(lang));
    }
    if !loader {
        lines.push(t("report.caveat.not_proof").into());
    }
    let unsure = loader || gaps || r.stats.depth_limit.is_some();
    answer(q, t("answer.no"), if unsure { Tone::Unsure } else { Tone::Good }, lines)
}

/// One logged step of an agent run. "Hide my info" replaces the computer name
/// in the copied or saved report.
pub fn run_line(run: &AgentRun, lang: Lang) -> String {
    let time = run.time.clone().unwrap_or_else(|| msg("run.no_time"));
    let what = match run.kind {
        RunKind::Downloaded => match &run.file {
            Some(file) => msg("run.downloaded_as").arg("file", file.as_str()),
            None => msg("run.downloaded"),
        },
        RunKind::Adopted => msg("run.adopted"),
        RunKind::Resumed => msg("run.resumed"),
        RunKind::Started => match &run.host {
            Some(host) => msg("run.started_as").arg("host", host.as_str()),
            None => msg("run.started"),
        },
        RunKind::Failed => msg("run.failed"),
    };
    let line = match run.source.file_name() {
        Some(n) => msg("run.line_from").arg("file", n.to_string_lossy().into_owned()),
        None => msg("run.line"),
    };
    line.arg("time", time).arg("what", what).render(lang)
}

fn still_active(r: &ScanResult, lang: Lang) -> Answer {
    let t = |key| tr(lang, key);
    let mut lines = Vec::new();
    for f in findings(r) {
        let line = match f.kind {
            K::LauncherRunning => t("answer.active.launcher").to_string(),
            K::DllLoaded => msg("answer.active.dll_loaded").arg("programs", program_names(f, lang).join(", ")).render(lang),
            K::RegistryKey => t("answer.active.registry").to_string(),
            K::ChromeDll | K::LegacyDll => title_line(f, lang),
            _ => continue,
        };
        push_new(&mut lines, line);
    }
    let q = t("answer.active.question");
    if lines.is_empty() {
        // The running launcher without a sign of the agent is an Info finding: "not running" would be wrong.
        let launcher = findings(r).any(|f| matches!(f.title, Text::Msg("finding.launcher_running_clean.title", _)));
        lines.push(t(if launcher { "answer.active.launcher_clean" } else { "answer.active.none" }).into());
        return answer(q, t("answer.no"), Tone::Good, lines);
    }
    answer(q, t("answer.yes"), Tone::Bad, lines)
}

fn to_clean(r: &ScanResult, lang: Lang) -> Answer {
    let t = |key| tr(lang, key);
    let path = |key, p: &Path| msg(key).arg("path", p.display().to_string()).render(lang);
    let mut lines = Vec::new();
    for f in findings(r) {
        let line = match f.kind {
            K::ChromeDll => msg("answer.clean.dll_folder")
                .arg("browser", browser(f, lang))
                .arg("path", dll_folder(f).display().to_string())
                .render(lang),
            K::RegistryKey => t("answer.clean.registry").into(),
            K::RegistryLeftover => t("answer.clean.leftover").into(),
            K::LegacyDll => path("answer.clean.legacy", f.path.as_deref().unwrap_or(Path::new(""))),
            K::TempFile => path("answer.clean.temp", f.path.as_deref().and_then(Path::parent).unwrap_or(Path::new(""))),
            _ => continue,
        };
        push_new(&mut lines, line);
    }
    for c in caches(r).iter().filter(|c| c.traces) {
        push_new(&mut lines, path(if c.login { "answer.clean.login_profile" } else { "answer.clean.cache" }, &c.tbs));
    }
    let q = t("answer.clean.question");
    if !lines.is_empty() {
        return answer(q, t("answer.yes"), Tone::Bad, lines);
    }
    if has_target(r, TargetKind::LauncherData) {
        lines.push(t("answer.clean.none_cache").into());
    } else {
        lines.push(t("answer.clean.none").into());
    }
    answer(q, t("answer.no"), Tone::Good, lines)
}

fn protected(r: &ScanResult, lang: Lang) -> Answer {
    let t = |key| tr(lang, key);
    let q = t("answer.protected.question");
    let ip_line = t("answer.protected.ip").to_string();
    let Some(h) = &r.hosts else {
        return answer(q, t("answer.cannot_tell"), Tone::Unsure, vec![t("answer.protected.not_checked").into(), ip_line]);
    };
    let mut lines: Vec<String> = h.note.iter().map(|n| n.render(lang)).collect();
    lines.extend(h.domains.iter().map(|(d, b)| {
        msg("answer.protected.domain").arg("domain", *d).arg("state", report::block_state(*b, lang)).render(lang)
    }));
    lines.push(ip_line);
    let blocked = h.domains.iter().filter(|(_, b)| *b == Some(true)).count();
    let (reply, tone) = if h.domains.iter().any(|(_, b)| b.is_none()) {
        ("answer.cannot_tell", Tone::Unsure)
    } else if blocked == h.domains.len() {
        ("answer.yes", Tone::Good)
    } else if blocked > 0 {
        ("answer.partly", Tone::Unsure)
    } else {
        ("answer.no", Tone::Bad)
    };
    answer(q, t(reply), tone, lines)
}

/// "6ae90538-3214f, uploaded ..., 205,135 bytes, one of the 5 known builds."
pub fn build_line(b: &PayloadBuild, lang: Lang) -> String {
    let mut s = b.etag.clone().unwrap_or_else(|| tr(lang, "build.no_etag").into());
    match (&b.uploaded, &b.last_modified) {
        (Some(t), _) => s += &msg("build.uploaded").arg("time", t.as_str()).render(lang),
        (None, Some(t)) => s += &msg("build.last_modified").arg("time", t.as_str()).render(lang),
        _ => {}
    }
    if let Some(size) = b.size {
        s += &msg("build.size").arg("size", report::thousands(size)).render(lang);
    }
    let known = if b.known { "build.known" } else { "build.unknown" };
    s += &msg(known).arg("n", KNOWN_BUILDS.len().to_string()).render(lang);
    if let Some(t) = &b.time {
        s.push(' ');
        s += &msg("build.received").arg("time", t.clone()).render(lang);
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
    /// (button label, text to copy).
    Copy(String, String),
    TaskManager,
    RegistryEditor,
    SaveReport,
    CopyReport,
    ScanFolder,
    FullScan,
}

/// A text part from the catalog.
fn text(lang: Lang, key: &'static str) -> Part {
    Part::Text(tr(lang, key).into())
}

fn copy(lang: Lang, label: &'static str, what: impl Into<String>) -> Action {
    Action::Copy(tr(lang, label).into(), what.into())
}

fn step(title: impl Into<String>, parts: Vec<Part>) -> Step {
    Step { title: title.into(), parts }
}

/// The launcher runs or a program has the DLL loaded: the window opens on the steps.
pub fn act_now(r: &ScanResult) -> bool {
    any(r, &[K::LauncherRunning, K::DllLoaded])
}

pub fn steps(r: &ScanResult, lang: Lang) -> Vec<Step> {
    let found = r.verdict != Verdict::NotFound;
    // Scanning the install reads debug.log, which can turn the result into Infected.
    let rescan = found && !has_target(r, TargetKind::InstallDir);
    let mut out = Vec::new();
    if !found {
        out.push(scan_folder_step(r, lang));
    }
    if act_now(r) {
        out.push(close_step(r, lang));
    }
    if matches!(r.verdict, Verdict::Infected | Verdict::Exposed) {
        // Before the DLL step: its restart closes this window.
        out.push(save_step(r, restart_first(r), lang));
    }
    // After a quick scan without proof of the agent, the full scan is the next check.
    let quick_unsure = matches!(r.verdict, Verdict::NoTraces | Verdict::Exposed) && r.stats.depth_limit.is_some();
    if rescan && r.verdict != Verdict::Infected {
        out.push(scan_folder_step(r, lang));
    } else if quick_unsure {
        out.push(step(tr(lang, "step.full_scan.title"), full_scan_parts(r, lang)));
    }
    if any(r, &PERSISTENCE) {
        out.push(dll_step(r, lang));
    }
    if found {
        out.push(cache_step(r, lang));
        out.push(password_step(r, lang));
    }
    out.push(block_step(r, lang));
    if rescan && r.verdict == Verdict::Infected {
        out.push(scan_folder_step(r, lang));
    }
    out.push(wait_step(r.verdict == Verdict::Infected && any(r, &RAN), lang));
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

fn scan_folder_step(r: &ScanResult, lang: Lang) -> Step {
    let mut parts = if cfg!(windows) {
        let cmd = powershell_cli(r" 'D:\Games\NIKKE'");
        vec![
            text(lang, "step.scan_folder.windows"),
            Part::Code(cmd.clone()),
            Part::Actions(vec![Action::ScanFolder, copy(lang, "common.copy_command", cmd)]),
        ]
    } else {
        vec![text(lang, "step.scan_folder.other"), Part::Actions(vec![Action::ScanFolder])]
    };
    parts.extend(full_scan_parts(r, lang));
    step(tr(lang, "step.scan_folder.title"), parts)
}

/// After a quick scan: what the full scan adds, its button and its command.
fn full_scan_parts(r: &ScanResult, lang: Lang) -> Vec<Part> {
    let Some(depth) = r.stats.depth_limit else {
        return Vec::new();
    };
    let mut parts = vec![Part::Text(msg("step.full_scan.intro").arg("depth", depth.to_string()).render(lang))];
    if cfg!(windows) {
        let cmd = powershell_cli(" --full");
        parts.push(text(lang, "step.full_scan.powershell"));
        parts.push(Part::Code(cmd.clone()));
        parts.push(Part::Actions(vec![Action::FullScan, copy(lang, "common.copy_command", cmd)]));
    } else {
        parts.push(text(lang, "step.full_scan.terminal"));
        parts.push(Part::Actions(vec![Action::FullScan]));
    }
    parts
}

fn close_step(r: &ScanResult, lang: Lang) -> Step {
    let mut parts = Vec::new();
    let mut programs = Vec::new();
    if any(r, &[K::LauncherRunning]) {
        parts.push(text(lang, "step.close.launcher"));
        programs.push("nikke_launcher.exe".to_string());
    }
    let mut explorer = false;
    for f in of(r, &[K::DllLoaded]) {
        let names = program_names(f, lang);
        let key = if names.len() == 1 { "step.close.dll_loaded_one" } else { "step.close.dll_loaded_other" };
        parts.push(Part::Text(msg(key).arg("programs", names.join(", ")).render(lang)));
        for name in names {
            if name.eq_ignore_ascii_case("explorer.exe") {
                explorer = true;
            } else {
                push_new(&mut programs, name);
            }
        }
    }
    if explorer {
        parts.push(text(lang, "step.close.explorer"));
    }
    if !programs.is_empty() {
        parts.push(Part::Text(msg("step.close.programs").arg("programs", programs.join(", ")).render(lang)));
    }
    if cfg!(windows) {
        if !programs.is_empty() {
            parts.push(text(lang, "step.close.task_manager"));
            parts.push(Part::Actions(vec![Action::TaskManager]));
        }
    } else {
        let cmd = "pkill -f nikke_launcher.exe";
        parts.push(text(lang, "step.close.pkill"));
        parts.push(Part::Code(cmd.into()));
        parts.push(Part::Actions(vec![copy(lang, "common.copy_command", cmd)]));
    }
    let title = if any(r, &[K::LauncherRunning]) { "step.close.title_launcher" } else { "step.close.title_programs" };
    step(tr(lang, title), parts)
}

fn save_step(r: &ScanResult, restart: bool, lang: Lang) -> Step {
    let mut why = vec!["step.save.record"];
    if any(r, &[K::AgentState]) {
        why.push("step.save.agent_state");
    } else if caches(r).iter().any(|c| c.traces) {
        why.push("step.save.cache_traces");
    }
    if restart {
        why.push("step.save.restart");
    }
    step(
        tr(lang, "step.save.title"),
        vec![
            Part::Text(sentences(lang, &why)),
            text(lang, "step.save.hide"),
            Part::Actions(vec![Action::SaveReport, Action::CopyReport]),
        ],
    )
}

/// The browser name kept in a ChromeDll title ("Edge persistence is installed").
fn browser(f: &Finding, lang: Lang) -> String {
    f.title.get("browser").map_or_else(|| "Chrome".into(), |b| b.render(lang))
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

fn dll_step(r: &ScanResult, lang: Lang) -> Step {
    let mut browsers: Vec<String> = Vec::new();
    for f in of(r, &[K::ChromeDll]) {
        push_new(&mut browsers, browser(f, lang));
    }
    if browsers.is_empty() {
        browsers.push("Chrome".into());
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
    let mut num = |s: String| {
        n += 1;
        Part::Text(format!("{n}. {s}"))
    };
    if cfg!(windows) {
        if any(r, &[K::RegistryKey]) || loaded {
            parts.push(text(lang, if loaded { "step.dll.offline_loaded" } else { "step.dll.offline_key" }));
        }
        if restart && !keys.is_empty() {
            parts.push(text(lang, "step.dll.order"));
        }
        if !keys.is_empty() {
            parts.push(num(tr(lang, "step.dll.delete_key").into()));
            for (i, key) in keys.iter().enumerate() {
                parts.push(Part::Code(key.clone()));
                let mut actions = vec![copy(lang, "common.copy_key_path", key.as_str())];
                if i == 0 {
                    actions.push(Action::RegistryEditor);
                }
                parts.push(Part::Actions(actions));
            }
            if leftover {
                parts.push(text(lang, "step.dll.leftover"));
            }
        }
        if restart {
            parts.push(num(tr(lang, "step.dll.restart").into()));
        }
    } else {
        if wine {
            parts.push(text(lang, if files { "step.dll.wine_files" } else { "step.dll.wine_key" }));
        }
        if drive {
            parts.push(text(lang, "step.dll.drive"));
        }
    }
    // "Delete ..." or "After the restart, delete ...", then on Windows a hint for a file in use.
    let delete = |now: &'static str, after: &'static str| {
        let mut keys = vec![if restart { after } else { now }];
        if cfg!(windows) && !restart {
            keys.push("step.dll.in_use");
        }
        sentences(lang, &keys)
    };
    if dll {
        parts.push(num(delete("step.dll.delete_folder", "step.dll.delete_folder_after_restart")));
        for f in of(r, &[K::ChromeDll]) {
            let folder = dll_folder(f);
            parts.push(Part::Code(folder.display().to_string()));
            parts.push(Part::Actions(vec![Action::Reveal(folder)]));
        }
    }
    if legacy {
        parts.push(num(delete("step.dll.delete_legacy", "step.dll.delete_legacy_after_restart")));
        for f in of(r, &[K::LegacyDll]) {
            parts.push(Part::Code(shown(f.path.as_deref())));
            parts.extend(f.open_path.clone().map(|p| Part::Actions(vec![Action::Reveal(p)])));
        }
    }
    // The files can be gone while a program still has the DLL loaded.
    if loaded && !dll && !legacy {
        parts.push(num(delete("step.dll.delete_file", "step.dll.delete_file_after_restart")));
        for f in of(r, &[K::DllLoaded]) {
            parts.push(Part::Code(shown(f.open_path.as_deref())));
            parts.extend(f.open_path.clone().map(|p| Part::Actions(vec![Action::Reveal(p)])));
        }
    }
    if wine && !keys.is_empty() {
        parts.push(num(tr(lang, "step.dll.wine_regedit").into()));
        for f in of(r, &[K::RegistryKey, K::RegistryLeftover]) {
            let Some(reg) = f.path.as_deref() else {
                continue;
            };
            let prefix = reg.parent().unwrap_or(reg);
            let cmd = format!("WINEPREFIX={} wine regedit", sh_quote(&prefix.display().to_string()));
            parts.push(Part::Code(cmd.clone()));
            parts.push(Part::Actions(vec![copy(lang, "common.copy_command", cmd), Action::Reveal(reg.to_path_buf())]));
            if let Some(id) = steam_game_id(prefix) {
                let cmd = format!("protontricks -c 'wine regedit' {id}");
                parts.push(text(lang, "step.dll.protontricks"));
                parts.push(Part::Code(cmd.clone()));
                parts.push(Part::Actions(vec![copy(lang, "common.copy_command", cmd)]));
            }
        }
    }
    if drive {
        parts.push(num(tr(lang, "step.dll.drive_key").into()));
        for key in scan::CLSID_KEYS {
            parts.push(Part::Code(key.into()));
            parts.push(Part::Actions(vec![copy(lang, "common.copy_key_path", key)]));
        }
    }
    let defender = cfg!(windows) || drive;
    let again: &[&'static str] = if defender { &["step.dll.scan_again", "step.dll.defender"] } else { &["step.dll.scan_again"] };
    parts.push(Part::Text(sentences(lang, again)));
    let title = if files {
        msg("step.dll.title_files").arg("browsers", and(lang, &browsers)).render(lang)
    } else if leftover && !any(r, &[K::RegistryKey]) {
        tr(lang, "step.dll.title_leftover").into()
    } else {
        tr(lang, "step.dll.title_key").into()
    };
    step(title, parts)
}

/// A launcher data folder and its browser cache, or the launcher's login
/// browser profile (the whole folder) when it holds traces.
struct Cache {
    tbs: PathBuf,
    traces: bool,
    login: bool,
}

fn caches(r: &ScanResult) -> Vec<Cache> {
    r.targets
        .iter()
        .filter(|t| matches!(t.kind, TargetKind::LauncherData | TargetKind::LoginProfile))
        .map(|t| {
            let login = t.kind == TargetKind::LoginProfile;
            Cache {
                tbs: if login { t.path.clone() } else { t.path.join("tbs_cache") },
                traces: r
                    .groups
                    .iter()
                    .filter(|g| g.path.as_deref() == Some(t.path.as_path()))
                    .flat_map(|g| &g.findings)
                    .any(|f| CACHE_TRACES.contains(&f.kind)),
                login,
            }
        })
        // Other CEF programs can use the same profile: only one with traces is named.
        .filter(|c| !c.login || c.traces)
        .collect()
}

fn cache_step(r: &ScanResult, lang: Lang) -> Step {
    let mut parts = vec![text(lang, "step.cache.intro")];
    let caches = caches(r);
    if !caches.iter().any(|c| !c.login) {
        parts.push(text(lang, "step.cache.none"));
    }
    let mut login_note = false;
    for c in caches {
        if c.login && !login_note {
            login_note = true;
            parts.push(text(lang, "step.cache.login"));
        }
        parts.push(Part::Code(c.tbs.display().to_string()));
        parts.push(Part::Actions(vec![Action::Reveal(c.tbs)]));
    }
    step(tr(lang, "step.cache.title"), parts)
}

/// The accounts and secrets to change, from what the agent could read.
pub fn password_list(r: &ScanResult, lang: Lang) -> Vec<String> {
    let t = |key| tr(lang, key).to_string();
    let none = Exposure::default();
    let e = r.exposure.as_ref().unwrap_or(&none);
    let mut out = vec![t("step.password.first")];
    let mut browsers: Vec<(&str, Vec<&str>)> = Vec::new();
    for l in &e.logins {
        match browsers.iter_mut().find(|(b, _)| *b == l.browser) {
            Some((_, profiles)) => profiles.push(&l.profile),
            None => browsers.push((l.browser, vec![&l.profile])),
        }
    }
    if browsers.is_empty() {
        out.push(t("step.password.browsers"));
    }
    for (b, profiles) in browsers {
        let key = if profiles.len() == 1 { "step.password.browser_one" } else { "step.password.browser_other" };
        out.push(msg(key).arg("browser", b).arg("profiles", profiles.join(", ")).render(lang));
    }
    out.push(t("step.password.sessions"));
    if e.wallets.is_empty() {
        out.push(t("step.password.crypto"));
    }
    for w in &e.wallets {
        let line = msg("step.password.wallet").arg("wallet", w.name).arg("browser", w.browser).arg("profile", w.profile.as_str());
        out.push(line.render(lang));
    }
    if e.secrets.is_empty() {
        out.push(t("step.password.tokens"));
    }
    for s in &e.secrets {
        let line = msg("step.password.secret").arg("what", msg(s.what)).arg("path", s.path.display().to_string());
        out.push(line.render(lang));
    }
    if !e.wallets.is_empty() || !e.secrets.is_empty() {
        out.push(t("step.password.other"));
    }
    if cfg!(unix) && has_target(r, TargetKind::WinePrefix) {
        out.push(t("step.password.wine"));
    }
    out.extend(home_note(r, lang).map(str::to_string));
    out
}

/// A folder scan that found a Wine prefix also checks this computer's home
/// folder, but the prefix may have been copied from another computer.
pub fn home_note(r: &ScanResult, lang: Lang) -> Option<&'static str> {
    (cfg!(unix) && r.scope != scan::COMPUTER_SCOPE && r.exposure.is_some() && has_target(r, TargetKind::WinePrefix))
        .then(|| tr(lang, "exposure.home_note"))
}

fn password_step(r: &ScanResult, lang: Lang) -> Step {
    let intro = match r.verdict {
        Verdict::Infected => "step.password.intro_infected",
        Verdict::Exposed => "step.password.intro_exposed",
        _ => return step(tr(lang, "step.password.title_maybe"), vec![text(lang, "step.password.maybe")]),
    };
    let list = password_list(r, lang);
    let mut parts = vec![text(lang, intro)];
    parts.extend(list.iter().cloned().map(Part::Item));
    if r.exposure.as_ref().is_some_and(|e| !e.logins.is_empty() || !e.wallets.is_empty() || !e.secrets.is_empty()) {
        parts.push(text(lang, "step.password.not_opened"));
    }
    parts.push(Part::Actions(vec![copy(lang, "common.copy_list", list.join("\n"))]));
    step(tr(lang, "step.password.title"), parts)
}

fn block_step(r: &ScanResult, lang: Lang) -> Step {
    let lines = match &r.hosts {
        Some(h) => report::block_lines(h),
        None => scan::DOMAINS.iter().map(|d| format!("0.0.0.0 {d}")).collect(),
    };
    let mut parts = Vec::new();
    let title = if lines.is_empty() {
        parts.push(text(lang, "step.block.all_blocked"));
        "step.block.title_ips"
    } else {
        if cfg!(windows) {
            let hosts = scan::hosts_path().display().to_string();
            parts.push(text(lang, "step.block.notepad"));
            parts.push(Part::Code(hosts.clone()));
            parts.push(Part::Actions(vec![copy(lang, "common.copy_hosts_path", hosts)]));
            parts.push(text(lang, "step.block.paste"));
            parts.push(Part::Code(lines.join("\n")));
            parts.push(Part::Actions(vec![copy(lang, "common.copy_lines", lines.join("\n"))]));
        } else {
            let cmd = format!("printf '\\n{}\\n' | sudo tee -a /etc/hosts", lines.join("\\n"));
            let deck: &[&'static str] = if cfg!(target_os = "macos") { &["step.block.tee"] } else { &["step.block.tee", "step.block.deck"] };
            parts.push(Part::Text(sentences(lang, deck)));
            parts.push(Part::Code(cmd.clone()));
            parts.push(Part::Actions(vec![copy(lang, "common.copy_command", cmd)]));
        }
        parts.push(text(lang, "step.block.scan_again"));
        "step.block.title_domains"
    };
    let [a, b] = ATTACKER_IPS;
    parts.push(text(lang, "step.block.ips"));
    if cfg!(windows) {
        let cmd = format!("New-NetFirewallRule -DisplayName \"Block NIKKE malware servers\" -Direction Outbound -RemoteAddress {a},{b} -Action Block");
        parts.push(text(lang, "step.block.firewall"));
        parts.push(Part::Code(cmd.clone()));
        parts.push(Part::Actions(vec![copy(lang, "common.copy_command", cmd)]));
    } else if cfg!(target_os = "macos") {
        parts.push(text(lang, "step.block.macos"));
    } else {
        parts.extend(linux_firewall_parts(Firewall::find(), lang));
    }
    step(tr(lang, title), parts)
}

/// The Linux firewall tools the IP step knows, in the order it prefers them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Firewall {
    Firewalld,
    Ufw,
    Nftables,
}

impl Firewall {
    /// The first tool whose program is installed. Only looks for the files: nothing is run.
    fn find() -> Option<Firewall> {
        // ufw and nft are in /usr/sbin, which some distributions leave out of a user's PATH.
        let mut dirs: Vec<PathBuf> = std::env::var_os("PATH").map(|p| std::env::split_paths(&p).collect()).unwrap_or_default();
        dirs.extend(["/usr/sbin", "/sbin"].map(PathBuf::from));
        let has = |name: &str| dirs.iter().any(|d| d.join(name).is_file());
        [(Firewall::Firewalld, "firewall-cmd"), (Firewall::Ufw, "ufw"), (Firewall::Nftables, "nft")]
            .into_iter()
            .find(|(_, name)| has(name))
            .map(|(f, _)| f)
    }
}

/// The text and the command that block the attacker's IPs with `tool`.
fn linux_firewall_parts(tool: Option<Firewall>, lang: Lang) -> Vec<Part> {
    let [a, b] = ATTACKER_IPS;
    let mut parts = Vec::new();
    let mut command = |key: &'static str, cmd: String| {
        parts.push(text(lang, key));
        parts.push(Part::Code(cmd.clone()));
        parts.push(Part::Actions(vec![copy(lang, "common.copy_command", cmd)]));
    };
    match tool {
        Some(Firewall::Firewalld) => {
            let p = "sudo firewall-cmd --permanent --policy nikke-block";
            let reject = |ip| format!("{p} --add-rich-rule='rule family=\"ipv4\" destination address=\"{ip}\" reject'");
            let cmd = format!(
                "sudo firewall-cmd --permanent --new-policy nikke-block && {p} --add-ingress-zone HOST && {p} --add-egress-zone ANY && {} && {} && sudo firewall-cmd --reload",
                reject(a),
                reject(b)
            );
            command("step.block.firewalld", cmd);
            command("step.block.firewalld_check", "sudo firewall-cmd --policy nikke-block --list-all".into());
        }
        Some(Firewall::Ufw) => command("step.block.ufw", format!("sudo ufw deny out to {a} && sudo ufw deny out to {b}")),
        Some(Firewall::Nftables) => command(
            "step.block.nft",
            format!(
                "sudo nft add table inet nikke_block && sudo nft add chain inet nikke_block output '{{ type filter hook output priority 0; }}' && sudo nft add rule inet nikke_block output ip daddr '{{ {a}, {b} }}' reject"
            ),
        ),
        None => parts.push(text(lang, "step.block.no_firewall")),
    }
    parts
}

fn wait_step(agent_ran: bool, lang: Lang) -> Step {
    let mut parts = vec![text(lang, "step.wait.fixed"), text(lang, "step.wait.evidence"), text(lang, "step.wait.keep_blocked")];
    if agent_ran {
        parts.push(text(lang, "step.wait.reinstall"));
    }
    step(tr(lang, "step.wait.title"), parts)
}

fn shown(path: Option<&Path>) -> String {
    path.map(|p| p.display().to_string()).unwrap_or_default()
}

/// Program names from the DllLoaded evidence lines.
fn program_names(f: &Finding, lang: Lang) -> Vec<String> {
    let mut names: Vec<String> = f.evidence.iter().filter_map(|e| e.get("program")).map(|p| p.render(lang)).collect();
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

    pub fn title(self, lang: Lang) -> &'static str {
        tr(
            lang,
            match self {
                Section::Proof => "section.proof",
                Section::Cleanup => "section.cleanup",
                Section::Signs => "section.signs",
                Section::Info => "section.info",
                Section::Coverage => "section.coverage",
            },
        )
    }
}

/// One line on what a finding means for the user.
pub fn meaning(kind: K, lang: Lang) -> &'static str {
    tr(
        lang,
        match kind {
            K::AgentRan => "meaning.agent_ran",
            K::PayloadDownloaded => "meaning.payload_downloaded",
            K::PayloadFile => "meaning.payload_file",
            K::AgentState => "meaning.agent_state",
            K::AgentServerContacted => "meaning.agent_server",
            K::LoaderCached => "meaning.loader_cached",
            K::LauncherContacted => "meaning.launcher_contacted",
            K::ChromeDll => "meaning.chrome_dll",
            K::RegistryKey => "meaning.registry_key",
            K::RegistryLeftover => "meaning.registry_leftover",
            K::LegacyDll => "meaning.legacy_dll",
            K::DllLoaded => "meaning.dll_loaded",
            K::TempFile => "meaning.temp_file",
            K::LauncherRunning => "meaning.launcher_running",
            K::Coverage => "meaning.coverage",
            K::Info => "meaning.info",
        },
    )
}

/// The exposure lists of the Details tab: (heading, [(what, path)]).
pub fn exposure_lists(e: &Exposure, lang: Lang) -> [(&'static str, Vec<(String, PathBuf)>); 3] {
    let login = |l: &crate::exposure::BrowserLogins| {
        msg("exposure.login").arg("browser", l.browser).arg("profile", l.profile.as_str()).arg("files", l.files.join(", "))
    };
    let wallet = |w: &crate::exposure::Wallet| {
        msg("exposure.wallet").arg("wallet", w.name).arg("id", w.id).arg("browser", w.browser).arg("profile", w.profile.as_str())
    };
    [
        (tr(lang, "exposure.saved_passwords"), e.logins.iter().map(|l| (login(l).render(lang), l.path.clone())).collect()),
        (tr(lang, "exposure.wallets"), e.wallets.iter().map(|w| (wallet(w).render(lang), w.path.clone())).collect()),
        (tr(lang, "exposure.secrets"), e.secrets.iter().map(|s| (tr(lang, s.what).to_string(), s.path.clone())).collect()),
    ]
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::locate::{Target, WalkStats};
    use crate::scan::{Group, HostsStatus, Severity};

    const EN: Lang = Lang::En;

    fn finding(kind: K, severity: Severity, title: &str) -> Finding {
        // A ChromeDll title keeps the browser name, as the scan writes it.
        let title = match title.strip_suffix(" persistence is installed") {
            Some(browser) if kind == K::ChromeDll => scan::persistence_title(browser),
            _ => title.into(),
        };
        Finding {
            kind,
            severity,
            title,
            detail: "".into(),
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
        steps(r, EN).into_iter().map(|s| s.title).collect()
    }

    #[test]
    fn steps_follow_the_findings() {
        let mut dll = finding(K::ChromeDll, Severity::Critical, "Edge persistence is installed");
        let hash = "a".repeat(64);
        dll.path = Some(PathBuf::from("/p/PlatformExperienceHelper"));
        dll.open_path = Some(PathBuf::from(format!("/p/PlatformExperienceHelper/{hash}/platform_experience_helper.dll")));
        let mut loaded = finding(K::DllLoaded, Severity::Critical, "The persistence DLL is loaded now");
        loaded.evidence = vec![
            scan::dll_loaded_line(9, "msedge.exe", "C:\\e\\msedge.exe", "C:\\x.dll"),
            scan::dll_loaded_line(4, "explorer.exe", "C:\\explorer.exe", "C:\\x.dll"),
        ];
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
                "Before you open the launcher again",
            ]
        );
        let all = steps(&infected, EN);
        let codes: Vec<&str> = all.iter().flat_map(|s| &s.parts).filter_map(|p| if let Part::Code(c) = p { Some(c.as_str()) } else { None }).collect();
        assert!(codes.contains(&format!("/p/PlatformExperienceHelper/{hash}").as_str()), "{codes:?}");
        let cache = Path::new("/d/nikke_launcher").join("tbs_cache").display().to_string();
        assert!(codes.contains(&cache.as_str()), "{codes:?}");
        let close = format!("{:?}", all[0].parts);
        assert!(close.contains("Programs to end: msedge.exe.") && close.contains("Do not end explorer.exe"), "{close}");
        let [ran, active, clean, protect] = answers(&infected, EN);
        assert_eq!((ran.reply, active.reply, clean.reply, protect.reply), ("Yes", "Yes", "Yes", "Partly"));
        assert!(clean.lines.iter().any(|l| l.contains("tbs_cache")), "{:?}", clean.lines);

        // A quick scan's "No" is unsure, and its steps offer the full scan.
        let mut quick_clean = result(Verdict::NoTraces, vec![], vec![(TargetKind::InstallDir, "/n"), (TargetKind::LauncherData, "/d/nikke_launcher")]);
        quick_clean.stats.depth_limit = Some(5);
        let [ran, ..] = answers(&quick_clean, EN);
        assert_eq!((ran.reply, ran.tone), ("No", Tone::Unsure));
        assert_eq!(titles(&quick_clean)[0], "Run the full scan");

        let clean_scan = result(Verdict::NoTraces, vec![], vec![(TargetKind::InstallDir, "/n"), (TargetKind::LauncherData, "/d/nikke_launcher")]);
        assert_eq!(
            titles(&clean_scan),
            [
                "Clear the launcher cache",
                "Change your NIKKE password if the launcher was open on or after October 23",
                "Block the domains",
                "Before you open the launcher again",
            ]
        );
        let [ran, active, clean, _] = answers(&clean_scan, EN);
        assert_eq!((ran.reply, active.reply, clean.reply), ("No", "No", "No"));
        assert_eq!(ran.tone, Tone::Good);

        let exposed = result(Verdict::Exposed, vec![finding(K::LoaderCached, Severity::Warning, "Loader")], vec![(TargetKind::LauncherData, "/d/nikke_launcher")]);
        let t = titles(&exposed);
        // Scanning the install can change the result, so it comes before the cleanup.
        assert_eq!(t[..3], ["Save the report before you delete anything", "Scan the folder where NIKKE is installed", "Clear the launcher cache"]);
        assert!(t.contains(&"Change your passwords from another device".to_string()));
        let ran = &answers(&exposed, EN)[0];
        assert_eq!(ran.reply, "No");
        assert!(!ran.lines.iter().any(|l| l.starts_with("Finding nothing")), "{:?}", ran.lines);

        let none = result(Verdict::NotFound, vec![], vec![]);
        assert_eq!(titles(&none)[0], "Scan the folder where NIKKE is installed");
        assert_eq!(answers(&none, EN)[0].reply, "Cannot tell");
        // Only a quick scan offers the full scan.
        let offers_full = |r: &ScanResult| {
            steps(r, EN)[0].parts.iter().any(|p| matches!(p, Part::Actions(a) if a.iter().any(|a| matches!(a, Action::FullScan))))
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
        assert_eq!(answers(&gap, EN)[0].tone, Tone::Unsure);
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
        let step = dll_step(&drive, EN);
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
        let step = dll_step(&wine, EN);
        assert_eq!(step.title, "Delete the leftover registry key");
        let t = texts(&step);
        assert!(t.contains("The key is inside a Wine prefix") && !t.contains("Windows drive"), "{t}");
        assert!(t.contains("WINEPREFIX='/s/steamapps/compatdata/123/pfx' wine regedit"), "{t}");
        assert!(t.contains("protontricks -c 'wine regedit' 123"), "{t}");
        assert!(!t.contains("Defender"), "{t}");
        let [_, active, clean, _] = answers(&wine, EN);
        assert_eq!(active.reply, "No");
        assert!(clean.lines[0].contains("left after the malware cleared the DLL path"), "{:?}", clean.lines);

        // Only the files of the older version: no 64-hex folder to point at.
        let mut legacy = finding(K::LegacyDll, Severity::Critical, "Files of an older Chrome persistence are installed");
        legacy.path = Some(PathBuf::from(format!("{pfx}/drive_c/Program Files/Google/Chrome/Application/PlatformExperienceHelper")));
        let step = dll_step(&result(Verdict::Infected, vec![legacy], vec![(TargetKind::WinePrefix, pfx)]), EN);
        let t = texts(&step);
        assert!(!t.contains("64 hex") && t.contains("1. In the folder below, delete only platform_experience_helper.dll"), "{t}");
    }

    #[test]
    fn running_launcher_needs_a_sign_of_the_agent() {
        let targets = || vec![(TargetKind::InstallDir, "/n"), (TargetKind::LauncherData, "/d/nikke_launcher")];
        // A clean, reinstalled launcher that runs: listed for information, no step to close it.
        let mut running = finding(K::Info, Severity::Info, "");
        running.title = msg("finding.launcher_running_clean.title");
        let clean = result(Verdict::NoTraces, vec![running], targets());
        assert!(!act_now(&clean));
        assert!(!titles(&clean).iter().any(|t| t == "Close the launcher"), "{:?}", titles(&clean));
        let active = &answers(&clean, EN)[1];
        assert_eq!(active.reply, "No");
        assert!(active.lines[0].starts_with("The NIKKE launcher is running, but"), "{:?}", active.lines);
        // With the agent's traces, the launcher is critical and closing it comes first.
        let running = finding(K::LauncherRunning, Severity::Critical, "The NIKKE launcher is running now");
        let infected = result(Verdict::Infected, vec![running, finding(K::AgentState, Severity::Critical, "Agent state")], targets());
        assert!(act_now(&infected));
        assert_eq!(titles(&infected)[0], "Close the launcher");
        assert_eq!(answers(&infected, EN)[1].reply, "Yes");
    }

    #[test]
    fn firewall_commands_follow_the_tool() {
        let codes = |tool| {
            linux_firewall_parts(tool, EN).into_iter().filter_map(|p| if let Part::Code(c) = p { Some(c) } else { None }).collect::<Vec<_>>()
        };
        let firewalld = codes(Some(Firewall::Firewalld));
        assert_eq!(firewalld.len(), 2);
        assert!(firewalld[0].starts_with("sudo firewall-cmd --permanent --new-policy nikke-block && "), "{}", firewalld[0]);
        assert!(firewalld[0].contains(r#"--add-rich-rule='rule family="ipv4" destination address="89.126.250.172" reject'"#), "{}", firewalld[0]);
        assert!(firewalld[0].ends_with(" && sudo firewall-cmd --reload"));
        assert_eq!(firewalld[1], "sudo firewall-cmd --policy nikke-block --list-all");
        assert_eq!(codes(Some(Firewall::Ufw)), ["sudo ufw deny out to 89.127.233.127 && sudo ufw deny out to 89.126.250.172"]);
        let nft = codes(Some(Firewall::Nftables));
        assert!(nft[0].ends_with("output ip daddr '{ 89.127.233.127, 89.126.250.172 }' reject"), "{}", nft[0]);
        assert!(codes(None).is_empty());
        assert!(format!("{:?}", linux_firewall_parts(None, EN)).contains("No firewall tool was found"));
    }

    #[test]
    fn login_profile_with_traces_is_cleaned_too() {
        let cef = "/x/AppData/Local/CEF/User Data";
        let mut state = finding(K::AgentState, Severity::Critical, "Agent state");
        state.path = Some(PathBuf::from(cef));
        let mut r = result(Verdict::Infected, vec![], vec![(TargetKind::LauncherData, "/d/nikke_launcher"), (TargetKind::LoginProfile, cef)]);
        r.groups = vec![Group { label: "Login".into(), path: Some(PathBuf::from(cef)), findings: vec![state] }];
        let step = cache_step(&r, EN);
        let t = texts(&step);
        assert!(t.contains("login browser profile below also holds traces") && t.contains(&format!("Code({cef:?})")), "{t}");
        assert!(answers(&r, EN)[2].lines.iter().any(|l| l.starts_with("The launcher's login browser profile")));
        // Without traces the profile is another program's data as much as the launcher's: not named.
        r.groups.clear();
        assert!(!texts(&cache_step(&r, EN)).contains("CEF"));
    }

    #[test]
    fn password_list_keeps_the_general_lines() {
        use crate::exposure::SecretFile;
        let mut r = result(Verdict::Infected, vec![finding(K::AgentRan, Severity::Critical, "The malware agent ran")], vec![(TargetKind::InstallDir, "/n")]);
        let step = password_step(&r, EN);
        assert!(!texts(&step).contains("only checked that these files exist"), "{}", texts(&step));
        r.exposure = Some(Exposure { secrets: vec![SecretFile { what: "npm token", path: PathBuf::from("/h/.npmrc") }], ..Exposure::default() });
        let list = password_list(&r, EN);
        assert!(list.iter().any(|l| l == "Revoke and replace: npm token, /h/.npmrc."), "{list:?}");
        assert!(list.iter().any(|l| l.starts_with("Any other password, API token, SSH key or wallet")), "{list:?}");
        assert!(texts(&password_step(&r, EN)).contains("only checked that these files exist"));
    }

    #[test]
    fn powershell_names_are_quoted() {
        assert_eq!(ps_command("nikke-check-windows-x86_64 (1).exe", ""), r"& '.\nikke-check-windows-x86_64 (1).exe' --cli | Out-Host");
        assert_eq!(ps_command("it's.exe", " 'D:\\x'"), r"& '.\it''s.exe' --cli 'D:\x' | Out-Host");
    }

    #[test]
    fn run_lines() {
        let run = AgentRun { kind: RunKind::Started, time: Some("11-03 01:47:36".into()), agent_id: None, host: Some("COLONY".into()), file: None, source: PathBuf::new() };
        assert_eq!(run_line(&run, EN), "11-03 01:47:36: the agent sent the computer name COLONY to the attacker");
        let run = AgentRun { source: PathBuf::from("/n/debug.log"), host: None, ..run };
        assert_eq!(run_line(&run, EN), "11-03 01:47:36: the agent sent the computer name to the attacker (from debug.log)");
    }
}
