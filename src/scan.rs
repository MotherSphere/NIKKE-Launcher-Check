//! The checks. Pure logic: reads files, never writes, never uses the network.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use walkdir::WalkDir;

use crate::locate::{self, Discovery, TargetKind, WalkStats, find_ci};

pub const DOMAINS: [&str; 3] = ["insightjs.com", "analytics.insightjs.com", "insightjs.org"];
pub const PAYLOAD_IP: &str = "89.127.233.127";
pub const CLSID: &str = "{E77CC89B-7401-4C04-8CED-149DB35ADD04}";

const MAX_FILE: u64 = 64 * 1024 * 1024;
const MAX_EVIDENCE: usize = 5;
const EVIDENCE_CHARS: usize = 240;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

impl Severity {
    pub fn tag(self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Warning => "WARNING",
            Severity::Critical => "CRITICAL",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub severity: Severity,
    pub title: String,
    pub detail: String,
    pub path: Option<PathBuf>,
    pub evidence: Vec<String>,
    pub time: Option<String>,
}

impl Finding {
    fn new(severity: Severity, title: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            severity,
            title: title.into(),
            detail: detail.into(),
            path: None,
            evidence: Vec::new(),
            time: None,
        }
    }

    fn at(mut self, path: &Path) -> Self {
        self.path = Some(path.to_path_buf());
        self
    }

    fn evidence(mut self, lines: impl IntoIterator<Item = String>) -> Self {
        self.evidence = lines.into_iter().take(MAX_EVIDENCE).map(|l| clip(&l)).collect();
        self
    }

    fn time(mut self, time: Option<String>) -> Self {
        self.time = time;
        self
    }
}

/// Findings for one location.
#[derive(Debug, Clone)]
pub struct Group {
    pub label: String,
    pub path: Option<PathBuf>,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Infected,
    Exposed,
    NoTraces,
    NotFound,
}

impl Verdict {
    pub fn exit_code(self) -> u8 {
        match self {
            Verdict::NoTraces => 0,
            Verdict::Exposed => 1,
            Verdict::Infected => 2,
            Verdict::NotFound => 3,
        }
    }
}

#[derive(Debug, Clone)]
pub struct HostsStatus {
    pub path: PathBuf,
    pub readable: bool,
    /// (domain, blocked)
    pub domains: Vec<(&'static str, bool)>,
}

#[derive(Debug, Clone)]
pub struct ScanResult {
    pub scope: String,
    pub started: String,
    pub verdict: Verdict,
    pub targets: Vec<locate::Target>,
    pub groups: Vec<Group>,
    pub hosts: Option<HostsStatus>,
    pub stats: WalkStats,
    pub seconds: f64,
}

pub fn scan_computer() -> ScanResult {
    let start = Instant::now();
    let discovery = locate::discover_computer();
    run("this computer".into(), discovery, true, start)
}

pub fn scan_folders(paths: &[PathBuf]) -> ScanResult {
    let start = Instant::now();
    let scope = paths
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    run(scope, locate::discover_folders(paths), true, start)
}

/// Runs every check on the discovered targets. `system_checks` adds the
/// running-process check and the hosts file (left out in tests).
pub fn run(scope: String, discovery: Discovery, system_checks: bool, start: Instant) -> ScanResult {
    let started = utc(SystemTime::now()).unwrap_or_default();
    let mut groups = Vec::new();
    if system_checks {
        let running = check_processes();
        if !running.is_empty() {
            groups.push(Group { label: "Running programs".into(), path: None, findings: running });
        }
    }
    for target in &discovery.targets {
        let mut findings = match target.kind {
            TargetKind::InstallDir => check_install(&target.path),
            TargetKind::LauncherData => check_launcher_data(&target.path),
            TargetKind::UserProfile => check_profile(&target.path, target.host),
            TargetKind::WinePrefix => check_prefix(&target.path),
        };
        if !findings.is_empty() {
            findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
            groups.push(Group {
                label: target.kind.label().into(),
                path: Some(target.path.clone()),
                findings,
            });
        }
    }
    let coverage = check_coverage(&discovery);
    if !coverage.is_empty() {
        groups.push(Group { label: "Scan coverage".into(), path: None, findings: coverage });
    }
    let worst = groups.iter().flat_map(|g| &g.findings).map(|f| f.severity).max();
    let found = discovery
        .targets
        .iter()
        .any(|t| matches!(t.kind, TargetKind::InstallDir | TargetKind::LauncherData));
    let verdict = match worst {
        Some(Severity::Critical) => Verdict::Infected,
        Some(Severity::Warning) => Verdict::Exposed,
        _ if found => Verdict::NoTraces,
        _ => Verdict::NotFound,
    };
    ScanResult {
        scope,
        started,
        verdict,
        targets: discovery.targets,
        groups,
        hosts: system_checks.then(check_hosts),
        stats: discovery.stats,
        seconds: start.elapsed().as_secs_f64(),
    }
}

/// What the scan could not check: the install, unreadable folders, network drives.
fn check_coverage(discovery: &Discovery) -> Vec<Finding> {
    let mut out = Vec::new();
    let has = |kind| discovery.targets.iter().any(|t| t.kind == kind);
    if has(TargetKind::LauncherData) && !has(TargetKind::InstallDir) {
        out.push(Finding::new(
            Severity::Info,
            "The NIKKE install folder was not found",
            "Launcher data was found, but not the install folder, so debug.log and the download logs were not checked. If you know where NIKKE is installed, scan that folder: \"Scan a folder...\" in the window, or nikke-check --cli <folder>.",
        ));
    }
    let shown = |paths: &[PathBuf]| capped(paths.iter().map(|p| p.display().to_string()).collect());
    let stats = &discovery.stats;
    if !stats.unreadable.is_empty() {
        out.push(
            Finding::new(
                Severity::Info,
                "Some folders could not be read",
                "The scan was not allowed to open these folders, so nothing in them was checked. On macOS, give Terminal (or the app you started this tool from) Full Disk Access in System Settings > Privacy & Security, then scan again. Elsewhere, scan again as a user who can read them.",
            )
            .evidence(shown(&stats.unreadable)),
        );
    }
    if !stats.skipped_mounts.is_empty() {
        out.push(
            Finding::new(
                Severity::Info,
                "Network drives were not scanned",
                "\"Scan this computer\" skips network drives and remote mounts, because reading them is slow and a disconnected one can stop the scan. If NIKKE is installed on one, scan it with \"Scan a folder...\" or nikke-check --cli <folder>.",
            )
            .evidence(shown(&stats.skipped_mounts)),
        );
    }
    out
}

// ---------------------------------------------------------------- A: install

fn check_install(dir: &Path) -> Vec<Finding> {
    let mut out = Vec::new();
    let launcher = find_ci(dir, &["Launcher"]);
    let debug = launcher.as_deref().and_then(|l| find_ci(l, &["intl_service", "debug.log"]));

    // A1
    let debug_note = match debug.as_deref() {
        None => "No Launcher/intl_service/debug.log was found. The launcher rewrites this file at each start, so it may also have been deleted.".to_string(),
        Some(path) => match read_small(path) {
            None => "Launcher/intl_service/debug.log exists but could not be read (too large or no permission).".to_string(),
            Some(bytes) => {
                if contains(&bytes, b"k2f_chan") {
                    let lines = snippets(
                        &bytes,
                        &[b"k2f_chan", b"adopted ", b"agent started as", b"lua downloaded to"],
                        MAX_EVIDENCE,
                    );
                    let time = lines.iter().find_map(|l| cef_time(l));
                    out.push(
                        Finding::new(
                            Severity::Critical,
                            "The malware agent ran",
                            "debug.log shows the remote-access agent starting inside the launcher (k2f_chan registered). While the launcher was open, the attacker could run commands on this computer.",
                        )
                        .at(path)
                        .evidence(lines)
                        .time(time),
                    );
                }
                let lines = snippets(&bytes, &[b"insightjs"], MAX_EVIDENCE);
                if !lines.is_empty() {
                    let time = lines.iter().find_map(|l| cef_time(l));
                    out.push(
                        Finding::new(
                            Severity::Critical,
                            "The launcher log mentions insightjs",
                            "debug.log names insightjs, the domain that serves the malicious script and the agent.",
                        )
                        .at(path)
                        .evidence(lines)
                        .time(time),
                    );
                }
                "Launcher/intl_service/debug.log was checked. It only covers the last launch.".to_string()
            }
        },
    };

    // A2
    if let Some(log) = launcher.as_deref().and_then(|l| find_ci(l, &["log"])) {
        for path in files_under(&log, 8) {
            let Some(bytes) = read_small(&path) else {
                continue;
            };
            if bytes.starts_with(b"\x1bLJ") {
                out.push(
                    Finding::new(
                        Severity::Critical,
                        "The malware file is still on disk",
                        "This file in the launcher's log folder is LuaJIT bytecode. The launcher saved the downloaded agent (insight.bundle) under a tinyget log name.",
                    )
                    .at(&path)
                    .evidence([format!(
                        "LuaJIT bytecode header (1B 4C 4A), {} bytes. The known agent is 205,135 bytes.",
                        bytes.len()
                    )])
                    .time(mtime(&path)),
                );
                continue;
            }
            let bundle = contains(&bytes, b"insight.bundle");
            if !bundle && !contains(&bytes, b"insightjs") {
                continue;
            }
            let name = file_name(&path);
            let (title, detail, needle): (&str, String, &[u8]) = if bundle {
                (
                    "The launcher downloaded the malware",
                    format!("{name} records the launcher downloading insight.bundle from analytics.insightjs.com. That file is the remote-access agent."),
                    b"insight.bundle",
                )
            } else {
                (
                    "A launcher log mentions insightjs",
                    format!("{name} names insightjs, the domain that serves the malicious script and the agent."),
                    b"insightjs",
                )
            };
            let lines = snippets(&bytes, &[needle], MAX_EVIDENCE);
            let time = lines.iter().find_map(|l| log_time(l));
            out.push(Finding::new(Severity::Critical, title, detail).at(&path).evidence(lines).time(time));
        }
    }

    // A3
    let debug_time = debug.as_deref().and_then(mtime);
    let detail = match &debug_time {
        Some(t) => format!("{debug_note} Last written {t}."),
        None => debug_note,
    };
    out.push(Finding::new(Severity::Info, format!("NIKKE install found at {}", dir.display()), detail).at(dir));
    out
}

// ---------------------------------------------------------- B: launcher data

#[derive(Default)]
struct Hits {
    files: usize,
    first: Option<PathBuf>,
    evidence: Vec<String>,
    newest: Option<SystemTime>,
}

impl Hits {
    fn add(&mut self, path: &Path, rel: &str, snippet: Option<String>) {
        self.files += 1;
        self.first.get_or_insert_with(|| path.to_path_buf());
        if self.evidence.len() < MAX_EVIDENCE {
            self.evidence.push(match snippet {
                Some(s) => format!("{rel}: {s}"),
                None => rel.to_string(),
            });
        }
        let modified = fs::metadata(path).and_then(|m| m.modified()).ok();
        self.newest = self.newest.max(modified);
    }

    fn finding(self, severity: Severity, title: &str, detail: String) -> Option<Finding> {
        let first = self.first?;
        Some(
            Finding::new(severity, title, detail)
                .at(&first)
                .evidence(self.evidence)
                .time(self.newest.and_then(utc)),
        )
    }
}

fn plural(n: usize, word: &str) -> String {
    if n == 1 { format!("1 {word}") } else { format!("{n} {word}s") }
}

fn check_launcher_data(dir: &Path) -> Vec<Finding> {
    let (mut agent, mut cache, mut network, mut other) =
        (Hits::default(), Hits::default(), Hits::default(), Hits::default());
    let mut checked = 0usize;
    for path in files_under(dir, 12) {
        let Some(bytes) = read_small(&path) else {
            continue;
        };
        checked += 1;
        let rel = path.strip_prefix(dir).unwrap_or(&path).display().to_string();
        if contains(&bytes, b"k2f_chan") {
            agent.add(&path, &rel, snippets(&bytes, &[b"k2f_chan"], 1).pop());
        }
        if contains(&bytes, b"insightjs") {
            let snippet = snippets(&bytes, &[b"insightjs"], 1).pop();
            let name = file_name(&path);
            // Exact names: the CEF profile folder itself is called tbs_cache.
            let in_cache = path.strip_prefix(dir).unwrap_or(&path).components().any(|c| {
                let c = c.as_os_str().to_string_lossy();
                c.eq_ignore_ascii_case("Code Cache") || c.eq_ignore_ascii_case("Cache")
            });
            let bucket = if ["Network Persistent State", "TransportSecurity", "Reporting and NEL"].contains(&name.as_str()) {
                &mut network
            } else if in_cache {
                &mut cache
            } else {
                &mut other
            };
            bucket.add(&path, &rel, snippet);
        }
    }
    let mut out = Vec::new();
    let (a, c, n, o) = (agent.files, cache.files, network.files, other.files);
    out.extend(agent.finding(
        Severity::Critical,
        "The malware agent left traces in the launcher data",
        format!("k2f_chan, the agent's bridge channel name, appears in {} in the launcher data.", plural(a, "file")),
    ));
    out.extend(cache.finding(
        Severity::Warning,
        "The launcher loaded the malicious script",
        format!("The insightjs.com loader address appears in {} cached by the launcher's built-in browser. The injected script ran; this alone does not show that the agent was downloaded.", plural(c, "file")),
    ));
    out.extend(network.finding(
        Severity::Warning,
        "The launcher connected to insightjs.com",
        format!("insightjs.com appears in {} of network state, so the launcher's built-in browser contacted it.", plural(n, "file")),
    ));
    out.extend(other.finding(
        Severity::Warning,
        "Launcher data mentions insightjs.com",
        format!("insightjs.com appears in {} in the launcher data.", plural(o, "file")),
    ));
    if out.is_empty() {
        out.push(
            Finding::new(Severity::Info, "No traces in the launcher data", format!("Checked {}.", plural(checked, "file")))
                .at(dir),
        );
    }
    out
}

// ---------------------------------------------------------- C: user profile

fn check_profile(profile: &Path, host: bool) -> Vec<Finding> {
    let mut out = Vec::new();
    let local = find_ci(profile, &["AppData", "Local"]);

    // C1
    if let Some(helper) = local
        .as_deref()
        .and_then(|l| find_ci(l, &["Google", "Chrome", "User Data", "PlatformExperienceHelper"]))
        .filter(|p| p.is_dir())
    {
        let contents: Vec<String> = WalkDir::new(&helper)
            .follow_links(false)
            .min_depth(1)
            .max_depth(3)
            .into_iter()
            .flatten()
            .map(|e| e.path().strip_prefix(&helper).unwrap_or(e.path()).display().to_string())
            .collect();
        let mut evidence = contents.clone();
        if contents.is_empty() {
            evidence.push("(empty folder)".into());
        } else if contents.len() > MAX_EVIDENCE {
            evidence.truncate(MAX_EVIDENCE - 1);
            evidence.push(format!("... {} entries in total", contents.len()));
        }
        out.push(
            Finding::new(
                Severity::Critical,
                "Chrome persistence is installed",
                "The malware's folder exists in Chrome's user data. It holds platform_experience_helper.dll, which a hijacked HKCU COM registration makes Google Chrome load.",
            )
            .at(&helper)
            .evidence(evidence)
            .time(mtime(&helper)),
        );
    }

    // C2, C3
    let mut temps: Vec<PathBuf> = local.as_deref().and_then(|l| find_ci(l, &["Temp"])).into_iter().collect();
    if host && cfg!(windows) {
        temps.push(std::env::temp_dir());
    }
    let mut seen = Vec::new();
    for temp in temps {
        let key = fs::canonicalize(&temp).unwrap_or_else(|_| temp.clone());
        if !seen.contains(&key) {
            seen.push(key);
            check_temp(&temp, &mut out);
        }
    }

    // C5
    #[cfg(windows)]
    if host {
        out.extend(check_host_registry());
    }
    out
}

fn check_temp(temp: &Path, out: &mut Vec<Finding>) {
    let Ok(entries) = fs::read_dir(temp) else {
        return;
    };
    let mut k2f = Vec::new();
    let mut markers = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let lower = name.to_ascii_lowercase();
        if lower.starts_with("k2f") {
            k2f.push(entry.path());
        } else if lower.ends_with(".tmp")
            && entry.metadata().is_ok_and(|m| m.is_file() && m.len() == 22)
            && let Ok(bytes) = fs::read(entry.path())
            && bytes.iter().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        {
            markers.push((entry.path(), String::from_utf8_lossy(&bytes).into_owned()));
        }
    }
    k2f.sort();
    markers.sort();
    if let Some(first) = k2f.first() {
        let mut evidence: Vec<String> = k2f.iter().map(|p| file_name(p)).collect();
        if k2f.len() > MAX_EVIDENCE {
            evidence.truncate(MAX_EVIDENCE - 1);
            evidence.push(format!("... {} in total", plural(k2f.len(), "file")));
        }
        out.push(
            Finding::new(
                Severity::Critical,
                "Files left by the malware in Temp",
                "The agent names its temporary files k2f-bcreds-* (collected browser credentials) and k2f_screen_*.jpg (screenshots).",
            )
            .at(first)
            .evidence(evidence)
            .time(mtime(first)),
        );
    }
    if let Some((first, _)) = markers.first() {
        let evidence: Vec<String> = markers
            .iter()
            .map(|(p, id)| match mtime(p) {
                Some(t) => format!("{}: {id} ({t})", file_name(p)),
                None => format!("{}: {id}", file_name(p)),
            })
            .collect();
        out.push(
            Finding::new(
                Severity::Warning,
                "Possible infection marker",
                "A 22-byte .tmp file in Temp holds a 22-character hex ID. The malware writes a file like this one second before it downloads the agent. On its own this is a weak sign: other programs can write similar files.",
            )
            .at(first)
            .evidence(evidence)
            .time(mtime(first)),
        );
    }
}

#[cfg(windows)]
fn check_host_registry() -> Option<Finding> {
    use windows_sys::Win32::System::Registry::{HKEY_CURRENT_USER, KEY_WOW64_32KEY, KEY_WOW64_64KEY};
    let key = format!("Software\\Classes\\CLSID\\{CLSID}\\InprocServer32");
    // The 32-bit launcher could also have written the key into the WOW6432Node view.
    let views = [
        (KEY_WOW64_64KEY, "HKCU\\Software\\Classes\\CLSID"),
        (KEY_WOW64_32KEY, "HKCU\\Software\\Classes\\WOW6432Node\\CLSID"),
    ];
    let lines: Vec<String> = views
        .into_iter()
        .filter_map(|(view, label)| {
            let value = locate::reg_string(HKEY_CURRENT_USER, &key, None, view)?;
            Some(format!("{label}\\{CLSID}\\InprocServer32 (Default) = {}", value.as_deref().unwrap_or("(value not set)")))
        })
        .collect();
    if lines.is_empty() {
        return None;
    }
    Some(
        Finding::new(
            Severity::Critical,
            "Registry persistence found (HKCU CLSID hijack)",
            format!("The key {CLSID}\\InprocServer32 exists under HKCU (see below). The malware registers it so Google Chrome loads its DLL. The HKLM copy that points to wpc.dll is part of Windows and is normal."),
        )
        .evidence(lines),
    )
}

// -------------------------------------------------- C4: Wine prefix registry

fn check_prefix(prefix: &Path) -> Vec<Finding> {
    let Some(user_reg) = find_ci(prefix, &["user.reg"]) else {
        return Vec::new();
    };
    let Some(bytes) = read_small(&user_reg) else {
        return Vec::new();
    };
    // user.reg is HKCU. system.reg (HKLM) has a normal copy pointing to wpc.dll.
    let evidence = clsid_keys(&String::from_utf8_lossy(&bytes));
    if evidence.is_empty() {
        return Vec::new();
    }
    vec![
        Finding::new(
            Severity::Critical,
            "Registry persistence found (HKCU CLSID hijack)",
            format!("user.reg (the HKCU hive of this Wine prefix) registers {CLSID}, the COM class the malware hijacks so Google Chrome loads its DLL. The HKLM copy in system.reg that points to wpc.dll is normal; this HKCU copy is not."),
        )
        .at(&user_reg)
        .evidence(evidence)
        .time(mtime(&user_reg)),
    ]
}

/// Section headers for the CLSID and their default (`@=`) values.
fn clsid_keys(reg: &str) -> Vec<String> {
    // Wine .reg files double every backslash in key names.
    let needle = format!("clsid\\\\{}", CLSID.to_ascii_lowercase());
    let mut out = Vec::new();
    let mut inside = false;
    for line in reg.lines().map(str::trim) {
        if line.starts_with('[') {
            inside = line.to_ascii_lowercase().contains(&needle);
            if inside {
                // Drop Wine's trailing timestamp after "]".
                out.push(line.split_once(']').map_or(line, |(k, _)| k).to_string() + "]");
            }
        } else if inside && line.starts_with("@=") {
            out.push(line.to_string());
        }
    }
    out
}

// ------------------------------------------------------------- D: hosts

pub fn hosts_path() -> PathBuf {
    if cfg!(windows) {
        let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
        Path::new(&root).join("System32\\drivers\\etc\\hosts")
    } else {
        PathBuf::from("/etc/hosts")
    }
}

fn check_hosts() -> HostsStatus {
    let path = hosts_path();
    let text = fs::read(&path).ok().map(|b| String::from_utf8_lossy(&b).into_owned());
    HostsStatus {
        readable: text.is_some(),
        domains: parse_hosts(text.as_deref().unwrap_or("")),
        path,
    }
}

/// Which of [`DOMAINS`] the hosts file maps to a null or loopback address.
pub fn parse_hosts(text: &str) -> Vec<(&'static str, bool)> {
    DOMAINS
        .iter()
        .map(|&domain| {
            let blocked = text.lines().any(|line| {
                let line = line.split('#').next().unwrap_or("");
                let mut fields = line.split_whitespace();
                fields
                    .next()
                    .is_some_and(|ip| matches!(ip, "0.0.0.0" | "127.0.0.1" | "::1" | "::"))
                    && fields.any(|h| h.eq_ignore_ascii_case(domain))
            });
            (domain, blocked)
        })
        .collect()
}

// --------------------------------------------------------- E: processes

fn check_processes() -> Vec<Finding> {
    use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};
    let mut system = System::new();
    system.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::nothing().with_cmd(UpdateKind::Always).without_tasks(),
    );
    let me = sysinfo::get_current_pid().ok();
    let mut evidence: Vec<String> = system
        .processes()
        .iter()
        .filter(|(pid, _)| Some(**pid) != me)
        .filter_map(|(pid, p)| {
            let name = p.name().to_string_lossy();
            // Linux truncates names to 15 bytes ("nikke_launcher."); Wine shows the .exe in the command line.
            let hit = name.to_ascii_lowercase().starts_with("nikke_launcher")
                || p.cmd().iter().any(|arg| {
                    let arg = arg.to_string_lossy();
                    arg.rsplit(['/', '\\']).next().is_some_and(|b| b.eq_ignore_ascii_case("nikke_launcher.exe"))
                });
            let cmd: Vec<String> = p.cmd().iter().map(|a| a.to_string_lossy().into_owned()).collect();
            hit.then(|| format!("PID {pid}: {}", if cmd.is_empty() { name.into_owned() } else { cmd.join(" ") }))
        })
        .collect();
    if evidence.is_empty() {
        return Vec::new();
    }
    evidence.sort();
    vec![
        Finding::new(
            Severity::Critical,
            "The NIKKE launcher is running now",
            "Close the launcher immediately (end the process if it does not close) and disconnect from the network. While it runs, the attacker can send commands to this computer.",
        )
        .evidence(evidence),
    ]
}

// ------------------------------------------------------------- helpers

/// At most MAX_EVIDENCE lines, the last one giving the total when some are left out.
fn capped(mut lines: Vec<String>) -> Vec<String> {
    if lines.len() > MAX_EVIDENCE {
        let total = lines.len();
        lines.truncate(MAX_EVIDENCE - 1);
        lines.push(format!("... {total} in total"));
    }
    lines
}

fn read_small(path: &Path) -> Option<Vec<u8>> {
    let meta = fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_FILE {
        return None;
    }
    fs::read(path).ok()
}

/// Regular files under `dir`, without following symlinks (not even `dir` itself).
fn files_under(dir: &Path, max_depth: usize) -> Vec<PathBuf> {
    WalkDir::new(dir)
        .follow_links(false)
        .follow_root_links(false)
        .max_depth(max_depth)
        .into_iter()
        .flatten()
        .filter(|e| e.file_type().is_file())
        .map(walkdir::DirEntry::into_path)
        .collect()
}

fn file_name(path: &Path) -> String {
    path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
}

pub(crate) fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    find(haystack, needle).is_some()
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Text around each match, one per line (or printable run in a binary file).
fn snippets(bytes: &[u8], needles: &[&[u8]], max: usize) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for segment in bytes.split(|&b| (b < 0x20 && b != b'\t') || b == 0x7f) {
        if out.len() >= max {
            break;
        }
        let Some(pos) = needles.iter().filter_map(|n| find(segment, n)).min() else {
            continue;
        };
        // Keep the line start (and its timestamp) unless the match is far into it.
        let start = if pos < 200 { 0 } else { pos - 80 };
        let end = segment.len().min(start + 300);
        let mut text = String::from_utf8_lossy(&segment[start..end]).trim().to_string();
        if start > 0 {
            text.insert_str(0, "...");
        }
        if !out.contains(&text) {
            out.push(text);
        }
    }
    out
}

fn clip(line: &str) -> String {
    if line.chars().count() <= EVIDENCE_CHARS {
        return line.to_string();
    }
    let mut cut: String = line.chars().take(EVIDENCE_CHARS - 3).collect();
    cut.push_str("...");
    cut
}

/// "[2026-11-03 01:47:35.556]..." (tinyget logs) to "2026-11-03 01:47:35".
fn log_time(line: &str) -> Option<String> {
    let start = line.find('[')? + 1;
    let s = line.get(start..start + 19)?;
    let ok = s.bytes().enumerate().all(|(i, c)| match i {
        4 | 7 => c == b'-',
        10 => c == b' ',
        13 | 16 => c == b':',
        _ => c.is_ascii_digit(),
    });
    ok.then(|| s.to_string())
}

/// "[1103/014736.593:INFO..." (CEF debug.log, no year) to "11-03 01:47:36".
fn cef_time(line: &str) -> Option<String> {
    let start = line.find('[')? + 1;
    let s = line.get(start..start + 11)?;
    let b = s.as_bytes();
    let ok = b.iter().enumerate().all(|(i, c)| if i == 4 { *c == b'/' } else { c.is_ascii_digit() });
    ok.then(|| format!("{}-{} {}:{}:{}", &s[0..2], &s[2..4], &s[5..7], &s[7..9], &s[9..11]))
}

fn mtime(path: &Path) -> Option<String> {
    utc(fs::metadata(path).ok()?.modified().ok()?)
}

/// UTC date and time without a date crate (days-to-civil, H. Hinnant).
pub(crate) fn utc(time: SystemTime) -> Option<String> {
    let secs = i64::try_from(time.duration_since(UNIX_EPOCH).ok()?.as_secs()).ok()?;
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    Some(format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02} UTC",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    struct Fixture(PathBuf);

    impl Fixture {
        fn new(tag: &str) -> Self {
            static COUNTER: AtomicUsize = AtomicUsize::new(0);
            let n = COUNTER.fetch_add(1, Ordering::SeqCst);
            let root = std::env::temp_dir().join(format!("nikke-check-test-{}-{tag}-{n}", std::process::id()));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir_all(&root).unwrap();
            Self(root)
        }

        fn file(&self, rel: &str, contents: &[u8]) -> PathBuf {
            let path = self.0.join(rel);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, contents).unwrap();
            path
        }

        fn dir(&self, rel: &str) -> PathBuf {
            let path = self.0.join(rel);
            fs::create_dir_all(&path).unwrap();
            path
        }

        fn scan(&self) -> ScanResult {
            let discovery = locate::discover_folders(std::slice::from_ref(&self.0));
            run("test".into(), discovery, false, Instant::now())
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            // remove_dir_all removes symlinks themselves, never their targets.
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn findings(r: &ScanResult) -> Vec<&Finding> {
        r.groups.iter().flat_map(|g| &g.findings).collect()
    }

    fn has(r: &ScanResult, severity: Severity, title: &str) -> bool {
        findings(r).iter().any(|f| f.severity == severity && f.title == title)
    }

    const DEBUG_LOG: &[u8] = b"[1103/014735.001:INFO:CONSOLE(1)] \"page loaded\", source:  (1)\r\n\
[1103/014736.558:INFO:CONSOLE(1)] \"lua downloaded to log\\tinyget\\tinyget.20261103-014735-553.log\", source:  (1)\r\n\
[1103/014736.593:INFO:CONSOLE(1)] \"k2f_chan registered\", source:  (1)\r\n\
[1103/014736.623:INFO:CONSOLE(1)] \"adopted 3c4c9b75-09e5-4619-99ee-97c1dc3c0373\", source:  (1)\r\n\
[1103/014736.625:INFO:CONSOLE(1)] \"agent started as TESTHOST\", source:  (1)\r\n";

    const TINYGET_LOG: &[u8] = b"[2026-11-03 01:47:25.874][316][INFO][main.cpp(1)]start\n\
[2026-11-03 01:47:35.556][316][ERROR][tiny_downloader.cpp(103)]tiny_downloader::TinyDownloader::AddTask\tadd task, task_id=2147483648, url=https://analytics.insightjs.com/comm/assets/insight.bundle, path=S:\\NIKKE\\Launcher\\log\\tinyget\\tinyget.20261103-014735-553.log\n";

    #[test]
    fn infected_install() {
        let fx = Fixture::new("infected");
        fx.file("NIKKE/Launcher/nikke_launcher.exe", b"MZ");
        fx.file("NIKKE/Launcher/intl_service/debug.log", DEBUG_LOG);
        fx.file("NIKKE/Launcher/log/tinyget/tinyget.20261103-014725-874.log", TINYGET_LOG);
        fx.file("NIKKE/Launcher/log/tinyget/tinyget.20261103-014735-553.log", b"\x1bLJ\x02payload");
        let r = fx.scan();
        assert_eq!(r.verdict, Verdict::Infected);
        let ran = findings(&r).into_iter().find(|f| f.title == "The malware agent ran").expect("A1");
        assert_eq!(ran.severity, Severity::Critical);
        assert_eq!(ran.evidence.len(), 4);
        assert!(ran.evidence.iter().any(|l| l.contains("agent started as TESTHOST")));
        assert_eq!(ran.time.as_deref(), Some("11-03 01:47:36"));
        let dl = findings(&r)
            .into_iter()
            .find(|f| f.title == "The launcher downloaded the malware")
            .expect("A2");
        assert_eq!(dl.time.as_deref(), Some("2026-11-03 01:47:35"));
        assert!(dl.detail.contains("tinyget.20261103-014725-874.log"));
        assert!(has(&r, Severity::Critical, "The malware file is still on disk"));
        assert!(findings(&r).iter().all(|f| f.evidence.len() <= 5 && f.evidence.iter().all(|e| e.chars().count() <= 240)));
    }

    #[test]
    fn exposed_only() {
        let fx = Fixture::new("exposed");
        fx.file("NIKKE/Launcher/nikke_launcher.exe", b"MZ");
        fx.file("NIKKE/Launcher/intl_service/debug.log", b"[1103/014735.001:INFO:CONSOLE(1)] \"page loaded\"\n");
        fx.file("NIKKE/prefix/system.reg", b"WINE REGISTRY Version 2\n");
        fx.file(
            "NIKKE/prefix/drive_c/users/steamuser/AppData/Roaming/nikke_launcher/tbs_cache/Code Cache/js/dd65fa4d61079e7e_0",
            b"\x00\x01\x02\xc3https://insightjs.com/l.js?f=aegis\x00\x10more",
        );
        fx.file(
            "NIKKE/prefix/drive_c/users/steamuser/AppData/Roaming/nikke_launcher/tbs_cache/Network Persistent State",
            br#"{"net":{"http_server_properties":{"servers":[{"server":"https://insightjs.com"}]}}}"#,
        );
        let r = fx.scan();
        assert_eq!(r.verdict, Verdict::Exposed);
        let f = findings(&r)
            .into_iter()
            .find(|f| f.title == "The launcher loaded the malicious script")
            .expect("B");
        assert_eq!(f.evidence.len(), 1, "{:?}", f.evidence);
        assert!(f.evidence[0].contains("https://insightjs.com/l.js?f=aegis"), "{:?}", f.evidence);
        assert!(has(&r, Severity::Warning, "The launcher connected to insightjs.com"));
        // The install was found through the prefix's parent folder too.
        assert!(r.targets.iter().any(|t| t.kind == TargetKind::InstallDir));
    }

    #[test]
    fn clean_install() {
        let fx = Fixture::new("clean");
        fx.file("Games/NIKKE/Launcher/nikke_launcher.exe", b"MZ");
        fx.file("Games/NIKKE/Launcher/intl_service/debug.log", b"[1103/014735.001:INFO:CONSOLE(1)] \"ok\"\n");
        fx.file("Games/NIKKE/Launcher/log/tinyget/tinyget.log", b"[2026-11-03 01:47:25.874] nothing\n");
        let r = fx.scan();
        assert_eq!(r.verdict, Verdict::NoTraces);
        assert!(findings(&r).iter().all(|f| f.severity == Severity::Info));
    }

    #[test]
    fn empty_dir_is_not_found() {
        let fx = Fixture::new("empty");
        assert_eq!(fx.scan().verdict, Verdict::NotFound);
    }

    const CLSID_KEY: &str = "[Software\\\\Classes\\\\CLSID\\\\{E77CC89B-7401-4C04-8CED-149DB35ADD04}\\\\InprocServer32] 1790724375\n#time=1dd5069ebfe1648\n";

    #[test]
    fn user_reg_clsid_is_critical() {
        let fx = Fixture::new("userreg");
        fx.dir("pfx/drive_c/users/steamuser");
        let reg = format!(
            "WINE REGISTRY Version 2\n\n{CLSID_KEY}@=\"C:\\\\users\\\\steamuser\\\\AppData\\\\Local\\\\Google\\\\Chrome\\\\User Data\\\\PlatformExperienceHelper\\\\ab\\\\platform_experience_helper.dll\"\n\"ThreadingModel\"=\"Both\"\n"
        );
        fx.file("pfx/user.reg", reg.as_bytes());
        let r = fx.scan();
        assert_eq!(r.verdict, Verdict::Infected);
        let f = findings(&r)
            .into_iter()
            .find(|f| f.title == "Registry persistence found (HKCU CLSID hijack)")
            .expect("C4");
        assert!(f.evidence.iter().any(|e| e.starts_with("@=") && e.contains("platform_experience_helper.dll")));
    }

    #[test]
    fn system_reg_clsid_alone_is_not_reported() {
        let fx = Fixture::new("systemreg");
        fx.dir("pfx/drive_c/users/steamuser");
        let reg = format!("WINE REGISTRY Version 2\n\n{CLSID_KEY}@=\"C:\\\\windows\\\\system32\\\\wpc.dll\"\n");
        fx.file("pfx/system.reg", reg.as_bytes());
        fx.file("pfx/user.reg", b"WINE REGISTRY Version 2\n\n[Software\\\\Wine] 1\n");
        let r = fx.scan();
        assert!(findings(&r).is_empty(), "{:?}", findings(&r));
        assert_eq!(r.verdict, Verdict::NotFound);
    }

    #[test]
    fn platform_experience_helper_is_critical() {
        let fx = Fixture::new("peh");
        fx.file(
            "pfx/drive_c/users/steamuser/AppData/Local/Google/Chrome/User Data/PlatformExperienceHelper/0123abcd/platform_experience_helper.dll",
            b"MZ",
        );
        let r = fx.scan();
        let f = findings(&r).into_iter().find(|f| f.title == "Chrome persistence is installed").expect("C1");
        assert_eq!(f.severity, Severity::Critical);
        assert!(f.evidence.iter().any(|e| e.contains("platform_experience_helper.dll")));
        assert_eq!(r.verdict, Verdict::Infected);
    }

    #[test]
    fn k2f_temp_file_is_critical() {
        let fx = Fixture::new("k2f");
        fx.file("pfx/drive_c/users/steamuser/AppData/Local/Temp/k2f-bcreds-1234", b"x");
        let r = fx.scan();
        assert!(has(&r, Severity::Critical, "Files left by the malware in Temp"));
        assert_eq!(r.verdict, Verdict::Infected);
    }

    #[test]
    fn hex_marker_is_warning() {
        let fx = Fixture::new("marker");
        fx.file("pfx/drive_c/users/steamuser/AppData/Local/Temp/onominan.tmp", b"b8fd3eedb60ef8e517b3c6");
        fx.file("pfx/drive_c/users/steamuser/AppData/Local/Temp/other.tmp", b"NOT-HEX-0123456789abcd");
        fx.file("pfx/drive_c/users/steamuser/AppData/Local/Temp/short.tmp", b"b8fd3eed");
        let r = fx.scan();
        let f = findings(&r).into_iter().find(|f| f.title == "Possible infection marker").expect("C3");
        assert_eq!(f.severity, Severity::Warning);
        assert_eq!(f.evidence.len(), 1);
        assert!(f.evidence[0].starts_with("onominan.tmp: b8fd3eedb60ef8e517b3c6"));
        assert_eq!(r.verdict, Verdict::Exposed);
    }

    #[test]
    fn hosts_parsing() {
        let text = "127.0.0.1 localhost\n0.0.0.0 insightjs.com # blocked\n# 0.0.0.0 insightjs.org\n10.0.0.5 analytics.insightjs.com\n::1\tlocalhost ANALYTICS.INSIGHTJS.COM\n";
        assert_eq!(
            parse_hosts(text),
            vec![("insightjs.com", true), ("analytics.insightjs.com", true), ("insightjs.org", false)]
        );
        assert!(parse_hosts("").iter().all(|(_, blocked)| !blocked));
    }

    #[test]
    fn time_formats() {
        assert_eq!(utc(UNIX_EPOCH).as_deref(), Some("1970-01-01 00:00:00 UTC"));
        assert_eq!(utc(UNIX_EPOCH + Duration::from_secs(951_868_799)).as_deref(), Some("2000-02-29 23:59:59 UTC"));
        assert_eq!(
            utc(UNIX_EPOCH + Duration::from_secs(1_793_666_855)).as_deref(),
            Some("2026-11-03 00:47:35 UTC")
        );
        assert_eq!(log_time("[2026-11-03 01:47:35.556][316]").as_deref(), Some("2026-11-03 01:47:35"));
        assert_eq!(log_time("[not a time]"), None);
        assert_eq!(cef_time("[1103/014736.593:INFO").as_deref(), Some("11-03 01:47:36"));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_loops_are_not_followed() {
        use std::os::unix::fs::symlink;
        let fx = Fixture::new("loop");
        fx.file("NIKKE/Launcher/nikke_launcher.exe", b"MZ");
        let data = fx.dir("NIKKE/prefix/drive_c/users/steamuser/AppData/Roaming/nikke_launcher");
        let dosdevices = fx.dir("NIKKE/prefix/dosdevices");
        symlink(&fx.0, dosdevices.join("z:")).unwrap();
        symlink("/", dosdevices.join("root")).unwrap();
        symlink(".", fx.0.join("NIKKE/prefix/pfx")).unwrap();
        symlink("/", data.join("everything")).unwrap();
        symlink(&fx.0, fx.0.join("NIKKE/Launcher/loop")).unwrap();
        fs::create_dir_all(fx.0.join("NIKKE/Launcher/log")).unwrap();
        symlink("/", fx.0.join("NIKKE/Launcher/log/root")).unwrap();
        let r = fx.scan();
        assert!(r.stats.entries < 200, "visited {}", r.stats.entries);
        assert_eq!(r.verdict, Verdict::NoTraces);
        assert_eq!(r.targets.iter().filter(|t| t.kind == TargetKind::InstallDir).count(), 1);
    }

    #[test]
    fn entry_cap_is_reported() {
        let fx = Fixture::new("cap");
        for i in 0..20 {
            fx.file(&format!("d{i}/f"), b"");
        }
        let d = locate::discover_folders_with_cap(std::slice::from_ref(&fx.0), 10);
        assert!(d.stats.cap_hit);
        assert_eq!(d.stats.entries, 10);
    }
}
