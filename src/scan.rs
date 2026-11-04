//! The checks. Pure logic: reads files, never writes, never uses the network.

use std::collections::HashSet;
use std::ffi::OsString;
use std::fs;
use std::io::{self, BufRead};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering::Relaxed;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use walkdir::WalkDir;

use crate::exposure::{self, Exposure};
use crate::hsts;
use crate::i18n::{Lang, Text, msg, tr};
use crate::ldb;
use crate::locate::{self, Discovery, Progress, Stage, TargetKind, WalkStats, find_ci};
use crate::timeline::{self, AgentRun, PayloadBuild, RunKind};

pub const DOMAINS: [&str; 3] = ["insightjs.com", "analytics.insightjs.com", "insightjs.org"];
pub const PAYLOAD_IP: &str = "89.127.233.127";
/// The attacker's servers: 89.127.233.127 sent the agent, 89.126.250.172 served
/// insightjs.com until about October 21, 2026 (reported by a victim).
pub const ATTACKER_IPS: [&str; 2] = [PAYLOAD_IP, "89.126.250.172"];
pub const CLSID: &str = "{E77CC89B-7401-4C04-8CED-149DB35ADD04}";

const MAX_FILE: u64 = 64 * 1024 * 1024;
/// Longer lines are cut when a file is read line by line.
const MAX_LINE: usize = 64 * 1024;
const MAX_EVIDENCE: usize = 5;
const EVIDENCE_CHARS: usize = 240;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

impl Severity {
    pub fn tag(self, lang: Lang) -> &'static str {
        tr(
            lang,
            match self {
                Severity::Info => "severity.info",
                Severity::Warning => "severity.warning",
                Severity::Critical => "severity.critical",
            },
        )
    }
}

/// What a finding means. The window and the report group findings by kind and
/// pick the steps to show from it.
#[cfg_attr(not(windows), allow(dead_code))] // DllLoaded is only built on Windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FindingKind {
    /// debug.log shows the agent starting.
    AgentRan,
    /// A launcher log records the download of insight.bundle.
    PayloadDownloaded,
    /// The downloaded agent is still in the launcher's log folder.
    PayloadFile,
    /// k2f.agent.state or k2f_chan in the launcher data.
    AgentState,
    /// The loader script in the launcher's browser cache.
    LoaderCached,
    /// The launcher contacted insightjs.com, or one of its logs names insightjs.
    LauncherContacted,
    /// The launcher contacted analytics.insightjs.com, the server that sends the agent.
    AgentServerContacted,
    /// platform_experience_helper.dll in a browser's PlatformExperienceHelper folder.
    ChromeDll,
    /// The HKCU CLSID key that makes the browser load the DLL.
    RegistryKey,
    /// The HKCU CLSID key with no DLL path: the DLL was installed, then uninstalled.
    RegistryLeftover,
    /// Files of an earlier version in Chrome's Application\PlatformExperienceHelper folder.
    LegacyDll,
    /// A running program has the DLL loaded.
    DllLoaded,
    /// k2f files in Temp.
    TempFile,
    /// The launcher runs while the scan also found a sign of the agent. Without
    /// one, the running launcher is an `Info` finding.
    LauncherRunning,
    /// A place the scan could not check.
    Coverage,
    /// Context that does not change the verdict.
    Info,
}

/// Kinds that show the agent itself reached this computer.
pub const AGENT_SIGNS: [FindingKind; 11] = [
    FindingKind::AgentRan,
    FindingKind::AgentState,
    FindingKind::PayloadDownloaded,
    FindingKind::PayloadFile,
    FindingKind::AgentServerContacted,
    FindingKind::TempFile,
    FindingKind::ChromeDll,
    FindingKind::RegistryKey,
    FindingKind::RegistryLeftover,
    FindingKind::LegacyDll,
    FindingKind::DllLoaded,
];

/// Titles, details, tool-written evidence lines and times are messages, so a
/// result shows in any language after the scan. Lines quoted from files stay raw.
#[derive(Debug, Clone)]
pub struct Finding {
    pub kind: FindingKind,
    pub severity: Severity,
    pub title: Text,
    pub detail: Text,
    pub path: Option<PathBuf>,
    /// What "Open folder" shows: a file to select, or a folder.
    pub open_path: Option<PathBuf>,
    /// Text for a copy button, such as the registry key to delete.
    pub copy_text: Option<String>,
    pub evidence: Vec<Text>,
    pub time: Option<Text>,
}

impl Finding {
    fn new(kind: FindingKind, severity: Severity, title: Text, detail: Text) -> Self {
        Self {
            kind,
            severity,
            title,
            detail,
            path: None,
            open_path: None,
            copy_text: None,
            evidence: Vec::new(),
            time: None,
        }
    }

    /// Sets the path, and what "Open folder" shows unless [`Finding::open`] changes it.
    fn at(mut self, path: &Path) -> Self {
        self.path = Some(path.to_path_buf());
        self.open_path = Some(path.to_path_buf());
        self
    }

    fn open(mut self, path: &Path) -> Self {
        self.open_path = Some(path.to_path_buf());
        self
    }

    fn copy(mut self, text: impl Into<String>) -> Self {
        self.copy_text = Some(text.into());
        self
    }

    fn evidence<T: Into<Text>>(mut self, lines: impl IntoIterator<Item = T>) -> Self {
        self.evidence = lines.into_iter().take(MAX_EVIDENCE).map(Into::into).collect();
        self
    }

    fn time<T: Into<Text>>(mut self, time: Option<T>) -> Self {
        self.time = time.map(Into::into);
        self
    }

    /// The evidence as shown, each line cut to EVIDENCE_CHARS.
    pub fn evidence_lines(&self, lang: Lang) -> Vec<String> {
        self.evidence.iter().map(|e| clip(&e.render(lang))).collect()
    }
}

/// Findings for one location.
#[derive(Debug, Clone)]
pub struct Group {
    pub label: Text,
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
    /// Shown when the file is missing or could not be read.
    pub note: Option<Text>,
    /// (domain, blocked). `None` when the file could not be read.
    pub domains: Vec<(&'static str, Option<bool>)>,
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
    /// Agent steps from debug.log and the tinyget logs, in log order per install.
    pub runs: Vec<AgentRun>,
    /// insight.bundle builds from the download headers in the tinyget logs.
    pub builds: Vec<PayloadBuild>,
    /// What the agent could read. None when no NIKKE install or launcher data was found.
    pub exposure: Option<Exposure>,
}

/// The `scope` of a computer scan, quick or full; a folder scan has its paths.
/// Only compared: the window and the report show a translated text in its place.
pub const COMPUTER_SCOPE: &str = "this computer";

/// `full` opens every folder; otherwise the walk stops [`locate::QUICK_DEPTH`] levels down.
pub fn scan_computer(full: bool, progress: &Progress) -> ScanResult {
    let start = Instant::now();
    let discovery = locate::discover_computer(full, progress);
    run(COMPUTER_SCOPE.into(), discovery, true, start, progress)
}

pub fn scan_folders(paths: &[PathBuf], progress: &Progress) -> ScanResult {
    let start = Instant::now();
    let scope = paths
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    run(scope, locate::discover_folders(paths, progress), true, start, progress)
}

/// Runs every check on the discovered targets. `system_checks` adds the
/// running-process check, the hosts file and the real home folder of a
/// Linux or macOS user (left out in tests). A cancelled scan skips the
/// remaining targets; its result is incomplete and is dropped.
pub fn run(scope: String, discovery: Discovery, system_checks: bool, start: Instant, progress: &Progress) -> ScanResult {
    let started = utc(SystemTime::now()).unwrap_or_default();
    let tally = |findings: &[Finding]| {
        for f in findings {
            progress.findings[f.severity as usize].fetch_add(1, Relaxed);
        }
    };
    let mut groups = Vec::new();
    let mut running = Vec::new();
    // Its severity depends on the other findings, so it is counted after the locations.
    let mut launcher = Vec::new();
    if system_checks {
        progress.set_stage(Stage::Programs);
        launcher = launcher_processes();
    }
    progress.set_stage(Stage::Locations);
    progress.checks_total.store(discovery.targets.len(), Relaxed);
    let (mut runs, mut builds) = (Vec::new(), Vec::new());
    for target in &discovery.targets {
        if progress.cancelled() {
            break;
        }
        progress.show(&target.path);
        let mut findings = match target.kind {
            TargetKind::InstallDir => check_install(&target.path, &mut runs, &mut builds),
            TargetKind::LauncherData => check_launcher_data(&target.path, false),
            TargetKind::LoginProfile => check_launcher_data(&target.path, true),
            TargetKind::UserProfile => check_profile(&target.path, target.host),
            TargetKind::WinePrefix => check_prefix(&target.path),
        };
        tally(&findings);
        progress.checks_done.fetch_add(1, Relaxed);
        if !findings.is_empty() {
            findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
            groups.push(Group {
                label: msg(target.kind.key()),
                path: Some(target.path.clone()),
                findings,
            });
        }
    }
    // After the locations: Windows keeps the DLL loaded until a restart, even once its files are gone.
    #[cfg(windows)]
    if system_checks && !progress.cancelled() {
        let loaded = check_loaded_dlls();
        tally(&loaded);
        running.extend(loaded);
    }
    if !launcher.is_empty() {
        let agent = groups.iter().flat_map(|g: &Group| &g.findings).chain(&running).any(|f| AGENT_SIGNS.contains(&f.kind));
        let f = launcher_running(launcher, agent);
        tally(std::slice::from_ref(&f));
        running.insert(0, f);
    }
    if !running.is_empty() {
        groups.insert(0, Group { label: msg("group.running"), path: None, findings: running });
    }
    let coverage = check_coverage(&discovery);
    tally(&coverage);
    if !coverage.is_empty() {
        groups.push(Group { label: msg("group.coverage"), path: None, findings: coverage });
    }
    let worst = groups.iter().flat_map(|g| &g.findings).map(|f| f.severity).max();
    let has = |kind| discovery.targets.iter().any(|t| t.kind == kind);
    let found = has(TargetKind::InstallDir) || has(TargetKind::LauncherData);
    let verdict = match worst {
        Some(Severity::Critical) => Verdict::Infected,
        Some(Severity::Warning) => Verdict::Exposed,
        _ if found => Verdict::NoTraces,
        _ => Verdict::NotFound,
    };
    let exposure = (found && !progress.cancelled()).then(|| {
        let mut homes: Vec<PathBuf> =
            discovery.targets.iter().filter(|t| t.kind == TargetKind::UserProfile).map(|t| t.path.clone()).collect();
        // Under Wine the agent's commands reach the whole home folder through Z:.
        if system_checks && cfg!(unix) && has(TargetKind::WinePrefix) {
            homes.extend(locate::real_home());
        }
        let mut seen = HashSet::new();
        homes.retain(|h| seen.insert(fs::canonicalize(h).unwrap_or_else(|_| h.clone())));
        exposure::collect(&homes)
    });
    let hosts = system_checks.then(|| {
        progress.set_stage(Stage::Hosts);
        check_hosts()
    });
    progress.set_stage(Stage::Done);
    ScanResult {
        scope,
        started,
        verdict,
        targets: discovery.targets,
        groups,
        hosts,
        stats: discovery.stats,
        seconds: start.elapsed().as_secs_f64(),
        runs,
        builds,
        exposure,
    }
}

/// What the scan could not check: the install, unreadable folders, network drives.
fn check_coverage(discovery: &Discovery) -> Vec<Finding> {
    let mut out = Vec::new();
    let has = |kind| discovery.targets.iter().any(|t| t.kind == kind);
    if has(TargetKind::LauncherData) && !has(TargetKind::InstallDir) {
        out.push(Finding::new(
            FindingKind::Coverage,
            Severity::Info,
            msg("finding.no_install.title"),
            msg("finding.no_install.detail"),
        ));
    }
    let shown = |paths: &[PathBuf]| capped(paths.iter().map(|p| p.display().to_string()).collect());
    let stats = &discovery.stats;
    if let Some(depth) = stats.depth_limit {
        let detail = if cfg!(windows) {
            msg("finding.quick_scan.detail_windows")
        } else if cfg!(target_os = "macos") {
            msg("finding.quick_scan.detail_macos")
        } else {
            msg("finding.quick_scan.detail_linux")
        };
        out.push(Finding::new(
            FindingKind::Info,
            Severity::Info,
            msg("finding.quick_scan.title"),
            detail.arg("depth", depth.to_string()),
        ));
    }
    if !stats.unreadable.is_empty() {
        out.push(
            Finding::new(
                FindingKind::Coverage,
                Severity::Info,
                msg("finding.unreadable.title"),
                msg("finding.unreadable.detail"),
            )
            .evidence(shown(&stats.unreadable)),
        );
    }
    if !stats.skipped_mounts.is_empty() {
        out.push(
            Finding::new(
                FindingKind::Coverage,
                Severity::Info,
                msg("finding.network.title"),
                msg("finding.network.detail"),
            )
            .evidence(shown(&stats.skipped_mounts)),
        );
    }
    out
}

// ---------------------------------------------------------------- A: install

/// Needles of the agent's debug.log lines quoted in "The malware agent ran".
const AGENT_LINES: [&[u8]; 5] = [b"k2f_chan", b"adopted ", b"resuming ", b"agent started as", b"lua downloaded to"];
const MENTIONS: [&[u8]; 1] = [b"insightjs"];
/// Names that only the agent stage puts in a log. A line that names insightjs without
/// them is the loader alone, for example the insightjs.org fallback script failing to run.
const AGENT_SERVER: [&[u8]; 2] = [b"analytics.insightjs.com", b"insight.bundle"];

/// The finding for a launcher log that names insightjs: critical with the agent server, a warning without it.
fn log_mention(name: &str, lines: Vec<String>, time: Option<Text>, server: bool) -> Finding {
    let (kind, severity, title, detail) = if server {
        (FindingKind::AgentServerContacted, Severity::Critical, "finding.log_server.title", "finding.log_server.detail")
    } else {
        (FindingKind::LauncherContacted, Severity::Warning, "finding.log_mention.title", "finding.log_mention.detail")
    };
    Finding::new(kind, severity, msg(title).arg("file", name), msg(detail).arg("file", name)).evidence(lines).time(time)
}

fn check_install(dir: &Path, all_runs: &mut Vec<AgentRun>, all_builds: &mut Vec<PayloadBuild>) -> Vec<Finding> {
    let mut out = Vec::new();
    let launcher = find_ci(dir, &["Launcher"]);
    let debug = launcher.as_deref().and_then(|l| find_ci(l, &["intl_service", "debug.log"]));
    let mut runs = Vec::new();

    // A1: read line by line, because the launcher appends to debug.log at every launch.
    let debug_note = match debug.as_deref() {
        None => msg("finding.install_found.debug_missing"),
        Some(path) => {
            let (mut ran, mut server, mut agent, mut mentions) = (false, false, Vec::new(), Vec::new());
            let read = each_line(path, |line| {
                ran |= contains(line, b"k2f_chan");
                server |= AGENT_SERVER.iter().any(|n| contains(line, n));
                for (lines, needles) in [(&mut agent, &AGENT_LINES[..]), (&mut mentions, &MENTIONS[..])] {
                    if lines.len() < MAX_EVIDENCE {
                        for s in snippets(line, needles, 1) {
                            if !lines.contains(&s) {
                                lines.push(s);
                            }
                        }
                    }
                }
                runs.extend(timeline::debug_event(&String::from_utf8_lossy(line), path));
            });
            if read.is_err() {
                out.push(
                    Finding::new(
                        FindingKind::Coverage,
                        Severity::Info,
                        msg("finding.debug_unreadable.title"),
                        msg("finding.debug_unreadable.detail"),
                    )
                    .at(path),
                );
                msg("finding.install_found.debug_unreadable")
            } else {
                if ran {
                    let time = agent.iter().find_map(|l| cef_time(l));
                    out.push(
                        Finding::new(
                            FindingKind::AgentRan,
                            Severity::Critical,
                            msg("finding.agent_ran.title"),
                            msg("finding.agent_ran.detail"),
                        )
                        .at(path)
                        .evidence(agent)
                        .time(time),
                    );
                }
                if !mentions.is_empty() {
                    let time = mentions.iter().find_map(|l| cef_time(l));
                    out.push(log_mention("debug.log", mentions, time, server).at(path));
                }
                msg("finding.install_found.debug_checked")
            }
        }
    };

    // A2
    let mut downloads = Vec::new();
    if let Some(log) = launcher.as_deref().and_then(|l| find_ci(l, &["log"])) {
        for path in files_under(&log, 8) {
            let Some(bytes) = read_small(&path) else {
                continue;
            };
            if bytes.starts_with(b"\x1bLJ") {
                out.push(
                    Finding::new(
                        FindingKind::PayloadFile,
                        Severity::Critical,
                        msg("finding.payload_file.title"),
                        msg("finding.payload_file.detail"),
                    )
                    .at(&path)
                    .evidence([msg("evidence.luajit").arg("size", bytes.len().to_string())])
                    .time(mtime(&path)),
                );
                continue;
            }
            let bundle = contains(&bytes, b"insight.bundle");
            if !bundle && !contains(&bytes, b"insightjs") {
                continue;
            }
            let name = file_name(&path);
            if !bundle {
                let lines = snippets(&bytes, &MENTIONS, MAX_EVIDENCE);
                let time = lines.iter().find_map(|l| log_time(l));
                out.push(log_mention(&name, lines, time, contains(&bytes, AGENT_SERVER[0])).at(&path));
                continue;
            }
            let text = String::from_utf8_lossy(&bytes);
            downloads.extend(timeline::tinyget_downloads(&text, &path));
            for build in timeline::payload_builds(&text, &path) {
                if !all_builds.iter().any(|b| b.etag == build.etag && b.last_modified == build.last_modified) {
                    all_builds.push(build);
                }
            }
            let lines = snippets(&bytes, &[b"insight.bundle"], MAX_EVIDENCE);
            let time = lines.iter().find_map(|l| log_time(l));
            // A request the server never answered (curl_error=7, total=0) is only an attempt.
            let finding = if timeline::bundle_downloaded(&text) {
                Finding::new(
                    FindingKind::PayloadDownloaded,
                    Severity::Critical,
                    msg("finding.downloaded.title"),
                    msg("finding.downloaded.detail").arg("file", name),
                )
            } else {
                Finding::new(
                    FindingKind::LauncherContacted,
                    Severity::Warning,
                    msg("finding.download_attempt.title"),
                    msg("finding.download_attempt.detail").arg("file", name),
                )
            };
            out.push(finding.at(&path).evidence(lines).time(time));
        }
    }
    // A tinyget download that debug.log does not record (debug.log deleted or cut) is a run of its own.
    for download in downloads {
        let logged = |r: &AgentRun| r.kind == RunKind::Downloaded && r.file == download.file;
        if !runs.iter().any(logged) {
            runs.push(download);
        }
    }
    all_runs.extend(runs);

    // A3
    let debug_time = debug.as_deref().and_then(mtime);
    let detail = match debug_time {
        Some(t) => msg("finding.install_found.written").arg("note", debug_note).arg("time", t),
        None => debug_note,
    };
    let title = msg("finding.install_found.title").arg("path", dir.display().to_string());
    out.push(Finding::new(FindingKind::Info, Severity::Info, title, detail).at(dir));
    out
}

// ---------------------------------------------------------- B: launcher data

#[derive(Default)]
struct Hits {
    files: usize,
    first: Option<PathBuf>,
    evidence: Vec<Text>,
    newest: Option<SystemTime>,
    /// A logged time that replaces the file times.
    observed: Option<String>,
}

impl Hits {
    /// `snippet` is a line quoted from the file, or a line the scan wrote.
    fn add(&mut self, path: &Path, rel: &str, snippet: Option<Text>) {
        self.files += 1;
        self.first.get_or_insert_with(|| path.to_path_buf());
        if self.evidence.len() < MAX_EVIDENCE {
            self.evidence.push(match snippet {
                Some(Text::Raw(s)) => Text::Raw(format!("{rel}: {s}")),
                Some(text) => msg("evidence.in_file").arg("file", rel).arg("text", text),
                None => rel.into(),
            });
        }
        let modified = fs::metadata(path).and_then(|m| m.modified()).ok();
        self.newest = self.newest.max(modified);
    }

    /// The finding for these hits; `detail` gets their file count as `{files}`.
    fn finding(self, kind: FindingKind, severity: Severity, title: &'static str, detail: &'static str) -> Option<Finding> {
        let first = self.first?;
        Some(
            Finding::new(kind, severity, msg(title), msg(detail).arg("files", files(self.files)))
                .at(&first)
                .evidence(self.evidence)
                .time(self.observed.or_else(|| self.newest.and_then(utc))),
        )
    }
}

/// "1 file", "2 files".
fn files(n: usize) -> Text {
    msg(if n == 1 { "common.files_one" } else { "common.files_other" }).arg("n", n.to_string())
}

/// The launcher data folder, or with `login` the launcher's login browser profile
/// (CEF/User Data). Other CEF programs can share that profile, so it reports
/// only the traces and never "no traces".
fn check_launcher_data(dir: &Path, login: bool) -> Vec<Finding> {
    let Some(real) = linked_dir(dir) else {
        let shown = fs::read_link(dir).map_or_else(|_| msg("finding.data_link.unknown_target"), |t| t.display().to_string().into());
        return vec![
            Finding::new(
                FindingKind::Coverage,
                Severity::Info,
                msg("finding.data_link.title"),
                msg("finding.data_link.detail").arg("target", shown),
            )
            .at(dir),
        ];
    };
    let dir = real.as_path();
    let (mut agent, mut server, mut cache, mut network, mut other) =
        (Hits::default(), Hits::default(), Hits::default(), Hits::default(), Hits::default());
    let mut checked = 0usize;
    for path in files_under(dir, 12) {
        let Some(raw) = read_small(&path) else {
            continue;
        };
        checked += 1;
        let rel = path.strip_prefix(dir).unwrap_or(&path).display().to_string();
        let name = file_name(&path);
        // Local Storage tables are often Snappy-compressed: search their records instead.
        let bytes = if name.ends_with(".ldb") { ldb::readable(&raw).unwrap_or(raw) } else { raw };
        // k2f.agent.state is the agent's saved ID in Local Storage. It outlives the install folder and its debug.log.
        if contains(&bytes, b"k2f_chan") || contains(&bytes, b"k2f.agent") {
            // The key name only: the saved state that follows holds the agent's password.
            let snippet = snippets(&bytes, &[b"k2f_chan", b"k2f.agent"], 1)
                .pop()
                .map(|s| s.split("agent_pass").next().unwrap_or_default().into());
            agent.add(&path, &rel, snippet);
        }
        // TransportSecurity stores hashed host names, so it never contains "insightjs".
        if name == "TransportSecurity" {
            let entries = hsts::entries(&String::from_utf8_lossy(&bytes));
            let when = |seen: Option<u64>| seen.and_then(|s| UNIX_EPOCH.checked_add(Duration::from_secs(s))).and_then(utc);
            let line = Text::List(
                entries
                    .iter()
                    .map(|(host, seen)| match when(*seen) {
                        Some(t) => msg("evidence.hsts").arg("host", *host).arg("time", t),
                        None => msg("evidence.hsts_no_time").arg("host", *host),
                    })
                    .collect(),
            );
            if let Some((_, seen)) = entries.iter().find(|(host, _)| *host == "analytics.insightjs.com") {
                server.add(&path, &rel, Some(line));
                server.observed = when(*seen);
            } else if !entries.is_empty() {
                network.add(&path, &rel, Some(line));
            }
        } else if contains(&bytes, b"insightjs") {
            // Exact names: the CEF profile folder itself is called tbs_cache.
            let in_cache = path.strip_prefix(dir).unwrap_or(&path).components().any(|c| {
                let c = c.as_os_str().to_string_lossy();
                c.eq_ignore_ascii_case("Code Cache") || c.eq_ignore_ascii_case("Cache")
            });
            if name == "Network Persistent State" && contains(&bytes, b"analytics.insightjs.com") {
                server.add(&path, &rel, snippets(&bytes, &[b"analytics.insightjs.com"], 1).pop().map(Text::Raw));
                continue;
            }
            let bucket = if ["Network Persistent State", "Reporting and NEL"].contains(&name.as_str()) {
                &mut network
            } else if in_cache {
                &mut cache
            } else {
                &mut other
            };
            bucket.add(&path, &rel, snippets(&bytes, &[b"insightjs"], 1).pop().map(Text::Raw));
        }
    }
    let mut out = Vec::new();
    let (agent_title, agent_detail, mention_title, mention_detail) = if login {
        ("finding.login_agent_state.title", "finding.login_agent_state.detail", "finding.login_mention.title", "finding.login_mention.detail")
    } else {
        ("finding.agent_state.title", "finding.agent_state.detail", "finding.data_mention.title", "finding.data_mention.detail")
    };
    out.extend(agent.finding(FindingKind::AgentState, Severity::Critical, agent_title, agent_detail));
    out.extend(server.finding(
        FindingKind::AgentServerContacted,
        Severity::Critical,
        "finding.agent_server.title",
        "finding.agent_server.detail",
    ));
    out.extend(cache.finding(FindingKind::LoaderCached, Severity::Warning, "finding.loader_cached.title", "finding.loader_cached.detail"));
    out.extend(network.finding(
        FindingKind::LauncherContacted,
        Severity::Warning,
        "finding.network_state.title",
        "finding.network_state.detail",
    ));
    out.extend(other.finding(FindingKind::LauncherContacted, Severity::Warning, mention_title, mention_detail));
    if out.is_empty() && !login {
        let detail = msg("finding.data_clean.detail").arg("files", files(checked));
        out.push(Finding::new(FindingKind::Info, Severity::Info, msg("finding.data_clean.title"), detail).at(dir));
    }
    out
}

/// The folder to read for a launcher data folder that may be a symlink or a
/// junction. None for a link to a drive root or to a folder above itself, which
/// is not followed.
fn linked_dir(dir: &Path) -> Option<PathBuf> {
    if !dir.symlink_metadata().is_ok_and(|m| m.file_type().is_symlink()) {
        return Some(dir.to_path_buf());
    }
    let target = fs::canonicalize(dir).ok()?;
    let parent = dir.parent().and_then(|p| fs::canonicalize(p).ok());
    (target.parent().is_some() && !parent.is_some_and(|p| p.starts_with(&target))).then_some(target)
}

// ---------------------------------------------------------- C: user profile

fn check_profile(profile: &Path, host: bool) -> Vec<Finding> {
    let mut out = Vec::new();
    let local = find_ci(profile, &["AppData", "Local"]);

    // C1: the HKCU key is per user, so any Chromium browser of this user could be the target.
    for (browser, firefox, rel) in exposure::BROWSERS {
        if firefox || !rel.starts_with("AppData/") {
            continue;
        }
        let parts: Vec<&str> = rel.split('/').chain(["PlatformExperienceHelper"]).collect();
        if let Some(helper) = find_ci(profile, &parts).filter(|p| p.is_dir()) {
            out.push(check_helper(browser, &helper));
        }
    }

    // C6: an earlier agent version put its files in Chrome's own Application folder.
    #[cfg_attr(not(windows), allow(unused_mut))]
    let mut apps: Vec<PathBuf> = find_ci(profile, &["AppData", "Local", "Google", "Chrome", "Application"]).into_iter().collect();
    #[cfg(windows)]
    if host {
        for var in ["ProgramW6432", "ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"] {
            if let Some(dir) = std::env::var_os(var) {
                apps.push(Path::new(&dir).join("Google\\Chrome\\Application"));
            }
        }
    }
    check_legacy(apps, &mut out);

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

/// A browser's PlatformExperienceHelper folder in its user data.
fn check_helper(browser: &str, helper: &Path) -> Finding {
    let entries: Vec<walkdir::DirEntry> = WalkDir::new(helper).follow_links(false).min_depth(1).into_iter().flatten().collect();
    // Chrome's own helper (platform_experience_helper.exe, LoadFeatures) lives in this
    // folder too. The malware adds <sha256>/platform_experience_helper.dll.
    let dll = entries
        .iter()
        .find(|e| e.file_name().to_string_lossy().eq_ignore_ascii_case("platform_experience_helper.dll"));
    let hash_dir = entries
        .iter()
        .find(|e| e.depth() == 1 && e.file_type().is_dir() && is_sha256(&e.file_name().to_string_lossy()));
    let mut contents: Vec<String> = entries
        .iter()
        .map(|e| e.path().strip_prefix(helper).unwrap_or(e.path()).display().to_string())
        .collect();
    contents.sort();
    let mut evidence = capped(contents);
    if evidence.is_empty() {
        evidence.push(msg("evidence.empty_folder"));
    }
    let finding = if dll.is_some() || hash_dir.is_some() {
        let key = if dll.is_some() { "finding.persistence.dll" } else { "finding.persistence.hash_dir" };
        let mut detail = msg(key).arg("browser", browser);
        // chrome_install creates the folder without checking that Chrome is installed.
        if browser == "Chrome" {
            detail = msg("finding.persistence.chrome").arg("text", detail);
        }
        let target = dll.or(hash_dir).map_or(helper, |e| e.path());
        Finding::new(FindingKind::ChromeDll, Severity::Critical, persistence_title(browser), detail)
            .at(helper)
            .open(target)
    } else {
        let detail = msg(if browser == "Chrome" { "finding.helper_folder.chrome" } else { "finding.helper_folder.other" });
        let title = msg("finding.helper_folder.title").arg("browser", browser);
        Finding::new(FindingKind::Info, Severity::Info, title, detail).at(helper)
    };
    finding.evidence(evidence).time(mtime(helper))
}

/// The title of a ChromeDll finding, which keeps the browser name for the steps.
pub fn persistence_title(browser: &str) -> Text {
    msg("finding.persistence.title").arg("browser", browser)
}

/// Files the agent's cleanup code deletes from `<Chrome Application>/PlatformExperienceHelper`,
/// left by an earlier version. Chrome's own platform_experience_helper.exe sits there too.
const LEGACY_FILES: [&str; 3] = ["platform_experience_helper.dll", "platform_experience_helper.dll.old", "old-clsid.txt"];

fn check_legacy(apps: Vec<PathBuf>, out: &mut Vec<Finding>) {
    let mut seen = HashSet::new();
    for app in apps {
        let Some(helper) = find_ci(&app, &["PlatformExperienceHelper"]) else {
            continue;
        };
        if !seen.insert(fs::canonicalize(&helper).unwrap_or_else(|_| helper.clone())) {
            continue;
        }
        let found: Vec<PathBuf> = LEGACY_FILES.iter().filter_map(|f| find_ci(&helper, &[f])).filter(|p| p.is_file()).collect();
        let Some(first) = found.first() else {
            continue;
        };
        out.push(
            Finding::new(
                FindingKind::LegacyDll,
                Severity::Critical,
                msg("finding.legacy.title"),
                msg("finding.legacy.detail"),
            )
            .at(&helper)
            .open(first)
            .evidence(found.iter().map(|p| file_name(p)))
            .time(mtime(first)),
        );
    }
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
        // .NET names its temp folders and files at random (k2fkuxjm.qu0); the agent's names go on with - or _.
        if (lower.starts_with("k2f-") || lower.starts_with("k2f_")) && entry.file_type().is_ok_and(|t| t.is_file()) {
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
        let evidence = capped(k2f.iter().map(|p| file_name(p)).collect());
        out.push(
            Finding::new(
                FindingKind::TempFile,
                Severity::Critical,
                msg("finding.temp.title"),
                msg("finding.temp.detail"),
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
                FindingKind::Info,
                Severity::Info,
                msg("finding.hex_id.title"),
                msg("finding.hex_id.detail"),
            )
            .at(first)
            .evidence(evidence)
            .time(mtime(first)),
        );
    }
}

/// Copied for the user, to paste into `reg delete`.
pub const CLSID_KEYS: [&str; 2] = [
    "HKCU\\Software\\Classes\\CLSID\\{E77CC89B-7401-4C04-8CED-149DB35ADD04}",
    "HKCU\\Software\\Classes\\WOW6432Node\\CLSID\\{E77CC89B-7401-4C04-8CED-149DB35ADD04}",
];

/// The registry finding for the CLSID key: the DLL it names, or the empty key
/// the agent's chrome_uninstall leaves (it clears the default value only).
/// `detail` says where the key is.
fn clsid_finding(installed: bool, detail: Text) -> Finding {
    let (kind, title, text) = if installed {
        (FindingKind::RegistryKey, "finding.registry.title", "finding.registry.detail")
    } else {
        (FindingKind::RegistryLeftover, "finding.registry_leftover.title", "finding.registry_leftover.detail")
    };
    Finding::new(kind, Severity::Critical, msg(title), msg(text).arg("detail", detail))
}

/// HKCU only: HKLM has the normal wpc.dll entry.
#[cfg(windows)]
fn check_host_registry() -> Vec<Finding> {
    use windows_sys::Win32::System::Registry::{HKEY_CURRENT_USER, KEY_WOW64_32KEY, KEY_WOW64_64KEY};
    let key = format!("Software\\Classes\\CLSID\\{CLSID}\\InprocServer32");
    // The 32-bit launcher could also have written the key into the WOW6432Node view.
    let mut installed = Vec::new();
    let mut leftover = Vec::new();
    for (view, copy) in [KEY_WOW64_64KEY, KEY_WOW64_32KEY].into_iter().zip(CLSID_KEYS) {
        let Some(value) = locate::reg_string(HKEY_CURRENT_USER, &key, None, view) else {
            continue;
        };
        let shown = value.clone().map_or_else(|| msg("evidence.value_not_set"), Text::Raw);
        let line = msg("evidence.registry_value").arg("key", copy).arg("value", shown);
        let bucket = if value.is_some_and(|v| !v.trim().is_empty()) { &mut installed } else { &mut leftover };
        bucket.push((line, copy));
    }
    [(true, installed), (false, leftover)]
        .into_iter()
        .filter(|(_, keys)| !keys.is_empty())
        .map(|(dll, keys)| {
            let copy = keys.iter().map(|(_, k)| *k).collect::<Vec<_>>().join("\n");
            let detail = msg("finding.registry.where_windows");
            clsid_finding(dll, detail).evidence(keys.into_iter().map(|(line, _)| line)).copy(copy)
        })
        .collect()
}

// -------------------------------------------------- C4: Wine prefix registry

fn check_prefix(prefix: &Path) -> Vec<Finding> {
    let mut out = Vec::new();
    if let Some(drive_c) = find_ci(prefix, &["drive_c"]) {
        let apps = ["Program Files", "Program Files (x86)"]
            .iter()
            .filter_map(|pf| find_ci(&drive_c, &[pf, "Google", "Chrome", "Application"]))
            .collect();
        check_legacy(apps, &mut out);
    }
    // user.reg is HKCU. system.reg (HKLM) has a normal copy pointing to wpc.dll.
    let Some(user_reg) = find_ci(prefix, &["user.reg"]) else {
        return out;
    };
    let Some(bytes) = read_small(&user_reg) else {
        return out;
    };
    let evidence = clsid_keys(&String::from_utf8_lossy(&bytes));
    if evidence.is_empty() {
        return out;
    }
    let installed = evidence.iter().any(|l| l.strip_prefix("@=").is_some_and(|v| v.trim() != "\"\""));
    let detail = msg("finding.registry.where_wine");
    out.push(clsid_finding(installed, detail).at(&user_reg).copy(CLSID_KEYS[0]).evidence(evidence).time(mtime(&user_reg)));
    out
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
    let (note, domains) = match fs::read(&path) {
        Ok(bytes) => (None, known(parse_hosts(&String::from_utf8_lossy(&bytes)))),
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            (Some(msg("hosts.missing")), known(parse_hosts("")))
        }
        Err(_) => (
            Some(msg("hosts.unreadable")),
            DOMAINS.iter().map(|&d| (d, None)).collect(),
        ),
    };
    HostsStatus { path, note, domains }
}

fn known(domains: Vec<(&'static str, bool)>) -> Vec<(&'static str, Option<bool>)> {
    domains.into_iter().map(|(d, blocked)| (d, Some(blocked))).collect()
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

/// "PID 1234: <command line>" for each running launcher process.
fn launcher_processes() -> Vec<String> {
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
            let cmd: Vec<String> = p.cmd().iter().map(|a| a.to_string_lossy().into_owned()).collect();
            is_launcher_process(&name, p.cmd())
                .then(|| format!("PID {pid}: {}", if cmd.is_empty() { name.into_owned() } else { cmd.join(" ") }))
        })
        .collect();
    evidence.sort();
    evidence
}

/// The running launcher is critical only next to a sign of the agent: a clean,
/// reinstalled launcher runs too, and on its own it is listed for information.
fn launcher_running(evidence: Vec<String>, agent: bool) -> Finding {
    let finding = if agent {
        Finding::new(
            FindingKind::LauncherRunning,
            Severity::Critical,
            msg("finding.launcher_running.title"),
            msg("finding.launcher_running.detail"),
        )
    } else {
        Finding::new(
            FindingKind::Info,
            Severity::Info,
            msg("finding.launcher_running_clean.title"),
            msg("finding.launcher_running_clean.detail"),
        )
    };
    finding.evidence(evidence)
}

/// The launcher itself, not a program that only names its file (sha256sum, an
/// editor, a disassembler). Linux truncates process names to 15 bytes
/// ("nikke_launcher."), and Wine sets argv[0] to the Windows path of the .exe.
fn is_launcher_process(name: &str, cmd: &[OsString]) -> bool {
    let base = |arg: &OsString| arg.to_string_lossy().rsplit(['/', '\\']).next().unwrap_or_default().to_ascii_lowercase();
    let first = cmd.first().map(base);
    let wine = first
        .as_deref()
        .is_some_and(|b| matches!(b, "wine" | "wine64" | "wine-preloader" | "wine64-preloader"));
    name.to_ascii_lowercase().starts_with("nikke_launcher")
        || first.as_deref() == Some("nikke_launcher.exe")
        || (wine && cmd[1..].iter().any(|arg| base(arg) == "nikke_launcher.exe"))
}

/// Programs that have the malware's DLL loaded. Toolhelp snapshots only read
/// the process and module lists; processes that deny access are skipped.
#[cfg(windows)]
fn check_loaded_dlls() -> Vec<Finding> {
    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_BAD_LENGTH, GetLastError, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, MODULEENTRY32W, Module32FirstW, Module32NextW, PROCESSENTRY32W, Process32FirstW,
        Process32NextW, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS,
    };
    use windows_sys::Win32::System::Registry::{HKEY_CURRENT_USER, KEY_WOW64_32KEY, KEY_WOW64_64KEY};
    let key = format!("Software\\Classes\\CLSID\\{CLSID}\\InprocServer32");
    let registered: Vec<String> = [KEY_WOW64_64KEY, KEY_WOW64_32KEY]
        .into_iter()
        .filter_map(|view| locate::reg_string(HKEY_CURRENT_USER, &key, None, view).flatten())
        .filter(|v| !v.trim().is_empty())
        .collect();
    let wide = |s: &[u16]| String::from_utf16_lossy(&s[..s.iter().position(|&c| c == 0).unwrap_or(s.len())]);
    let me = std::process::id();
    let mut evidence = Vec::new();
    let mut first_dll = None;
    // SAFETY: the entry structs are zeroed with dwSize set, as the API requires,
    // and live across the First/Next calls. Each snapshot handle is closed once.
    unsafe {
        let procs = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if procs == INVALID_HANDLE_VALUE {
            return Vec::new();
        }
        let mut pe = PROCESSENTRY32W { dwSize: size_of::<PROCESSENTRY32W>() as u32, ..Default::default() };
        let mut more = Process32FirstW(procs, &mut pe) != 0;
        while more {
            let pid = pe.th32ProcessID;
            if pid != 0 && pid != me {
                // ERROR_BAD_LENGTH: the module list changed during the snapshot; the documented fix is to retry.
                let mut snap = INVALID_HANDLE_VALUE;
                for _ in 0..3 {
                    snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
                    if snap != INVALID_HANDLE_VALUE || GetLastError() != ERROR_BAD_LENGTH {
                        break;
                    }
                }
                if snap != INVALID_HANDLE_VALUE {
                    let mut me32 = MODULEENTRY32W { dwSize: size_of::<MODULEENTRY32W>() as u32, ..Default::default() };
                    let mut modules = Vec::new();
                    let mut next = Module32FirstW(snap, &mut me32) != 0;
                    while next {
                        modules.push(wide(&me32.szExePath));
                        next = Module32NextW(snap, &mut me32) != 0;
                    }
                    CloseHandle(snap);
                    // The first module is the program itself.
                    if let Some(dll) = modules.iter().find(|m| is_persistence_dll(m, &registered)) {
                        let exe = modules.first().cloned().unwrap_or_default();
                        evidence.push(dll_loaded_line(pid, &wide(&pe.szExeFile), &exe, dll));
                        first_dll.get_or_insert_with(|| PathBuf::from(dll));
                    }
                }
            }
            more = Process32NextW(procs, &mut pe) != 0;
        }
        CloseHandle(procs);
    }
    let Some(dll) = first_dll else {
        return Vec::new();
    };
    evidence.sort_by_cached_key(|line| line.render(Lang::En));
    vec![
        Finding::new(
            FindingKind::DllLoaded,
            Severity::Critical,
            msg("finding.dll_loaded.title"),
            msg("finding.dll_loaded.detail"),
        )
        .open(&dll)
        .evidence(capped_text(evidence)),
    ]
}

/// One program with the DLL loaded. The steps read the program name back from it.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn dll_loaded_line(pid: u32, program: &str, exe: &str, dll: &str) -> Text {
    msg("evidence.dll_loaded").arg("pid", pid.to_string()).arg("program", program).arg("exe", exe).arg("dll", dll)
}

/// A module path that is the malware's DLL: platform_experience_helper.dll in a
/// PlatformExperienceHelper folder or in a 64-hex subfolder of one (Chrome's own
/// helper there is an .exe), or the DLL that the HKCU CLSID key names.
#[cfg_attr(not(windows), allow(dead_code))]
fn is_persistence_dll(path: &str, registered: &[String]) -> bool {
    let unquoted = |p: &str| p.trim().trim_matches('"').to_string();
    if registered.iter().any(|r| unquoted(r).eq_ignore_ascii_case(&unquoted(path))) {
        return true;
    }
    let lower = path.to_ascii_lowercase();
    let mut parts = lower.rsplit(['\\', '/']);
    if parts.next() != Some("platform_experience_helper.dll") {
        return false;
    }
    match parts.next() {
        Some("platformexperiencehelper") => true,
        Some(dir) if is_sha256(dir) => parts.next() == Some("platformexperiencehelper"),
        _ => false,
    }
}

// ------------------------------------------------------------- helpers

/// At most MAX_EVIDENCE lines, the last one giving the total when some are left out.
fn capped(lines: Vec<String>) -> Vec<Text> {
    capped_text(lines.into_iter().map(Text::Raw).collect())
}

fn capped_text(mut lines: Vec<Text>) -> Vec<Text> {
    if lines.len() > MAX_EVIDENCE {
        let total = lines.len();
        lines.truncate(MAX_EVIDENCE - 1);
        lines.push(msg("evidence.total").arg("total", total.to_string()));
    }
    lines
}

fn is_sha256(name: &str) -> bool {
    name.len() == 64 && name.bytes().all(|b| b.is_ascii_hexdigit())
}

fn read_small(path: &Path) -> Option<Vec<u8>> {
    let meta = fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_FILE {
        return None;
    }
    fs::read(path).ok()
}

/// Calls `f` on each line of a file of any size, without its line end. Lines
/// longer than MAX_LINE are cut, so a file without line breaks cannot fill memory.
fn each_line(path: &Path, mut f: impl FnMut(&[u8])) -> io::Result<()> {
    let mut reader = io::BufReader::new(fs::File::open(path)?);
    let mut line = Vec::new();
    loop {
        let buf = reader.fill_buf()?;
        if buf.is_empty() {
            break;
        }
        let newline = buf.iter().position(|&b| b == b'\n');
        let part = &buf[..newline.unwrap_or(buf.len())];
        line.extend_from_slice(&part[..part.len().min(MAX_LINE.saturating_sub(line.len()))]);
        let used = newline.map_or(buf.len(), |n| n + 1);
        reader.consume(used);
        if newline.is_some() {
            f(line.strip_suffix(b"\r").unwrap_or(&line));
            line.clear();
        }
    }
    if !line.is_empty() {
        f(line.strip_suffix(b"\r").unwrap_or(&line));
    }
    Ok(())
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
        // Binary files can leave a broken UTF-8 byte at either end of a run.
        let mut text = String::from_utf8_lossy(&segment[start..end])
            .trim_matches(|c: char| c.is_whitespace() || c == char::REPLACEMENT_CHARACTER)
            .to_string();
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

/// "[2026-11-03 01:47:35.556]..." (tinyget logs) to "2026-11-03 01:47:35 (local time)".
/// Log lines carry the clock of the computer that ran the launcher, not UTC.
pub(crate) fn log_time(line: &str) -> Option<Text> {
    let start = line.find('[')? + 1;
    let s = line.get(start..start + 19)?;
    let ok = s.bytes().enumerate().all(|(i, c)| match i {
        4 | 7 => c == b'-',
        10 => c == b' ',
        13 | 16 => c == b':',
        _ => c.is_ascii_digit(),
    });
    ok.then(|| msg("time.local").arg("time", s))
}

/// "[1103/014736.593:INFO..." (CEF debug.log, no year) to "11-03 01:47:36 (local time, ...)".
pub(crate) fn cef_time(line: &str) -> Option<Text> {
    let start = line.find('[')? + 1;
    let s = line.get(start..start + 11)?;
    let b = s.as_bytes();
    let ok = b.iter().enumerate().all(|(i, c)| if i == 4 { *c == b'/' } else { c.is_ascii_digit() });
    ok.then(|| msg("time.local_no_year").arg("time", format!("{}-{} {}:{}:{}", &s[0..2], &s[2..4], &s[5..7], &s[7..9], &s[9..11])))
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
            scan(std::slice::from_ref(&self.0))
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            // remove_dir_all removes symlinks themselves, never their targets.
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn scan(roots: &[PathBuf]) -> ScanResult {
        let progress = Progress::default();
        run("test".into(), locate::discover_folders(roots, &progress), false, Instant::now(), &progress)
    }

    fn findings(r: &ScanResult) -> Vec<&Finding> {
        r.groups.iter().flat_map(|g| &g.findings).collect()
    }

    fn has(r: &ScanResult, severity: Severity, title: &str) -> bool {
        findings(r).iter().any(|f| f.severity == severity && f.title.en() == title)
    }

    const DEBUG_LOG: &[u8] = b"[1103/014735.001:INFO:CONSOLE(1)] \"page loaded\", source:  (1)\r\n\
[1103/014736.558:INFO:CONSOLE(1)] \"lua downloaded to log\\tinyget\\tinyget.20261103-014735-553.log\", source:  (1)\r\n\
[1103/014736.593:INFO:CONSOLE(1)] \"k2f_chan registered\", source:  (1)\r\n\
[1103/014736.623:INFO:CONSOLE(1)] \"adopted 3c4c9b75-09e5-4619-99ee-97c1dc3c0373\", source:  (1)\r\n\
[1103/014736.625:INFO:CONSOLE(1)] \"agent started as TESTHOST\", source:  (1)\r\n";

    const TINYGET_LOG: &[u8] = b"[2026-11-03 01:47:25.874][316][INFO][main.cpp(1)]start\n\
[2026-11-03 01:47:35.556][316][ERROR][tiny_downloader.cpp(103)]tiny_downloader::TinyDownloader::AddTask\tadd task, task_id=2147483648, url=https://analytics.insightjs.com/comm/assets/insight.bundle, path=S:\\NIKKE\\Launcher\\log\\tinyget\\tinyget.20261103-014735-553.log\n\
[2026-11-03 01:47:36.147][1492][ERROR][download_task.cpp(519)]tiny_downloader::DownloadTask::OnDownloadResult\tOnDownloadResult, task=2147483648, result=0, error_code=0, strategy=0, total=205135, err_msg=, url=https://analytics.insightjs.com/comm/assets/insight.bundle\n";

    #[test]
    fn loader_only_log_is_a_warning() {
        let fx = Fixture::new("loader-only");
        fx.file("NIKKE/Launcher/nikke_launcher.exe", b"MZ");
        fx.file(
            "NIKKE/Launcher/intl_service/debug.log",
            b"[1103/120001.001:INFO:CONSOLE(61)] \"Uncaught SyntaxError: Invalid or unexpected token\", source: https://insightjs.org/l.js?f=aegis (61)\r\n",
        );
        fx.file("NIKKE/Launcher/log/other.log", b"[2026-11-03 12:00:01.000][1][INFO][x]x\tGET https://insightjs.org/l.js?f=vue\n");
        let r = fx.scan();
        assert_eq!(r.verdict, Verdict::Exposed);
        assert!(has(&r, Severity::Warning, "debug.log mentions insightjs"));
        assert!(has(&r, Severity::Warning, "other.log mentions insightjs"));

        fx.file("NIKKE/Launcher/log/other.log", b"GET https://analytics.insightjs.com/comm/assets/x\n");
        let r = fx.scan();
        assert_eq!(r.verdict, Verdict::Infected);
        assert!(has(&r, Severity::Critical, "other.log names the agent server"));
    }

    #[test]
    fn infected_install() {
        let fx = Fixture::new("infected");
        fx.file("NIKKE/Launcher/nikke_launcher.exe", b"MZ");
        fx.file("NIKKE/Launcher/intl_service/debug.log", DEBUG_LOG);
        fx.file("NIKKE/Launcher/log/tinyget/tinyget.20261103-014725-874.log", TINYGET_LOG);
        fx.file("NIKKE/Launcher/log/tinyget/tinyget.20261103-014735-553.log", b"\x1bLJ\x02payload");
        let r = fx.scan();
        assert_eq!(r.verdict, Verdict::Infected);
        let ran = findings(&r).into_iter().find(|f| f.title.en() == "The malware agent ran").expect("A1");
        assert_eq!(ran.severity, Severity::Critical);
        assert_eq!(ran.evidence.len(), 4);
        assert!(ran.evidence_lines(Lang::En).iter().any(|l| l.contains("agent started as TESTHOST")));
        assert_eq!(ran.time.as_ref().map(Text::en).as_deref(), Some("11-03 01:47:36 (local time, year not logged)"));
        let dl = findings(&r)
            .into_iter()
            .find(|f| f.title.en() == "The launcher downloaded the malware")
            .expect("A2");
        assert_eq!(dl.time.as_ref().map(Text::en).as_deref(), Some("2026-11-03 01:47:35 (local time)"));
        assert!(dl.detail.en().contains("tinyget.20261103-014725-874.log"));
        assert!(has(&r, Severity::Critical, "The malware file is still on disk"));
        assert!(findings(&r).iter().all(|f| f.evidence.len() <= 5 && f.evidence_lines(Lang::En).iter().all(|e| e.chars().count() <= 240)));
    }

    #[test]
    fn failed_download_is_only_an_attempt() {
        let fx = Fixture::new("attempt");
        fx.file("NIKKE/Launcher/nikke_launcher.exe", b"MZ");
        fx.file("NIKKE/Launcher/intl_service/debug.log", b"[1103/204159.001:INFO:CONSOLE(1)] \"page loaded\"\n");
        fx.file(
            "NIKKE/Launcher/log/tinyget/tinyget.20261103-204150-000.log",
            b"[2026-11-03 20:41:59.453][316][ERROR][tiny_downloader.cpp(103)]tiny_downloader::TinyDownloader::AddTask\tadd task, task_id=2147483648, url=https://analytics.insightjs.com/comm/assets/insight.bundle, path=C:\\NIKKE\\Launcher\\log\\tinyget\\tinyget.20261103-204159-450.log\n\
[2026-11-03 20:41:59.613][1492][ERROR][download_task.cpp(519)]tiny_downloader::DownloadTask::OnDownloadResult\tOnDownloadResult, task=2147483648, result=2, error_code=7, strategy=0, total=0, err_msg=, url=https://analytics.insightjs.com/comm/assets/insight.bundle\n",
        );
        let r = fx.scan();
        assert_eq!(r.verdict, Verdict::Exposed);
        assert!(has(&r, Severity::Warning, "The launcher asked for the malware, but no download finished"));
        assert!(!findings(&r).iter().any(|f| f.kind == FindingKind::PayloadDownloaded));
        assert!(r.runs.is_empty());
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
            .find(|f| f.title.en() == "The launcher loaded the malicious script")
            .expect("B");
        assert_eq!(f.evidence.len(), 1, "{:?}", f.evidence);
        assert!(f.evidence[0].en().contains("https://insightjs.com/l.js?f=aegis"), "{:?}", f.evidence);
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
            .find(|f| f.title.en() == "Registry persistence found (HKCU CLSID hijack)")
            .expect("C4");
        assert!(f.evidence_lines(Lang::En).iter().any(|e| e.starts_with("@=") && e.contains("platform_experience_helper.dll")));
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
        let f = findings(&r).into_iter().find(|f| f.title.en() == "Chrome persistence is installed").expect("C1");
        assert_eq!(f.severity, Severity::Critical);
        assert!(f.evidence_lines(Lang::En).iter().any(|e| e.contains("platform_experience_helper.dll")));
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
    fn dotnet_temp_names_are_not_k2f_files() {
        let fx = Fixture::new("dotnet");
        let temp = "pfx/drive_c/users/steamuser/AppData/Local/Temp";
        fx.dir(&format!("{temp}/k2fkuxjm.qu0"));
        fx.file(&format!("{temp}/k2fb4mxe.n2t"), b"x");
        fx.dir(&format!("{temp}/k2f-folder"));
        let r = fx.scan();
        assert!(!findings(&r).iter().any(|f| f.kind == FindingKind::TempFile), "{:?}", findings(&r));
        assert_eq!(r.verdict, Verdict::NotFound);
        fx.file(&format!("{temp}/k2f-bcreds-1793800000-123456.db"), b"x");
        let r = fx.scan();
        let f = findings(&r).into_iter().find(|f| f.kind == FindingKind::TempFile).expect("C2");
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.evidence_lines(Lang::En), ["k2f-bcreds-1793800000-123456.db"]);
    }

    #[test]
    fn hex_marker_is_info() {
        // Other Tencent games write the same onominan.tmp, so it never sets the verdict.
        let fx = Fixture::new("marker");
        fx.file("pfx/drive_c/users/steamuser/AppData/Local/Temp/onominan.tmp", b"c8f9eef3c60a28fb67b716");
        fx.file("pfx/drive_c/users/steamuser/AppData/Local/Temp/other.tmp", b"NOT-HEX-0123456789abcd");
        fx.file("pfx/drive_c/users/steamuser/AppData/Local/Temp/short.tmp", b"b8fd3eed");
        let r = fx.scan();
        let f = findings(&r).into_iter().find(|f| f.title.en() == "Hex ID file in Temp").expect("C3");
        assert_eq!(f.severity, Severity::Info);
        assert_eq!(f.evidence.len(), 1);
        assert!(f.evidence[0].en().starts_with("onominan.tmp: c8f9eef3c60a28fb67b716"));
        assert_eq!(r.verdict, Verdict::NotFound);
    }

    #[test]
    fn agent_state_in_local_storage_is_critical() {
        // The install, with its debug.log, is gone; the agent's saved state remains.
        let fx = Fixture::new("agentstate");
        let data = "pfx/drive_c/users/steamuser/AppData/Roaming/nikke_launcher";
        fx.file(
            &format!("{data}/tbs_cache/Local Storage/leveldb/000003.log"),
            b"\x01\x00\x00_https://www.nikkelauncher.com\x00\x01k2f.agent.state\xf3\x01\x01{\"agent_id\":\"3c4c9b75-09e5-4619-99ee-97c1dc3c0373\",\"agent_pass\":\"s3cret-pass\",\"c2s_counter\":4,\"s2c_counter\":17936}",
        );
        fx.file(&format!("{data}/tbs_cache/Code Cache/js/aa_0"), b"\x00https://insightjs.com/l.js?f=aegis\x00");
        let r = fx.scan();
        let f = findings(&r)
            .into_iter()
            .find(|f| f.title.en() == "The malware agent left traces in the launcher data")
            .expect("B agent");
        assert_eq!(f.severity, Severity::Critical);
        assert!(f.evidence_lines(Lang::En).iter().any(|e| e.ends_with(": k2f.agent.state")), "{:?}", f.evidence);
        let all = findings(&r);
        assert!(all.iter().flat_map(|f| f.evidence_lines(Lang::En)).all(|e| !e.contains("agent_pass") && !e.contains("s3cret")));
        assert_eq!(r.verdict, Verdict::Infected);
        // The report says the install, with debug.log, was not checked.
        assert!(has(&r, Severity::Info, "The NIKKE install folder was not found"));
    }

    #[test]
    fn chrome_own_helper_is_not_critical() {
        let fx = Fixture::new("pehlegit");
        let peh = "pfx/drive_c/users/steamuser/AppData/Local/Google/Chrome/User Data/PlatformExperienceHelper";
        fx.file(&format!("{peh}/platform_experience_helper.exe"), b"MZ");
        fx.file(&format!("{peh}/LoadFeatures"), b"");
        let r = fx.scan();
        let f = findings(&r)
            .into_iter()
            .find(|f| f.title.en() == "Chrome's Platform Experience Helper folder")
            .expect("C1 info");
        assert_eq!(f.severity, Severity::Info);
        assert!(!has(&r, Severity::Critical, "Chrome persistence is installed"));
        assert_eq!(r.verdict, Verdict::NotFound);

        // A 64-hex subfolder is the malware's layout even when the DLL is gone.
        fx.dir(&format!("{peh}/{}", "ab".repeat(32)));
        let r = fx.scan();
        let f = findings(&r).into_iter().find(|f| f.title.en() == "Chrome persistence is installed").expect("C1");
        assert!(f.detail.en().contains("was not found"), "{:?}", f.detail);
        assert_eq!(r.verdict, Verdict::Infected);
    }

    #[test]
    fn windows_profile_in_a_folder_scan() {
        let fx = Fixture::new("winprofile");
        let local = "win/Users/Bob/AppData/Local";
        fx.file(
            &format!("{local}/Google/Chrome/User Data/PlatformExperienceHelper/{}/platform_experience_helper.dll", "0f".repeat(32)),
            b"MZ",
        );
        fx.file(&format!("{local}/Temp/k2f-bcreds-1"), b"x");
        fx.dir("win/Users/Bob/AppData/Roaming/nikke_launcher");
        fx.dir("win/Users/Public/AppData/Local");
        for root in [fx.0.join("win"), fx.0.join("win/Users/Bob")] {
            let r = scan(std::slice::from_ref(&root));
            assert_eq!(r.verdict, Verdict::Infected, "{root:?}");
            assert!(has(&r, Severity::Critical, "Chrome persistence is installed"));
            assert!(has(&r, Severity::Critical, "Files left by the malware in Temp"));
            let profiles: Vec<_> = r.targets.iter().filter(|t| t.kind == TargetKind::UserProfile).collect();
            assert_eq!(profiles.len(), 1, "{profiles:?}");
            assert!(profiles[0].path.ends_with("Users/Bob"));
        }
    }

    #[test]
    fn deep_install_inside_drive_c() {
        let fx = Fixture::new("deepdrivec");
        let launcher = "a/b/c/d/pfx/drive_c/Games/Launchers/Level Infinite/NIKKE/Launcher";
        fx.file(&format!("{launcher}/nikke_launcher.exe"), b"MZ");
        fx.file(&format!("{launcher}/intl_service/debug.log"), DEBUG_LOG);
        for root in [fx.0.clone(), fx.0.join("a/b/c/d/pfx/drive_c")] {
            let r = scan(std::slice::from_ref(&root));
            assert_eq!(r.verdict, Verdict::Infected, "{root:?}");
            assert!(has(&r, Severity::Critical, "The malware agent ran"));
        }
    }

    #[test]
    fn running_launcher_is_critical_only_with_the_agent() {
        let evidence = || vec!["PID 7: nikke_launcher.exe".to_string()];
        let clean = launcher_running(evidence(), false);
        assert_eq!((clean.kind, clean.severity), (FindingKind::Info, Severity::Info));
        assert_eq!(clean.title.en(), "The NIKKE launcher is running");
        let infected = launcher_running(evidence(), true);
        assert_eq!((infected.kind, infected.severity), (FindingKind::LauncherRunning, Severity::Critical));
        assert_eq!(infected.evidence.len(), 1);
    }

    #[test]
    fn login_browser_profile_is_read_for_the_iocs() {
        let fx = Fixture::new("cefprofile");
        let cef = "pfx/drive_c/users/steamuser/AppData/Local/CEF/User Data";
        // Another CEF program's data: no finding, and NIKKE is not found.
        fx.file(&format!("{cef}/Default/Network Persistent State"), br#"{"servers":[{"server":"https://example.com"}]}"#);
        let r = fx.scan();
        assert!(r.targets.iter().any(|t| t.kind == TargetKind::LoginProfile));
        assert!(findings(&r).is_empty(), "{:?}", findings(&r));
        assert_eq!(r.verdict, Verdict::NotFound);

        fx.file(&format!("{cef}/Default/Local Storage/leveldb/000003.log"), b"\x01_https://www.nikkelauncher.com\x00\x01k2f.agent.state\xf3{}");
        fx.file(&format!("{cef}/Default/Code Cache/js/aa_0"), b"\x00https://insightjs.com/l.js?f=aegis\x00");
        let r = fx.scan();
        assert_eq!(r.verdict, Verdict::Infected);
        let group = r.groups.iter().find(|g| g.label.en() == "Launcher's login browser profile").expect("group");
        assert!(group.findings.iter().any(|f| f.title.en() == "The malware agent left traces in the launcher's login browser profile"));
        assert!(group.findings.iter().any(|f| f.kind == FindingKind::LoaderCached));
    }

    #[test]
    fn launcher_process_is_matched_on_argv0() {
        let args = |a: &[&str]| a.iter().map(OsString::from).collect::<Vec<_>>();
        assert!(is_launcher_process("nikke_launcher.", &args(&[])));
        assert!(is_launcher_process("nikke_launcher.", &args(&["S:\\NIKKE\\Launcher\\nikke_launcher.exe"])));
        assert!(is_launcher_process("x", &args(&["C:\\Games\\NIKKE\\Launcher\\NIKKE_LAUNCHER.EXE"])));
        assert!(is_launcher_process("wine64-preloader", &args(&["/usr/bin/wine64", "/g/NIKKE/Launcher/nikke_launcher.exe"])));
        assert!(!is_launcher_process("python3", &args(&["python3", "-c", "pass", "/tmp/x/Launcher/nikke_launcher.exe"])));
        assert!(!is_launcher_process("sha256sum", &args(&["sha256sum", "nikke_launcher.exe"])));
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
        assert_eq!(log_time("[2026-11-03 01:47:35.556][316]").map(|t| t.en()).as_deref(), Some("2026-11-03 01:47:35 (local time)"));
        assert_eq!(log_time("[not a time]"), None);
        assert_eq!(
            cef_time("[1103/014736.593:INFO").map(|t| t.en()).as_deref(),
            Some("11-03 01:47:36 (local time, year not logged)")
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_launcher_data_is_read() {
        use std::os::unix::fs::symlink;
        let fx = Fixture::new("datalink");
        fx.file("real/tbs_cache/Code Cache/js/aa_0", b"\x00https://insightjs.com/l.js?f=aegis\x00");
        let roaming = fx.dir("scan/pfx/drive_c/users/steamuser/AppData/Roaming");
        symlink(fx.0.join("real"), roaming.join("nikke_launcher")).unwrap();
        let r = scan(&[fx.0.join("scan")]);
        assert!(has(&r, Severity::Warning, "The launcher loaded the malicious script"));
        assert_eq!(r.verdict, Verdict::Exposed);

        // A link to a folder above itself is reported, not walked.
        let up = fx.dir("up/drive_c/users/u/AppData/Roaming");
        symlink(&fx.0, up.join("nikke_launcher")).unwrap();
        let r = scan(&[fx.0.join("up")]);
        assert!(has(&r, Severity::Info, "Launcher data folder is a link and was not read"));
    }

    #[cfg(unix)]
    #[test]
    fn install_is_found_from_the_registry() {
        use std::os::unix::fs::symlink;
        // The install sits outside the scanned folder; user.reg names it through drive S:.
        let fx = Fixture::new("reghint");
        fx.file("elsewhere/Games/NIKKE/Launcher/nikke_launcher.exe", b"MZ");
        fx.file("elsewhere/Games/NIKKE/Launcher/intl_service/debug.log", DEBUG_LOG);
        fx.dir("scan/pfx/drive_c/users/steamuser");
        let dosdevices = fx.dir("scan/pfx/dosdevices");
        symlink(fx.0.join("elsewhere"), dosdevices.join("s:")).unwrap();
        // The App Paths value uses other letter cases than the disk.
        fx.file(
            "scan/pfx/user.reg",
            b"WINE REGISTRY Version 2\n\n[Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\App Paths\\\\nikke_launcher.exe] 1793276426\n\"InstallPath\"=\"S:\\\\games\\\\nikke\\\\launcher\\\\nikke_launcher.exe\"\n",
        );
        let r = scan(&[fx.0.join("scan")]);
        assert_eq!(r.verdict, Verdict::Infected);
        let installs: Vec<_> = r.targets.iter().filter(|t| t.kind == TargetKind::InstallDir).collect();
        assert_eq!(installs.len(), 1);
        assert_eq!(installs[0].path, fs::canonicalize(fx.0.join("elsewhere/Games/NIKKE")).unwrap());
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
        let d = locate::discover_folders_with_cap(std::slice::from_ref(&fx.0), 10, &Progress::default());
        assert!(d.stats.cap_hit);
        assert_eq!(d.stats.entries, 10);
    }

    /// The layout of `exposed_only`, which has one target of each kind.
    fn exposed_fixture() -> Fixture {
        let fx = Fixture::new("progress");
        fx.file("NIKKE/Launcher/nikke_launcher.exe", b"MZ");
        fx.file("NIKKE/Launcher/intl_service/debug.log", DEBUG_LOG);
        fx.file(
            "NIKKE/prefix/drive_c/users/steamuser/AppData/Roaming/nikke_launcher/tbs_cache/Code Cache/js/aa_0",
            b"\x00https://insightjs.com/l.js?f=aegis\x00",
        );
        for i in 0..100 {
            fx.file(&format!("NIKKE/Data/d{i}/f"), b"");
        }
        fx
    }

    #[test]
    fn progress_matches_the_result() {
        let fx = exposed_fixture();
        let progress = Progress::default();
        let d = locate::discover_folders(std::slice::from_ref(&fx.0), &progress);
        assert_eq!(progress.entries.load(Relaxed), d.stats.entries);
        assert_eq!(progress.folders.load(Relaxed), d.stats.folders);
        for kind in [TargetKind::InstallDir, TargetKind::LauncherData, TargetKind::WinePrefix, TargetKind::UserProfile] {
            let n = d.targets.iter().filter(|t| t.kind == kind).count();
            assert!(n > 0, "{kind:?}");
            assert_eq!(progress.found[kind as usize].load(Relaxed), n, "{kind:?}");
        }
        let total = d.targets.len();
        let r = run("test".into(), d, false, Instant::now(), &progress);
        assert_eq!(progress.stage(), Stage::Done);
        assert_eq!(progress.checks_total.load(Relaxed), total);
        assert_eq!(progress.checks_done.load(Relaxed), total);
        for severity in [Severity::Info, Severity::Warning, Severity::Critical] {
            let n = findings(&r).iter().filter(|f| f.severity == severity).count();
            assert_eq!(progress.findings[severity as usize].load(Relaxed), n, "{severity:?}");
        }
        assert_eq!(r.verdict, Verdict::Infected);
    }

    #[test]
    fn cancel_stops_the_scan() {
        let fx = exposed_fixture();
        let progress = Progress::default();
        progress.cancel();
        let d = locate::discover_folders(std::slice::from_ref(&fx.0), &progress);
        assert_eq!(d.stats.entries, 0);
        assert!(d.targets.is_empty());

        // Cancelled after discovery: no target is checked.
        let progress = Progress::default();
        let d = locate::discover_folders(std::slice::from_ref(&fx.0), &progress);
        assert!(d.stats.entries > 100 && !d.targets.is_empty());
        progress.cancel();
        let r = run("test".into(), d, false, Instant::now(), &progress);
        assert_eq!(progress.checks_done.load(Relaxed), 0);
        assert!(r.groups.is_empty());
    }

    const DATA: &str = "pfx/drive_c/users/steamuser/AppData/Roaming/nikke_launcher/tbs_cache";

    fn transport_security(hosts: &[&str]) -> String {
        let entries: Vec<String> = hosts
            .iter()
            .map(|h| format!(r#"{{"expiry":1825202857.5,"host":"{}","mode":"force-https","sts_include_subdomains":false,"sts_observed":1793666857.588157}}"#, hsts::key(h)))
            .collect();
        format!(r#"{{"expect_ct":[],"sts":[{}],"version":2}}"#, entries.join(","))
    }

    #[test]
    fn agent_server_in_network_state_is_critical() {
        let fx = Fixture::new("agentserver");
        fx.file(&format!("{DATA}/TransportSecurity"), transport_security(&["insightjs.com", "analytics.insightjs.com"]).as_bytes());
        fx.file(
            &format!("{DATA}/Network Persistent State"),
            br#"{"net":{"http_server_properties":{"servers":[{"server":"https://insightjs.com"},{"server":"https://analytics.insightjs.com"}]}}}"#,
        );
        let r = fx.scan();
        assert_eq!(r.verdict, Verdict::Infected);
        let f = findings(&r).into_iter().find(|f| f.kind == FindingKind::AgentServerContacted).expect("server");
        assert_eq!((f.severity, f.title.en().as_str()), (Severity::Critical, "The launcher contacted the agent server"));
        assert_eq!(f.evidence.len(), 2, "{:?}", f.evidence);
        let lines = f.evidence_lines(Lang::En);
        assert!(lines.iter().any(|e| e.contains("HSTS entry for analytics.insightjs.com, last received 2026-11-03 00:47:37 UTC")));
        assert!(lines.iter().any(|e| e.contains("https://analytics.insightjs.com")));
        assert_eq!(f.time.as_ref().map(Text::en).as_deref(), Some("2026-11-03 00:47:37 UTC"));
        // Both files went to the critical finding, none to the warning.
        assert!(!has(&r, Severity::Warning, "The launcher connected to insightjs.com"));
    }

    #[test]
    fn out_of_range_times_do_not_stop_the_scan() {
        let fx = Fixture::new("hugetime");
        let ts = transport_security(&["analytics.insightjs.com"]).replace("1793666857.588157", "18446744073709551615.0");
        fx.file(&format!("{DATA}/TransportSecurity"), ts.as_bytes());
        fx.file("NIKKE/Launcher/nikke_launcher.exe", b"MZ");
        fx.file(
            "NIKKE/Launcher/log/tinyget/tinyget.mem.log",
            b"[2026-11-03 01:47:35.891][7][TRACE][x]x\t[CURL]Header out: GET /comm/assets/insight.bundle HTTP/1.1\n[2026-11-03 01:47:36.013][7][TRACE][x]x\t[CURL]Header in: ETag: \"ffffffffffffffff-3214f\"\n",
        );
        let r = fx.scan();
        assert_eq!(r.verdict, Verdict::Infected);
        let f = findings(&r).into_iter().find(|f| f.kind == FindingKind::AgentServerContacted).expect("server");
        assert!(f.evidence[0].en().contains("HSTS entry for analytics.insightjs.com") && !f.evidence[0].en().contains("last received"), "{:?}", f.evidence);
        assert_eq!(r.builds.len(), 1);
        assert_eq!(r.builds[0].uploaded, None);
    }

    #[test]
    fn loader_host_alone_is_a_warning() {
        let fx = Fixture::new("loaderhost");
        fx.file(&format!("{DATA}/TransportSecurity"), transport_security(&["insightjs.com", "www.google.com"]).as_bytes());
        let r = fx.scan();
        assert_eq!(r.verdict, Verdict::Exposed);
        let f = findings(&r).into_iter().find(|f| f.title.en() == "The launcher connected to insightjs.com").expect("warning");
        assert_eq!(f.kind, FindingKind::LauncherContacted);
        assert!(f.evidence[0].en().contains("HSTS entry for insightjs.com,"), "{:?}", f.evidence);
    }

    #[test]
    fn registry_leftover_is_critical() {
        for value in ["@=\"\"\n", ""] {
            let fx = Fixture::new("leftover");
            fx.dir("pfx/drive_c/users/steamuser");
            fx.file("pfx/user.reg", format!("WINE REGISTRY Version 2\n\n{CLSID_KEY}{value}").as_bytes());
            let r = fx.scan();
            assert_eq!(r.verdict, Verdict::Infected);
            let f = findings(&r).into_iter().find(|f| f.kind == FindingKind::RegistryLeftover).expect("leftover");
            assert_eq!(f.severity, Severity::Critical);
            assert_eq!(f.copy_text.as_deref(), Some(CLSID_KEYS[0]));
            assert!(!findings(&r).iter().any(|f| f.kind == FindingKind::RegistryKey));
        }
    }

    #[test]
    fn legacy_dll_in_chrome_application() {
        let fx = Fixture::new("legacy");
        let pf = "pfx/drive_c/Program Files/Google/Chrome/Application/PlatformExperienceHelper";
        fx.file(&format!("{pf}/platform_experience_helper.exe"), b"MZ");
        fx.dir("pfx/drive_c/users/steamuser");
        let r = fx.scan();
        assert!(findings(&r).is_empty(), "{:?}", findings(&r));
        fx.file(&format!("{pf}/old-clsid.txt"), b"{x}");
        fx.file(
            "pfx/drive_c/users/steamuser/AppData/Local/Google/Chrome/Application/PlatformExperienceHelper/platform_experience_helper.dll.old",
            b"MZ",
        );
        let r = fx.scan();
        assert_eq!(r.verdict, Verdict::Infected);
        let legacy: Vec<&Finding> = findings(&r).into_iter().filter(|f| f.kind == FindingKind::LegacyDll).collect();
        assert_eq!(legacy.len(), 2);
        assert!(legacy.iter().all(|f| f.severity == Severity::Critical && f.evidence.len() == 1));
        assert!(legacy.iter().any(|f| f.open_path.as_ref().is_some_and(|p| p.ends_with("old-clsid.txt"))));
    }

    #[test]
    fn other_browsers_helper_folder() {
        let fx = Fixture::new("edge");
        let hash = "ab".repeat(32);
        let dll = format!("pfx/drive_c/users/steamuser/AppData/Local/Microsoft/Edge/User Data/PlatformExperienceHelper/{hash}/platform_experience_helper.dll");
        let dll = fx.file(&dll, b"MZ");
        let r = fx.scan();
        let f = findings(&r).into_iter().find(|f| f.title.en() == "Edge persistence is installed").expect("edge");
        assert_eq!((f.kind, f.severity), (FindingKind::ChromeDll, Severity::Critical));
        assert_eq!(f.open_path.as_deref(), Some(dll.as_path()));
        assert_eq!(r.verdict, Verdict::Infected);
    }

    #[test]
    fn runs_and_builds() {
        let fx = Fixture::new("runs");
        fx.file("NIKKE/Launcher/nikke_launcher.exe", b"MZ");
        // An earlier run whose debug.log lines are gone is still found through its tinyget log.
        let resumed = b"[1103/120000.001:INFO:CONSOLE(1)] \"resuming 3c4c9b75-09e5-4619-99ee-97c1dc3c0373\", source:  (1)\r\n";
        fx.file("NIKKE/Launcher/intl_service/debug.log", &[DEBUG_LOG, resumed].concat());
        fx.file("NIKKE/Launcher/log/tinyget/tinyget.20261103-014725-874.log", TINYGET_LOG);
        fx.file(
            "NIKKE/Launcher/log/tinyget/tinyget.20261102-183405-583.log",
            b"[2026-11-02 18:34:10.000][316][ERROR][tiny_downloader.cpp(103)]tiny_downloader::TinyDownloader::AddTask\tadd task, task_id=2147483648, url=https://analytics.insightjs.com/comm/assets/insight.bundle, path=S:\\NIKKE\\Launcher\\log\\tinyget\\tinyget.20261102-183410-000.log\n\
[2026-11-02 18:34:10.600][1492][ERROR][download_task.cpp(519)]tiny_downloader::DownloadTask::OnDownloadResult\tOnDownloadResult, task=2147483648, result=0, error_code=0, strategy=0, total=205135, err_msg=, url=https://analytics.insightjs.com/comm/assets/insight.bundle\n",
        );
        fx.file(
            "NIKKE/Launcher/log/tinyget/tinyget.mem.log",
            b"\x86\x96\x00\x00[2026-11-03 01:47:35.891][1492][TRACE][http_curl.cpp(502)]x\t[CURL]Header out: GET /comm/assets/insight.bundle HTTP/1.1\n.\n[2026-11-03 01:47:36.013][1492][TRACE][http_curl.cpp(499)]x\t[CURL]Header in: ETag: \"6ae90538-3214f\"\n",
        );
        let r = fx.scan();
        let kinds: Vec<RunKind> = r.runs.iter().map(|run| run.kind).collect();
        assert_eq!(
            kinds,
            [RunKind::Downloaded, RunKind::Adopted, RunKind::Started, RunKind::Resumed, RunKind::Downloaded]
        );
        assert_eq!(r.runs[2].host.as_deref(), Some("TESTHOST"));
        assert_eq!(r.runs[4].file.as_deref(), Some("tinyget.20261102-183410-000.log"));
        assert_eq!(r.runs[4].time.as_ref().map(Text::en).as_deref(), Some("2026-11-02 18:34:10 (local time)"));
        assert_eq!(r.builds.len(), 1);
        assert!(r.builds[0].known);
        assert_eq!(r.builds[0].uploaded.as_deref(), Some("2026-11-02 21:48:40 UTC"));
        let ran = findings(&r).into_iter().find(|f| f.kind == FindingKind::AgentRan).expect("A1");
        assert_eq!(ran.evidence.len(), 5);
    }

    #[test]
    fn exposure_needs_nikke() {
        let fx = Fixture::new("exposure");
        fx.file("pfx/drive_c/users/steamuser/.aws/credentials", b"");
        assert!(fx.scan().exposure.is_none());
        fx.dir("pfx/drive_c/users/steamuser/AppData/Roaming/nikke_launcher");
        let e = fx.scan().exposure.expect("exposure");
        assert_eq!(e.checked.len(), 1);
        assert_eq!(e.secrets.len(), 1);
    }

    #[test]
    fn persistence_dll_paths() {
        let hash = "0f".repeat(32);
        let user = format!("C:\\Users\\Bob\\AppData\\Local\\Google\\Chrome\\User Data\\PlatformExperienceHelper\\{hash}\\platform_experience_helper.dll");
        assert!(is_persistence_dll(&user, &[]));
        assert!(is_persistence_dll(&user.to_uppercase(), &[]));
        assert!(is_persistence_dll("C:\\Program Files\\Google\\Chrome\\Application\\PlatformExperienceHelper\\platform_experience_helper.dll", &[]));
        assert!(!is_persistence_dll("C:\\Program Files\\Google\\Chrome\\Application\\PlatformExperienceHelper\\platform_experience_helper.exe", &[]));
        assert!(!is_persistence_dll("C:\\Windows\\System32\\wpc.dll", &[]));
        assert!(!is_persistence_dll("C:\\x\\abc\\platform_experience_helper.dll", &[]));
        assert!(is_persistence_dll("C:\\x\\y.dll", &["\"c:\\x\\y.dll\"".into()]));
    }

    #[test]
    fn long_lines_are_cut() {
        let fx = Fixture::new("lines");
        let mut text = vec![b'a'; MAX_LINE * 2 + 10];
        text.extend_from_slice(b"\r\nshort\r\nlast");
        let path = fx.file("f.log", &text);
        let mut lines = Vec::new();
        each_line(&path, |l| lines.push(l.to_vec())).unwrap();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0].len(), MAX_LINE);
        assert_eq!((lines[1].as_slice(), lines[2].as_slice()), (&b"short"[..], &b"last"[..]));
    }
}
