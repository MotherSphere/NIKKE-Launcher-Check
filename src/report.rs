//! Plain-text report (CLI output, "Copy report" and "Save report...") and the
//! texts the window shares with it.

use std::fmt::Write;

use crate::guide::{self, Action, EXPOSURE_NOTE, EXPOSURE_TITLE, Part, Section};
use crate::locate::TargetKind;
use crate::scan::{ATTACKER_IPS, COMPUTER_SCOPE, Finding, FindingKind, Group, HostsStatus, ScanResult, Verdict};

pub const APP_NAME: &str = "NIKKE Launcher Check";
pub const GIST_URL: &str = "https://gist.github.com/MotherSphere/d6c049a09ba8ac3085c51ee9df24a4e5";

/// What was scanned, with "quick scan" or "full scan" for this computer.
pub fn scope(r: &ScanResult) -> String {
    match (r.scope == COMPUTER_SCOPE, r.stats.depth_limit) {
        (true, Some(_)) => format!("{} (quick scan)", r.scope),
        (true, None) => format!("{} (full scan)", r.scope),
        _ => r.scope.clone(),
    }
}

pub const ABOUT: &str = "On 2026-09-27, four files on Level Infinite's CDN were changed to load a script from insightjs.com inside the NIKKE PC launcher. From October 23, 2026 at the latest, that script downloaded a remote-access agent (insight.bundle) that can run commands, read files, take screenshots and collect browser data. Three of the files were replaced on November 3. The fourth was cleaned on October 28, but some CDN servers still delivered the old copy on November 3. This tool looks for the traces the loader and the agent leave on disk.";

pub const READ_ONLY: &str = "Read-only. No network access.";

pub const CAVEATS: [&str; 3] = [
    "debug.log is lost when the NIKKE folder is deleted or reinstalled. The k2f.agent.state check in the launcher data does not depend on it.",
    "Finding nothing is not proof that the computer is clean.",
    "The commands the agent ran leave no logs, so this tool cannot tell what the attacker did.",
];

pub fn headline(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Infected => "Infected",
        Verdict::Exposed => "Exposed",
        Verdict::NoTraces => "No traces found",
        Verdict::NotFound => "NIKKE not found",
    }
}

pub fn summary(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Infected => "Critical traces were found: the agent was downloaded or ran, it left persistence, or the launcher is running now. Treat this computer as compromised.",
        Verdict::Exposed => "The launcher loaded the malicious script or contacted insightjs.com, but no sign that the agent ran was found.",
        Verdict::NoTraces => "No trace of the malicious script or the agent was found in the NIKKE files this scan located.",
        Verdict::NotFound => "No NIKKE install or launcher data was found in the places this scan checked.",
    }
}

/// Lines to paste into the hosts file, for the domains it does not block yet.
pub fn block_lines(h: &HostsStatus) -> Vec<String> {
    h.domains
        .iter()
        .filter(|(_, blocked)| *blocked != Some(true))
        .map(|(d, _)| format!("0.0.0.0 {d}"))
        .collect()
}

pub fn block_state(blocked: Option<bool>) -> &'static str {
    match blocked {
        Some(true) => "blocked",
        Some(false) => "not blocked",
        None => "unknown",
    }
}

pub const BLOCK_LINES_INTRO: &str = "To block the domains that are not shown as blocked, add these lines to the hosts file:";

pub const HOSTS_NOTE: &str = "Editing the hosts file needs administrator rights. This tool never edits it.";

pub fn ip_note() -> String {
    format!(
        "The IPs {} and {} cannot be blocked in the hosts file. Block them in your firewall or router.",
        ATTACKER_IPS[0], ATTACKER_IPS[1]
    )
}

/// 1234567 to "1,234,567".
pub fn thousands(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// "1 NIKKE install, 2 Wine prefixes, ..." for the targets that were checked.
pub fn checked_summary(r: &ScanResult) -> String {
    let kinds = [
        (TargetKind::InstallDir, "NIKKE install", "NIKKE installs"),
        (TargetKind::LauncherData, "launcher data folder", "launcher data folders"),
        (TargetKind::WinePrefix, "Wine prefix", "Wine prefixes"),
        (TargetKind::UserProfile, "user profile", "user profiles"),
    ];
    let parts: Vec<String> = kinds
        .iter()
        .filter_map(|(kind, one, many)| {
            let n = r.targets.iter().filter(|t| t.kind == *kind).count();
            match n {
                0 => None,
                1 => Some(format!("1 {one}")),
                _ => Some(format!("{n} {many}")),
            }
        })
        .collect();
    if parts.is_empty() { "nothing to check".into() } else { parts.join(", ") }
}

pub fn stats_line(r: &ScanResult) -> String {
    let s = &r.stats;
    let cap = if s.cap_hit {
        " The entry limit was reached, so some folders were not visited."
    } else {
        ""
    };
    let skipped = match s.skipped_mounts.len() {
        0 => String::new(),
        1 => ", 1 network drive skipped".into(),
        n => format!(", {n} network drives skipped"),
    };
    format!(
        "{} entries visited ({} folders), {} permission errors{skipped}, {:.1} s.{cap}",
        s.entries, s.folders, s.permission_errors, r.seconds
    )
}

/// The findings of one Details section, with the location group of each.
pub fn section(r: &ScanResult, s: Section) -> Vec<(usize, usize, &Group, &Finding)> {
    let mut out: Vec<(usize, usize, &Group, &Finding)> = r
        .groups
        .iter()
        .enumerate()
        .flat_map(|(gi, g)| g.findings.iter().enumerate().map(move |(fi, f)| (gi, fi, g, f)))
        .filter(|(_, _, _, f)| Section::of(f.kind) == s)
        .collect();
    out.sort_by_key(|(_, _, _, f)| std::cmp::Reverse(f.severity));
    out
}

/// "NIKKE install: /path", the location a finding was found in.
pub fn location(g: &Group) -> String {
    match &g.path {
        Some(p) => format!("{}: {}", g.label, p.display()),
        None => g.label.clone(),
    }
}

/// The label of a finding's copy text.
pub fn copy_label(f: &Finding) -> &'static str {
    match f.kind {
        FindingKind::RegistryKey | FindingKind::RegistryLeftover => "Registry key",
        _ => "Text",
    }
}

pub fn render(r: &ScanResult) -> String {
    let mut out = String::new();
    let o = &mut out;
    let _ = writeln!(o, "{APP_NAME} {}", env!("CARGO_PKG_VERSION"));
    let _ = writeln!(o, "Scan of: {}", scope(r));
    let _ = writeln!(o, "Started: {}", r.started);
    let _ = writeln!(o);
    let _ = writeln!(o, "VERDICT: {}", headline(r.verdict).to_uppercase());
    let _ = writeln!(o, "{}", summary(r.verdict));
    let _ = writeln!(o);

    let _ = writeln!(o, "WHAT HAPPENED");
    for a in guide::answers(r) {
        let _ = writeln!(o, "  {} {}.", a.question, a.reply);
        for line in &a.lines {
            let _ = writeln!(o, "    - {line}");
        }
        if !a.runs.is_empty() {
            let _ = writeln!(o, "    Agent runs in the logs:");
            for run in &a.runs {
                let _ = writeln!(o, "      {run}");
            }
        }
    }
    for b in &r.builds {
        let _ = writeln!(o, "  Payload build: {}", guide::build_line(b));
    }
    let _ = writeln!(o);

    let _ = writeln!(o, "WHAT TO DO");
    for (i, s) in guide::steps(r).iter().enumerate() {
        let _ = writeln!(o, "  {}. {}", i + 1, s.title);
        for part in &s.parts {
            match part {
                Part::Text(t) => {
                    let _ = writeln!(o, "     {t}");
                }
                Part::Item(t) => {
                    let _ = writeln!(o, "     - {t}");
                }
                Part::Code(c) => {
                    for line in c.lines() {
                        let _ = writeln!(o, "       {line}");
                    }
                }
                // Buttons only, except a folder to open that the step does not show already.
                Part::Actions(actions) => {
                    for a in actions {
                        if let Action::Reveal(p) = a
                            && !s.parts.iter().any(|q| matches!(q, Part::Code(c) if *c == p.display().to_string()))
                        {
                            let _ = writeln!(o, "     Open: {}", p.display());
                        }
                    }
                }
            }
        }
        let _ = writeln!(o);
    }

    let _ = writeln!(o, "DETAILS");
    let _ = writeln!(o, "  Locations checked: {}", checked_summary(r));
    for t in &r.targets {
        let _ = writeln!(o, "    [{}] {}", t.kind.label(), t.path.display());
    }
    for s in Section::ALL {
        if s == Section::Info
            && let Some(e) = &r.exposure
        {
            let _ = writeln!(o, "\n  {EXPOSURE_TITLE}");
            let _ = writeln!(o, "    {EXPOSURE_NOTE}");
            if let Some(note) = guide::home_note(r) {
                let _ = writeln!(o, "    {note}");
            }
            for (heading, items) in guide::exposure_lists(e) {
                if items.is_empty() {
                    let _ = writeln!(o, "    {heading}: none found.");
                    continue;
                }
                let _ = writeln!(o, "    {heading}:");
                for (what, path) in items {
                    let _ = writeln!(o, "      {what}: {}", path.display());
                }
            }
            let _ = writeln!(o, "    Folders checked:");
            for p in &e.checked {
                let _ = writeln!(o, "      {}", p.display());
            }
        }
        let found = section(r, s);
        if found.is_empty() {
            continue;
        }
        let _ = writeln!(o, "\n  {}", s.title());
        for (_, _, g, f) in found {
            write_finding(o, g, f);
        }
    }
    if r.groups.is_empty() {
        let _ = writeln!(o, "\n  No findings.");
    }
    let _ = writeln!(o);

    if let Some(h) = &r.hosts {
        let _ = writeln!(o, "PROTECTION (hosts file: {})", h.path.display());
        let _ = writeln!(o, "  This is not an infection check. It shows whether the domains are blocked.");
        if let Some(note) = h.note {
            let _ = writeln!(o, "  {note}");
        }
        for (domain, blocked) in &h.domains {
            let _ = writeln!(o, "  {domain}: {}", block_state(*blocked));
        }
        let lines = block_lines(h);
        if !lines.is_empty() {
            let _ = writeln!(o, "  {BLOCK_LINES_INTRO}");
            for line in lines {
                let _ = writeln!(o, "    {line}");
            }
        }
        let _ = writeln!(o, "  {HOSTS_NOTE}");
        let _ = writeln!(o, "  {}", ip_note());
        let _ = writeln!(o);
    }

    let _ = writeln!(o, "LIMITS OF THIS CHECK");
    for c in CAVEATS {
        let _ = writeln!(o, "  - {c}");
    }
    let _ = writeln!(o, "  Write-up: {GIST_URL}");
    let _ = writeln!(o);
    let _ = writeln!(o, "Scan stats: {}", stats_line(r));
    out
}

fn write_finding(o: &mut String, g: &Group, f: &Finding) {
    let _ = writeln!(o, "    [{}] {}", f.severity.tag(), f.title);
    let _ = writeln!(o, "      {}", f.detail);
    let _ = writeln!(o, "      What this means: {}", guide::meaning(f.kind));
    let _ = writeln!(o, "      Found in: {}", location(g));
    if let Some(p) = &f.path {
        let _ = writeln!(o, "      Path: {}", p.display());
    }
    if let Some(p) = f.open_path.as_ref().filter(|p| f.path.as_ref() != Some(*p)) {
        let _ = writeln!(o, "      Open: {}", p.display());
    }
    if let Some(t) = &f.time {
        let _ = writeln!(o, "      Time: {t}");
    }
    for line in f.copy_text.iter().flat_map(|t| t.lines()) {
        let _ = writeln!(o, "      {}: {line}", copy_label(f));
    }
    for e in &f.evidence {
        let _ = writeln!(o, "      | {e}");
    }
}
