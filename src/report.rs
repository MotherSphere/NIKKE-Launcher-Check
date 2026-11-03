//! Plain-text report and the shared advice text (CLI output and "Copy report").

use std::fmt::Write;

use crate::locate::TargetKind;
use crate::scan::{DOMAINS, PAYLOAD_IP, ScanResult, Verdict};

pub const APP_NAME: &str = "NIKKE Launcher Check";
pub const GIST_URL: &str = "https://gist.github.com/MotherSphere/d6c049a09ba8ac3085c51ee9df24a4e5";

pub const ABOUT: &str = "On 2026-09-27, two files on Level Infinite's CDN were changed to load a script from insightjs.com inside the NIKKE PC launcher. From about November 2, 2026, that script downloaded a remote-access agent (insight.bundle) that can run commands, read files, take screenshots and collect browser data. This tool looks for the traces the loader and the agent leave on disk.";

pub const READ_ONLY: &str = "Read-only. No network access.";

pub const CAVEATS: [&str; 3] = [
    "The launcher rewrites debug.log each time it starts, so an infection from an earlier launch may no longer show in it.",
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

const BLOCK: &str = "Block insightjs.com, analytics.insightjs.com and insightjs.org in your hosts file (see Protection), and block the IP 89.127.233.127 in your firewall or router.";
const DO_NOT_OPEN: &str = "Do not open the NIKKE launcher until Level Infinite confirms a fix.";

/// Steps for any computer where the agent may have run.
const ACCOUNT_STEPS: [&str; 5] = [
    "From a clean device, change your passwords: the NIKKE / Level Infinite account first, then email, Discord, banking, and every password saved in your browsers.",
    "Log out of all sessions on those services. The agent can collect browser cookies, and a stolen cookie works without the password.",
    "Revoke API tokens and SSH keys that were stored on this computer.",
    "If you hold cryptocurrency, move it to a wallet with a new seed phrase created on a clean device.",
    "Linux and macOS (Proton, umu, Wine, CrossOver, Whisky): the Wine Z: drive maps to /, so the remote commands could read your whole home folder and the environment variables of the launcher process, not only the Wine prefix.",
];

pub fn advice(verdict: Verdict) -> Vec<&'static str> {
    let mut steps = match verdict {
        Verdict::Infected => vec![
            "Close the launcher now (end the process if it does not close) and disconnect this computer from the network.",
            DO_NOT_OPEN,
            BLOCK,
            "On Windows, in %LOCALAPPDATA%\\Google\\Chrome\\User Data\\PlatformExperienceHelper, delete the subfolder named with 64 hex characters that holds platform_experience_helper.dll, then delete the registry key HKCU\\Software\\Classes\\CLSID\\{E77CC89B-7401-4C04-8CED-149DB35ADD04} (and the WOW6432Node copy if the report lists one). Leave the rest alone: Chrome keeps its own platform_experience_helper.exe in that folder, and the HKLM copy of the CLSID points to wpc.dll, which is part of Windows.",
            "Reinstalling Windows is the safest way to be sure the computer is clean, because the agent could run any command.",
        ],
        Verdict::Exposed => vec![
            DO_NOT_OPEN,
            BLOCK,
            "The agent was served from about November 2, 2026. If the launcher was open on or after that date, treat this computer as infected and follow these steps:",
        ],
        Verdict::NoTraces => vec![
            DO_NOT_OPEN,
            BLOCK,
            "If the launcher was open on or after November 2, 2026, change your NIKKE / Level Infinite password from a clean device anyway.",
        ],
        Verdict::NotFound => vec![
            "If NIKKE is installed somewhere unusual, scan that folder: \"Scan a folder...\" in the window, or nikke-check --cli <folder>.",
            DO_NOT_OPEN,
            BLOCK,
        ],
    };
    if matches!(verdict, Verdict::Infected | Verdict::Exposed) {
        steps.extend(ACCOUNT_STEPS);
    }
    steps
}

/// Lines to paste into the hosts file.
pub fn block_lines() -> Vec<String> {
    DOMAINS.iter().map(|d| format!("0.0.0.0 {d}")).collect()
}

pub const HOSTS_NOTE: &str = "Editing the hosts file needs administrator rights. This tool never edits it.";

pub fn ip_note() -> String {
    format!("The IP {PAYLOAD_IP} cannot be blocked in the hosts file. Block it in your firewall or router.")
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

pub fn render(r: &ScanResult) -> String {
    let mut out = String::new();
    let o = &mut out;
    let _ = writeln!(o, "{APP_NAME} {}", env!("CARGO_PKG_VERSION"));
    let _ = writeln!(o, "Scan of: {}", r.scope);
    let _ = writeln!(o, "Started: {}", r.started);
    let _ = writeln!(o);
    let _ = writeln!(o, "VERDICT: {}", headline(r.verdict).to_uppercase());
    let _ = writeln!(o, "{}", summary(r.verdict));
    let _ = writeln!(o);

    let _ = writeln!(o, "Locations checked: {}", checked_summary(r));
    for t in &r.targets {
        let _ = writeln!(o, "  [{}] {}", t.kind.label(), t.path.display());
    }
    let _ = writeln!(o);

    let _ = writeln!(o, "FINDINGS");
    if r.groups.is_empty() {
        let _ = writeln!(o, "  None.");
    }
    for g in &r.groups {
        match &g.path {
            Some(p) => {
                let _ = writeln!(o, "\n{}: {}", g.label, p.display());
            }
            None => {
                let _ = writeln!(o, "\n{}", g.label);
            }
        }
        for f in &g.findings {
            let _ = writeln!(o, "  [{}] {}", f.severity.tag(), f.title);
            let _ = writeln!(o, "    {}", f.detail);
            if let Some(p) = &f.path {
                let _ = writeln!(o, "    Path: {}", p.display());
            }
            if let Some(t) = &f.time {
                let _ = writeln!(o, "    Time: {t}");
            }
            for e in &f.evidence {
                let _ = writeln!(o, "    | {e}");
            }
        }
    }
    let _ = writeln!(o);

    if let Some(h) = &r.hosts {
        let _ = writeln!(o, "PROTECTION (hosts file: {})", h.path.display());
        let _ = writeln!(o, "  This is not an infection check. It shows whether the domains are blocked.");
        if !h.readable {
            let _ = writeln!(o, "  The hosts file could not be read.");
        }
        for (domain, blocked) in &h.domains {
            let _ = writeln!(o, "  {domain}: {}", if *blocked { "blocked" } else { "not blocked" });
        }
        if h.domains.iter().any(|(_, blocked)| !blocked) {
            let _ = writeln!(o, "  To block them, add these lines to the hosts file:");
            for line in block_lines() {
                let _ = writeln!(o, "    {line}");
            }
        }
        let _ = writeln!(o, "  {HOSTS_NOTE}");
        let _ = writeln!(o, "  {}", ip_note());
        let _ = writeln!(o);
    }

    let _ = writeln!(o, "WHAT TO DO");
    for a in advice(r.verdict) {
        let _ = writeln!(o, "  - {a}");
    }
    let _ = writeln!(o);
    let _ = writeln!(o, "LIMITS OF THIS CHECK");
    for c in CAVEATS {
        let _ = writeln!(o, "  - {c}");
    }
    let _ = writeln!(o, "  Details: {GIST_URL}");
    let _ = writeln!(o);
    let _ = writeln!(o, "Scan stats: {}", stats_line(r));
    out
}
