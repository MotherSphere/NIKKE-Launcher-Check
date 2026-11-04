//! Plain-text report (CLI output, "Copy report" and "Save report...") and the
//! texts the window shares with it.

use std::fmt::Write;

use crate::guide::{self, Action, Part, Section};
use crate::i18n::{Lang, msg, tr};
use crate::locate::TargetKind;
use crate::scan::{COMPUTER_SCOPE, Finding, FindingKind, Group, HostsStatus, ScanResult, Verdict};

pub const APP_NAME: &str = "NIKKE Launcher Check";
pub const GIST_URL: &str = "https://gist.github.com/MotherSphere/d6c049a09ba8ac3085c51ee9df24a4e5";

/// What was scanned, with "quick scan" or "full scan" for this computer.
pub fn scope(r: &ScanResult, lang: Lang) -> String {
    match (r.scope == COMPUTER_SCOPE, r.stats.depth_limit) {
        (true, Some(_)) => tr(lang, "report.scope.quick").into(),
        (true, None) => tr(lang, "report.scope.full").into(),
        _ => r.scope.clone(),
    }
}

pub fn caveats(lang: Lang) -> [&'static str; 3] {
    ["report.caveat.debug_log", "report.caveat.not_proof", "report.caveat.no_logs"].map(|k| tr(lang, k))
}

pub fn headline(verdict: Verdict, lang: Lang) -> &'static str {
    tr(
        lang,
        match verdict {
            Verdict::Infected => "verdict.infected.title",
            Verdict::Exposed => "verdict.exposed.title",
            Verdict::NoTraces => "verdict.no_traces.title",
            Verdict::NotFound => "verdict.not_found.title",
        },
    )
}

pub fn summary(verdict: Verdict, lang: Lang) -> &'static str {
    tr(
        lang,
        match verdict {
            Verdict::Infected => "verdict.infected.summary",
            Verdict::Exposed => "verdict.exposed.summary",
            Verdict::NoTraces => "verdict.no_traces.summary",
            Verdict::NotFound => "verdict.not_found.summary",
        },
    )
}

/// Lines to paste into the hosts file, for the domains it does not block yet.
pub fn block_lines(h: &HostsStatus) -> Vec<String> {
    h.domains
        .iter()
        .filter(|(_, blocked)| *blocked != Some(true))
        .map(|(d, _)| format!("0.0.0.0 {d}"))
        .collect()
}

pub fn block_state(blocked: Option<bool>, lang: Lang) -> &'static str {
    tr(
        lang,
        match blocked {
            Some(true) => "hosts.blocked",
            Some(false) => "hosts.not_blocked",
            None => "hosts.unknown",
        },
    )
}

/// 1234567 to "1,234,567".
// shortcut: comma groups in every language, use the language's separator if translators ask.
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
pub fn checked_summary(r: &ScanResult, lang: Lang) -> String {
    let kinds = [
        (TargetKind::InstallDir, "report.checked.install_one", "report.checked.install_other"),
        (TargetKind::LauncherData, "report.checked.launcher_data_one", "report.checked.launcher_data_other"),
        (TargetKind::WinePrefix, "report.checked.wine_prefix_one", "report.checked.wine_prefix_other"),
        (TargetKind::UserProfile, "report.checked.user_profile_one", "report.checked.user_profile_other"),
        (TargetKind::LoginProfile, "report.checked.login_profile_one", "report.checked.login_profile_other"),
    ];
    let parts: Vec<String> = kinds
        .iter()
        .filter_map(|(kind, one, many)| {
            let n = r.targets.iter().filter(|t| t.kind == *kind).count();
            (n > 0).then(|| msg(if n == 1 { one } else { many }).arg("n", n.to_string()).render(lang))
        })
        .collect();
    if parts.is_empty() { tr(lang, "report.checked.nothing").into() } else { parts.join(", ") }
}

pub fn stats_line(r: &ScanResult, lang: Lang) -> String {
    let s = &r.stats;
    let skipped = match s.skipped_mounts.len() {
        0 => String::new(),
        1 => tr(lang, "report.stats.skipped_one").into(),
        n => msg("report.stats.skipped_other").arg("n", n.to_string()).render(lang),
    };
    let mut line = msg("report.stats")
        .arg("entries", s.entries.to_string())
        .arg("folders", s.folders.to_string())
        .arg("errors", s.permission_errors.to_string())
        .arg("skipped", skipped)
        .arg("seconds", format!("{:.1}", r.seconds))
        .render(lang);
    if s.cap_hit {
        line.push(' ');
        line.push_str(tr(lang, "report.stats.cap"));
    }
    line
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
pub fn location(g: &Group, lang: Lang) -> String {
    match &g.path {
        Some(p) => msg("report.location").arg("label", g.label.clone()).arg("path", p.display().to_string()).render(lang),
        None => g.label.render(lang),
    }
}

/// The label of a finding's copy text.
pub fn copy_label(f: &Finding, lang: Lang) -> &'static str {
    match f.kind {
        FindingKind::RegistryKey | FindingKind::RegistryLeftover => tr(lang, "details.copy_label.registry"),
        _ => tr(lang, "details.copy_label.text"),
    }
}

pub fn render(r: &ScanResult, lang: Lang) -> String {
    let t = |key| tr(lang, key);
    let mut out = String::new();
    let o = &mut out;
    let _ = writeln!(o, "{APP_NAME} {}", env!("CARGO_PKG_VERSION"));
    let _ = writeln!(o, "{}", msg("report.scan_of").arg("scope", scope(r, lang)).render(lang));
    let _ = writeln!(o, "{}", msg("report.started").arg("time", r.started.as_str()).render(lang));
    let _ = writeln!(o);
    let _ = writeln!(o, "{}", msg("report.verdict").arg("verdict", headline(r.verdict, lang).to_uppercase()).render(lang));
    let _ = writeln!(o, "{}", summary(r.verdict, lang));
    let _ = writeln!(o);

    let _ = writeln!(o, "{}", t("report.what_happened"));
    for a in guide::answers(r, lang) {
        let _ = writeln!(o, "  {}", msg("report.answer").arg("question", a.question).arg("reply", a.reply).render(lang));
        for line in &a.lines {
            let _ = writeln!(o, "    - {line}");
        }
        if !a.runs.is_empty() {
            let _ = writeln!(o, "    {}", t("report.agent_runs"));
            for run in &a.runs {
                let _ = writeln!(o, "      {run}");
            }
        }
    }
    for b in &r.builds {
        let _ = writeln!(o, "  {}", msg("report.payload_build").arg("build", guide::build_line(b, lang)).render(lang));
    }
    let _ = writeln!(o);

    let _ = writeln!(o, "{}", t("report.what_to_do"));
    for (i, s) in guide::steps(r, lang).iter().enumerate() {
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
                            let _ = writeln!(o, "     {}", msg("report.open").arg("path", p.display().to_string()).render(lang));
                        }
                    }
                }
            }
        }
        let _ = writeln!(o);
    }

    let _ = writeln!(o, "{}", t("report.details"));
    let _ = writeln!(o, "  {}", msg("report.locations_checked").arg("summary", checked_summary(r, lang)).render(lang));
    for target in &r.targets {
        let _ = writeln!(o, "    [{}] {}", target.kind.label(lang), target.path.display());
    }
    for s in Section::ALL {
        if s == Section::Info
            && let Some(e) = &r.exposure
        {
            let _ = writeln!(o, "\n  {}", t("exposure.title"));
            let _ = writeln!(o, "    {}", t("exposure.note"));
            if let Some(note) = guide::home_note(r, lang) {
                let _ = writeln!(o, "    {note}");
            }
            for (heading, items) in guide::exposure_lists(e, lang) {
                if items.is_empty() {
                    let _ = writeln!(o, "    {}", msg("report.exposure_none").arg("heading", heading).render(lang));
                    continue;
                }
                let _ = writeln!(o, "    {}", msg("report.exposure_heading").arg("heading", heading).render(lang));
                for (what, path) in items {
                    let item = msg("report.exposure_item").arg("what", what).arg("path", path.display().to_string());
                    let _ = writeln!(o, "      {}", item.render(lang));
                }
            }
            let _ = writeln!(o, "    {}", t("report.folders_checked"));
            for p in &e.checked {
                let _ = writeln!(o, "      {}", p.display());
            }
        }
        let found = section(r, s);
        if found.is_empty() {
            continue;
        }
        let _ = writeln!(o, "\n  {}", s.title(lang));
        for (_, _, g, f) in found {
            write_finding(o, g, f, lang);
        }
    }
    if r.groups.is_empty() {
        let _ = writeln!(o, "\n  {}", t("report.no_findings"));
    }
    let _ = writeln!(o);

    if let Some(h) = &r.hosts {
        let _ = writeln!(o, "{}", msg("report.protection").arg("path", h.path.display().to_string()).render(lang));
        let _ = writeln!(o, "  {}", t("report.protection_note"));
        if let Some(note) = &h.note {
            let _ = writeln!(o, "  {}", note.render(lang));
        }
        for (domain, blocked) in &h.domains {
            let state = msg("report.domain_state").arg("domain", *domain).arg("state", block_state(*blocked, lang));
            let _ = writeln!(o, "  {}", state.render(lang));
        }
        let lines = block_lines(h);
        if !lines.is_empty() {
            let _ = writeln!(o, "  {}", t("hosts.block_lines_intro"));
            for line in lines {
                let _ = writeln!(o, "    {line}");
            }
        }
        let _ = writeln!(o, "  {}", t("hosts.note"));
        let _ = writeln!(o, "  {}", t("hosts.ip_note"));
        let _ = writeln!(o);
    }

    let _ = writeln!(o, "{}", t("report.limits"));
    for c in caveats(lang) {
        let _ = writeln!(o, "  - {c}");
    }
    let _ = writeln!(o, "  {}", msg("report.write_up").arg("url", GIST_URL).render(lang));
    let _ = writeln!(o);
    let _ = writeln!(o, "{}", msg("report.scan_stats").arg("stats", stats_line(r, lang)).render(lang));
    out
}

fn write_finding(o: &mut String, g: &Group, f: &Finding, lang: Lang) {
    let path = |key, p: &std::path::Path| msg(key).arg("path", p.display().to_string()).render(lang);
    let _ = writeln!(o, "    [{}] {}", f.severity.tag(lang), f.title.render(lang));
    let _ = writeln!(o, "      {}", f.detail.render(lang));
    let _ = writeln!(o, "      {}", msg("details.meaning").arg("text", guide::meaning(f.kind, lang)).render(lang));
    let _ = writeln!(o, "      {}", msg("details.found_in").arg("location", location(g, lang)).render(lang));
    if let Some(p) = &f.path {
        let _ = writeln!(o, "      {}", path("details.path", p));
    }
    if let Some(p) = f.open_path.as_ref().filter(|p| f.path.as_ref() != Some(*p)) {
        let _ = writeln!(o, "      {}", path("report.open", p));
    }
    if let Some(t) = &f.time {
        let _ = writeln!(o, "      {}", msg("details.time").arg("time", t.clone()).render(lang));
    }
    for line in f.copy_text.iter().flat_map(|t| t.lines()) {
        let _ = writeln!(o, "      {}", msg("details.copy").arg("label", copy_label(f, lang)).arg("text", line).render(lang));
    }
    for e in f.evidence_lines(lang) {
        let _ = writeln!(o, "      | {e}");
    }
}
