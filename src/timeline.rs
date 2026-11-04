//! The agent's runs, from debug.log and the tinyget logs, and the builds of
//! insight.bundle the launcher received, from the response headers in tinyget.mem.log.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

use crate::scan::{cef_time, log_time, utc};

/// The ETags of the builds of insight.bundle seen so far (nginx: hex mtime and
/// hex size, 0x3214f = 205,135 bytes), uploaded Oct 31 15:38:43, Nov 1 01:06:14,
/// Nov 1 18:08:55, Nov 2 17:48:47, Nov 2 21:48:40, Nov 3 12:31:04 and Nov 3 14:56:40 GMT.
pub const KNOWN_BUILDS: [&str; 7] = [
    "6ae60b83-3214f",
    "6ae69086-3214f",
    "6ae78037-3214f",
    "6ae8ccff-3214f",
    "6ae90538-3214f",
    "6ae9d408-3214f",
    "6ae9f628-3214f",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunKind {
    /// "lua downloaded to log\tinyget\<file>" in debug.log, or a tinyget download of insight.bundle.
    Downloaded,
    /// "adopted <id>": the first run on this computer, which created the agent ID.
    Adopted,
    /// "resuming <id>": a later run with the saved ID.
    Resumed,
    /// "agent started as <host>": the agent sent the computer name.
    Started,
}

/// One logged step of an agent run.
#[derive(Debug, Clone)]
pub struct AgentRun {
    pub kind: RunKind,
    /// As logged, with its clock: "11-03 01:47:36 (local time, year not logged)".
    pub time: Option<String>,
    /// Adopted and Resumed. Kept whole here; the report decides whether to show it.
    pub agent_id: Option<String>,
    /// Started: the computer name the agent sent.
    pub host: Option<String>,
    /// Downloaded: the file name the launcher saved the agent under.
    pub file: Option<String>,
    /// The log the line comes from.
    pub source: PathBuf,
}

/// A build of insight.bundle, from the response headers of one download.
#[derive(Debug, Clone, PartialEq)]
pub struct PayloadBuild {
    /// "6ae90538-3214f", without the quotes.
    pub etag: Option<String>,
    /// "Mon, 02 Nov 2026 21:48:40 GMT", as sent.
    pub last_modified: Option<String>,
    /// Upload time from the ETag, in UTC.
    pub uploaded: Option<String>,
    /// Size from the ETag, in bytes.
    pub size: Option<u64>,
    /// The ETag is one of [`KNOWN_BUILDS`].
    pub known: bool,
    /// When the launcher received the headers (log time).
    pub time: Option<String>,
    pub source: PathBuf,
}

const DEBUG_EVENTS: [(&str, RunKind); 4] = [
    ("\"lua downloaded to ", RunKind::Downloaded),
    ("\"adopted ", RunKind::Adopted),
    ("\"resuming ", RunKind::Resumed),
    ("\"agent started as ", RunKind::Started),
];

/// The agent step logged on a debug.log line (a CEF console message), if any.
pub fn debug_event(line: &str, source: &Path) -> Option<AgentRun> {
    let (kind, rest) = DEBUG_EVENTS
        .iter()
        .find_map(|(needle, kind)| line.split_once(needle).map(|(_, rest)| (*kind, rest)))?;
    let value = rest.split('"').next().unwrap_or_default().trim().to_string();
    let mut run = AgentRun { kind, time: cef_time(line), agent_id: None, host: None, file: None, source: source.to_path_buf() };
    match kind {
        RunKind::Downloaded => run.file = Some(base_name(&value)),
        RunKind::Adopted | RunKind::Resumed => run.agent_id = Some(value),
        RunKind::Started => run.host = Some(value),
    }
    Some(run)
}

/// The insight.bundle download on a tinyget "AddTask" line, with the file it was saved as.
pub fn tinyget_download(line: &str, source: &Path) -> Option<AgentRun> {
    if !line.contains("AddTask") || !line.contains("insight.bundle") {
        return None;
    }
    let path = line.split_once("path=")?.1.split(',').next()?.trim();
    Some(AgentRun {
        kind: RunKind::Downloaded,
        time: log_time(line),
        agent_id: None,
        host: None,
        file: Some(base_name(path)),
        source: source.to_path_buf(),
    })
}

/// The insight.bundle downloads in a tinyget log that finished. The launcher logs
/// AddTask first and OnDownloadResult later under the same task ID. A failed
/// attempt (server down, curl_error=7, result=2, total=0) is not a download.
pub fn tinyget_downloads(text: &str, source: &Path) -> Vec<AgentRun> {
    let mut out = Vec::new();
    let mut pending: HashMap<&str, AgentRun> = HashMap::new();
    for line in text.lines() {
        if let Some(run) = tinyget_download(line, source) {
            if let Some(id) = field(line, "task_id=") {
                pending.insert(id, run);
            }
        } else if line.contains("OnDownloadResult")
            && line.contains("insight.bundle")
            && let Some(run) = field(line, "task=").and_then(|id| pending.remove(id))
            && finished(line)
        {
            out.push(run);
        }
    }
    out
}

/// A line that shows an insight.bundle download completing, even when the buffer
/// of tinyget.mem.log no longer holds its AddTask line.
pub fn bundle_downloaded(text: &str) -> bool {
    text.lines().any(|l| {
        l.contains("insight.bundle") && (l.contains("curl perform success") || (l.contains("OnDownloadResult") && finished(l)))
    })
}

fn finished(line: &str) -> bool {
    field(line, "result=") == Some("0") && field(line, "total=").is_some_and(|t| t != "0")
}

/// The value after `key` in a tinyget line, up to the next separator.
fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    line.split_once(key)?.1.split([',', ' ', ';', '\t']).next()
}

fn base_name(path: &str) -> String {
    path.rsplit(['\\', '/']).next().unwrap_or(path).to_string()
}

/// The insight.bundle builds in a tinyget log. curl logs each header on its own
/// line, and downloads run on several threads at once, so headers are matched to
/// the request by the thread ID in the second bracket.
pub fn payload_builds(text: &str, source: &Path) -> Vec<PayloadBuild> {
    let mut out: Vec<PayloadBuild> = Vec::new();
    let mut open: HashMap<&str, usize> = HashMap::new();
    for line in text.lines() {
        let Some(thread) = line.split(']').nth(1).map(|t| t.trim_start_matches('[')) else {
            continue;
        };
        if let Some((_, request)) = line.split_once("Header out: GET ") {
            if request.contains("insight.bundle") {
                open.insert(thread, out.len());
                out.push(PayloadBuild {
                    etag: None,
                    last_modified: None,
                    uploaded: None,
                    size: None,
                    known: false,
                    time: log_time(line),
                    source: source.to_path_buf(),
                });
            } else {
                open.remove(thread);
            }
        } else if let Some(&i) = open.get(thread) {
            if let Some((_, v)) = line.split_once("Header in: ETag: ") {
                out[i].etag = Some(v.trim().trim_matches('"').to_string());
            } else if let Some((_, v)) = line.split_once("Header in: Last-Modified: ") {
                out[i].last_modified = Some(v.trim().to_string());
            }
        }
    }
    out.retain(|b| b.etag.is_some() || b.last_modified.is_some());
    for b in &mut out {
        let parts = b.etag.as_deref().and_then(|e| e.split_once('-'));
        b.uploaded = parts
            .and_then(|(mtime, _)| u64::from_str_radix(mtime, 16).ok())
            // The server sets the ETag, so the value can be past what SystemTime holds.
            .and_then(|s| UNIX_EPOCH.checked_add(Duration::from_secs(s)))
            .and_then(utc);
        b.size = parts.and_then(|(_, size)| u64::from_str_radix(size, 16).ok());
        b.known = b.etag.as_deref().is_some_and(|e| KNOWN_BUILDS.contains(&e));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_log_events() {
        let src = Path::new("debug.log");
        let ev = |line: &str| debug_event(line, src).unwrap();
        let d = ev(r#"[1103/014736.558:INFO:CONSOLE(1)] "lua downloaded to log\tinyget\tinyget.20261103-014735-553.log", source:  (1)"#);
        assert_eq!(d.kind, RunKind::Downloaded);
        assert_eq!(d.file.as_deref(), Some("tinyget.20261103-014735-553.log"));
        assert_eq!(d.time.as_deref(), Some("11-03 01:47:36 (local time, year not logged)"));
        let a = ev(r#"[1103/014736.623:INFO:CONSOLE(1)] "adopted 3c4c9b75-09e5-4619-99ee-97c1dc3c0373", source:  (1)"#);
        assert_eq!((a.kind, a.agent_id.as_deref()), (RunKind::Adopted, Some("3c4c9b75-09e5-4619-99ee-97c1dc3c0373")));
        let r = ev(r#"[1024/011602.100:INFO:CONSOLE(1)] "resuming 3c4c9b75-09e5-4619-99ee-97c1dc3c0373", source:  (1)"#);
        assert_eq!(r.kind, RunKind::Resumed);
        let s = ev(r#"[1103/014736.625:INFO:CONSOLE(1)] "agent started as COLONY", source:  (1)"#);
        assert_eq!((s.kind, s.host.as_deref()), (RunKind::Started, Some("COLONY")));
        let k = ev(r#"[1024/011601.000:INFO:CONSOLE(1)] "lua downloaded to log\tinyget\k2f.lua", source:  (1)"#);
        assert_eq!(k.file.as_deref(), Some("k2f.lua"));
        assert!(debug_event(r#"[1103/014735.001:INFO:CONSOLE(1)] "page loaded", source:  (1)"#, src).is_none());
        assert!(debug_event("the user adopted a cat", src).is_none());
    }

    #[test]
    fn tinyget_add_task() {
        let line = "[2026-11-03 01:47:35.556][316][ERROR][tiny_downloader.cpp(103)]tiny_downloader::TinyDownloader::AddTask\tadd task, task_id=2147483648, url=https://analytics.insightjs.com/comm/assets/insight.bundle, path=S:\\NIKKE\\Launcher\\log\\tinyget\\tinyget.20261103-014735-553.log";
        let run = tinyget_download(line, Path::new("t.log")).unwrap();
        assert_eq!(run.file.as_deref(), Some("tinyget.20261103-014735-553.log"));
        assert_eq!(run.time.as_deref(), Some("2026-11-03 01:47:35 (local time)"));
        assert!(tinyget_download("[2026-11-03 01:47:35.556][316] AddTask url=https://x/y.zip, path=C:\\y.zip", Path::new("t")).is_none());
    }

    #[test]
    fn only_finished_downloads_count() {
        let add = "[2026-11-03 01:47:35.556][316][ERROR][tiny_downloader.cpp(103)]tiny_downloader::TinyDownloader::AddTask\tadd task, task_id=2147483648, url=https://analytics.insightjs.com/comm/assets/insight.bundle, path=S:\\NIKKE\\Launcher\\log\\tinyget\\tinyget.20261103-014735-553.log";
        let ok = "[2026-11-03 01:47:36.147][1492][ERROR][download_task.cpp(519)]tiny_downloader::DownloadTask::OnDownloadResult\tOnDownloadResult, task=2147483648, result=0, error_code=0, strategy=0, total=205135, err_msg=, url=https://analytics.insightjs.com/comm/assets/insight.bundle";
        let failed = "[2026-11-03 20:41:59.613][1492][ERROR][download_task.cpp(519)]tiny_downloader::DownloadTask::OnDownloadResult\tOnDownloadResult, task=2147483648, result=2, error_code=7, strategy=0, total=0, err_msg=, url=https://analytics.insightjs.com/comm/assets/insight.bundle";
        let src = Path::new("t.log");
        assert_eq!(tinyget_downloads(&format!("{add}\n{ok}\n"), src).len(), 1);
        assert!(tinyget_downloads(&format!("{add}\n{failed}\n"), src).is_empty());
        // The second session's failure does not undo the first one's download.
        assert_eq!(tinyget_downloads(&format!("{add}\n{ok}\n{add}\n{failed}\n"), src).len(), 1);
        assert!(bundle_downloaded(ok) && !bundle_downloaded(&format!("{add}\n{failed}")));
    }

    #[test]
    fn builds_from_curl_headers() {
        let text = "\
[2026-11-03 01:47:35.891][1492][TRACE][http_curl.cpp(502)]x\t[CURL]Header out: GET /comm/assets/insight.bundle HTTP/1.1
[2026-11-03 01:47:35.900][504][TRACE][cgi_curl.cpp(657)]x\t[CURL]Header out: GET /api/other HTTP/1.1
[2026-11-03 01:47:35.950][504][TRACE][cgi_curl.cpp(657)]x\t[CURL]Header in: ETag: \"aaaa-1\"
[2026-11-03 01:47:36.013][1492][TRACE][http_curl.cpp(499)]x\t[CURL]Header in: Last-Modified: Mon, 02 Nov 2026 21:48:40 GMT
.
[2026-11-03 01:47:36.013][1492][TRACE][http_curl.cpp(499)]x\t[CURL]Header in: ETag: \"6ae90538-3214f\"
[2026-11-01 12:14:40.000][900][TRACE][http_curl.cpp(502)]x\t[CURL]Header out: GET /comm/assets/insight.bundle HTTP/1.1
[2026-11-01 12:14:40.100][900][TRACE][http_curl.cpp(499)]x\t[CURL]Header in: ETag: \"6ae00000-30000\"
";
        let builds = payload_builds(text, Path::new("tinyget.mem.log"));
        assert_eq!(builds.len(), 2, "{builds:?}");
        let b = &builds[0];
        assert_eq!(b.etag.as_deref(), Some("6ae90538-3214f"));
        assert_eq!(b.last_modified.as_deref(), Some("Mon, 02 Nov 2026 21:48:40 GMT"));
        assert_eq!(b.uploaded.as_deref(), Some("2026-11-02 21:48:40 UTC"));
        assert_eq!(b.size, Some(205_135));
        assert!(b.known);
        assert_eq!(b.time.as_deref(), Some("2026-11-03 01:47:35 (local time)"));
        assert!(!builds[1].known);
        // The attacker's server sets the ETag: a time past what SystemTime holds is dropped.
        let huge = "[2026-11-03 01:47:35.891][7][TRACE][x]x\t[CURL]Header out: GET /comm/assets/insight.bundle HTTP/1.1\n[2026-11-03 01:47:36.013][7][TRACE][x]x\t[CURL]Header in: ETag: \"ffffffffffffffff-3214f\"\n";
        let b = &payload_builds(huge, Path::new("tinyget.mem.log"))[0];
        assert_eq!((b.uploaded.as_deref(), b.size), (None, Some(205_135)));
        // Every known ETag decodes to its upload time.
        let uploaded: Vec<String> = KNOWN_BUILDS
            .iter()
            .map(|e| utc(UNIX_EPOCH + Duration::from_secs(u64::from_str_radix(&e[..8], 16).unwrap())).unwrap())
            .collect();
        assert_eq!(
            uploaded,
            [
                "2026-10-31 15:38:43 UTC",
                "2026-11-01 01:06:14 UTC",
                "2026-11-01 18:08:55 UTC",
                "2026-11-02 17:48:47 UTC",
                "2026-11-02 21:48:40 UTC",
                "2026-11-03 12:31:04 UTC",
                "2026-11-03 14:56:40 UTC"
            ]
        );
    }
}
