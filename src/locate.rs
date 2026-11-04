//! Finds NIKKE installs, launcher data folders, user profiles and Wine
//! prefixes on disk. Never follows symlinks while walking: Wine prefixes link
//! `dosdevices/z:` to `/`, which would turn a walk into a loop.

use std::collections::HashSet;
use std::ffi::OsStr;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::time::{Duration, Instant};

/// Safety stop for one scan. Full-scan walks have no depth limit; a full disk stays far below this.
pub const ENTRY_CAP: u64 = 50_000_000;

/// How many folder levels below each drive root (or `/`) the quick computer scan
/// opens. `D:\Games\Level Infinite\NIKKE\Launcher` is level 4. Wine prefixes, launcher
/// data and the install paths the launcher records are read whatever their depth.
pub const QUICK_DEPTH: usize = 5;

/// What a running scan does now, in the order the stages run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Stage {
    Searching,
    Programs,
    Locations,
    Hosts,
    Done,
}

/// Live state of a running scan, shared with the window. The scan thread writes
/// it and the window reads it on each frame. Relaxed ordering is enough: every
/// value is shown on its own, and nothing else is published through them.
#[derive(Debug, Default)]
pub struct Progress {
    stage: AtomicU8,
    pub entries: AtomicU64,
    pub folders: AtomicU64,
    /// Locations found so far, indexed by `TargetKind as usize`.
    pub found: [AtomicUsize; 4],
    pub checks_done: AtomicUsize,
    pub checks_total: AtomicUsize,
    /// Findings so far, indexed by `Severity as usize` (info, warning, critical).
    pub findings: [AtomicUsize; 3],
    /// The folder walked or the location checked now.
    pub folder: Mutex<PathBuf>,
    cancel: AtomicBool,
}

impl Progress {
    pub fn stage(&self) -> Stage {
        match self.stage.load(Relaxed) {
            0 => Stage::Searching,
            1 => Stage::Programs,
            2 => Stage::Locations,
            3 => Stage::Hosts,
            _ => Stage::Done,
        }
    }

    pub fn set_stage(&self, stage: Stage) {
        self.stage.store(stage as u8, Relaxed);
        self.show(Path::new(""));
    }

    pub fn show(&self, folder: &Path) {
        if let Ok(mut shown) = self.folder.lock() {
            folder.clone_into(&mut shown);
        }
    }

    pub fn cancel(&self) {
        self.cancel.store(true, Relaxed);
    }

    pub fn cancelled(&self) -> bool {
        self.cancel.load(Relaxed)
    }
}

/// Launcher data folder names under `AppData/Roaming`.
pub const LAUNCHER_DATA_NAMES: [&str; 2] = ["nikke_launcher", "nikke_launcher_hmt"];

/// Folder names never entered by a discovery walk.
const SKIP_NAMES: [&str; 8] = [
    "node_modules",
    ".git",
    ".cache",
    "$Recycle.Bin",
    "System Volume Information",
    "dosdevices",
    // macOS Time Machine copies of the whole disk.
    ".timemachine",
    "Backups.backupdb",
];

/// Profile folders under `Users` that belong to no real user.
const NOT_USERS: [&str; 4] = ["Public", "Default", "Default User", "All Users"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TargetKind {
    InstallDir,
    LauncherData,
    WinePrefix,
    UserProfile,
}

impl TargetKind {
    pub fn label(self) -> &'static str {
        match self {
            TargetKind::InstallDir => "NIKKE install",
            TargetKind::LauncherData => "Launcher data",
            TargetKind::WinePrefix => "Wine prefix",
            TargetKind::UserProfile => "User profile",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Target {
    pub kind: TargetKind,
    pub path: PathBuf,
    /// The Windows profile of the user running this tool (not a Wine user).
    pub host: bool,
}

#[derive(Debug, Clone, Default)]
pub struct WalkStats {
    pub roots: Vec<PathBuf>,
    pub entries: u64,
    pub folders: u64,
    pub permission_errors: u64,
    pub cap_hit: bool,
    /// Search roots and known locations (prefix folders, bottles) that could not be listed.
    pub unreadable: Vec<PathBuf>,
    /// Network drives and remote mounts left out of a computer scan.
    pub skipped_mounts: Vec<PathBuf>,
    /// Quick computer scan: the deepest folder level it opened below each search root.
    pub depth_limit: Option<usize>,
}

#[derive(Debug, Clone, Default)]
pub struct Discovery {
    pub targets: Vec<Target>,
    pub stats: WalkStats,
}

/// Searches the usual places on this computer. The quick scan opens the search
/// roots only [`QUICK_DEPTH`] levels deep; the full scan opens every folder.
pub fn discover_computer(full: bool, progress: &Progress) -> Discovery {
    let mut finder = Finder::new(ENTRY_CAP, progress);
    finder.stats.depth_limit = (!full).then_some(QUICK_DEPTH);
    plan_computer(&mut finder);
    finder.finish()
}

/// Searches the given folders only (GUI "Scan a folder...", CLI paths).
pub fn discover_folders(paths: &[PathBuf], progress: &Progress) -> Discovery {
    discover_folders_with_cap(paths, ENTRY_CAP, progress)
}

pub fn discover_folders_with_cap(paths: &[PathBuf], cap: u64, progress: &Progress) -> Discovery {
    let mut finder = Finder::new(cap, progress);
    // A scan of the user's own profile, or of a folder above it, also gets the host-only checks.
    #[cfg(windows)]
    if let Some(profile) = std::env::var_os("USERPROFILE").map(PathBuf::from) {
        let canon = |p: &Path| fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
        let own = canon(&profile);
        if paths.iter().any(|p| own.starts_with(canon(p))) {
            finder.add(TargetKind::UserProfile, &profile, true);
        }
    }
    for path in paths {
        finder.root(path);
    }
    finder.finish()
}

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Generic,
    /// Walking a prefix's drive_c: the root itself is not a new prefix and
    /// drive_c/windows is skipped.
    DriveC,
}

struct Finder<'p> {
    cap: u64,
    /// Mount points a walk never opens (network and remote filesystems).
    skip_mounts: HashSet<PathBuf>,
    stats: WalkStats,
    seen: HashSet<(TargetKind, PathBuf)>,
    targets: Vec<Target>,
    pending_prefixes: Vec<PathBuf>,
    /// Quick scan: roots that get their own walk, so the other walks do not enter them.
    separate_roots: HashSet<PathBuf>,
    progress: &'p Progress,
    /// When the folder shown in the window last changed.
    shown_at: Instant,
}

impl<'p> Finder<'p> {
    fn new(cap: u64, progress: &'p Progress) -> Self {
        Self {
            cap,
            skip_mounts: HashSet::new(),
            stats: WalkStats::default(),
            seen: HashSet::new(),
            targets: Vec::new(),
            pending_prefixes: Vec::new(),
            separate_roots: HashSet::new(),
            progress,
            shown_at: Instant::now(),
        }
    }

    fn add(&mut self, kind: TargetKind, path: &Path, host: bool) {
        let key = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        if !self.seen.insert((kind, key)) {
            return;
        }
        self.progress.found[kind as usize].fetch_add(1, Relaxed);
        if kind == TargetKind::WinePrefix {
            self.pending_prefixes.push(path.to_path_buf());
        }
        self.targets.push(Target { kind, path: path.to_path_buf(), host });
    }

    /// Walks a top-level search root if it exists.
    fn root(&mut self, path: &Path) {
        if path.is_dir() {
            self.stats.roots.push(path.to_path_buf());
            self.walk(path, Mode::Generic, self.stats.depth_limit);
        }
    }

    fn note_denied(&mut self, path: &Path, err: &io::Error) {
        if err.kind() == io::ErrorKind::PermissionDenied && !self.stats.unreadable.iter().any(|p| p == path) {
            self.stats.unreadable.push(path.to_path_buf());
        }
    }

    #[cfg(unix)]
    fn prefix_candidate(&mut self, path: &Path) {
        match fs::metadata(path.join("drive_c")) {
            Ok(meta) if meta.is_dir() => self.add(TargetKind::WinePrefix, path, false),
            Ok(_) => {}
            Err(err) => self.note_denied(path, &err),
        }
    }

    /// Subfolders of `dir` that are not network mounts, without opening or stating
    /// them (the directory entry type is enough), and without following links.
    #[cfg(all(unix, not(target_os = "macos")))]
    fn local_subdirs(&mut self, dir: &Path) -> Vec<PathBuf> {
        let Ok(entries) = fs::read_dir(dir) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if self.skip_mounts.contains(&path) {
                if !self.stats.skipped_mounts.contains(&path) {
                    self.stats.skipped_mounts.push(path);
                }
            } else if entry.file_type().is_ok_and(|t| t.is_dir()) && !skip_dir(&path, &entry.file_name()) {
                out.push(path);
            }
        }
        out
    }

    /// Subfolders of `dir` (symlinks to folders included).
    #[cfg(unix)]
    fn children(&mut self, dir: &Path) -> Vec<PathBuf> {
        match fs::read_dir(dir) {
            Ok(entries) => entries.flatten().map(|e| e.path()).filter(|p| p.is_dir()).collect(),
            Err(err) => {
                self.note_denied(dir, &err);
                Vec::new()
            }
        }
    }

    /// Counts one entry. False once the entry cap is reached or the scan is cancelled.
    fn count(&mut self, is_dir: bool) -> bool {
        if self.progress.cancelled() {
            return false;
        }
        if self.stats.entries >= self.cap {
            self.stats.cap_hit = true;
            return false;
        }
        self.stats.entries += 1;
        self.stats.folders += u64::from(is_dir);
        // Batched so the hot loop does not write a shared cache line on every entry.
        if self.stats.entries.is_multiple_of(64) {
            self.publish();
        }
        true
    }

    fn publish(&self) {
        self.progress.entries.store(self.stats.entries, Relaxed);
        self.progress.folders.store(self.stats.folders, Relaxed);
    }

    /// Shows `dir` in the window, at most every 50 ms.
    fn walking(&mut self, dir: &Path) {
        if self.shown_at.elapsed() >= Duration::from_millis(50) {
            self.shown_at = Instant::now();
            self.progress.show(dir);
        }
    }

    /// A plain stack walk rather than walkdir: walkdir opens a folder before the
    /// caller can skip it, and opening a dead network mount can block forever.
    /// `limit` is the deepest folder level opened below `root`; deeper folders are
    /// still checked by name (a prefix's drive_c, launcher data) but not entered.
    fn walk(&mut self, root: &Path, mode: Mode, limit: Option<usize>) {
        if !self.count(true) {
            return;
        }
        let drive_root = root.parent().is_none();
        if !self.visit_dir(root, 0, mode, drive_root) {
            return;
        }
        let mut stack = vec![(root.to_path_buf(), 0)];
        while let Some((dir, depth)) = stack.pop() {
            self.walking(&dir);
            let entries = match fs::read_dir(&dir) {
                Ok(entries) => entries,
                Err(err) => {
                    if err.kind() == io::ErrorKind::PermissionDenied {
                        self.stats.permission_errors += 1;
                        if depth == 0 {
                            self.note_denied(&dir, &err);
                        }
                    }
                    continue;
                }
            };
            for entry in entries.flatten() {
                let path = entry.path();
                // Checked before anything touches the mount itself.
                if self.skip_mounts.contains(&path) {
                    if !self.stats.skipped_mounts.contains(&path) {
                        self.stats.skipped_mounts.push(path);
                    }
                    continue;
                }
                if self.separate_roots.contains(&path) {
                    continue;
                }
                let Ok(file_type) = entry.file_type() else {
                    continue;
                };
                if !self.count(file_type.is_dir()) {
                    return;
                }
                if file_type.is_dir() {
                    if self.visit_dir(&path, depth + 1, mode, drive_root) && limit.is_none_or(|l| depth < l) {
                        stack.push((path, depth + 1));
                    }
                } else if file_type.is_file()
                    && let Some(install) = install_dir_for_file(&path)
                {
                    self.add(TargetKind::InstallDir, &install, false);
                }
            }
        }
    }

    /// Registers what `dir` is. False when the walk must not enter it.
    fn visit_dir(&mut self, dir: &Path, depth: usize, mode: Mode, drive_root: bool) -> bool {
        let Some(name) = dir.file_name() else {
            return true;
        };
        let windows_dir = depth == 1 && eq(name, "windows");
        if depth > 0 && (skip_dir(dir, name) || (windows_dir && (mode == Mode::DriveC || drive_root))) {
            return false;
        }
        if eq(name, "drive_c") && !(mode == Mode::DriveC && depth == 0) {
            // The prefix logic walks drive_c itself.
            if let Some(prefix) = dir.parent() {
                self.add(TargetKind::WinePrefix, prefix, false);
            }
            return false;
        }
        if is_launcher_data(dir) {
            self.add(TargetKind::LauncherData, dir, false);
            self.add_installs_from_reg(&dir.join("url_protocol.reg"), None);
            return false;
        }
        // A Windows profile (Users/<name>, or a Wine user) is the folder that holds AppData.
        if eq(name, "AppData")
            && let Some(profile) = dir.parent()
            && profile.file_name().is_some_and(|n| !NOT_USERS.iter().any(|u| eq(n, u)))
            && (find_ci(dir, &["Local"]).is_some() || find_ci(dir, &["Roaming"]).is_some())
        {
            self.add(TargetKind::UserProfile, profile, false);
        }
        true
    }

    fn scan_prefix(&mut self, prefix: &Path) {
        let Some(drive_c) = find_ci(prefix, &["drive_c"]) else {
            return;
        };
        // user.reg is HKCU, where the launcher records its install path.
        let mut reg_files: Vec<PathBuf> = find_ci(prefix, &["user.reg"]).into_iter().collect();
        if let Some(users) = find_ci(&drive_c, &["users"])
            && let Ok(entries) = fs::read_dir(&users)
        {
            for entry in entries.flatten() {
                // A symlinked user (Proton links <login> to steamuser) is the same profile.
                let is_dir = entry.file_type().is_ok_and(|t| t.is_dir());
                if !is_dir || eq(&entry.file_name(), "Public") {
                    continue;
                }
                let user = entry.path();
                self.add(TargetKind::UserProfile, &user, false);
                for name in LAUNCHER_DATA_NAMES {
                    if let Some(data) = find_ci(&user, &["AppData", "Roaming", name])
                        && data.is_dir()
                    {
                        self.add(TargetKind::LauncherData, &data, false);
                        reg_files.extend(find_ci(&data, &["url_protocol.reg"]));
                    }
                }
            }
        }
        self.walk(&drive_c, Mode::DriveC, None);
        // Installs often hold their own prefix (NIKKE/prefix next to NIKKE/Launcher).
        if let Some(parent) = prefix.parent()
            && is_install_dir(parent)
        {
            self.add(TargetKind::InstallDir, parent, false);
        }
        // The registry names the install even when no walk reaches it.
        for file in reg_files {
            self.add_installs_from_reg(&file, Some(prefix));
        }
    }

    /// Adds the installs named in a .reg file. Inside a Wine prefix the drive
    /// letters go through its dosdevices links; otherwise the paths are only
    /// usable on a Windows host.
    fn add_installs_from_reg(&mut self, file: &Path, prefix: Option<&Path>) {
        if prefix.is_none() && !cfg!(windows) {
            return;
        }
        let Ok(bytes) = fs::read(file) else {
            return;
        };
        for dir in install_dirs_in_reg(&reg_text(&bytes)) {
            let path = match prefix {
                Some(prefix) => wine_path(prefix, &dir),
                None => Some(PathBuf::from(&dir)),
            };
            if let Some(path) = path {
                self.add_install(&path);
            }
        }
    }

    /// Adds `path` as an install if it is one. Registry paths can be stale.
    fn add_install(&mut self, path: &Path) {
        if is_install_dir(path) {
            self.add(TargetKind::InstallDir, path, false);
        }
    }

    fn finish(mut self) -> Discovery {
        while !self.progress.cancelled()
            && let Some(prefix) = self.pending_prefixes.pop()
        {
            self.scan_prefix(&prefix);
        }
        self.publish();
        self.targets.sort_by(|a, b| (a.kind, &a.path).cmp(&(b.kind, &b.path)));
        Discovery { targets: self.targets, stats: self.stats }
    }
}

fn eq(name: &OsStr, expected: &str) -> bool {
    name.to_string_lossy().eq_ignore_ascii_case(expected)
}

fn name_is(path: Option<&Path>, expected: &str) -> bool {
    path.and_then(Path::file_name).is_some_and(|n| eq(n, expected))
}

fn skip_dir(path: &Path, name: &OsStr) -> bool {
    let name = name.to_string_lossy();
    if SKIP_NAMES.iter().any(|s| name.eq_ignore_ascii_case(s)) || name.starts_with(".Trash") {
        return true;
    }
    if path.parent() == Some(Path::new("/")) && matches!(&*name, "proc" | "sys" | "dev") {
        return true;
    }
    // The sealed system volume; its Volumes/Data firmlinks would walk the whole disk twice.
    if cfg!(target_os = "macos") && path == Path::new("/System") {
        return true;
    }
    // FUSE mounts (gvfs, document portal) live here and can hang a walk.
    path == Path::new("/run/user")
}

fn is_launcher_data(path: &Path) -> bool {
    let named = path
        .file_name()
        .is_some_and(|n| LAUNCHER_DATA_NAMES.iter().any(|d| eq(n, d)));
    named && name_is(path.parent(), "Roaming")
}

/// `<install>/Launcher/nikke_launcher.exe` or `<install>/Launcher/intl_service/debug.log`.
fn install_dir_for_file(path: &Path) -> Option<PathBuf> {
    let name = path.file_name()?;
    let parent = path.parent()?;
    if eq(name, "nikke_launcher.exe") && name_is(Some(parent), "Launcher") {
        return parent.parent().map(Path::to_path_buf);
    }
    if eq(name, "debug.log") && name_is(Some(parent), "intl_service") {
        let launcher = parent.parent()?;
        if name_is(Some(launcher), "Launcher") {
            return launcher.parent().map(Path::to_path_buf);
        }
    }
    None
}

pub fn is_install_dir(dir: &Path) -> bool {
    let Some(launcher) = find_ci(dir, &["Launcher"]) else {
        return false;
    };
    find_ci(&launcher, &["nikke_launcher.exe"]).is_some()
        || find_ci(&launcher, &["intl_service", "debug.log"]).is_some()
}

/// Joins `parts` onto `base`, matching each part case-insensitively.
pub fn find_ci(base: &Path, parts: &[&str]) -> Option<PathBuf> {
    let mut current = base.to_path_buf();
    for part in parts {
        let exact = current.join(part);
        current = if exact.symlink_metadata().is_ok() {
            exact
        } else {
            fs::read_dir(&current)
                .ok()?
                .flatten()
                .find(|e| eq(&e.file_name(), part))?
                .path()
        };
    }
    Some(current)
}

/// Text of a .reg file: regedit writes UTF-16LE with a BOM, Wine writes UTF-8.
fn reg_text(bytes: &[u8]) -> String {
    match bytes.strip_prefix(&[0xFF, 0xFE]) {
        Some(rest) => {
            let units: Vec<u16> = rest.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
            String::from_utf16_lossy(&units)
        }
        None => String::from_utf8_lossy(bytes).into_owned(),
    }
}

/// Install folders (Windows paths) named in .reg text: the launcher writes
/// `X:\...\Launcher\nikke_launcher.exe` into App Paths, its Uninstall key and
/// the nikkelauncher URL protocol.
fn install_dirs_in_reg(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    // regedit exports can end lines with CR only.
    for line in text.split(['\r', '\n']) {
        // .reg values escape backslashes and quotes.
        let mut value = String::with_capacity(line.len());
        let mut chars = line.chars();
        while let Some(c) = chars.next() {
            value.push(if c == '\\' { chars.next().unwrap_or(c) } else { c });
        }
        if let Some(dir) = install_dir_in_value(&value)
            && !out.contains(&dir)
        {
            out.push(dir);
        }
    }
    out
}

/// `"C:\Games\NIKKE\Launcher\nikke_launcher.exe" "%1"` to `C:\Games\NIKKE`.
fn install_dir_in_value(value: &str) -> Option<String> {
    // ASCII lowercasing keeps byte offsets, so they index `value` too.
    let lower = value.to_ascii_lowercase();
    let end = lower.find("\\launcher\\nikke_launcher.exe")?;
    let start = lower[..end].rfind(":\\")?.checked_sub(1)?;
    lower.as_bytes()[start]
        .is_ascii_alphabetic()
        .then(|| value[start..end].to_string())
}

/// Host path of a Windows path inside a Wine prefix, through `dosdevices/<letter>:`.
fn wine_path(prefix: &Path, win: &str) -> Option<PathBuf> {
    let (drive, rest) = win.split_once(":\\")?;
    if drive.len() != 1 || !drive.as_bytes()[0].is_ascii_alphabetic() {
        return None;
    }
    let device = prefix.join("dosdevices").join(format!("{}:", drive.to_ascii_lowercase()));
    let parts: Vec<&str> = rest.split('\\').filter(|p| !p.is_empty()).collect();
    // The OS resolves the drive link; canonical form keeps dosdevices out of the report.
    find_ci(&device, &parts).map(|p| fs::canonicalize(&p).unwrap_or(p))
}

/// Library paths from Steam's libraryfolders.vdf (`"path"  "/x/y"` lines).
#[cfg(any(test, all(unix, not(target_os = "macos"))))]
pub fn vdf_library_paths(text: &str) -> Vec<PathBuf> {
    text.lines()
        .filter_map(|line| {
            let rest = line.trim().strip_prefix("\"path\"")?;
            let value = rest.trim().strip_prefix('"')?.strip_suffix('"')?;
            Some(PathBuf::from(value.replace("\\\\", "\\")))
        })
        .collect()
}

#[cfg(unix)]
fn home() -> Option<PathBuf> {
    std::env::var_os("HOME").filter(|h| !h.is_empty()).map(PathBuf::from)
}

/// The home folder of the user who started the tool, also under sudo or pkexec.
#[cfg(all(unix, not(target_os = "macos")))]
pub fn real_home() -> Option<PathBuf> {
    real_user().0
}

#[cfg(target_os = "macos")]
pub fn real_home() -> Option<PathBuf> {
    home()
}

/// None on Windows, where the user's profile is a scan target already.
#[cfg(windows)]
pub fn real_home() -> Option<PathBuf> {
    None
}

/// A string value of a registry key (`None` name: the default value). The outer
/// `None` means the key does not exist. `view` is 0, KEY_WOW64_64KEY or KEY_WOW64_32KEY.
#[cfg(windows)]
pub(crate) fn reg_string(
    root: windows_sys::Win32::System::Registry::HKEY,
    subkey: &str,
    name: Option<&str>,
    view: u32,
) -> Option<Option<String>> {
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::System::Registry::{
        HKEY, KEY_QUERY_VALUE, RRF_NOEXPAND, RRF_RT_REG_EXPAND_SZ, RRF_RT_REG_SZ, RegCloseKey, RegGetValueW,
        RegOpenKeyExW,
    };
    let wide = |s: &str| s.encode_utf16().chain([0]).collect::<Vec<u16>>();
    let subkey = wide(subkey);
    let name = name.map(wide);
    let name_ptr = name.as_ref().map_or(null(), |n| n.as_ptr());
    let flags = RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | RRF_NOEXPAND;
    let mut key: HKEY = null_mut();
    // SAFETY: NUL-terminated UTF-16 strings and out pointers to live locals. The
    // buffer is `size` bytes long, and the key is closed before returning.
    unsafe {
        if RegOpenKeyExW(root, subkey.as_ptr(), 0, KEY_QUERY_VALUE | view, &mut key) != ERROR_SUCCESS {
            return None;
        }
        let mut value = None;
        let mut size = 0u32;
        if RegGetValueW(key, null(), name_ptr, flags, null_mut(), null_mut(), &mut size) == ERROR_SUCCESS {
            let mut buf = vec![0u16; (size as usize).div_ceil(2)];
            if RegGetValueW(key, null(), name_ptr, flags, null_mut(), buf.as_mut_ptr().cast(), &mut size) == ERROR_SUCCESS {
                let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
                value = Some(String::from_utf16_lossy(&buf[..len]));
            }
        }
        RegCloseKey(key);
        Some(value)
    }
}

#[cfg(windows)]
fn plan_computer(f: &mut Finder<'_>) {
    use std::env;
    use windows_sys::Win32::Storage::FileSystem::GetDriveTypeW;
    use windows_sys::Win32::System::Registry::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_WOW64_32KEY, KEY_WOW64_64KEY};
    use windows_sys::Win32::System::WindowsProgramming::{DRIVE_FIXED, DRIVE_REMOTE, DRIVE_REMOVABLE};
    if let Some(profile) = env::var_os("USERPROFILE") {
        f.add(TargetKind::UserProfile, Path::new(&profile), true);
    }
    if let Some(appdata) = env::var_os("APPDATA") {
        for name in LAUNCHER_DATA_NAMES {
            let data = Path::new(&appdata).join(name);
            if data.is_dir() {
                f.add(TargetKind::LauncherData, &data, true);
                f.add_installs_from_reg(&data.join("url_protocol.reg"), None);
            }
        }
    }
    // The launcher records where it is installed, which also covers network drives the walk leaves out.
    let icon = reg_string(HKEY_CURRENT_USER, "Software\\Classes\\nikkelauncher\\DefaultIcon", None, 0);
    if let Some(dir) = icon.flatten().as_deref().and_then(install_dir_in_value) {
        f.add_install(Path::new(&dir));
    }
    let uninstall = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\nikke_launcher";
    for (root, view) in [(HKEY_CURRENT_USER, 0), (HKEY_LOCAL_MACHINE, KEY_WOW64_64KEY), (HKEY_LOCAL_MACHINE, KEY_WOW64_32KEY)] {
        if let Some(Some(dir)) = reg_string(root, uninstall, Some("GameInstallPath"), view) {
            f.add_install(Path::new(&dir));
        }
    }
    for letter in b'A'..=b'Z' {
        let drive = format!("{}:\\", letter as char);
        let wide: Vec<u16> = drive.encode_utf16().chain([0]).collect();
        // SAFETY: NUL-terminated root path. GetDriveTypeW does not contact network servers.
        let kind = unsafe { GetDriveTypeW(wide.as_ptr()) };
        match kind {
            DRIVE_FIXED | DRIVE_REMOVABLE => f.root(Path::new(&drive)),
            DRIVE_REMOTE => f.stats.skipped_mounts.push(PathBuf::from(&drive)),
            _ => {}
        }
    }
}

/// Mount points of filesystems that are not local, from the kernel's cached
/// mount table (MNT_NOWAIT never asks a server, so a dead share cannot block it).
#[cfg(target_os = "macos")]
fn non_local_mounts() -> HashSet<PathBuf> {
    use std::ffi::CStr;
    use std::os::unix::ffi::OsStrExt;
    // SAFETY: the first call only counts mounts. The second writes at most `size`
    // bytes into `buf`, and set_len keeps only the entries it reports as filled.
    unsafe {
        let n = libc::getfsstat(std::ptr::null_mut(), 0, libc::MNT_NOWAIT);
        if n <= 0 {
            return HashSet::new();
        }
        let mut buf: Vec<libc::statfs> = Vec::with_capacity(n as usize);
        let size = (buf.capacity() * std::mem::size_of::<libc::statfs>()) as libc::c_int;
        let got = libc::getfsstat(buf.as_mut_ptr(), size, libc::MNT_NOWAIT);
        buf.set_len(got.clamp(0, n) as usize);
        buf.iter()
            .filter(|m| m.f_flags & libc::MNT_LOCAL as u32 == 0)
            .map(|m| PathBuf::from(OsStr::from_bytes(CStr::from_ptr(m.f_mntonname.as_ptr()).to_bytes())))
            .collect()
    }
}

#[cfg(target_os = "macos")]
fn plan_computer(f: &mut Finder<'_>) {
    let home = home();
    // A network home folder is still scanned.
    f.skip_mounts = non_local_mounts()
        .into_iter()
        .filter(|m| !home.as_ref().is_some_and(|h| h.starts_with(m)))
        .collect();
    // The whole disk, local volumes in /Volumes included. "Macintosh HD" there is a
    // symlink to /, and walks never follow links.
    f.root(Path::new("/"));
    let mut candidates = Vec::new();
    let mut folders = vec![PathBuf::from("/Applications")];
    if let Some(home) = &home {
        candidates.push(home.join(".wine"));
        candidates.extend(f.children(&home.join("Library/Application Support/CrossOver/Bottles")));
        candidates.extend(f.children(&home.join("Library/Containers/com.isaacmarovitz.Whisky/Bottles")));
        candidates.extend(f.children(&home.join("Games/Heroic/Prefixes")));
        candidates.extend(f.children(&home.join("Games/Heroic/Prefixes/default")));
        folders.push(home.join("Applications"));
    }
    // Wineskin, Kegworks and Sikarugir wrappers keep the prefix inside the .app
    // bundle. Their Winery saves new wrappers one folder down, in
    // ~/Applications/Wineskin (or Kegworks, Sikarugir).
    let is_app = |p: &Path| p.extension().is_some_and(|e| e == "app");
    let mut apps = Vec::new();
    for folder in folders {
        for child in f.children(&folder) {
            if is_app(&child) {
                apps.push(child);
            } else {
                apps.extend(f.children(&child).into_iter().filter(|p| is_app(p)));
            }
        }
    }
    for app in apps {
        candidates.push(app.join("Contents/SharedSupport/prefix"));
    }
    for candidate in candidates {
        f.prefix_candidate(&candidate);
    }
}

/// Kernel filesystems whose data lives on another machine.
#[cfg(any(test, all(unix, not(target_os = "macos"))))]
fn is_network_fs(fstype: &str) -> bool {
    const NETWORK: [&str; 13] = [
        "nfs", "nfs4", "cifs", "smb3", "smbfs", "ncpfs", "afs", "ceph", "glusterfs", "lustre", "9p", "davfs", "sshfs",
    ];
    // FUSE filesystems that keep their data on local disks. Any other fuse.* type
    // (sshfs, rclone, s3fs, MTP phones...) is treated as remote.
    const LOCAL_FUSE: [&str; 10] = [
        "mergerfs", "bindfs", "gocryptfs", "encfs", "cryfs", "ntfs-3g", "fuse-overlayfs", "squashfuse", "lxcfs", "unionfs",
    ];
    NETWORK.contains(&fstype)
        || fstype == "fuse"
        || fstype.strip_prefix("fuse.").is_some_and(|sub| !LOCAL_FUSE.contains(&sub))
}

/// mountinfo and fstab write a space in a path as `\040` (octal escapes).
#[cfg(any(test, all(unix, not(target_os = "macos"))))]
fn unescape_mount(field: &str) -> PathBuf {
    let b = field.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let octal = b
            .get(i + 1..i + 4)
            .filter(|d| b[i] == b'\\' && d.iter().all(|c| (b'0'..=b'7').contains(c)));
        match octal {
            Some(d) => {
                out.push(d.iter().fold(0u32, |n, c| n * 8 + u32::from(c - b'0')) as u8);
                i += 4;
            }
            None => {
                out.push(b[i]);
                i += 1;
            }
        }
    }
    PathBuf::from(String::from_utf8_lossy(&out).into_owned())
}

/// Network and remote FUSE mount points in /proc/self/mountinfo. An automount
/// point that is not mounted yet counts too, unless fstab gives it a local type:
/// opening it would mount it, and a network share can then block the walk.
#[cfg(any(test, all(unix, not(target_os = "macos"))))]
fn network_mounts(mountinfo: &str, fstab: &str) -> Vec<PathBuf> {
    let mut mounts: Vec<(PathBuf, &str)> = Vec::new();
    for line in mountinfo.lines() {
        let Some((left, right)) = line.split_once(" - ") else {
            continue;
        };
        if let (Some(point), Some(fstype)) = (left.split(' ').nth(4), right.split(' ').next()) {
            mounts.push((unescape_mount(point), fstype));
        }
    }
    let local_in_fstab = |point: &Path| {
        fstab.lines().filter(|l| !l.trim_start().starts_with('#')).any(|l| {
            let mut fields = l.split_whitespace();
            fields.nth(1).is_some_and(|p| unescape_mount(p) == point) && fields.next().is_some_and(|t| !is_network_fs(t))
        })
    };
    let mut out = Vec::new();
    for (point, fstype) in &mounts {
        let skip = if *fstype == "autofs" {
            !mounts.iter().any(|(p, t)| p == point && *t != "autofs") && !local_in_fstab(point)
        } else {
            is_network_fs(fstype)
        };
        if skip && !out.contains(point) {
            out.push(point.clone());
        }
    }
    out
}

/// (login, home) from the /etc/passwd line whose field number `field` is `value`.
#[cfg(any(test, all(unix, not(target_os = "macos"))))]
fn passwd_entry(passwd: &str, field: usize, value: &str) -> Option<(String, PathBuf)> {
    passwd
        .lines()
        .map(|line| line.split(':').collect::<Vec<_>>())
        .find(|f| f.len() >= 7 && f[field] == value)
        .map(|f| (f[0].to_string(), PathBuf::from(f[5])))
}

/// Home folder and login to scan. Under sudo or pkexec, HOME and USER name root,
/// so the user who ran the command is looked up in /etc/passwd instead.
#[cfg(all(unix, not(target_os = "macos")))]
fn real_user() -> (Option<PathBuf>, Option<std::ffi::OsString>) {
    let var = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
    let passwd = || fs::read_to_string("/etc/passwd").unwrap_or_default();
    let found = if let Some(login) = var("SUDO_USER").filter(|_| var("USER").as_deref() == Some("root")) {
        passwd_entry(&passwd(), 0, &login)
    } else if let Some(uid) = var("PKEXEC_UID") {
        passwd_entry(&passwd(), 2, &uid)
    } else {
        None
    };
    match found {
        Some((login, home)) => (Some(home), Some(login.into())),
        None => (home(), std::env::var_os("USER")),
    }
}

/// True when `dir` is on the same filesystem as `base`, so it is a plain folder and not
/// a mounted drive. Only called on folders that are not network mounts.
#[cfg(all(unix, not(target_os = "macos")))]
fn same_device(base: &Path, dir: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    match (fs::symlink_metadata(base), fs::symlink_metadata(dir)) {
        (Ok(a), Ok(b)) => a.dev() == b.dev(),
        _ => false,
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
fn plan_computer(f: &mut Finder<'_>) {
    let (home, _) = real_user();
    if let Ok(mountinfo) = fs::read_to_string("/proc/self/mountinfo") {
        let fstab = fs::read_to_string("/etc/fstab").unwrap_or_default();
        // A network home folder is still scanned.
        f.skip_mounts = network_mounts(&mountinfo, &fstab)
            .into_iter()
            .filter(|m| !home.as_ref().is_some_and(|h| h.starts_with(m)))
            .collect();
    }
    // A quick scan also counts its levels from the home folder and from each drive
    // under /mnt, /media and /run/media. The walk from / leaves those folders to them.
    let mut roots = Vec::new();
    if f.stats.depth_limit.is_some() {
        // A home of / is already the walk from /.
        roots.extend(home.as_deref().and_then(|h| fs::canonicalize(h).ok()).filter(|h| h.parent().is_some()));
        for base in ["/mnt", "/media", "/run/media"] {
            // The base itself can be a network mount, directly or through a link (Fedora
            // Atomic links /mnt to var/mnt). Check both before anything opens it.
            let raw = Path::new(base);
            let network = f.skip_mounts.contains(raw)
                || fs::read_link(raw).is_ok_and(|t| f.skip_mounts.contains(&Path::new("/").join(t)));
            if network {
                if !f.stats.skipped_mounts.iter().any(|p| p == raw) {
                    f.stats.skipped_mounts.push(raw.to_path_buf());
                }
                continue;
            }
            // Canonical, so the paths match the mount table.
            let Ok(base) = fs::canonicalize(raw) else {
                continue;
            };
            for dir in f.local_subdirs(&base) {
                // /media/<user> and /run/media/<user> hold the drives one level down.
                let user_dir = !base.ends_with("mnt") && same_device(&base, &dir);
                if user_dir {
                    roots.extend(f.local_subdirs(&dir));
                } else {
                    roots.push(dir);
                }
            }
        }
        roots.sort();
        roots.dedup();
        f.separate_roots = roots.iter().cloned().collect();
    }
    // The whole system: home, /mnt, /media and /run/media included.
    f.root(Path::new("/"));
    for root in roots {
        f.root(&root);
    }
    let Some(home) = home else {
        return;
    };
    let mut candidates = vec![home.join(".wine")];
    for steam in [
        ".local/share/Steam",
        ".steam/steam",
        ".var/app/com.valvesoftware.Steam/.local/share/Steam",
        "snap/steam/common/.local/share/Steam",
    ] {
        let steam = home.join(steam);
        let mut libraries = vec![steam.clone()];
        if let Ok(text) = fs::read_to_string(steam.join("steamapps/libraryfolders.vdf")) {
            libraries.extend(vdf_library_paths(&text));
        }
        for library in libraries {
            for game in f.children(&library.join("steamapps/compatdata")) {
                candidates.push(game.join("pfx"));
            }
        }
    }
    for dir in [
        "Games",
        "Games/umu",
        "Games/Heroic/Prefixes",
        "Games/Heroic/Prefixes/default",
        ".local/share/bottles/bottles",
        ".var/app/com.usebottles.bottles/data/bottles/bottles",
        "Faugus",
    ] {
        let found = f.children(&home.join(dir));
        candidates.extend(found);
    }
    for candidate in candidates {
        f.prefix_candidate(&candidate);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vdf_paths_are_parsed() {
        let text = "\"libraryfolders\"\n{\n\t\"0\"\n\t{\n\t\t\"path\"\t\t\"/home/u/.local/share/Steam\"\n\t}\n\t\"1\"\n\t{\n\t\t\"path\"\t\t\"D:\\\\SteamLibrary\"\n\t\t\"label\"\t\t\"\"\n\t}\n}\n";
        assert_eq!(
            vdf_library_paths(text),
            vec![PathBuf::from("/home/u/.local/share/Steam"), PathBuf::from("D:\\SteamLibrary")]
        );
    }

    #[test]
    fn install_dir_is_found_from_its_files() {
        assert_eq!(
            install_dir_for_file(Path::new("/g/NIKKE/launcher/NIKKE_LAUNCHER.EXE")),
            Some(PathBuf::from("/g/NIKKE"))
        );
        assert_eq!(
            install_dir_for_file(Path::new("/g/NIKKE/Launcher/intl_service/debug.log")),
            Some(PathBuf::from("/g/NIKKE"))
        );
        assert_eq!(install_dir_for_file(Path::new("/g/other/debug.log")), None);
    }

    #[test]
    fn install_paths_are_read_from_reg_files() {
        // Wine user.reg (UTF-8, doubled backslashes).
        let user_reg = "[Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\App Paths\\\\nikke_launcher.exe] 1793276426\n\
\"InstallPath\"=\"Z:\\\\mnt\\\\Jeux\\\\NIKKE\\\\launcher\\\\nikke_launcher.exe\"\n\
[Software\\\\Classes\\\\nikkelauncher\\\\Shell\\\\Open\\\\Command] 1793277019\n\
@=\"\\\"S:\\\\NIKKE\\\\Launcher\\\\nikke_launcher.exe\\\" \\\"%1\\\"\"\n\
\"UninstallString\"=\"Z:\\\\mnt\\\\Jeux\\\\NIKKE\\\\uninst.exe\"\n";
        assert_eq!(install_dirs_in_reg(user_reg), vec!["Z:\\mnt\\Jeux\\NIKKE", "S:\\NIKKE"]);

        // regedit export: UTF-16LE with a BOM and CR-only line ends.
        let export = "Windows Registry Editor Version 5.00\r\r\n[HKEY_CURRENT_USER\\SOFTWARE\\Classes\\nikkelauncher\\DefaultIcon]\r@=\"D:\\\\Games\\\\Level Infinite\\\\NIKKE\\\\Launcher\\\\nikke_launcher.exe\"\r\r\n";
        let mut bytes = vec![0xFF, 0xFE];
        bytes.extend(export.encode_utf16().flat_map(u16::to_le_bytes));
        assert_eq!(install_dirs_in_reg(&reg_text(&bytes)), vec!["D:\\Games\\Level Infinite\\NIKKE"]);
        assert_eq!(install_dir_in_value("nikke_launcher.exe"), None);
    }

    #[test]
    fn network_mounts_are_found() {
        let mountinfo = "\
36 25 0:32 / /mnt/nas rw,relatime shared:1 - nfs4 server:/export rw,vers=4.2
37 25 8:17 / /mnt/Jeux rw,noatime shared:2 - ext4 /dev/sdb1 rw
38 25 0:40 / /home/u/my\\040share rw - fuse.sshfs u@host: rw
39 25 0:41 / /mnt/pool rw - fuse.mergerfs pool rw
40 25 0:42 / /mnt/auto rw - autofs systemd-1 rw
41 25 0:43 / /mnt/games rw - autofs systemd-1 rw
42 41 8:33 / /mnt/games rw - ext4 /dev/sdc1 rw
43 25 0:44 / /mnt/local-auto rw - autofs systemd-1 rw
44 25 8:49 / /mnt/win rw - fuseblk /dev/sdd1 rw
45 25 0:45 / /mnt/gdrive rw - fuse.rclone gdrive: rw
";
        let fstab = "# comment\n/dev/sde1 /mnt/local-auto ext4 noauto,x-systemd.automount 0 2\nserver:/x /mnt/auto nfs x-systemd.automount 0 0\n";
        assert_eq!(
            network_mounts(mountinfo, fstab),
            ["/mnt/nas", "/home/u/my share", "/mnt/auto", "/mnt/gdrive"].map(PathBuf::from).to_vec()
        );
    }

    #[test]
    fn quick_walk_stops_at_its_depth() {
        let root = std::env::temp_dir().join(format!("nikke-check-test-{}-depth", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let shallow = root.join("Games/NIKKE");
        let deep = root.join("a/b/c/d/e/NIKKE");
        // A prefix at the last level is found by its drive_c, which is then walked in full.
        let in_prefix = root.join("a/b/pfx/drive_c/x/y/z/NIKKE");
        for dir in [&shallow, &deep, &in_prefix] {
            fs::create_dir_all(dir.join("Launcher")).unwrap();
            fs::write(dir.join("Launcher/nikke_launcher.exe"), b"MZ").unwrap();
        }
        let installs = |limit| {
            let progress = Progress::default();
            let mut f = Finder::new(ENTRY_CAP, &progress);
            f.stats.depth_limit = limit;
            f.root(&root);
            let mut found: Vec<PathBuf> =
                f.finish().targets.into_iter().filter(|t| t.kind == TargetKind::InstallDir).map(|t| t.path).collect();
            found.sort();
            found
        };
        let sorted = |mut v: Vec<PathBuf>| {
            v.sort();
            v
        };
        // Games/NIKKE/Launcher is level 3, a/b/c/d/e/NIKKE/Launcher level 7.
        assert_eq!(installs(Some(3)), sorted(vec![shallow.clone(), in_prefix.clone()]));
        assert_eq!(installs(None), sorted(vec![shallow, deep, in_prefix]));
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn quick_roots_skip_links_and_network_mounts() {
        let base = std::env::temp_dir().join(format!("nikke-check-test-{}-roots", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(base.join("drive")).unwrap();
        fs::create_dir_all(base.join("nas")).unwrap();
        std::os::unix::fs::symlink(base.join("drive"), base.join("link")).unwrap();
        let progress = Progress::default();
        let mut f = Finder::new(ENTRY_CAP, &progress);
        f.skip_mounts.insert(base.join("nas"));
        assert_eq!(f.local_subdirs(&base), [base.join("drive")]);
        assert_eq!(f.stats.skipped_mounts, [base.join("nas")]);
        assert!(same_device(&base, &base.join("drive")));
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn passwd_lookup() {
        let passwd = "root:x:0:0::/root:/bin/bash\nlin:x:1000:1000:Lin:/home/lin:/bin/zsh\n";
        assert_eq!(passwd_entry(passwd, 0, "lin"), Some(("lin".into(), PathBuf::from("/home/lin"))));
        assert_eq!(passwd_entry(passwd, 2, "1000"), Some(("lin".into(), PathBuf::from("/home/lin"))));
        assert_eq!(passwd_entry(passwd, 0, "nobody"), None);
    }
}
