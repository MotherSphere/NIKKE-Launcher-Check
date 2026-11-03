//! Finds NIKKE installs, launcher data folders, user profiles and Wine
//! prefixes on disk. Never follows symlinks while walking: Wine prefixes link
//! `dosdevices/z:` to `/`, which would turn a walk into a loop.

use std::collections::HashSet;
use std::ffi::OsStr;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use walkdir::WalkDir;

/// Upper bound on directory entries visited in one scan.
pub const ENTRY_CAP: u64 = 3_000_000;

/// Launcher data folder names under `AppData/Roaming`.
pub const LAUNCHER_DATA_NAMES: [&str; 2] = ["nikke_launcher", "nikke_launcher_hmt"];

/// Folder names never entered by a discovery walk.
const SKIP_NAMES: [&str; 6] = [
    "node_modules",
    ".git",
    ".cache",
    "$Recycle.Bin",
    "System Volume Information",
    "dosdevices",
];

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
}

#[derive(Debug, Clone, Default)]
pub struct Discovery {
    pub targets: Vec<Target>,
    pub stats: WalkStats,
}

/// Searches the usual places on this computer.
pub fn discover_computer() -> Discovery {
    let mut finder = Finder::new(ENTRY_CAP);
    plan_computer(&mut finder);
    finder.finish()
}

/// Searches the given folders only (GUI "Scan a folder...", CLI paths).
pub fn discover_folders(paths: &[PathBuf]) -> Discovery {
    discover_folders_with_cap(paths, ENTRY_CAP)
}

pub fn discover_folders_with_cap(paths: &[PathBuf], cap: u64) -> Discovery {
    let mut finder = Finder::new(cap);
    for path in paths {
        finder.root(path, 12);
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

struct Finder {
    cap: u64,
    stats: WalkStats,
    seen: HashSet<(TargetKind, PathBuf)>,
    targets: Vec<Target>,
    pending_prefixes: Vec<PathBuf>,
}

impl Finder {
    fn new(cap: u64) -> Self {
        Self {
            cap,
            stats: WalkStats::default(),
            seen: HashSet::new(),
            targets: Vec::new(),
            pending_prefixes: Vec::new(),
        }
    }

    fn add(&mut self, kind: TargetKind, path: &Path, host: bool) {
        let key = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        if !self.seen.insert((kind, key)) {
            return;
        }
        if kind == TargetKind::WinePrefix {
            self.pending_prefixes.push(path.to_path_buf());
        }
        self.targets.push(Target { kind, path: path.to_path_buf(), host });
    }

    /// Walks a top-level search root if it exists.
    fn root(&mut self, path: &Path, max_depth: usize) {
        if path.is_dir() {
            self.stats.roots.push(path.to_path_buf());
            self.walk(path, max_depth, Mode::Generic);
        }
    }

    #[cfg(unix)]
    fn prefix_candidate(&mut self, path: &Path) {
        if path.join("drive_c").is_dir() {
            self.add(TargetKind::WinePrefix, path, false);
        }
    }

    fn walk(&mut self, root: &Path, max_depth: usize, mode: Mode) {
        if self.stats.cap_hit {
            return;
        }
        let drive_root = root.parent().is_none();
        let mut it = WalkDir::new(root)
            .follow_links(false)
            .max_depth(max_depth)
            .into_iter();
        while let Some(next) = it.next() {
            let entry = match next {
                Ok(entry) => entry,
                Err(err) => {
                    if err.io_error().map(io::Error::kind) == Some(io::ErrorKind::PermissionDenied) {
                        self.stats.permission_errors += 1;
                    }
                    continue;
                }
            };
            if self.stats.entries >= self.cap {
                self.stats.cap_hit = true;
                return;
            }
            self.stats.entries += 1;
            let path = entry.path();
            let name = entry.file_name();
            let depth = entry.depth();
            let file_type = entry.file_type();

            if file_type.is_dir() {
                self.stats.folders += 1;
                let windows_dir = depth == 1 && eq(name, "windows");
                if depth > 0
                    && (skip_dir(path, name) || (windows_dir && (mode == Mode::DriveC || drive_root)))
                {
                    it.skip_current_dir();
                    continue;
                }
                if eq(name, "drive_c") && !(mode == Mode::DriveC && depth == 0) {
                    // The prefix logic walks drive_c itself.
                    if let Some(prefix) = path.parent() {
                        self.add(TargetKind::WinePrefix, prefix, false);
                    }
                    it.skip_current_dir();
                    continue;
                }
                if is_launcher_data(path) {
                    self.add(TargetKind::LauncherData, path, false);
                    it.skip_current_dir();
                }
            } else if file_type.is_file()
                && let Some(install) = install_dir_for_file(path)
            {
                self.add(TargetKind::InstallDir, &install, false);
            }
        }
    }

    fn scan_prefix(&mut self, prefix: &Path) {
        let Some(drive_c) = find_ci(prefix, &["drive_c"]) else {
            return;
        };
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
                    }
                }
            }
        }
        self.walk(&drive_c, 5, Mode::DriveC);
        // Installs often hold their own prefix (NIKKE/prefix next to NIKKE/Launcher).
        if let Some(parent) = prefix.parent()
            && is_install_dir(parent)
        {
            self.add(TargetKind::InstallDir, parent, false);
        }
    }

    fn finish(mut self) -> Discovery {
        while let Some(prefix) = self.pending_prefixes.pop() {
            self.scan_prefix(&prefix);
        }
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

/// Subfolders of `dir` (symlinks to folders included).
#[cfg(unix)]
fn children(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    entries.flatten().map(|e| e.path()).filter(|p| p.is_dir()).collect()
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

#[cfg(windows)]
fn plan_computer(f: &mut Finder) {
    use std::env;
    if let Some(profile) = env::var_os("USERPROFILE") {
        f.add(TargetKind::UserProfile, Path::new(&profile), true);
    }
    if let Some(appdata) = env::var_os("APPDATA") {
        for name in LAUNCHER_DATA_NAMES {
            let data = Path::new(&appdata).join(name);
            if data.is_dir() {
                f.add(TargetKind::LauncherData, &data, true);
            }
        }
    }
    for letter in b'A'..=b'Z' {
        let drive = PathBuf::from(format!("{}:\\", letter as char));
        // Depth 5 reaches C:\Program Files\Level Infinite\NIKKE\Launcher\nikke_launcher.exe.
        f.root(&drive, 5);
    }
}

#[cfg(target_os = "macos")]
fn plan_computer(f: &mut Finder) {
    let home = home();
    if let Some(home) = &home {
        f.root(home, 6);
    }
    f.root(Path::new("/Applications"), 4);
    if let Ok(volumes) = fs::read_dir("/Volumes") {
        for entry in volumes.flatten() {
            // "Macintosh HD" is a symlink to /: skip links, walk real volumes.
            if entry.file_type().is_ok_and(|t| t.is_dir()) {
                f.root(&entry.path(), 5);
            }
        }
    }
    let mut candidates = Vec::new();
    let mut apps = children(Path::new("/Applications"));
    if let Some(home) = &home {
        candidates.push(home.join(".wine"));
        candidates.extend(children(&home.join("Library/Application Support/CrossOver/Bottles")));
        candidates.extend(children(&home.join("Library/Containers/com.isaacmarovitz.Whisky/Bottles")));
        candidates.extend(children(&home.join("Games/Heroic/Prefixes")));
        candidates.extend(children(&home.join("Games/Heroic/Prefixes/default")));
        apps.extend(children(&home.join("Applications")));
    }
    // Wineskin and Kegworks wrappers keep the prefix inside the .app bundle.
    for app in apps {
        if app.extension().is_some_and(|e| e == "app") {
            candidates.push(app.join("Contents/SharedSupport/prefix"));
        }
    }
    for candidate in candidates {
        f.prefix_candidate(&candidate);
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
fn plan_computer(f: &mut Finder) {
    let home = home();
    if let Some(home) = &home {
        f.root(home, 7);
    }
    for root in ["/mnt", "/media", "/opt", "/games"] {
        f.root(Path::new(root), 6);
    }
    if let Some(user) = std::env::var_os("USER") {
        f.root(&Path::new("/run/media").join(user), 6);
    }
    let Some(home) = home else {
        return;
    };
    let mut candidates = vec![home.join(".wine")];
    for steam in [
        ".local/share/Steam",
        ".steam/steam",
        ".var/app/com.valvesoftware.Steam/.local/share/Steam",
    ] {
        let steam = home.join(steam);
        let mut libraries = vec![steam.clone()];
        if let Ok(text) = fs::read_to_string(steam.join("steamapps/libraryfolders.vdf")) {
            libraries.extend(vdf_library_paths(&text));
        }
        for library in libraries {
            for game in children(&library.join("steamapps/compatdata")) {
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
        candidates.extend(children(&home.join(dir)));
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
}
