//! "Hide my info" and --redact: replaces the computer name, the user names, the
//! agent IDs and the home folder in a report before it is copied or saved.

use std::path::{Path, PathBuf};

use crate::locate::{self, TargetKind};
use crate::scan::{CLSID, ScanResult};

const HOME: &str = "<home>";
const USER: &str = "<user>";
const COMPUTER: &str = "<computer>";
const AGENT_ID: &str = "<agent-id>";
/// Any other UUID: the agent's saved state can hold its ID outside the logged runs.
const ID: &str = "<id>";

/// The values to replace, folded to lower case, longest first.
#[derive(Debug, Clone, Default)]
pub struct Secrets {
    needles: Vec<(Vec<char>, &'static str)>,
}

impl Secrets {
    /// The values of this computer and the ones the scan found.
    pub fn of(r: &ScanResult) -> Self {
        let env = |k: &str| std::env::var(k).ok();
        let mut homes: Vec<PathBuf> = locate::real_home().into_iter().collect();
        homes.extend(["HOME", "USERPROFILE"].into_iter().filter_map(std::env::var_os).map(PathBuf::from));
        let profiles = r.targets.iter().filter(|t| t.kind == TargetKind::UserProfile).map(|t| &t.path);
        let mut users: Vec<String> = ["USER", "USERNAME", "LOGNAME", "SUDO_USER"].into_iter().filter_map(env).collect();
        users.extend(homes.iter().chain(profiles).filter_map(|p| last(p)));
        let mut computers: Vec<String> =
            [env("COMPUTERNAME"), env("HOSTNAME"), sysinfo::System::host_name()].into_iter().flatten().collect();
        computers.extend(r.runs.iter().filter_map(|run| run.host.clone()));
        let ids = r.runs.iter().filter_map(|run| run.agent_id.clone()).collect();
        Self::new(&homes, users, computers, ids)
    }

    fn new(homes: &[PathBuf], users: Vec<String>, computers: Vec<String>, ids: Vec<String>) -> Self {
        let mut needles: Vec<(Vec<char>, &'static str)> = Vec::new();
        let mut add = |value: &str, with: &'static str| {
            let folded: Vec<char> = value.trim().chars().map(fold).collect();
            if !folded.is_empty() && !needles.iter().any(|(n, _)| *n == folded) {
                needles.push((folded, with));
            }
        };
        // A drive or file system root is not a home folder.
        for home in homes.iter().filter(|h| last(h).is_some()) {
            let s = home.to_string_lossy();
            for variant in [s.to_string(), s.replace('\\', "/"), s.replace('/', "\\")] {
                add(&variant, HOME);
            }
        }
        for user in &users {
            add(user, USER);
        }
        for computer in &computers {
            add(computer, COMPUTER);
            // Windows and Wine use the short name, Linux can report "name.domain".
            if let Some((short, _)) = computer.split_once('.') {
                add(short, COMPUTER);
            }
        }
        for id in &ids {
            add(id, AGENT_ID);
        }
        needles.sort_by_key(|(n, _)| std::cmp::Reverse(n.len()));
        Self { needles }
    }

    /// `text` with every value replaced by its placeholder. A value only matches
    /// as a whole word (no letter or digit on either side), in any letter case.
    /// A user name also needs to be a path part (see `fits`). Any other UUID
    /// except the CLSID becomes [`ID`].
    pub fn apply(&self, text: &str) -> String {
        let chars: Vec<char> = text.chars().collect();
        let folded: Vec<char> = chars.iter().map(|&c| fold(c)).collect();
        let free = |i: usize| i >= chars.len() || !chars[i].is_alphanumeric();
        let mut out = String::with_capacity(text.len());
        let mut i = 0;
        while i < chars.len() {
            if i == 0 || free(i - 1) {
                let before = i.checked_sub(1).map(|j| chars[j]);
                let hit = self
                    .needles
                    .iter()
                    .find(|(n, with)| folded[i..].starts_with(n) && free(i + n.len()) && fits(with, n.len(), before, chars.get(i + n.len()).copied()))
                    .map(|(n, with)| (n.len(), *with))
                    .or_else(|| is_uuid(&chars[i..]).then_some((36, ID)));
                if let Some((len, with)) = hit {
                    out.push_str(with);
                    i += len;
                    continue;
                }
            }
            out.push(chars[i]);
            i += 1;
        }
        out
    }
}

/// Whether a value of `len` chars between `before` and `after` counts. One or two
/// letters ("jo") would match ordinary words, so they count only in a path. A user
/// name counts only as a path part: after a separator and not before a space, so
/// "deck" in "Steam deck" and "User" in "Chrome\User Data" stay.
fn fits(with: &str, len: usize, before: Option<char>, after: Option<char>) -> bool {
    let in_path = matches!(before, Some('/' | '\\'));
    if with != USER {
        return len > 2 || in_path;
    }
    // A dash joins the parts of a flattened path, as in "-home-alice-".
    (in_path || (len > 2 && before == Some('-'))) && after != Some(' ')
}

fn last(path: &Path) -> Option<String> {
    path.file_name().map(|n| n.to_string_lossy().into_owned()).filter(|n| !n.is_empty())
}

fn fold(c: char) -> char {
    c.to_lowercase().next().unwrap_or(c)
}

/// 8-4-4-4-12 hex digits not followed by a letter or digit, other than the CLSID.
fn is_uuid(s: &[char]) -> bool {
    let Some(head) = s.get(..36) else {
        return false;
    };
    let shape = head.iter().enumerate().all(|(i, c)| if matches!(i, 8 | 13 | 18 | 23) { *c == '-' } else { c.is_ascii_hexdigit() });
    let end = s.get(36).is_none_or(|c| !c.is_alphanumeric());
    let clsid: String = head.iter().collect();
    shape && end && !CLSID.trim_matches(['{', '}']).eq_ignore_ascii_case(&clsid)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secrets() -> Secrets {
        Secrets::new(
            &[PathBuf::from("/home/alice"), PathBuf::from("C:\\Users\\Alice"), PathBuf::from("/")],
            vec!["alice".into(), "steamuser".into(), "jo".into(), "Alice".into()],
            vec!["GAMEPC.lan".into(), "COLONY".into()],
            vec!["3c4c9b75-09e5-4619-99ee-97c1dc3c0373".into()],
        )
    }

    #[test]
    fn every_occurrence_is_replaced() {
        let text = "\
Scan of: /home/alice/Games/NIKKE
  [User profile] /home/alice/.steam/steam/steamapps/compatdata/1/pfx/drive_c/users/steamuser
    Path: C:\\Users\\Alice\\AppData\\Local\\Temp\\k2f-bcreds-1
    Path: c:/users/alice/AppData/Roaming/nikke_launcher
    | PID 812: Z:\\home\\alice\\Games\\nikke_launcher.exe /run/media/ALICE/Games
    | [1103/014736.623:INFO:CONSOLE(1)] \"adopted 3C4C9B75-09E5-4619-99EE-97C1DC3C0373\", source:  (1)
    | [1024/011602.100:INFO:CONSOLE(1)] \"resuming 3c4c9b75-09e5-4619-99ee-97c1dc3c0373\", source:  (1)
    | [1103/014736.625:INFO:CONSOLE(1)] \"agent started as COLONY\", source:  (1)
    | k2f.agent.state {\"id\":\"0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0\",
    | gamepc and gamepc.lan, k2f_screen_colony.jpg, /tmp/claude-1000/-home-alice-Documents
    | D:\\Users\\jo\\AppData and /home/jo/x
";
        let out = secrets().apply(text);
        for value in ["alice", "steamuser", "gamepc", "colony", "3c4c9b75", "0f1e2d3c", "\\jo\\", "/jo/"] {
            assert!(!out.to_lowercase().contains(value), "{value} left in:\n{out}");
        }
        assert!(out.contains("Scan of: <home>/Games/NIKKE"), "{out}");
        assert!(out.contains("Path: <home>\\AppData\\Local\\Temp"), "{out}");
        assert!(out.contains("Path: <home>/AppData/Roaming"), "{out}");
        assert!(out.contains("Z:<home>\\Games"), "{out}");
        assert!(out.contains("drive_c/users/<user>"), "{out}");
        assert!(out.contains("\"adopted <agent-id>\""), "{out}");
        assert!(out.contains("agent started as <computer>"), "{out}");
        assert!(out.contains("{\"id\":\"<id>\","), "{out}");
        assert!(out.contains("<computer> and <computer>, k2f_screen_<computer>.jpg"), "{out}");
        assert!(out.contains("-home-<user>-Documents"), "{out}");
    }

    #[test]
    fn other_text_is_kept() {
        let text = "Malice, Joanna and a jo-jo: HKCU\\Software\\Classes\\CLSID\\{E77CC89B-7401-4C04-8CED-149DB35ADD04} / alice2 / steamusers";
        assert_eq!(secrets().apply(text), text);
        // A root path is not taken as a home folder.
        assert_eq!(secrets().apply("/etc/hosts"), "/etc/hosts");
        assert_eq!(Secrets::default().apply("COLONY"), "COLONY");
    }

    #[test]
    fn common_user_names_stay_in_text() {
        let s = Secrets::new(&[PathBuf::from("/home/deck"), PathBuf::from("C:\\Users\\User")], vec!["deck".into(), "User".into()], vec![], vec![]);
        let text = "On a Steam deck, set a password. C:\\Users\\User\\AppData\\Local\\Google\\Chrome\\User Data and the prefix's user.reg file. D:\\Users\\User\n/mnt/c/Users/deck/x";
        assert_eq!(
            s.apply(text),
            "On a Steam deck, set a password. <home>\\AppData\\Local\\Google\\Chrome\\User Data and the prefix's user.reg file. D:\\Users\\<user>\n/mnt/c/Users/<user>/x"
        );
    }
}
