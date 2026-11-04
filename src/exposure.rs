//! What the agent's commands could read on this computer: browser password
//! stores, wallet extensions and secret files. Existence checks only: no file
//! found here is opened or read.

use std::fs;
use std::path::{Path, PathBuf};

use crate::locate::find_ci;

/// (browser, Firefox profile layout, folder under a home folder or Windows profile).
/// The Windows entries are the folders the agent's browserscan reads; the others
/// are the same browsers on Linux (native, Snap, Flatpak) and macOS.
pub const BROWSERS: [(&str, bool, &str); 33] = [
    ("Chrome", false, "AppData/Local/Google/Chrome/User Data"),
    ("Edge", false, "AppData/Local/Microsoft/Edge/User Data"),
    ("Brave", false, "AppData/Local/BraveSoftware/Brave-Browser/User Data"),
    ("Vivaldi", false, "AppData/Local/Vivaldi/User Data"),
    ("Opera", false, "AppData/Roaming/Opera Software/Opera Stable"),
    ("Opera GX", false, "AppData/Roaming/Opera Software/Opera GX Stable"),
    ("Chromium", false, "AppData/Local/Chromium/User Data"),
    ("Firefox", true, "AppData/Roaming/Mozilla/Firefox"),
    ("Chrome", false, ".config/google-chrome"),
    ("Chromium", false, ".config/chromium"),
    ("Brave", false, ".config/BraveSoftware/Brave-Browser"),
    ("Edge", false, ".config/microsoft-edge"),
    ("Vivaldi", false, ".config/vivaldi"),
    ("Opera", false, ".config/opera"),
    ("Firefox", true, ".mozilla/firefox"),
    ("Firefox", true, ".config/mozilla/firefox"),
    ("Chromium", false, "snap/chromium/common/chromium"),
    ("Firefox", true, "snap/firefox/common/.mozilla/firefox"),
    ("Chrome", false, ".var/app/com.google.Chrome/config/google-chrome"),
    ("Chromium", false, ".var/app/org.chromium.Chromium/config/chromium"),
    ("Brave", false, ".var/app/com.brave.Browser/config/BraveSoftware/Brave-Browser"),
    ("Edge", false, ".var/app/com.microsoft.Edge/config/microsoft-edge"),
    ("Vivaldi", false, ".var/app/com.vivaldi.Vivaldi/config/vivaldi"),
    ("Opera", false, ".var/app/com.opera.Opera/config/opera"),
    ("Firefox", true, ".var/app/org.mozilla.firefox/.mozilla/firefox"),
    ("Firefox", true, ".var/app/org.mozilla.firefox/config/mozilla/firefox"),
    ("Chrome", false, "Library/Application Support/Google/Chrome"),
    ("Chromium", false, "Library/Application Support/Chromium"),
    ("Brave", false, "Library/Application Support/BraveSoftware/Brave-Browser"),
    ("Edge", false, "Library/Application Support/Microsoft Edge"),
    ("Vivaldi", false, "Library/Application Support/Vivaldi"),
    ("Opera", false, "Library/Application Support/com.operasoftware.Opera"),
    ("Firefox", true, "Library/Application Support/Firefox"),
];

/// The 28 extension IDs of the agent's wallet_files command, with the wallet names.
pub const WALLETS: [(&str, &str); 28] = [
    ("acmacodkjbdgmoleebolmdjonilkdbch", "Rabby"),
    ("aflkmfhebedbjioipglgcbcmnbpgliof", "Backpack"),
    ("bfnaelmomeimhlpmgjnjophhpkkoljpa", "Phantom"),
    ("bhhhlbepdkbapadjdnnojkbgioiodbic", "Solflare"),
    ("cadiboklkpojfamcoggejbbdjcoiljjk", "Binance Wallet"),
    ("dmkamcknogkgcdfhhbddcghachkejeap", "Keplr"),
    ("egjidjbpglichdcondbcbdnbeeppgdph", "Trust Wallet"),
    ("fnjhmkhhmkbjkkabndcnnogagogbneec", "Ronin Wallet"),
    ("hnfanknocfeofbddgcijnmhnfnkdnaad", "Coinbase Wallet"),
    ("ibnejdfjmmkpcnlpebklmnkoeoihofec", "TronLink"),
    ("jiidiaalihmmhddjgbnbgdfflelocpak", "Bitget Wallet"),
    ("mcohilncbfahbmgdjkbpemcciiolgcge", "OKX Wallet"),
    ("nkbihfbeogaeaoehlefnkodbefgpgknn", "MetaMask"),
    ("omaabbefbmiijedngplfjmnooppbclkk", "Tonkeeper"),
    ("opcgpfmipidbgpenhmajoajpbobppdil", "Slush"),
    ("pdliaogehgdbhbnmkklieghmmjkpigpa", "Bybit Wallet"),
    ("jblndlipeogpafnldhgmapagcccfchpi", "Kaia Wallet"),
    ("aiifbnbfobpmeekipheeijimdpnlpgpp", "Station"),
    ("ppbibelpcjmhbdihakflkdcoccbgbkpo", "UniSat"),
    ("idnnbdplmphpflfnlkomgpfbpcgelopg", "Xverse"),
    ("mkpegjkblkkefacfnmkajcjmabijhclg", "Magic Eden"),
    ("ejjladinnckdgjemekebdpeokbikhfci", "Petra"),
    ("dlcobpjiigpikoobohmabehhmhfoodbb", "Ready"),
    ("gjagmgiddbbciopjhllkdnddhcglnemk", "HashPack"),
    ("onhogfjeacnfoofkfgppdlbmlmnplgbn", "SubWallet"),
    ("opfgelmcmbiajamepnmloijbpoleiama", "Rainbow"),
    ("jnlgamecbpmbajjfhmmmlhejkemejdma", "Braavos"),
    ("phkbamefinggmakgklpkljjmgibohnba", "Pontem"),
];

/// Secret files from the agent's keyscan list (catalog key of what each holds, path
/// relative to the home folder or Windows profile). SSH private keys (~/.ssh/id_*) are found separately.
const SECRETS: [(&str, &str); 43] = [
    ("secret.aws", ".aws/credentials"),
    ("secret.github_cli", ".config/gh/hosts.yml"),
    ("secret.github_cli", "AppData/Roaming/GitHub CLI/hosts.yml"),
    ("secret.git", ".git-credentials"),
    ("secret.git", ".config/git/credentials"),
    ("secret.npm", ".npmrc"),
    ("secret.docker", ".docker/config.json"),
    ("secret.kubernetes", ".kube/config"),
    ("secret.gcloud", ".config/gcloud/credentials.db"),
    ("secret.gcloud", ".config/gcloud/application_default_credentials.json"),
    ("secret.gcloud", "AppData/Roaming/gcloud/credentials.db"),
    ("secret.gcloud", "AppData/Roaming/gcloud/application_default_credentials.json"),
    ("secret.azure", ".azure/msal_token_cache.bin"),
    ("secret.azure", ".azure/msal_token_cache.json"),
    ("secret.azure", ".azure/accessTokens.json"),
    ("secret.claude", ".claude/.credentials.json"),
    ("secret.codex", ".codex/auth.json"),
    ("secret.gemini", ".gemini/oauth_creds.json"),
    ("secret.copilot", ".copilot/mcp-config.json"),
    ("secret.opencode", ".local/share/opencode/auth.json"),
    ("secret.filezilla", "AppData/Roaming/FileZilla/sitemanager.xml"),
    ("secret.filezilla", "AppData/Roaming/FileZilla/recentservers.xml"),
    ("secret.filezilla", ".config/filezilla/sitemanager.xml"),
    ("secret.filezilla", ".config/filezilla/recentservers.xml"),
    ("secret.netrc", ".netrc"),
    ("secret.netrc", "_netrc"),
    ("secret.pypi", ".pypirc"),
    ("secret.crates", ".cargo/credentials.toml"),
    ("secret.crates", ".cargo/credentials"),
    ("secret.vault", ".vault-token"),
    ("secret.terraform", ".terraform.d/credentials.tfrc.json"),
    ("secret.terraform", "AppData/Roaming/terraform.d/credentials.tfrc.json"),
    ("secret.pulumi", ".pulumi/credentials.json"),
    ("secret.kaggle", ".kaggle/kaggle.json"),
    ("secret.huggingface", ".cache/huggingface/token"),
    ("secret.rclone", ".config/rclone/rclone.conf"),
    ("secret.rclone", "AppData/Roaming/rclone/rclone.conf"),
    ("secret.s3cmd", ".s3cfg"),
    ("secret.databricks", ".databrickscfg"),
    ("secret.oci", ".oci/config"),
    ("secret.gnupg", ".gnupg/private-keys-v1.d"),
    ("secret.gnupg", "AppData/Roaming/gnupg/private-keys-v1.d"),
    ("secret.env", ".env"),
];

/// Everything found in the checked home folders.
#[derive(Debug, Clone, Default)]
pub struct Exposure {
    /// Home folders and Windows profiles that were checked.
    pub checked: Vec<PathBuf>,
    pub logins: Vec<BrowserLogins>,
    pub wallets: Vec<Wallet>,
    pub secrets: Vec<SecretFile>,
}

/// A browser profile with a password store file. Chromium creates Login Data in
/// every profile, so the file can be there with no saved password; it is not read.
#[derive(Debug, Clone)]
pub struct BrowserLogins {
    pub browser: &'static str,
    /// The profile folder name ("Default", "Profile 1", a Firefox profile ID).
    pub profile: String,
    pub path: PathBuf,
    /// The store files present: Login Data, Login Data For Account, logins.json, key4.db.
    pub files: Vec<&'static str>,
}

/// A wallet extension from [`WALLETS`] installed in a Chromium profile.
#[derive(Debug, Clone)]
pub struct Wallet {
    pub name: &'static str,
    pub id: &'static str,
    pub browser: &'static str,
    pub profile: String,
    /// The Extensions/<id> folder.
    pub path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct SecretFile {
    /// The catalog key of what the file holds ("AWS credentials").
    pub what: &'static str,
    pub path: PathBuf,
}

pub fn collect(homes: &[PathBuf]) -> Exposure {
    let mut out = Exposure { checked: homes.to_vec(), ..Exposure::default() };
    for home in homes {
        for (browser, firefox, rel) in BROWSERS {
            let Some(root) = find_ci(home, &rel.split('/').collect::<Vec<_>>()).filter(|p| p.is_dir()) else {
                continue;
            };
            // Chromium: Opera keeps its one profile in the root, the others in subfolders.
            // Firefox: Windows and macOS keep profiles in Profiles/, Linux in the root.
            let mut profiles = vec![root.clone()];
            profiles.extend(subdirs(&root));
            if firefox {
                profiles.extend(subdirs(&root.join("Profiles")));
            }
            for profile in profiles {
                check_profile(browser, firefox, &profile, &mut out);
            }
        }
        for (what, rel) in SECRETS {
            if let Some(path) = find_ci(home, &rel.split('/').collect::<Vec<_>>()) {
                out.secrets.push(SecretFile { what, path });
            }
        }
        let mut keys: Vec<PathBuf> = find_ci(home, &[".ssh"])
            .and_then(|ssh| fs::read_dir(ssh).ok())
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| {
                let name = e.file_name().to_string_lossy().into_owned();
                name.starts_with("id_") && !name.ends_with(".pub") && e.file_type().is_ok_and(|t| t.is_file())
            })
            .map(|e| e.path())
            .collect();
        keys.sort();
        out.secrets.extend(keys.into_iter().map(|path| SecretFile { what: "secret.ssh", path }));
    }
    out
}

fn check_profile(browser: &'static str, firefox: bool, profile: &Path, out: &mut Exposure) {
    let names: &[&'static str] =
        if firefox { &["logins.json", "key4.db"] } else { &["Login Data", "Login Data For Account"] };
    let files: Vec<&'static str> = names.iter().copied().filter(|n| profile.join(n).is_file()).collect();
    let name = profile.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    if !files.is_empty() {
        out.logins.push(BrowserLogins { browser, profile: name.clone(), path: profile.to_path_buf(), files });
    }
    if firefox {
        return;
    }
    let installed: Vec<String> = fs::read_dir(profile.join("Extensions"))
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    for (id, wallet) in WALLETS {
        if installed.iter().any(|n| n == id) {
            let path = profile.join("Extensions").join(id);
            out.wallets.push(Wallet { name: wallet, id, browser, profile: name.clone(), path });
        }
    }
}

fn subdirs(dir: &Path) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .map(|e| e.path())
        .collect();
    dirs.sort();
    dirs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::{Lang, tr};

    #[test]
    fn exposure_is_found_by_name() {
        let root = std::env::temp_dir().join(format!("nikke-check-test-{}-exposure", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let touch = |rel: &str| {
            let path = root.join(rel);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, b"").unwrap();
        };
        // A Wine user and a Linux home side by side.
        let win = "user/AppData/Local/Google/Chrome/User Data";
        touch(&format!("{win}/Default/Login Data"));
        touch(&format!("{win}/Profile 1/Extensions/nkbihfbeogaeaoehlefnkodbefgpgknn/12.0_0/manifest.json"));
        touch(&format!("{win}/Profile 1/Extensions/aaaabbbbccccddddeeeeffffgggghhhh/1.0/manifest.json"));
        touch("user/AppData/Roaming/Opera Software/Opera Stable/Login Data");
        touch("user/AppData/Roaming/Mozilla/Firefox/Profiles/x1.default-release/logins.json");
        touch("user/.aws/credentials");
        touch("home/.mozilla/firefox/ab12.default/key4.db");
        touch("home/.config/BraveSoftware/Brave-Browser/Default/Extensions/bfnaelmomeimhlpmgjnjophhpkkoljpa/1/x");
        touch("home/.ssh/id_ed25519");
        touch("home/.ssh/id_ed25519.pub");
        touch("home/.ssh/known_hosts");
        touch("home/.config/gh/hosts.yml");
        let e = collect(&[root.join("user"), root.join("home")]);
        let logins: Vec<(&str, &str)> = e.logins.iter().map(|l| (l.browser, l.profile.as_str())).collect();
        assert_eq!(logins, [("Chrome", "Default"), ("Opera", "Opera Stable"), ("Firefox", "x1.default-release"), ("Firefox", "ab12.default")]);
        let wallets: Vec<(&str, &str)> = e.wallets.iter().map(|w| (w.name, w.browser)).collect();
        assert_eq!(wallets, [("MetaMask", "Chrome"), ("Phantom", "Brave")]);
        let secrets: Vec<&str> = e.secrets.iter().map(|s| tr(Lang::En, s.what)).collect();
        assert_eq!(secrets, ["AWS credentials", "GitHub CLI token", "SSH private key"]);
        assert!(e.secrets[2].path.ends_with(".ssh/id_ed25519"));
        let _ = fs::remove_dir_all(&root);
    }
}
