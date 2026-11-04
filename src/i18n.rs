//! Languages and texts. Each language has a catalog in locales/<code>.txt
//! (`key = text` lines), built into the program. A text missing from a catalog
//! falls back to English. The language comes from the system at start, or from
//! --lang, and only lives in memory: nothing is saved.

use std::collections::HashMap;
use std::fmt;
use std::sync::LazyLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Lang {
    #[default]
    En,
    Ja,
    Ko,
    ZhHans,
    ZhHant,
    Th,
    Vi,
    Id,
    Fr,
    De,
    Es,
    PtBr,
    Ru,
    Pl,
    Tr,
    It,
}

/// (language, code, native name, catalog), in the order of [`Lang`] and of the
/// language menu. A new language is a variant above and one line here.
const LANGS: [(Lang, &str, &str, &str); 16] = [
    (Lang::En, "en", "English", include_str!("../locales/en.txt")),
    (Lang::Ja, "ja", "日本語", include_str!("../locales/ja.txt")),
    (Lang::Ko, "ko", "한국어", include_str!("../locales/ko.txt")),
    (Lang::ZhHans, "zh-Hans", "简体中文", include_str!("../locales/zh-Hans.txt")),
    (Lang::ZhHant, "zh-Hant", "繁體中文", include_str!("../locales/zh-Hant.txt")),
    (Lang::Th, "th", "ไทย", include_str!("../locales/th.txt")),
    (Lang::Vi, "vi", "Tiếng Việt", include_str!("../locales/vi.txt")),
    (Lang::Id, "id", "Bahasa Indonesia", include_str!("../locales/id.txt")),
    (Lang::Fr, "fr", "Français", include_str!("../locales/fr.txt")),
    (Lang::De, "de", "Deutsch", include_str!("../locales/de.txt")),
    (Lang::Es, "es", "Español", include_str!("../locales/es.txt")),
    (Lang::PtBr, "pt-BR", "Português (Brasil)", include_str!("../locales/pt-BR.txt")),
    (Lang::Ru, "ru", "Русский", include_str!("../locales/ru.txt")),
    (Lang::Pl, "pl", "Polski", include_str!("../locales/pl.txt")),
    (Lang::Tr, "tr", "Türkçe", include_str!("../locales/tr.txt")),
    (Lang::It, "it", "Italiano", include_str!("../locales/it.txt")),
];

impl Lang {
    pub const ALL: [Lang; 16] = {
        let mut all = [Lang::En; 16];
        let mut i = 0;
        while i < all.len() {
            all[i] = LANGS[i].0;
            i += 1;
        }
        all
    };

    pub fn code(self) -> &'static str {
        LANGS[self as usize].1
    }

    /// A code as --lang takes it, in any letter case.
    pub fn from_code(code: &str) -> Option<Lang> {
        LANGS.iter().find(|l| l.1.eq_ignore_ascii_case(code)).map(|l| l.0)
    }

    /// "en ja ko ...", for the help and the errors of --lang.
    pub fn codes() -> String {
        LANGS.map(|l| l.1).join(" ")
    }

    /// The first of the system's preferred languages that has a catalog, else English.
    /// sys-locale reads GetUserPreferredUILanguages on Windows, the preferred
    /// languages on macOS, and LANGUAGE, LC_ALL, LC_MESSAGES and LANG elsewhere.
    pub fn detect() -> Lang {
        first_supported(sys_locale::get_locales())
    }

    /// The language of a locale such as "fr-FR", "zh_TW.UTF-8" or "zh-Hant-HK".
    /// None for "C", "POSIX" and languages without a catalog.
    fn from_locale(locale: &str) -> Option<Lang> {
        // Drop the encoding and the modifier: "de_DE.UTF-8@euro" is "de_DE".
        let tag = locale.split(['.', '@']).next()?.trim().to_ascii_lowercase();
        let mut parts = tag.split(['-', '_']);
        let primary = parts.next()?;
        let rest: Vec<&str> = parts.collect();
        let has = |subtags: &[&str]| rest.iter().any(|p| subtags.contains(p));
        match primary {
            // A script subtag decides; without one, the region does.
            "zh" if has(&["hans"]) => Some(Lang::ZhHans),
            "zh" if has(&["hant", "tw", "hk", "mo"]) => Some(Lang::ZhHant),
            "zh" => Some(Lang::ZhHans),
            // The one Portuguese catalog is Brazilian.
            "pt" => Some(Lang::PtBr),
            // "in" is the old code for Indonesian (Java, older Android).
            "in" => Some(Lang::Id),
            _ => Lang::ALL.into_iter().find(|l| l.code() == primary),
        }
    }
}

fn first_supported(locales: impl IntoIterator<Item = String>) -> Lang {
    locales.into_iter().find_map(|l| Lang::from_locale(&l)).unwrap_or_default()
}

/// The native name, as the language menu shows it.
impl fmt::Display for Lang {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(LANGS[*self as usize].2)
    }
}

/// The entries of a catalog, with the line number of each line that is not one.
/// Blank lines and lines starting with # are skipped.
fn entries(catalog: &str) -> impl Iterator<Item = Result<(&str, String), String>> {
    catalog.lines().enumerate().filter_map(|(i, line)| {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return None;
        }
        let entry = line
            .split_once('=')
            .map(|(key, text)| (key.trim(), text.trim()))
            .filter(|(key, _)| !key.is_empty() && key.bytes().all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.')));
        Some(match entry {
            Some((key, text)) => Ok((key, unescape(text))),
            None => Err(format!("line {}: not a \"key = text\" entry: {line}", i + 1)),
        })
    })
}

/// `\n` is a new line and `\\` a backslash; any other backslash stays as it is.
fn unescape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match (c, chars.peek()) {
            ('\\', Some('n')) => {
                chars.next();
                out.push('\n');
            }
            ('\\', Some('\\')) => {
                chars.next();
                out.push('\\');
            }
            _ => out.push(c),
        }
    }
    out
}

/// One map per language, in the order of [`LANGS`]. A broken line is skipped
/// here; the tests reject it.
static CATALOGS: LazyLock<Vec<HashMap<&'static str, String>>> =
    LazyLock::new(|| LANGS.iter().map(|l| entries(l.3).filter_map(Result::ok).collect()).collect());

/// The text of `key` in `lang`, else in English, else the key itself.
pub fn tr(lang: Lang, key: &'static str) -> &'static str {
    let get = |l: Lang| CATALOGS[l as usize].get(key).map(String::as_str);
    get(lang).or_else(|| get(Lang::En)).unwrap_or(key)
}

/// A placeholder name: `{name}` with lowercase ASCII letters and underscores.
fn is_name(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
}

/// `template` with each `{name}` that `value` knows replaced. Other braces stay.
fn fill(template: &str, value: impl Fn(&str) -> Option<String>) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        rest = &rest[open..];
        let filled = rest.find('}').and_then(|close| {
            let name = &rest[1..close];
            is_name(name).then(|| value(name)).flatten().map(|v| (v, close))
        });
        match filled {
            Some((v, close)) => {
                out.push_str(&v);
                rest = &rest[close + 1..];
            }
            None => {
                out.push('{');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// A text to show in any language: kept as data in findings and notices, and
/// rendered when the window draws or the report is written.
#[derive(Debug, Clone, PartialEq)]
pub enum Text {
    /// Shown as it is: a path, a file name, a line quoted from a file.
    Raw(String),
    /// A catalog key and the values of its placeholders.
    Msg(&'static str, Vec<(&'static str, Text)>),
    /// Texts shown one after the other, separated by "; ".
    List(Vec<Text>),
}

/// The catalog text `key`; add its placeholders with [`Text::arg`].
pub fn msg(key: &'static str) -> Text {
    Text::Msg(key, Vec::new())
}

impl Text {
    /// Sets the placeholder `{name}` of a message.
    pub fn arg(mut self, name: &'static str, value: impl Into<Text>) -> Self {
        if let Text::Msg(_, args) = &mut self {
            args.push((name, value.into()));
        }
        self
    }

    /// The value given for `{name}`.
    pub fn get(&self, name: &str) -> Option<&Text> {
        match self {
            Text::Msg(_, args) => args.iter().find(|(n, _)| *n == name).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn render(&self, lang: Lang) -> String {
        match self {
            Text::Raw(s) => s.clone(),
            Text::Msg(key, args) => fill(tr(lang, key), |name| {
                args.iter().find(|(n, _)| *n == name).map(|(_, v)| v.render(lang))
            }),
            Text::List(items) => items.iter().map(|t| t.render(lang)).collect::<Vec<_>>().join("; "),
        }
    }

    #[cfg(test)]
    pub fn en(&self) -> String {
        self.render(Lang::En)
    }
}

impl From<String> for Text {
    fn from(s: String) -> Self {
        Text::Raw(s)
    }
}

impl From<&str> for Text {
    fn from(s: &str) -> Self {
        Text::Raw(s.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeSet, HashSet};

    fn placeholders(text: &str) -> BTreeSet<&str> {
        text.split('{').skip(1).filter_map(|s| s.split_once('}')).map(|(name, _)| name).filter(|n| is_name(n)).collect()
    }

    /// Every catalog parses, has no key twice and no empty text. Each
    /// translation uses only English keys, with the same placeholders.
    #[test]
    fn i18n_catalogs_are_valid() {
        let english: HashMap<&str, String> = entries(LANGS[0].3).map(Result::unwrap).collect();
        for (i, (lang, code, _, catalog)) in LANGS.iter().enumerate() {
            assert_eq!(*lang as usize, i, "{code}: LANGS is not in the order of Lang");
            let mut seen = HashSet::new();
            for entry in entries(catalog) {
                let (key, text) = entry.unwrap_or_else(|e| panic!("locales/{code}.txt {e}"));
                assert!(seen.insert(key), "locales/{code}.txt: {key} is there twice");
                assert!(!text.is_empty(), "locales/{code}.txt: {key} has no text");
                let Some(en) = english.get(key) else {
                    panic!("locales/{code}.txt: {key} is not a key of en.txt");
                };
                assert_eq!(placeholders(&text), placeholders(en), "locales/{code}.txt: {key} must keep the placeholders of en.txt");
            }
        }
    }

    /// The keys in the source (string literals in a key namespace) and the keys of
    /// en.txt are the same set: none missing, none unused.
    #[test]
    fn i18n_every_key_is_used_and_defined() {
        const SOURCES: [&str; 13] = [
            include_str!("exposure.rs"),
            include_str!("guide.rs"),
            include_str!("hsts.rs"),
            include_str!("i18n.rs"),
            include_str!("ldb.rs"),
            include_str!("locate.rs"),
            include_str!("main.rs"),
            include_str!("open.rs"),
            include_str!("redact.rs"),
            include_str!("report.rs"),
            include_str!("scan.rs"),
            include_str!("timeline.rs"),
            include_str!("ui.rs"),
        ];
        const SPACES: [&str; 22] = [
            "answer", "build", "cli", "common", "details", "evidence", "exposure", "finding", "group", "hosts", "kind",
            "meaning", "open", "report", "run", "secret", "section", "severity", "step", "time", "ui", "verdict",
        ];
        let english: HashSet<&str> = entries(LANGS[0].3).map(|e| e.unwrap().0).collect();
        let mut used = HashSet::new();
        for source in SOURCES {
            for (i, _) in source.match_indices('"') {
                let rest = &source[i + 1..];
                let Some(end) = rest.find('"') else { continue };
                let key = &rest[..end];
                let space = key.split('.').next().unwrap_or_default();
                // The file names of SOURCES above are not keys.
                let file = key.ends_with(".rs");
                if key.contains('.') && !file && SPACES.contains(&space) && key.bytes().all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.')) {
                    used.insert(key);
                }
            }
        }
        let mut missing: Vec<_> = used.difference(&english).collect();
        let mut unused: Vec<_> = english.difference(&used).collect();
        missing.sort();
        unused.sort();
        assert!(missing.is_empty(), "keys used in the code but not in en.txt: {missing:?}");
        assert!(unused.is_empty(), "keys of en.txt that the code never uses: {unused:?}");
    }

    #[test]
    fn i18n_parsing_and_placeholders() {
        let catalog = "# comment\n\nzz.example = a {name}\\nb \\\\ c \\x {E77CC89B-7401} {other}\nbroken line\n";
        let parsed: Vec<_> = entries(catalog).collect();
        assert_eq!(parsed[0], Ok(("zz.example", "a {name}\nb \\ c \\x {E77CC89B-7401} {other}".to_string())));
        assert!(parsed[1].as_ref().is_err_and(|e| e.starts_with("line 4:")));
        let value = |name: &str| (name == "name").then(|| "X".to_string());
        assert_eq!(fill("a {name} {E77C-1} {other} {} {name", value), "a X {E77C-1} {other} {} {name");
        assert_eq!(placeholders("{a} {b_c} {D} {}"), BTreeSet::from(["a", "b_c"]));
        // English texts render, with nested messages; an unknown key shows as itself.
        let t = msg("common.and").arg("a", "Chrome").arg("b", msg("common.files_one").arg("n", "1"));
        assert_eq!(t.render(Lang::En), "Chrome and 1 file");
        assert_eq!(tr(Lang::Ja, "zz.missing"), "zz.missing");
        assert_eq!(Text::List(vec!["a".into(), "b".into()]).en(), "a; b");
    }

    #[test]
    fn i18n_codes_and_names() {
        assert_eq!(Lang::codes(), "en ja ko zh-Hans zh-Hant th vi id fr de es pt-BR ru pl tr it");
        assert_eq!(Lang::from_code("PT-br"), Some(Lang::PtBr));
        assert_eq!(Lang::from_code("zh-hant"), Some(Lang::ZhHant));
        assert_eq!(Lang::from_code("pt"), None);
        assert_eq!(Lang::Ja.to_string(), "日本語");
        assert_eq!(Lang::ALL.map(Lang::code)[15], "it");
    }

    #[test]
    fn i18n_system_locales() {
        let cases = [
            ("fr_FR.UTF-8", Some(Lang::Fr)),
            ("de-CH", Some(Lang::De)),
            ("de_DE@euro", Some(Lang::De)),
            ("zh_TW.UTF-8", Some(Lang::ZhHant)),
            ("zh-Hant-TW", Some(Lang::ZhHant)),
            ("zh-HK", Some(Lang::ZhHant)),
            ("zh_MO", Some(Lang::ZhHant)),
            ("zh-Hans-HK", Some(Lang::ZhHans)),
            ("zh-CN", Some(Lang::ZhHans)),
            ("zh_SG", Some(Lang::ZhHans)),
            ("zh", Some(Lang::ZhHans)),
            ("es-419", Some(Lang::Es)),
            ("pt-PT", Some(Lang::PtBr)),
            ("pt", Some(Lang::PtBr)),
            ("PT_br", Some(Lang::PtBr)),
            ("in-ID", Some(Lang::Id)),
            ("id_ID.utf8", Some(Lang::Id)),
            ("JA-jp", Some(Lang::Ja)),
            ("ko_KR.EUC-KR", Some(Lang::Ko)),
            ("th-TH", Some(Lang::Th)),
            ("vi", Some(Lang::Vi)),
            ("ru_RU", Some(Lang::Ru)),
            ("pl-PL", Some(Lang::Pl)),
            ("tr_TR", Some(Lang::Tr)),
            ("it-IT", Some(Lang::It)),
            ("en_GB.UTF-8", Some(Lang::En)),
            ("nb-NO", None),
            ("C", None),
            ("C.UTF-8", None),
            ("POSIX", None),
            ("", None),
        ];
        for (locale, lang) in cases {
            assert_eq!(Lang::from_locale(locale), lang, "{locale}");
        }
        // The first supported language of the ordered list wins.
        let list = |l: &[&str]| l.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(first_supported(list(&["nb-NO", "C", "fr-CA", "ja-JP"])), Lang::Fr);
        assert_eq!(first_supported(list(&["nb-NO", "sv-SE"])), Lang::En);
        assert_eq!(first_supported(list(&[])), Lang::En);
    }
}
