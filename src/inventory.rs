//! What's on this Mac: Homebrew taps, formulae and casks, App Store apps, apps nothing can reinstall, dotfiles, macOS preference domains, and folders the user added.
//!
//! Everything is an [`Item`] keyed by `kind:id`; the package is the selected items.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Kind {
    Tap,
    Formula,
    Cask,
    MasApp,
    Dotfile,
    Folder,
    Defaults,
    ManualApp,
}

impl Kind {
    pub const ALL: [Kind; 8] = [
        Kind::Cask,
        Kind::MasApp,
        Kind::Formula,
        Kind::Tap,
        Kind::Dotfile,
        Kind::Folder,
        Kind::Defaults,
        Kind::ManualApp,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Kind::Tap => "Homebrew taps",
            Kind::Formula => "Homebrew formulae",
            Kind::Cask => "Apps from Homebrew",
            Kind::MasApp => "Apps from the App Store",
            Kind::Dotfile => "Settings and dotfiles",
            Kind::Folder => "Folders",
            Kind::Defaults => "macOS preferences",
            Kind::ManualApp => "Other apps (install by hand)",
        }
    }

    /// Whether the item carries files in the package (rather than being reinstalled).
    pub fn has_files(self) -> bool {
        matches!(self, Kind::Dotfile | Kind::Folder | Kind::Defaults)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Item {
    pub kind: Kind,
    /// Formula/cask token, App Store id, extension id, home-relative path, or defaults domain.
    pub id: String,
    pub label: String,
    #[serde(default)]
    pub detail: String,
    /// Bytes on disk, for items that carry files.
    #[serde(default)]
    pub size: Option<u64>,
    /// Too big to measure quickly (see `dotfile_size`).
    #[serde(default)]
    pub size_over: bool,
    /// Selected unless the user says otherwise.
    #[serde(default)]
    pub default_on: bool,
    /// Holds secrets (SSH keys, tokens): flagged in the UI.
    #[serde(default)]
    pub sensitive: bool,
}

impl Item {
    pub fn key(&self) -> String {
        format!("{:?}:{}", self.kind, self.id)
    }

    fn new(kind: Kind, id: impl Into<String>, label: impl Into<String>) -> Item {
        Item {
            kind,
            id: id.into(),
            label: label.into(),
            detail: String::new(),
            size: None,
            size_over: false,
            default_on: true,
            sensitive: false,
        }
    }
}

pub fn home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Homebrew's `brew`, wherever it is (apps opened from Finder have a bare PATH).
pub fn brew() -> Option<PathBuf> {
    ["/opt/homebrew/bin/brew", "/usr/local/bin/brew"]
        .iter()
        .map(PathBuf::from)
        .find(|p| p.exists())
        .or_else(|| which("brew"))
}

pub fn which(cmd: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join(cmd))
        .find(|p| p.is_file())
}

fn lines(cmd: &Path, args: &[&str]) -> Vec<String> {
    let Ok(out) = Command::new(cmd)
        .args(args)
        .env("HOMEBREW_NO_AUTO_UPDATE", "1")
        .output()
    else {
        return Vec::new();
    };
    if !out.status.success() {
        return Vec::new();
    }
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect()
}

/// Dotfiles and directories that are caches, history, toolchains or app state that gets
/// rebuilt: never offered.
const SKIP_DOTFILES: &[&str] = &[
    ".DS_Store",
    ".Trash",
    ".CFUserTextEncoding",
    ".cache",
    ".local",
    ".npm",
    ".cargo",
    ".rustup",
    ".vscode",
    ".vscode-insiders",
    ".cursor",
    ".zsh_sessions",
    ".bash_sessions",
    ".zsh_history",
    ".bash_history",
    ".lesshst",
    ".python_history",
    ".node_repl_history",
    ".psql_history",
    ".sqlite_history",
    ".viminfo",
    ".wget-hsts",
    ".gradle",
    ".m2",
    ".pyenv",
    ".nvm",
    ".bun",
    ".deno",
    ".gem",
    ".cocoapods",
    ".android",
    ".expo",
    ".yarn",
    ".pnpm-store",
    ".colima",
    ".orbstack",
    ".lima",
    ".ollama",
    ".dropbox",
    ".Spotlight-V100",
    ".fseventsd",
    ".swiftpm",
    ".dartServer",
    ".pub-cache",
    ".gk",
    ".matplotlib",
    ".ipython",
    ".keras",
    ".conda",
    ".gnupg/S.gpg-agent",
];

/// `~/.config` children that are caches too.
const SKIP_CONFIG: &[&str] = &["configstore", "gcloud/logs", "op/op-daemon.sock"];

/// Dotfiles bigger than this start unselected (they're usually state, not settings).
pub const BIG: u64 = 20 * 1024 * 1024;

/// Entries the package leaves out of folders: rebuilt by tools, and often huge.
pub const FOLDER_EXCLUDES: &[&str] = &[".DS_Store", "node_modules", ".venv", "__pycache__"];

fn is_sensitive(rel: &str) -> bool {
    [
        ".ssh",
        ".gnupg",
        ".aws",
        ".netrc",
        ".npmrc",
        ".pypirc",
        ".docker",
        ".kube",
        ".config/gh",
        ".git-credentials",
    ]
    .iter()
    .any(|s| rel == *s || rel.starts_with(&format!("{s}/")))
}

/// Size of a file or directory tree (symlinks count as themselves), giving up once it passes
/// `BIG` bytes or `MAX_ENTRIES` entries: past that it's state, not settings, and walking a
/// model cache or a VM image directory would stall the scan.
fn dotfile_size(p: &Path, total: &mut u64, entries: &mut u32) -> bool {
    const MAX_ENTRIES: u32 = 20_000;
    let Ok(meta) = std::fs::symlink_metadata(p) else {
        return true;
    };
    *entries += 1;
    *total += if meta.is_dir() { 0 } else { meta.len() };
    if *total > BIG || *entries > MAX_ENTRIES {
        return false;
    }
    if meta.is_dir() {
        for e in std::fs::read_dir(p).into_iter().flatten().flatten() {
            if !dotfile_size(&e.path(), total, entries) {
                return false;
            }
        }
    }
    true
}

pub fn dotfile_item(rel: &str) -> Item {
    let (mut size, mut entries) = (0, 0);
    let small = dotfile_size(&home().join(rel), &mut size, &mut entries);
    let mut it = Item::new(Kind::Dotfile, rel, format!("~/{rel}"));
    it.sensitive = is_sensitive(rel);
    it.default_on = small;
    if small {
        it.size = Some(size);
    } else {
        it.size_over = true;
    }
    if rel == ".ssh" {
        it.detail = "SSH keys and config".into();
    } else if it.sensitive {
        it.detail = "Contains credentials".into();
    } else if !small {
        it.detail = "Large; probably app state or caches".into();
    }
    it
}

/// Home dotfiles, with `~/.config` split into its children.
pub fn dotfiles(on: OnProgress) -> Vec<Item> {
    let home = home();
    let mut rels = Vec::new();
    for e in std::fs::read_dir(&home).into_iter().flatten().flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if !name.starts_with('.') || SKIP_DOTFILES.contains(&name.as_str()) {
            continue;
        }
        if name.starts_with(".zcompdump") || name.ends_with(".lock") {
            continue;
        }
        if name == ".config" {
            for c in std::fs::read_dir(e.path()).into_iter().flatten().flatten() {
                let child = c.file_name().to_string_lossy().to_string();
                if child == ".DS_Store" || SKIP_CONFIG.contains(&child.as_str()) {
                    continue;
                }
                rels.push(format!(".config/{child}"));
            }
            continue;
        }
        rels.push(name);
    }
    rels.sort();
    std::thread::scope(|sc| {
        let handles: Vec<_> = rels
            .iter()
            .map(|r| {
                sc.spawn(move || {
                    on(Progress::Detail(DOTFILES, format!("~/{r}")));
                    dotfile_item(r)
                })
            })
            .collect();
        handles.into_iter().filter_map(|h| h.join().ok()).collect()
    })
}

pub fn folder_item(rel: &str) -> Item {
    let mut it = Item::new(Kind::Folder, rel, format!("~/{rel}"));
    it.size = Some(folder_size(&home().join(rel)));
    it
}

fn folder_size(p: &Path) -> u64 {
    let Ok(meta) = std::fs::symlink_metadata(p) else {
        return 0;
    };
    if !meta.is_dir() {
        return meta.len();
    }
    std::fs::read_dir(p)
        .map(|it| {
            it.flatten()
                .filter(|e| !FOLDER_EXCLUDES.contains(&e.file_name().to_string_lossy().as_ref()))
                .map(|e| folder_size(&e.path()))
                .sum()
        })
        .unwrap_or(0)
}

/// macOS preference domains worth carrying over. Importing them replaces the domain, so
/// they start unselected.
const DEFAULTS: &[(&str, &str)] = &[
    ("com.apple.dock", "Dock"),
    ("com.apple.finder", "Finder"),
    ("com.apple.AppleMultitouchTrackpad", "Trackpad"),
    ("com.apple.screencapture", "Screenshots"),
    ("com.apple.Terminal", "Terminal"),
];

fn defaults_items() -> Vec<Item> {
    DEFAULTS
        .iter()
        .map(|(domain, label)| {
            let mut it = Item::new(Kind::Defaults, *domain, *label);
            it.detail = (*domain).into();
            it.default_on = false;
            it
        })
        .collect()
}

/// `brew info --json=v2 --installed`'s casks: token → the `.app` names they install.
fn cask_apps(brew: &Path) -> (Vec<Item>, HashSet<String>) {
    let out = Command::new(brew)
        .args(["info", "--cask", "--json=v2", "--installed"])
        .env("HOMEBREW_NO_AUTO_UPDATE", "1")
        .output();
    let mut items = Vec::new();
    let mut apps = HashSet::new();
    let Ok(out) = out else {
        return (items, apps);
    };
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&out.stdout) else {
        return (items, apps);
    };
    for c in v["casks"].as_array().into_iter().flatten() {
        let Some(token) = c["token"].as_str() else {
            continue;
        };
        let name = c["name"][0].as_str().unwrap_or(token);
        let mut it = Item::new(Kind::Cask, token, name);
        it.detail = c["desc"].as_str().unwrap_or_default().into();
        items.push(it);
        for art in c["artifacts"].as_array().into_iter().flatten() {
            for app in art["app"].as_array().into_iter().flatten() {
                if let Some(a) = app.as_str() {
                    apps.insert(a.rsplit('/').next().unwrap_or(a).to_string());
                }
            }
        }
    }
    items.sort_by_key(|a| a.label.to_lowercase());
    (items, apps)
}

/// `mas list` lines: `497799835  Xcode  (15.0)` (older mas: `497799835 Xcode (15.0)`).
pub fn parse_mas(lines: &[String]) -> Vec<Item> {
    lines
        .iter()
        .filter_map(|l| {
            let (id, rest) = l.trim().split_once(char::is_whitespace)?;
            id.parse::<u64>().ok()?;
            let name = match rest.rfind('(') {
                Some(i) => &rest[..i],
                None => rest,
            }
            .trim();
            Some(Item::new(Kind::MasApp, id, name))
        })
        .collect()
}

fn info_plist_value(app: &Path, key: &str) -> Option<String> {
    let out = Command::new("/usr/bin/plutil")
        .args(["-extract", key, "raw", "-o", "-"])
        .arg(app.join("Contents/Info.plist"))
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// `.app` name → cask token for every cask in Homebrew's catalogue, so apps installed by hand
/// can be reinstalled with Homebrew on the new Mac. The catalogue is ~20 MB, so the map is
/// cached for a week in the data dir. Empty when offline.
fn cask_catalogue() -> HashMap<String, String> {
    let cache = crate::store::data_dir().join("cask-apps.json");
    let fresh = std::fs::metadata(&cache)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.elapsed().ok())
        .is_some_and(|age| age.as_secs() < 7 * 86_400);
    if fresh
        && let Some(map) = std::fs::read(&cache)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
    {
        return map;
    }
    let Ok(out) = Command::new("/usr/bin/curl")
        .args([
            "-fsSL",
            "--max-time",
            "60",
            "https://formulae.brew.sh/api/cask.json",
        ])
        .output()
    else {
        return HashMap::new();
    };
    let Ok(serde_json::Value::Array(casks)) = serde_json::from_slice(&out.stdout) else {
        return HashMap::new();
    };
    let map = catalogue_apps(&casks);
    if !map.is_empty() {
        let _ = std::fs::create_dir_all(cache.parent().unwrap());
        let _ = std::fs::write(&cache, serde_json::to_vec(&map).unwrap_or_default());
    }
    map
}

/// The `.app`s each cask installs. Casks that only run a `.pkg` (Microsoft Office, Zoom) have
/// no app artifact; they're matched on their display name instead, when no other cask has it.
fn catalogue_apps(casks: &[serde_json::Value]) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let mut by_name: HashMap<String, Vec<String>> = HashMap::new();
    for c in casks {
        let Some(token) = c["token"].as_str() else {
            continue;
        };
        if c["deprecated"].as_bool() == Some(true) || c["disabled"].as_bool() == Some(true) {
            continue;
        }
        let mut has_app = false;
        for art in c["artifacts"].as_array().into_iter().flatten() {
            for app in art["app"].as_array().into_iter().flatten() {
                if let Some(a) = app.as_str() {
                    has_app = true;
                    let name = a.rsplit('/').next().unwrap_or(a).to_string();
                    // Prefer the plain cask over variants (`firefox` over `firefox@beta`).
                    let better = map
                        .get(&name)
                        .is_none_or(|t: &String| t.contains('@') && !token.contains('@'));
                    if better {
                        map.insert(name, token.to_string());
                    }
                }
            }
        }
        if !has_app && !token.contains('@') {
            for n in c["name"].as_array().into_iter().flatten() {
                if let Some(n) = n.as_str() {
                    by_name
                        .entry(format!("{n}.app"))
                        .or_default()
                        .push(token.to_string());
                }
            }
        }
    }
    for (app, tokens) in by_name {
        if let [token] = tokens.as_slice() {
            map.entry(app).or_insert_with(|| token.clone());
        }
    }
    map
}

/// Apps in /Applications that neither Homebrew nor the App Store installed, and aren't Apple's.
/// Ones Homebrew has a cask for become casks; the rest have to be installed by hand.
fn manual_apps(from_casks: &HashSet<String>, catalogue: &HashMap<String, String>) -> Vec<Item> {
    let mut items = Vec::new();
    for e in std::fs::read_dir("/Applications")
        .into_iter()
        .flatten()
        .flatten()
    {
        let name = e.file_name().to_string_lossy().to_string();
        let Some(label) = name.strip_suffix(".app") else {
            continue;
        };
        let path = e.path();
        if from_casks.contains(&name) || path.join("Contents/_MASReceipt").exists() {
            continue;
        }
        let id = info_plist_value(&path, "CFBundleIdentifier").unwrap_or_default();
        if id.starts_with("com.apple.") {
            continue;
        }
        let mut it = match catalogue.get(&name) {
            Some(token) => {
                let mut it = Item::new(Kind::Cask, token, label);
                it.detail = format!("Installed by hand; Homebrew has it as {token}");
                it
            }
            None => {
                let mut it = Item::new(Kind::ManualApp, &name, label);
                it.detail = id;
                it
            }
        };
        it.label = label.to_string();
        items.push(it);
    }
    items.sort_by_key(|a| a.label.to_lowercase());
    items
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Inventory {
    pub items: Vec<Item>,
    /// Missing tools worth telling the user about ("mas isn't installed…").
    pub notes: Vec<String>,
    /// Unix seconds when the scan finished.
    #[serde(default)]
    pub scanned: u64,
}

/// What a running scan reports, for showing progress. Steps run in parallel, so several can
/// be under way at once.
#[derive(Debug, Clone, PartialEq)]
pub enum Progress {
    Start(&'static str),
    /// What the step is looking at now (`~/.config/zed`).
    Detail(&'static str, String),
    /// Finished, with a short result ("35 found").
    Done(&'static str, String),
}

pub type OnProgress<'a> = &'a (dyn Fn(Progress) + Sync);

/// Runs `f` as a progress step, reporting how many items it found.
fn step<T>(on: OnProgress, name: &'static str, f: impl FnOnce() -> Vec<T>) -> Vec<T> {
    on(Progress::Start(name));
    let out = f();
    on(Progress::Done(name, format!("{} found", out.len())));
    out
}

fn cache_path() -> PathBuf {
    crate::store::data_dir().join("inventory.json")
}

impl Inventory {
    /// The last scan, so a relaunch shows it straight away while a fresh scan runs.
    pub fn load_cached() -> Option<Inventory> {
        serde_json::from_slice(&std::fs::read(cache_path()).ok()?).ok()
    }

    pub fn save_cached(&self) {
        let p = cache_path();
        let _ = std::fs::create_dir_all(p.parent().unwrap());
        let _ = std::fs::write(p, serde_json::to_vec(self).unwrap_or_default());
    }
}

/// Scans this Mac. Slow (seconds): run it off the UI thread.
pub fn scan(folders: &BTreeSet<String>, on: OnProgress) -> Inventory {
    let (mut inv, files, dirs) = std::thread::scope(|sc| {
        let files = sc.spawn(|| step(on, DOTFILES, || dotfiles(on)));
        let dirs = sc.spawn(|| {
            if folders.is_empty() {
                return Vec::new();
            }
            step(on, FOLDERS, || {
                std::thread::scope(|sc| {
                    let hs: Vec<_> = folders
                        .iter()
                        .map(|f| {
                            sc.spawn(move || {
                                on(Progress::Detail(FOLDERS, format!("~/{f}")));
                                folder_item(f)
                            })
                        })
                        .collect();
                    hs.into_iter().filter_map(|h| h.join().ok()).collect()
                })
            })
        });
        let inv = installs(on);
        (
            inv,
            files.join().unwrap_or_default(),
            dirs.join().unwrap_or_default(),
        )
    });
    let manual = inv.items.split_off(
        inv.items
            .iter()
            .position(|i| i.kind == Kind::ManualApp)
            .unwrap_or(inv.items.len()),
    );
    inv.items.extend(files);
    inv.items.extend(dirs);
    inv.items.extend(defaults_items());
    inv.items.extend(manual);
    inv.scanned = crate::package::now();
    inv
}

const DOTFILES: &str = "Settings and dotfiles";
const FOLDERS: &str = "Folders";

/// What gets reinstalled rather than copied: taps, formulae, casks, App Store apps, and (last) the apps nothing can reinstall.
pub fn installs(on: OnProgress) -> Inventory {
    let mut inv = Inventory::default();
    let mut from_casks = HashSet::new();
    match brew() {
        Some(brew) => {
            inv.items.extend(step(on, "Homebrew taps", || {
                lines(&brew, &["tap"])
                    .into_iter()
                    .filter(|t| t != "homebrew/core" && t != "homebrew/cask")
                    .map(|t| Item::new(Kind::Tap, &t, &t))
                    .collect()
            }));
            inv.items.extend(step(on, "Homebrew formulae", || {
                let mut leaves = lines(&brew, &["leaves", "--installed-on-request"]);
                if leaves.is_empty() {
                    leaves = lines(&brew, &["leaves"]);
                }
                leaves
                    .into_iter()
                    .map(|f| {
                        let label = f.rsplit('/').next().unwrap_or(&f).to_string();
                        Item::new(Kind::Formula, &f, label)
                    })
                    .collect()
            }));
            inv.items.extend(step(on, "Apps from Homebrew", || {
                let (casks, apps) = cask_apps(&brew);
                from_casks = apps;
                casks
            }));
        }
        None => inv
            .notes
            .push("Homebrew isn't installed, so formulae and casks aren't listed.".into()),
    }
    match which("mas").or_else(|| {
        ["/opt/homebrew/bin/mas", "/usr/local/bin/mas"]
            .iter()
            .map(PathBuf::from)
            .find(|p| p.exists())
    }) {
        Some(mas) => inv.items.extend(step(on, "App Store apps", || {
            parse_mas(&lines(&mas, &["list"]))
        })),
        None => inv.notes.push(
            "App Store apps are listed with `mas` (brew install mas); without it they show under Other apps."
                .into(),
        ),
    }
    let installed: HashSet<String> = inv
        .items
        .iter()
        .filter(|i| i.kind == Kind::Cask)
        .map(|i| i.id.clone())
        .collect();
    const APPS: &str = "Other apps in /Applications";
    on(Progress::Start(APPS));
    on(Progress::Detail(
        APPS,
        "Matching them to Homebrew casks".into(),
    ));
    let found = manual_apps(&from_casks, &cask_catalogue());
    on(Progress::Done(APPS, format!("{} found", found.len())));
    let (casks, manual): (Vec<Item>, Vec<Item>) = found
        .into_iter()
        .filter(|i| !(i.kind == Kind::Cask && installed.contains(&i.id)))
        .partition(|i| i.kind == Kind::Cask);
    inv.items.extend(casks);
    inv.items.extend(manual);
    inv
}

/// `/Users/me/projects/x` or `~/projects/x` → `projects/x`, for folders under home.
pub fn home_relative(input: &str) -> Option<String> {
    let s = input.trim().trim_end_matches('/');
    let home = home();
    let rel = if let Some(r) = s.strip_prefix("~/") {
        r.to_string()
    } else {
        Path::new(s)
            .strip_prefix(&home)
            .ok()?
            .to_string_lossy()
            .to_string()
    };
    let ok = !rel.is_empty() && !rel.split('/').any(|p| p == ".." || p.is_empty());
    ok.then_some(rel)
}

pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = bytes as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{bytes} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_mas_list() {
        let items = parse_mas(&[
            "497799835  Xcode  (15.0)".into(),
            "1295203466 Microsoft Remote Desktop (10.9.4)".into(),
            "garbage".into(),
        ]);
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].id, "497799835");
        assert_eq!(items[0].label, "Xcode");
        assert_eq!(items[1].label, "Microsoft Remote Desktop");
    }

    #[test]
    fn maps_apps_to_casks() {
        let casks: Vec<serde_json::Value> = serde_json::from_str(
            r#"[
              {"token": "firefox@beta", "artifacts": [{"app": ["Firefox.app"]}]},
              {"token": "firefox", "artifacts": [{"app": ["Firefox.app"]}]},
              {"token": "zoom", "name": ["Zoom"], "artifacts": [{"pkg": ["zoomusInstaller.pkg"]}]},
              {"token": "old", "deprecated": true, "artifacts": [{"app": ["Old.app"]}]}
            ]"#,
        )
        .unwrap();
        let map = catalogue_apps(&casks);
        assert_eq!(map.get("Firefox.app").map(String::as_str), Some("firefox"));
        assert_eq!(map.get("Zoom.app").map(String::as_str), Some("zoom"));
        assert_eq!(map.get("Old.app"), None);
    }

    #[test]
    fn folders_must_be_under_home() {
        let h = home().display().to_string();
        assert_eq!(home_relative("~/projects/").as_deref(), Some("projects"));
        assert_eq!(home_relative(&format!("{h}/a/b")).as_deref(), Some("a/b"));
        assert_eq!(home_relative("/etc"), None);
        assert_eq!(home_relative("~/../x"), None);
    }
}
