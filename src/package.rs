//! The package: a manifest of the selected items plus a gzipped tar of the files they carry.
//!
//! Tar layout: `home/<home-relative path>` for dotfiles and folders, `defaults/<domain>.plist`
//! for preference domains. Paths are home-relative, so a package moves between accounts with
//! different user names. Apps are never copied: the destination reinstalls them with
//! `brew bundle` from a Brewfile built out of the manifest.

use std::collections::HashSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, anyhow, bail};
use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use serde::{Deserialize, Serialize};

use crate::inventory::{self, FOLDER_EXCLUDES, Item, Kind};

pub const FORMAT: u32 = 1;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Manifest {
    pub format: u32,
    /// The sending Mac's name.
    pub from: String,
    /// Unix seconds.
    pub created: u64,
    pub items: Vec<Item>,
}

impl Manifest {
    pub fn new(from: String, items: Vec<Item>) -> Manifest {
        Manifest {
            format: FORMAT,
            from,
            created: now(),
            items,
        }
    }
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Counts bytes on their way to the inner writer.
struct Counting<W, F: Fn(u64)> {
    inner: W,
    total: u64,
    progress: F,
}

impl<W: Write, F: Fn(u64)> Write for Counting<W, F> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.total += n as u64;
        (self.progress)(self.total);
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Adds `path` (a file, symlink or directory tree) to the tar as `name`. Sockets and other
/// special files are skipped; `excludes` names are skipped at every level.
fn append<W: Write>(
    tar: &mut tar::Builder<W>,
    path: &Path,
    name: &Path,
    excludes: &[&str],
) -> Result<()> {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return Ok(());
    };
    let ft = meta.file_type();
    if ft.is_dir() {
        tar.append_path_with_name(path, name)?;
        let mut entries: Vec<_> = std::fs::read_dir(path)?.flatten().collect();
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            let file = e.file_name();
            if excludes.contains(&file.to_string_lossy().as_ref()) {
                continue;
            }
            append(tar, &e.path(), &name.join(&file), excludes)?;
        }
    } else if ft.is_file() || ft.is_symlink() {
        // Unreadable files (another user's, or locked) are skipped rather than failing it all.
        if let Err(e) = tar.append_path_with_name(path, name) {
            eprintln!("macpack: skipping {}: {e}", path.display());
        }
    }
    Ok(())
}

/// Streams the package's files for `items` as a gzipped tar into `w`. `on_item` hears which
/// item is being packed; `progress` gets the compressed bytes written so far.
pub fn write_files<W: Write>(
    items: &[Item],
    w: W,
    on_item: impl Fn(usize, &Item),
    progress: impl Fn(u64),
) -> Result<()> {
    let counting = Counting {
        inner: w,
        total: 0,
        progress,
    };
    let gz = GzEncoder::new(counting, Compression::default());
    let mut tar = tar::Builder::new(gz);
    tar.follow_symlinks(false);
    let home = inventory::home();
    for (i, it) in items.iter().enumerate() {
        if it.kind.has_files() {
            on_item(i, it);
        }
        match it.kind {
            Kind::Dotfile => append(
                &mut tar,
                &home.join(&it.id),
                &Path::new("home").join(&it.id),
                &[],
            )?,
            Kind::Folder => append(
                &mut tar,
                &home.join(&it.id),
                &Path::new("home").join(&it.id),
                FOLDER_EXCLUDES,
            )?,
            Kind::Defaults => {
                let out = Command::new("/usr/bin/defaults")
                    .args(["export", &it.id, "-"])
                    .output()
                    .context("run defaults")?;
                if !out.status.success() {
                    continue;
                }
                let mut h = tar::Header::new_gnu();
                h.set_size(out.stdout.len() as u64);
                h.set_mode(0o644);
                h.set_mtime(now());
                h.set_cksum();
                tar.append_data(&mut h, format!("defaults/{}.plist", it.id), &out.stdout[..])?;
            }
            _ => {}
        }
    }
    tar.into_inner()?.finish()?.flush()?;
    Ok(())
}

/// The Brewfile that reinstalls the selected taps, formulae, casks and App Store apps.
pub fn brewfile(items: &[&Item]) -> String {
    let q = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
    let mut out = String::new();
    for kind in [Kind::Tap, Kind::Formula, Kind::Cask, Kind::MasApp] {
        for it in items.iter().filter(|i| i.kind == kind) {
            let line = match kind {
                Kind::Tap => format!("tap \"{}\"", q(&it.id)),
                Kind::Formula => format!("brew \"{}\"", q(&it.id)),
                Kind::Cask => format!("cask \"{}\"", q(&it.id)),
                Kind::MasApp => match it.id.parse::<u64>() {
                    Ok(id) => format!("mas \"{}\", id: {id}", q(&it.label)),
                    Err(_) => continue,
                },
                _ => continue,
            };
            out.push_str(&line);
            out.push('\n');
        }
    }
    out
}

/// `home/.ssh/config` → `.ssh/config`, refusing anything that could escape home.
fn safe_rel(p: &Path) -> Option<PathBuf> {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::Normal(s) => out.push(s),
            Component::CurDir => {}
            _ => return None,
        }
    }
    (!out.as_os_str().is_empty()).then_some(out)
}

/// The selected item a `home/…` tar path belongs to.
fn owner<'a>(items: &'a [&Item], rel: &Path) -> Option<&'a Item> {
    items
        .iter()
        .filter(|i| matches!(i.kind, Kind::Dotfile | Kind::Folder))
        .find(|i| rel.starts_with(&i.id))
        .copied()
}

#[derive(Debug, Clone, PartialEq)]
pub enum Log {
    Step(String),
    Line(String),
    Ok(String),
    Fail(String),
}

/// Unpacks the selected items' files into `home`. Existing files they'd replace are moved to
/// `backup` first. Returns how many files were written.
pub fn unpack_files<R: Read>(
    r: R,
    selected: &[&Item],
    home: &Path,
    backup: &Path,
    defaults_dir: &Path,
) -> Result<usize> {
    let mut tar = tar::Archive::new(GzDecoder::new(r));
    tar.set_preserve_permissions(true);
    tar.set_overwrite(true);
    let mut written = 0;
    for entry in tar.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        if let Ok(rest) = path.strip_prefix("defaults") {
            let Some(domain) = rest
                .to_str()
                .and_then(|s| s.strip_suffix(".plist"))
                .filter(|d| !d.contains('/'))
            else {
                continue;
            };
            if selected
                .iter()
                .any(|i| i.kind == Kind::Defaults && i.id == domain)
            {
                std::fs::create_dir_all(defaults_dir)?;
                entry.unpack(defaults_dir.join(format!("{domain}.plist")))?;
            }
            continue;
        }
        let Some(rel) = path.strip_prefix("home").ok().and_then(safe_rel) else {
            continue;
        };
        if owner(selected, &rel).is_none() {
            continue;
        }
        let dest = home.join(&rel);
        let is_dir = entry.header().entry_type().is_dir();
        if let Ok(meta) = std::fs::symlink_metadata(&dest) {
            // A directory stays and is merged into; anything else in the way is backed up.
            if !(is_dir && meta.is_dir()) {
                let to = backup.join(&rel);
                std::fs::create_dir_all(to.parent().unwrap())?;
                std::fs::rename(&dest, &to)
                    .with_context(|| format!("back up {}", dest.display()))?;
            }
        }
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        entry
            .unpack(&dest)
            .with_context(|| format!("write {}", dest.display()))?;
        if !is_dir {
            written += 1;
        }
    }
    Ok(written)
}

/// ssh refuses keys other users can read: `~/.ssh` 700, keys 600, public keys 644.
#[cfg(unix)]
pub fn fix_ssh_permissions(home: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let ssh = home.join(".ssh");
    let Ok(meta) = std::fs::symlink_metadata(&ssh) else {
        return;
    };
    if !meta.is_dir() {
        return;
    }
    let _ = std::fs::set_permissions(&ssh, std::fs::Permissions::from_mode(0o700));
    for e in std::fs::read_dir(&ssh).into_iter().flatten().flatten() {
        let Ok(m) = std::fs::symlink_metadata(e.path()) else {
            continue;
        };
        if m.is_file() {
            let pubkey = e.path().extension().is_some_and(|x| x == "pub");
            let mode = if pubkey { 0o644 } else { 0o600 };
            let _ = std::fs::set_permissions(e.path(), std::fs::Permissions::from_mode(mode));
        }
    }
}

/// Runs `cmd`, sending each output line to `log`. Fails with the last line on a non-zero exit.
fn run_streaming(mut cmd: Command, log: &dyn Fn(Log)) -> Result<()> {
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("start command")?;
    let stderr = child.stderr.take().unwrap();
    let errs = std::thread::spawn(move || {
        BufReader::new(stderr)
            .lines()
            .map_while(Result::ok)
            .collect::<Vec<_>>()
    });
    for line in BufReader::new(child.stdout.take().unwrap())
        .lines()
        .map_while(Result::ok)
    {
        log(Log::Line(line));
    }
    let errs = errs.join().unwrap_or_default();
    for l in &errs {
        log(Log::Line(l.clone()));
    }
    let status = child.wait()?;
    if status.success() {
        Ok(())
    } else {
        Err(anyhow!(
            "{}",
            errs.last().map(String::as_str).unwrap_or("command failed")
        ))
    }
}

/// Applies a received package: files first (so apps find their settings on first launch),
/// then `brew bundle`, then preference domains. Each step reports to `log`; a failed step
/// doesn't stop the rest. Returns whether every step succeeded.
pub fn apply(pkg: &Path, manifest: &Manifest, keys: &HashSet<String>, log: &dyn Fn(Log)) -> bool {
    let selected: Vec<&Item> = manifest
        .items
        .iter()
        .filter(|i| keys.contains(&i.key()))
        .collect();
    let home = inventory::home();
    let work = crate::store::data_dir()
        .join("applied")
        .join(now().to_string());
    let backup = work.join("backup");
    let defaults_dir = work.join("defaults");
    let mut all_ok = true;
    let mut step = |name: &str, f: &mut dyn FnMut() -> Result<String>| {
        log(Log::Step(name.into()));
        match f() {
            Ok(msg) => log(Log::Ok(msg)),
            Err(e) => {
                all_ok = false;
                log(Log::Fail(format!("{e:#}")));
            }
        }
    };

    if selected.iter().any(|i| i.kind.has_files()) {
        step("Settings, dotfiles and folders", &mut || {
            let f = std::fs::File::open(pkg).with_context(|| format!("open {}", pkg.display()))?;
            let n = unpack_files(f, &selected, &home, &backup, &defaults_dir)?;
            #[cfg(unix)]
            fix_ssh_permissions(&home);
            let moved = backup.exists();
            Ok(if moved {
                format!(
                    "Wrote {n} files. Files they replaced are in {}",
                    backup.display()
                )
            } else {
                format!("Wrote {n} files")
            })
        });
    }

    let bundle = brewfile(&selected);
    if !bundle.is_empty() {
        step("Install apps and tools with Homebrew", &mut || {
            let Some(brew) = inventory::brew() else {
                bail!(
                    "Homebrew isn't installed. Install it from https://brew.sh, then apply this package again."
                );
            };
            std::fs::create_dir_all(&work)?;
            let file = work.join("Brewfile");
            std::fs::write(&file, &bundle)?;
            log(Log::Line(format!("Brewfile: {}", file.display())));
            let mut cmd = Command::new(&brew);
            cmd.args(["bundle", "install", "--no-upgrade", "--file"])
                .arg(&file)
                .env("HOMEBREW_NO_ENV_HINTS", "1")
                .env("HOMEBREW_NO_INSTALL_CLEANUP", "1");
            // Lets brew find `mas` once it has installed them.
            if let Some(dir) = brew.parent() {
                let path = std::env::var_os("PATH").unwrap_or_default();
                let mut paths = vec![dir.to_path_buf()];
                paths.extend(std::env::split_paths(&path));
                if let Ok(p) = std::env::join_paths(paths) {
                    cmd.env("PATH", p);
                }
            }
            run_streaming(cmd, log)?;
            Ok("Homebrew finished".into())
        });
    }

    let domains: Vec<&&Item> = selected
        .iter()
        .filter(|i| i.kind == Kind::Defaults)
        .collect();
    if !domains.is_empty() {
        step("macOS preferences", &mut || {
            let mut done = Vec::new();
            for d in &domains {
                let file = defaults_dir.join(format!("{}.plist", d.id));
                if !file.exists() {
                    continue;
                }
                let st = Command::new("/usr/bin/defaults")
                    .args(["import", &d.id])
                    .arg(&file)
                    .status()?;
                if !st.success() {
                    bail!("defaults import {} failed", d.id);
                }
                done.push(d.label.clone());
            }
            for app in ["Dock", "Finder"] {
                let _ = Command::new("/usr/bin/killall").arg(app).status();
            }
            Ok(format!("Imported {}", done.join(", ")))
        });
    }

    let manual: Vec<&str> = selected
        .iter()
        .filter(|i| i.kind == Kind::ManualApp)
        .map(|i| i.label.as_str())
        .collect();
    if !manual.is_empty() {
        log(Log::Step("Install these by hand".into()));
        for m in &manual {
            log(Log::Line(format!("• {m}")));
        }
        log(Log::Ok(format!(
            "{} apps came from outside Homebrew and the App Store",
            manual.len()
        )));
    }
    all_ok
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(kind: Kind, id: &str, label: &str) -> Item {
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

    #[test]
    fn builds_a_brewfile() {
        let items = [
            item(Kind::Cask, "signal", "Signal"),
            item(Kind::Tap, "vangheem/tap", "vangheem/tap"),
            item(Kind::Formula, "gh", "gh"),
            item(Kind::MasApp, "497799835", "Xcode"),
            item(Kind::Dotfile, ".zshrc", "~/.zshrc"),
        ];
        let refs: Vec<&Item> = items.iter().collect();
        assert_eq!(
            brewfile(&refs),
            "tap \"vangheem/tap\"\nbrew \"gh\"\ncask \"signal\"\nmas \"Xcode\", id: 497799835\n"
        );
    }

    #[test]
    fn rejects_escaping_paths() {
        assert_eq!(safe_rel(Path::new("../etc/passwd")), None);
        assert_eq!(safe_rel(Path::new("/etc/passwd")), None);
        assert_eq!(
            safe_rel(Path::new(".ssh/config")),
            Some(PathBuf::from(".ssh/config"))
        );
    }

    /// Packs a fake home and unpacks it into another: selected items land, existing files
    /// get backed up, unselected items and folder excludes stay behind.
    #[test]
    fn round_trips_files_between_homes() {
        let tmp = std::env::temp_dir().join(format!("macpack-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let (src, dst) = (tmp.join("src"), tmp.join("dst"));
        std::fs::create_dir_all(src.join(".ssh")).unwrap();
        std::fs::create_dir_all(src.join("code/app/node_modules/x")).unwrap();
        std::fs::write(src.join(".zshrc"), "export A=1\n").unwrap();
        std::fs::write(src.join(".gitconfig"), "[user]\n").unwrap();
        std::fs::write(src.join(".ssh/id_ed25519"), "KEY").unwrap();
        std::fs::write(src.join("code/app/main.rs"), "fn main(){}").unwrap();
        std::fs::write(src.join("code/app/node_modules/x/i.js"), "").unwrap();
        std::fs::create_dir_all(&dst).unwrap();
        std::fs::write(dst.join(".zshrc"), "old\n").unwrap();

        // write_files reads from $HOME, so build the tar by hand with the same layout.
        let mut buf = Vec::new();
        {
            let gz = GzEncoder::new(&mut buf, Compression::fast());
            let mut tar = tar::Builder::new(gz);
            for rel in [".zshrc", ".gitconfig", ".ssh"] {
                append(&mut tar, &src.join(rel), &Path::new("home").join(rel), &[]).unwrap();
            }
            append(
                &mut tar,
                &src.join("code"),
                Path::new("home/code"),
                FOLDER_EXCLUDES,
            )
            .unwrap();
            tar.into_inner().unwrap().finish().unwrap();
        }

        let items = [
            item(Kind::Dotfile, ".zshrc", ""),
            item(Kind::Dotfile, ".ssh", ""),
            item(Kind::Folder, "code", ""),
        ];
        let sel: Vec<&Item> = items.iter().collect();
        let backup = tmp.join("backup");
        let n = unpack_files(&buf[..], &sel, &dst, &backup, &tmp.join("defaults")).unwrap();
        assert_eq!(n, 3);
        assert_eq!(
            std::fs::read_to_string(dst.join(".zshrc")).unwrap(),
            "export A=1\n"
        );
        assert_eq!(
            std::fs::read_to_string(backup.join(".zshrc")).unwrap(),
            "old\n"
        );
        assert!(dst.join(".ssh/id_ed25519").exists());
        assert!(dst.join("code/app/main.rs").exists());
        assert!(!dst.join("code/app/node_modules").exists());
        assert!(!dst.join(".gitconfig").exists());
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
