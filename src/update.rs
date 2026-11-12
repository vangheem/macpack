//! Noticing newer releases, and updating Homebrew installs in place.

use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context, Result, anyhow};

use crate::appbundle;

pub const REPO: &str = "vangheem/macpack";

/// How often a running macpack looks for a new release.
pub const CHECK_EVERY_SECS: f64 = 6.0 * 3600.0;

pub fn current() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

fn parse(v: &str) -> Option<(u64, u64, u64)> {
    let mut it = v
        .trim()
        .trim_start_matches('v')
        .split('.')
        .map(|p| p.parse::<u64>().ok());
    Some((it.next()??, it.next()??, it.next()??))
}

/// Whether `latest` (a tag like `v0.4.0`) is newer than `current`.
pub fn is_newer(latest: &str, current: &str) -> bool {
    matches!((parse(latest), parse(current)), (Some(l), Some(c)) if l > c)
}

/// The latest release's tag, from GitHub's API through `curl` (always on macOS).
pub fn latest_release() -> Result<String> {
    let out = Command::new("/usr/bin/curl")
        .args([
            "-fsSL",
            "--max-time",
            "15",
            "-H",
            "Accept: application/vnd.github+json",
            &format!("https://api.github.com/repos/{REPO}/releases/latest"),
        ])
        .output()
        .context("run curl")?;
    if !out.status.success() {
        return Err(anyhow!(
            "curl: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let v: serde_json::Value = serde_json::from_slice(&out.stdout)?;
    let tag = v["tag_name"].as_str().unwrap_or_default().to_string();
    if parse(&tag).is_none() {
        return Err(anyhow!("unexpected release tag {tag:?}"));
    }
    Ok(tag)
}

/// Homebrew's prefix when this macpack was installed by Homebrew (`/opt/homebrew`).
pub fn brew_prefix() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?.canonicalize().ok()?;
    let s = exe.to_str()?;
    let (prefix, _) = s.split_once("/Cellar/macpack/")?;
    Some(PathBuf::from(prefix))
}

/// `brew update` (so the tap's new formula is seen), then upgrade macpack.
pub fn brew_upgrade(prefix: &std::path::Path) -> Result<()> {
    let brew = prefix.join("bin/brew");
    let run = |args: &[&str]| -> Result<()> {
        let out = Command::new(&brew)
            .args(args)
            .env("HOMEBREW_NO_ENV_HINTS", "1")
            .env("HOMEBREW_NO_AUTO_UPDATE", "1")
            .output()
            .with_context(|| format!("run {}", brew.display()))?;
        if out.status.success() {
            Ok(())
        } else {
            let err = String::from_utf8_lossy(&out.stderr);
            Err(anyhow!(
                "brew {} failed: {}",
                args.join(" "),
                err.trim().lines().last().unwrap_or("")
            ))
        }
    };
    run(&["update", "--quiet"])?;
    run(&["upgrade", "vangheem/tap/macpack"])
}

/// Starts the freshly installed macpack: through the app when this one was opened as the app,
/// else the binary at Homebrew's version-independent path.
pub fn relaunch() -> Result<()> {
    if appbundle::launched_from_app() && appbundle::installed() {
        Command::new("open")
            .arg("-n")
            .arg(appbundle::app_path())
            .spawn()?;
    } else {
        Command::new(appbundle::target_binary()?).spawn()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compares_versions_numerically() {
        assert!(is_newer("v0.10.0", "0.9.3"));
        assert!(is_newer("v1.0.0", "0.3.0"));
        assert!(!is_newer("v0.3.0", "0.3.0"));
        assert!(!is_newer("v0.2.9", "0.3.0"));
        assert!(!is_newer("latest", "0.3.0"));
    }
}

#[cfg(test)]
mod live_tests {
    use super::*;

    /// Hits GitHub and runs Homebrew: `cargo test -- --ignored`. Upgrading an up-to-date
    /// macpack is a no-op, so this proves the commands work without changing anything.
    #[test]
    #[ignore]
    fn reads_the_latest_release_and_brew_upgrade_runs() {
        let tag = latest_release().unwrap();
        assert!(parse(&tag).is_some());
        let prefix = PathBuf::from("/opt/homebrew");
        if prefix.join("Cellar/macpack").exists() {
            brew_upgrade(&prefix).unwrap();
        }
    }
}
