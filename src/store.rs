//! Persistent app data: this Mac's device id, the folders the user added, and which items
//! they turned on or off. Lives in `~/.local/share/macpack/state.json`; received packages sit
//! beside it in `inbox/`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Store {
    /// Random id this Mac advertises on the network.
    #[serde(default)]
    pub device_id: String,
    /// Home-relative folders to bring along.
    #[serde(default)]
    pub folders: BTreeSet<String>,
    /// Item key → selected, where the user overrode the default.
    #[serde(default)]
    pub choices: BTreeMap<String, bool>,
    /// The user chose "Don't ask again" for adding macpack.app to ~/Applications.
    #[serde(default)]
    pub skip_app_prompt: bool,
    /// A release the user chose to skip ("v0.4.0").
    #[serde(default)]
    pub skipped_version: Option<String>,
}

pub fn data_dir() -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".local/share"))
        .join("macpack")
}

impl Store {
    fn path() -> PathBuf {
        data_dir().join("state.json")
    }

    pub fn load() -> Store {
        let mut s: Store = std::fs::read(Self::path())
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default();
        if s.device_id.is_empty() {
            let mut b = [0u8; 6];
            getrandom::getrandom(&mut b).expect("system randomness");
            s.device_id = b.iter().map(|x| format!("{x:02x}")).collect();
            let _ = s.save();
        }
        s
    }

    pub fn save(&self) -> Result<()> {
        let path = Self::path();
        std::fs::create_dir_all(path.parent().unwrap()).context("create data dir")?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(self)?)?;
        std::fs::rename(tmp, path)?;
        Ok(())
    }
}
