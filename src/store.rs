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
    /// Named selections the user saved, to reuse later.
    #[serde(default)]
    pub sets: BTreeMap<String, Selection>,
    /// The set being edited: changes to the selection are saved into it.
    #[serde(default)]
    pub active_set: Option<String>,
    /// The user chose "Don't ask again" for adding macpack.app to ~/Applications.
    #[serde(default)]
    pub skip_app_prompt: bool,
    /// A release the user chose to skip ("v0.4.0").
    #[serde(default)]
    pub skipped_version: Option<String>,
}

/// What's ticked: folders added, and items turned on or off against their defaults.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Selection {
    #[serde(default)]
    pub folders: BTreeSet<String>,
    #[serde(default)]
    pub choices: BTreeMap<String, bool>,
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
            let _ = s.write();
        }
        s
    }

    fn selection(&self) -> Selection {
        Selection {
            folders: self.folders.clone(),
            choices: self.choices.clone(),
        }
    }

    /// Saves the current selection as `name` and makes it the active set.
    pub fn save_set(&mut self, name: &str) {
        self.sets.insert(name.to_string(), self.selection());
        self.active_set = Some(name.to_string());
    }

    /// Makes `name` the current selection.
    pub fn load_set(&mut self, name: &str) -> bool {
        let Some(sel) = self.sets.get(name).cloned() else {
            return false;
        };
        self.folders = sel.folders;
        self.choices = sel.choices;
        self.active_set = Some(name.to_string());
        true
    }

    pub fn delete_set(&mut self, name: &str) {
        self.sets.remove(name);
        if self.active_set.as_deref() == Some(name) {
            self.active_set = None;
        }
    }

    /// Writes the selection into the active set (and the state file). The selection itself is
    /// always saved, so a relaunch picks up where it left off.
    pub fn save(&mut self) -> Result<()> {
        if let Some(name) = self.active_set.clone()
            && self.sets.contains_key(&name)
        {
            let sel = self.selection();
            self.sets.insert(name, sel);
        }
        self.write()
    }

    fn write(&self) -> Result<()> {
        let path = Self::path();
        std::fs::create_dir_all(path.parent().unwrap()).context("create data dir")?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(self)?)?;
        std::fs::rename(tmp, path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sets_save_load_and_follow_edits() {
        let mut s = Store::default();
        s.folders.insert("projects".into());
        s.choices.insert("Cask:zoom".into(), false);
        s.sets.insert("work".into(), s.selection());
        s.active_set = Some("work".into());
        // Edits to the active set are kept in it.
        s.choices.insert("Cask:slack".into(), true);
        let sel = s.selection();
        s.sets.insert("work".into(), sel);
        s.save_set("personal");
        s.folders.clear();
        s.choices.clear();
        assert!(s.load_set("work"));
        assert!(s.folders.contains("projects"));
        assert_eq!(s.choices.get("Cask:slack"), Some(&true));
        assert_eq!(s.active_set.as_deref(), Some("work"));
        s.delete_set("work");
        assert_eq!(s.active_set, None);
        assert!(!s.load_set("work"));
    }
}
