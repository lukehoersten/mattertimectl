//! Local service state kept next to the Matter fabric storage.
//!
//! Two small JSON files, both written atomically (temp file + rename) so a
//! power loss mid-write never corrupts them:
//!
//! - `service-state.json`: per-node sync results, file-compatible with the
//!   TypeScript implementation.
//! - `nodes.json`: the node registry (id plus cached vendor/product names),
//!   written at commissioning time so `nodes` and `status` never need to
//!   start the Matter stack.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

use jiff::Timestamp;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct NodeState {
    pub last_successful_connection: Option<Timestamp>,
    pub last_successful_sync: Option<Timestamp>,
    pub last_attempted_sync: Option<Timestamp>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ServiceState {
    /// Keyed by node ID as a decimal string, like the TypeScript state file.
    pub nodes: BTreeMap<String, NodeState>,
}

/// Cached identity of a commissioned node, captured at commissioning.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct NodeInfo {
    pub vendor_name: Option<String>,
    pub product_name: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NodeRegistry {
    pub nodes: BTreeMap<String, NodeInfo>,
}

impl NodeRegistry {
    pub fn node_ids(&self) -> impl Iterator<Item = u64> + '_ {
        // Registry keys are written by us; a non-decimal key would be file
        // corruption, which the lenient loader already reduces to "empty".
        self.nodes.keys().filter_map(|key| key.parse().ok())
    }
}

pub fn service_state_path(storage: &Path) -> PathBuf {
    storage.join("service-state.json")
}

pub fn registry_path(storage: &Path) -> PathBuf {
    storage.join("nodes.json")
}

/// Reads a state file leniently: missing or corrupt files yield the default.
/// These files hold status metadata only; refusing to run over them would
/// turn a scratched cache into an outage.
pub fn load_or_default<T: DeserializeOwned + Default>(path: &Path) -> T {
    match std::fs::read_to_string(path) {
        Ok(raw) => serde_json::from_str(&raw).unwrap_or_default(),
        Err(_) => T::default(),
    }
}

/// Atomic JSON write: temp file in the same directory, then rename.
pub fn store<T: Serialize>(path: &Path, value: &T) -> io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    let tmp = path.with_extension("json.tmp");
    let body = serde_json::to_string_pretty(value).expect("state serialization cannot fail");
    write_private(&tmp, body.as_bytes())?;
    std::fs::rename(&tmp, path)
}

#[cfg(unix)]
pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.write_all(b"\n")
}

#[cfg(not(unix))]
pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    std::fs::write(path, [bytes, b"\n"].concat())
}

/// Merges a patch into one node's entry and persists the result.
pub fn update_node_state(
    path: &Path,
    node_id: u64,
    patch: impl FnOnce(&mut NodeState),
) -> io::Result<()> {
    let mut state: ServiceState = load_or_default(path);
    patch(state.nodes.entry(node_id.to_string()).or_default());
    store(path, &state)
}

/// Drops one node's entry (after decommissioning) and persists the result.
pub fn remove_node_state(path: &Path, node_id: u64) -> io::Result<()> {
    let mut state: ServiceState = load_or_default(path);
    state.nodes.remove(&node_id.to_string());
    store(path, &state)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("mts-state-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn state_round_trips_and_merges() {
        let path = tempdir().join("service-state.json");
        update_node_state(&path, 1, |node| {
            node.last_error = Some("boom".into());
        })
        .unwrap();
        update_node_state(&path, 1, |node| {
            node.last_error = None;
            node.last_successful_sync = Some("2026-07-27T02:20:24.240Z".parse().unwrap());
        })
        .unwrap();

        let state: ServiceState = load_or_default(&path);
        let node = &state.nodes["1"];
        assert_eq!(node.last_error, None);
        assert!(node.last_successful_sync.is_some());

        remove_node_state(&path, 1).unwrap();
        let state: ServiceState = load_or_default(&path);
        assert!(state.nodes.is_empty());
    }

    #[test]
    fn reads_typescript_state_files() {
        // Exact shape written by the TypeScript implementation.
        let raw = r#"{
            "nodes": {
                "1": {
                    "lastSuccessfulConnection": "2026-07-27T02:20:23.357Z",
                    "lastSuccessfulSync": "2026-07-27T02:20:24.240Z",
                    "lastAttemptedSync": "2026-07-27T02:20:22.437Z",
                    "lastError": null
                }
            }
        }"#;
        let state: ServiceState = serde_json::from_str(raw).unwrap();
        assert_eq!(state.nodes["1"].last_error, None);
        assert!(state.nodes["1"].last_successful_sync.is_some());
    }

    #[test]
    fn corrupt_files_reduce_to_defaults() {
        let path = tempdir().join("corrupt.json");
        std::fs::write(&path, "{ not json").unwrap();
        let state: ServiceState = load_or_default(&path);
        assert!(state.nodes.is_empty());
    }

    #[test]
    fn registry_lists_node_ids() {
        let mut registry = NodeRegistry::default();
        registry.nodes.insert(
            "1".into(),
            NodeInfo {
                vendor_name: Some("IKEA of Sweden".into()),
                product_name: Some("ALPSTUGA air quality monitor".into()),
            },
        );
        assert_eq!(registry.node_ids().collect::<Vec<_>>(), vec![1]);
    }
}
