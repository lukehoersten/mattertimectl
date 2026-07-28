//! Local device state kept next to the Matter fabric storage.
//!
//! One JSON file, `devices.json`, holds a record per commissioned device:
//! its cached identity (captured at commissioning, so `status` never has to
//! start the Matter stack) merged with its latest sync results. Written
//! atomically (temp file + rename) so a power loss mid-write never corrupts
//! it. The secret (the root CA key in `identity.json`) is a separate file so
//! these frequent writes never touch it.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

use jiff::Timestamp;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// Everything known locally about one commissioned device.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DeviceRecord {
    pub vendor_name: Option<String>,
    pub product_name: Option<String>,
    pub last_successful_connection: Option<Timestamp>,
    pub last_successful_sync: Option<Timestamp>,
    pub last_attempted_sync: Option<Timestamp>,
    pub last_error: Option<String>,
}

/// The device registry: one record per node, keyed by node ID as a decimal
/// string.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Devices {
    pub nodes: BTreeMap<String, DeviceRecord>,
}

impl Devices {
    pub fn node_ids(&self) -> impl Iterator<Item = u64> + '_ {
        // Keys are written by us; a non-decimal key would be file corruption,
        // which the lenient loader already reduces to "empty".
        self.nodes.keys().filter_map(|key| key.parse().ok())
    }
}

pub fn devices_path(storage: &Path) -> PathBuf {
    storage.join("devices.json")
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
    file.write_all(b"\n")?;
    // Flush to disk before the caller renames over the real file: the
    // atomicity claim is only true if the temp file's bytes are durable,
    // otherwise a power loss can surface the rename with empty content and
    // orphan the root CA key. A one-shot CLI does not care about the cost.
    file.sync_all()
}

#[cfg(not(unix))]
pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    std::fs::write(path, [bytes, b"\n"].concat())
}

/// Merges a patch into one device's record and persists the result.
pub fn update_device(
    path: &Path,
    node_id: u64,
    patch: impl FnOnce(&mut DeviceRecord),
) -> io::Result<()> {
    let mut devices: Devices = load_or_default(path);
    patch(devices.nodes.entry(node_id.to_string()).or_default());
    store(path, &devices)
}

/// Drops one device's record (after decommissioning) and persists the result.
pub fn remove_device(path: &Path, node_id: u64) -> io::Result<()> {
    let mut devices: Devices = load_or_default(path);
    devices.nodes.remove(&node_id.to_string());
    store(path, &devices)
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
    fn record_round_trips_and_merges() {
        let path = tempdir().join("devices.json");
        update_device(&path, 1, |device| {
            device.vendor_name = Some("IKEA of Sweden".into());
            device.last_error = Some("boom".into());
        })
        .unwrap();
        // A later patch merges into the same record, not replacing it.
        update_device(&path, 1, |device| {
            device.last_error = None;
            device.last_successful_sync = Some("2026-07-27T02:20:24.240Z".parse().unwrap());
        })
        .unwrap();

        let devices: Devices = load_or_default(&path);
        let device = &devices.nodes["1"];
        assert_eq!(device.vendor_name.as_deref(), Some("IKEA of Sweden"));
        assert_eq!(device.last_error, None);
        assert!(device.last_successful_sync.is_some());

        remove_device(&path, 1).unwrap();
        let devices: Devices = load_or_default(&path);
        assert!(devices.nodes.is_empty());
    }

    #[test]
    fn corrupt_files_reduce_to_defaults() {
        let path = tempdir().join("corrupt.json");
        std::fs::write(&path, "{ not json").unwrap();
        let devices: Devices = load_or_default(&path);
        assert!(devices.nodes.is_empty());
    }

    #[test]
    fn lists_node_ids() {
        let mut devices = Devices::default();
        devices.nodes.insert(
            "1".into(),
            DeviceRecord {
                vendor_name: Some("IKEA of Sweden".into()),
                product_name: Some("ALPSTUGA air quality monitor".into()),
                ..Default::default()
            },
        );
        assert_eq!(devices.node_ids().collect::<Vec<_>>(), vec![1]);
    }
}
