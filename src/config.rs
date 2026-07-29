//! Validated JSON configuration (`/etc/mattertimectl/config.json`, camelCase
//! keys).
//!
//! Unknown fields are rejected loudly via serde's `deny_unknown_fields`;
//! device membership deliberately lives in controller storage, not here.

use std::fmt;
use std::path::PathBuf;

use jiff::tz::TimeZone;
use serde::Deserialize;

pub const DEFAULT_CONFIG_PATH: &str = "/etc/mattertimectl/config.json";

/// Matter FabricDescriptorStruct label limit.
const FABRIC_LABEL_MAX_LENGTH: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read configuration file {path}: {source}")]
    Unreadable {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("configuration is not valid: {0}")]
    Invalid(#[from] serde_json::Error),
    #[error("\"timezone\" must be a valid IANA time-zone name (got {0:?})")]
    BadTimezone(String),
    #[error(
        "\"fabricLabel\" must be a non-empty string of at most {FABRIC_LABEL_MAX_LENGTH} characters"
    )]
    BadFabricLabel,
    #[error(
        "\"storagePath\" must be an absolute path (got {0:?}); JSON configs get no shell expansion"
    )]
    RelativeStoragePath(PathBuf),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Debug,
    #[default]
    Info,
    Warn,
    Error,
}

impl From<LogLevel> for log::LevelFilter {
    fn from(level: LogLevel) -> Self {
        match level {
            LogLevel::Debug => log::LevelFilter::Debug,
            LogLevel::Info => log::LevelFilter::Info,
            LogLevel::Warn => log::LevelFilter::Warn,
            LogLevel::Error => log::LevelFilter::Error,
        }
    }
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Warn => "warn",
            LogLevel::Error => "error",
        };
        f.write_str(name)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Config {
    /// Where this configuration was loaded from; not a config field.
    #[serde(skip)]
    pub source: PathBuf,
    /// Directory holding persistent Matter fabric state and service state.
    /// Contains the controller's private keys; mode 0700.
    pub storage_path: PathBuf,
    /// IANA time-zone name, e.g. "America/Chicago". Never a fixed UTC offset.
    #[serde(default = "default_timezone")]
    pub timezone: String,
    #[serde(default)]
    pub log_level: LogLevel,
    /// Fabric label other ecosystems display for this controller (e.g. the
    /// Apple Home Connected Services subtitle). Must be unique per device.
    #[serde(default = "default_fabric_label")]
    pub fabric_label: String,
}

fn default_timezone() -> String {
    "America/Chicago".into()
}

fn default_fabric_label() -> String {
    "Matter Time Controller".into()
}

impl Config {
    pub fn load(path: &std::path::Path) -> Result<Self, ConfigError> {
        let raw = std::fs::read_to_string(path).map_err(|source| ConfigError::Unreadable {
            path: path.to_owned(),
            source,
        })?;
        let mut config = Self::parse(&raw)?;
        config.source = path.to_owned();
        Ok(config)
    }

    pub fn parse(raw: &str) -> Result<Self, ConfigError> {
        let config: Config = serde_json::from_str(raw)?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        // No shell expansion happens on a JSON file, so a "~/..." or relative
        // path would silently land wherever the process happens to run.
        if !self.storage_path.is_absolute() {
            return Err(ConfigError::RelativeStoragePath(self.storage_path.clone()));
        }
        // Resolving through jiff's tzdb is the validation; a bare offset or
        // invented name fails here rather than at 3am on a DST transition.
        TimeZone::get(&self.timezone)
            .map_err(|_| ConfigError::BadTimezone(self.timezone.clone()))?;
        if self.fabric_label.trim().is_empty() || self.fabric_label.len() > FABRIC_LABEL_MAX_LENGTH
        {
            return Err(ConfigError::BadFabricLabel);
        }
        Ok(())
    }

    /// Warnings for path components that look like they expected shell
    /// expansion: a component starting with `~` or containing `$`. Such
    /// directories can legitimately exist, so these cannot be errors; but
    /// far more often they mean the config was written expecting a shell to
    /// expand it, and the data would land in a literal `~foo` directory.
    pub fn path_warnings(&self) -> Vec<String> {
        self.storage_path
            .components()
            .filter_map(|component| {
                let text = component.as_os_str().to_string_lossy();
                let looks_like = if text.starts_with('~') {
                    "a shell tilde"
                } else if text.contains('$') {
                    "an unexpanded shell variable"
                } else {
                    return None;
                };
                Some(format!(
                    "storagePath component {text:?} looks like {looks_like}; JSON configs get no \
                     shell expansion, so it will be used as a literal directory name"
                ))
            })
            .collect()
    }

    /// The configured zone, resolved against the system tzdb.
    pub fn time_zone(&self) -> TimeZone {
        // Validated at load time; a tzdb that shrinks between then and now is
        // not a scenario worth threading a Result through every caller for.
        TimeZone::get(&self.timezone).expect("timezone was validated at config load")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"{ "storagePath": "/var/lib/mattertimectl" }"#;

    #[test]
    fn minimal_config_applies_defaults() {
        let config = Config::parse(MINIMAL).unwrap();
        assert_eq!(
            config.storage_path,
            PathBuf::from("/var/lib/mattertimectl")
        );
        assert_eq!(config.timezone, "America/Chicago");
        assert_eq!(config.log_level, LogLevel::Info);
        assert_eq!(config.fabric_label, "Matter Time Controller");
    }

    #[test]
    fn full_config_round_trips() {
        let config = Config::parse(
            r#"{
                "storagePath": "/tmp/x",
                "timezone": "Europe/Berlin",
                "logLevel": "debug",
                "fabricLabel": "Lakeside Time Sync"
            }"#,
        )
        .unwrap();
        assert_eq!(config.timezone, "Europe/Berlin");
        assert_eq!(config.log_level, LogLevel::Debug);
        assert_eq!(config.fabric_label, "Lakeside Time Sync");
    }

    #[test]
    fn unknown_fields_are_rejected_loudly() {
        // Fields from abandoned designs are rejected, not ignored.
        for raw in [
            r#"{ "storagePath": "/x", "nodeId": "1" }"#,
            r#"{ "storagePath": "/x", "syncIntervalHours": 24 }"#,
            r#"{ "storagePath": "/x", "unexpected": 1 }"#,
        ] {
            let error = Config::parse(raw).unwrap_err();
            assert!(error.to_string().contains("unknown field"), "{error}");
        }
    }

    #[test]
    fn suspicious_path_components_warn_but_load() {
        let config = Config::parse(r#"{ "storagePath": "/data/~backup" }"#).unwrap();
        assert_eq!(config.path_warnings().len(), 1);
        assert!(config.path_warnings()[0].contains("shell tilde"));

        let config = Config::parse(r#"{ "storagePath": "/var/lib/$USER/mts" }"#).unwrap();
        assert!(config.path_warnings()[0].contains("unexpanded shell variable"));

        let config = Config::parse(r#"{ "storagePath": "/var/lib/mattertimectl" }"#).unwrap();
        assert!(config.path_warnings().is_empty());
    }

    #[test]
    fn non_absolute_storage_paths_are_rejected() {
        for path in ["~/mts-storage", "data", "./data"] {
            let raw = format!(r#"{{ "storagePath": {path:?} }}"#);
            let error = Config::parse(&raw).unwrap_err();
            assert!(
                error.to_string().contains("absolute"),
                "accepted {path:?}: {error}"
            );
        }
    }

    #[test]
    fn storage_path_is_required() {
        assert!(Config::parse(r#"{}"#).is_err());
    }

    #[test]
    fn invalid_timezones_are_rejected() {
        for tz in ["Central Time", "", "America/Springfield", "UTC-6"] {
            let raw = format!(r#"{{ "storagePath": "/x", "timezone": {tz:?} }}"#);
            assert!(Config::parse(&raw).is_err(), "accepted {tz:?}");
        }
    }

    #[test]
    fn invalid_log_levels_are_rejected() {
        assert!(Config::parse(r#"{ "storagePath": "/x", "logLevel": "verbose" }"#).is_err());
    }

    #[test]
    fn invalid_fabric_labels_are_rejected() {
        for label in ["", "   ", &"x".repeat(33)] {
            let raw = format!(r#"{{ "storagePath": "/x", "fabricLabel": {label:?} }}"#);
            assert!(Config::parse(&raw).is_err(), "accepted {label:?}");
        }
    }
}
