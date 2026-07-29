//! The typed output layer.
//!
//! Every command handler returns an [`Output`]; printing happens exactly
//! once, in `main`, from that value. The CLI invariants are enforced here by
//! construction rather than by convention:
//!
//! - the set of top-level JSON shapes is closed (this enum), so a command
//!   cannot invent an envelope or emit a naked array;
//! - JSON formatting is uniform because [`print_json`] is the only printer;
//! - the exit code is derived from the output value by [`Output::exit_code`],
//!   so it cannot disagree with what was reported;
//! - human and JSON renderings are fed by the same data, so they cannot
//!   drift apart in content.

use std::path::PathBuf;
use std::process::ExitCode;

use jiff::Timestamp;
use serde::Serialize;

use crate::controller::{CommissionOutcome, DecommissionOutcome, InspectOutcome, SyncOutcome};
use crate::time::CompactDuration;
use crate::tz::format_utc_offset;

/// A 64-bit Matter identifier (node ID, fabric ID). Serializes as a decimal
/// string, never as a JSON number, which silently loses precision beyond
/// 2^53 in many consumers. The rule lives in the type, so an ID field
/// cannot be emitted wrongly.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Id64(pub u64);

impl Serialize for Id64 {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl std::fmt::Display for Id64 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl From<u64> for Id64 {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

/// Everything a command can say. Untagged: each variant serializes as its
/// own object with descriptive top-level keys.
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum Output {
    Status(Box<StatusReport>),
    Inspection {
        nodes: Vec<InspectOutcome>,
    },
    Sync(SyncReport),
    Commissioned {
        nodes: Vec<CommissionOutcome>,
    },
    #[serde(rename_all = "camelCase")]
    Decommission {
        nodes: Vec<DecommissionOutcome>,
        remaining_nodes: Vec<String>,
    },
    Error {
        error: String,
    },
}

/// Everything that was parsed from the configuration file, echoed back so
/// an operator can see exactly what the tool is running with.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigReport {
    pub source: PathBuf,
    pub storage_path: PathBuf,
    pub timezone: String,
    pub log_level: String,
    pub fabric_label: String,
    pub output: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusReport {
    pub config: ConfigReport,
    pub storage_initialized: bool,
    pub controller_identity: IdentityReport,
    pub host_ntp_synchronized: bool,
    pub current_utc_offset_seconds: i32,
    pub current_utc_offset: String,
    pub next_dst_transition: Option<DstTransition>,
    pub matter_time_now_microseconds: String,
    /// One entry per commissioned device: registry identity merged with
    /// the latest sync state.
    pub nodes: Vec<NodeListing>,
}

#[derive(Debug, Serialize)]
#[serde(
    tag = "state",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum IdentityReport {
    NotCreated,
    Created {
        fabric_id: String,
        controller_node_id: String,
    },
    Unreadable,
    Inconsistent {
        reason: String,
    },
}

impl From<crate::controller::IdentityStatus> for IdentityReport {
    fn from(status: crate::controller::IdentityStatus) -> Self {
        use crate::controller::IdentityStatus as S;
        match status {
            S::NotCreated => Self::NotCreated,
            S::Created {
                fabric_id,
                controller_node_id,
            } => Self::Created {
                fabric_id: fabric_id.to_string(),
                controller_node_id: controller_node_id.to_string(),
            },
            S::Unreadable => Self::Unreadable,
            S::Inconsistent(reason) => Self::Inconsistent {
                reason: reason.to_string(),
            },
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DstTransition {
    pub at: String,
    pub offset_before_seconds: i32,
    pub offset_after_seconds: i32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeListing {
    pub node_id: Id64,
    pub vendor_name: Option<String>,
    pub product_name: Option<String>,
    pub last_successful_connection: Option<Timestamp>,
    pub last_successful_sync: Option<Timestamp>,
    pub last_attempted_sync: Option<Timestamp>,
    pub last_error: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncReport {
    pub host_ntp_synchronized: bool,
    /// Set when the operator supplied --time: the written instant.
    pub manual_time: Option<String>,
    pub nodes: Vec<SyncOutcome>,
}

impl Output {
    /// The exit code is a function of the reported outcome; a handler cannot
    /// return one that disagrees with its output. 0 = success (including
    /// empty-but-valid results), 1 = any failure. Skipped devices are not
    /// failures.
    pub fn exit_code(&self) -> ExitCode {
        let ok = match self {
            Output::Status(_) | Output::Commissioned { .. } => true,
            Output::Inspection { nodes } => nodes.iter().all(|n| n.error.is_none()),
            Output::Sync(report) => {
                // With --time the operator is the time source; the NTP
                // verdict is informational only.
                (report.host_ntp_synchronized || report.manual_time.is_some())
                    && report.nodes.iter().all(|n| n.success || n.skipped)
            }
            Output::Decommission { nodes, .. } => nodes.iter().all(|n| n.success),
            Output::Error { .. } => false,
        };
        if ok {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        }
    }

    /// The one JSON printer: pretty, one object, always parseable.
    pub fn print_json(&self) {
        match serde_json::to_string_pretty(self) {
            Ok(body) => println!("{body}"),
            // Build the fallback with the serializer too, so the error text
            // is escaped and stdout stays valid JSON even here.
            Err(error) => println!(
                "{}",
                serde_json::json!({ "error": format!("serialize output: {error}") })
            ),
        }
    }

    pub fn render_human(&self) {
        match self {
            Output::Status(report) => render_status(report),
            Output::Inspection { nodes } => render_inspection(nodes),
            Output::Sync(report) => render_sync(report),
            Output::Commissioned { nodes } => nodes.iter().for_each(render_commissioned),
            Output::Decommission {
                nodes,
                remaining_nodes,
            } => render_decommission(nodes, remaining_nodes),
            // Failures are already on stderr via the log; stdout stays quiet.
            Output::Error { .. } => {}
        }
    }
}

fn display_instant(at: Option<Timestamp>) -> String {
    at.map_or_else(|| "never".into(), |at| at.to_string())
}

/// The device's vendor and product names joined for display, or `None` when
/// neither is known; each caller supplies its own fallback text.
fn device_name(vendor: Option<&str>, product: Option<&str>) -> Option<String> {
    let joined = [vendor, product]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" ");
    (!joined.is_empty()).then_some(joined)
}

fn render_status(report: &StatusReport) {
    println!(
        "Configuration:        loaded from {}",
        report.config.source.display()
    );
    println!(
        "  storagePath:        {}",
        report.config.storage_path.display()
    );
    println!("  timezone:           {}", report.config.timezone);
    println!("  logLevel:           {}", report.config.log_level);
    println!("  fabricLabel:        {}", report.config.fabric_label);
    println!("  output:             {}", report.config.output);
    println!(
        "Controller storage:   {}",
        if report.storage_initialized {
            format!("present at {}", report.config.storage_path.display())
        } else {
            "NOT INITIALIZED".into()
        }
    );
    match &report.controller_identity {
        IdentityReport::NotCreated => {
            println!("Controller identity:  not created yet (\"commission\" will create it)")
        }
        IdentityReport::Created {
            fabric_id,
            controller_node_id,
        } => println!(
            "Controller identity:  created (fabric id {fabric_id}, controller node id {controller_node_id})"
        ),
        IdentityReport::Unreadable => {
            println!("Controller identity:  present but unreadable (run as the service user?)")
        }
        IdentityReport::Inconsistent { reason } => {
            println!("Controller identity:  INCONSISTENT: {reason}")
        }
    }
    println!(
        "Commissioned nodes:   {}",
        if report.nodes.is_empty() {
            "none recorded".into()
        } else {
            report
                .nodes
                .iter()
                .map(|n| n.node_id.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        }
    );
    println!(
        "Host NTP synced:      {}",
        if report.host_ntp_synchronized {
            "yes"
        } else {
            "no (or not determinable on this host)"
        }
    );
    println!("Current UTC offset:   {}", report.current_utc_offset);
    match &report.next_dst_transition {
        Some(transition) => println!(
            "Next DST transition:  {} ({} -> {})",
            transition.at,
            format_utc_offset(transition.offset_before_seconds),
            format_utc_offset(transition.offset_after_seconds)
        ),
        None => println!("Next DST transition:  none (fixed-offset zone)"),
    }
    println!(
        "Matter time now:      {} us since 2000-01-01T00:00:00Z",
        report.matter_time_now_microseconds
    );
    for node in &report.nodes {
        let name = device_name(node.vendor_name.as_deref(), node.product_name.as_deref());
        println!(
            "Node {}: {}",
            node.node_id,
            name.as_deref().unwrap_or("(no cached device info)")
        );
        println!(
            "  Last connection:      {}",
            display_instant(node.last_successful_connection)
        );
        println!(
            "  Last successful sync: {}",
            display_instant(node.last_successful_sync)
        );
        println!(
            "  Last attempted sync:  {}",
            display_instant(node.last_attempted_sync)
        );
        println!(
            "  Most recent error:    {}",
            node.last_error.as_deref().unwrap_or("none")
        );
    }
}

fn render_inspection(nodes: &[InspectOutcome]) {
    if nodes.is_empty() {
        println!("No devices are commissioned yet; run \"commission\" to add one.");
        return;
    }
    for outcome in nodes {
        println!("Node {}", outcome.node_id);
        if let Some(error) = &outcome.error {
            println!("  Error: {error}");
            println!();
            continue;
        }
        println!(
            "  Vendor:   {}",
            outcome.vendor_name.as_deref().unwrap_or("(unknown)")
        );
        println!(
            "  Product:  {}",
            outcome.product_name.as_deref().unwrap_or("(unknown)")
        );
        if let Some(time_sync) = &outcome.time_sync {
            println!("  Time Synchronization cluster (endpoint 0):");
            println!(
                "    features:             {:#x}{}",
                time_sync.feature_map,
                if time_sync.time_zone_feature {
                    " (timeZone)"
                } else {
                    ""
                }
            );
            println!(
                "    utcTime:              {}",
                time_sync.utc_time.as_deref().unwrap_or("unset")
            );
            println!("    granularity:          {}", time_sync.granularity);
            println!(
                "    dstOffsetListMaxSize: {}",
                time_sync.dst_offset_list_max_size
            );
        }
        println!(
            "  Our fabric entry: label {:?}, device fabric index {}",
            outcome.our_fabric_label.as_deref().unwrap_or("(none)"),
            outcome
                .our_fabric_index
                .map(|i| i.to_string())
                .unwrap_or_else(|| "?".into())
        );
        println!();
    }
}

fn render_sync(report: &SyncReport) {
    if !report.host_ntp_synchronized && report.manual_time.is_none() {
        // The refusal is already on stderr as a warning.
        return;
    }
    if let Some(manual) = &report.manual_time {
        println!("Manual time set: {manual} (host NTP state not enforced)");
    }
    for outcome in &report.nodes {
        println!("Node {}:", outcome.node_id);
        if let Some(before) = &outcome.clock_before {
            println!("  Assessment:   {before}");
        }
        if let Some(written) = &outcome.utc_time_written {
            println!("  Time written: {written}");
        }
        if let Some(zone) = &outcome.time_zone_written {
            println!("  Time zone:    {zone}");
        }
        if outcome.dst_entries_written > 0 {
            println!("  DST offsets:  {} entries", outcome.dst_entries_written);
        }
        if let Some(delta) = outcome.delta_after_micros {
            println!(
                "  Verification: device clock within {} of host after sync",
                CompactDuration(delta.unsigned_abs())
            );
        }
        match (&outcome.error, outcome.skipped) {
            (None, _) => println!("  Result:       OK"),
            (Some(reason), true) => println!("  Result:       SKIPPED ({reason})"),
            (Some(error), false) => println!("  Result:       FAILED ({error})"),
        }
    }
}

fn render_commissioned(outcome: &CommissionOutcome) {
    println!("Commissioning summary");
    println!("  Node ID:        {}", outcome.node_id);
    println!("  Fabric ID:      {}", outcome.fabric_id);
    println!(
        "  Device:         {}",
        device_name(
            outcome.vendor_name.as_deref(),
            outcome.product_name.as_deref()
        )
        .unwrap_or_default()
    );
    println!();
    println!("The device remains paired with its primary ecosystem; this controller");
    println!("was added as an additional Matter administrator. Run \"sync\" to");
    println!("synchronize its clock now.");
}

fn render_decommission(nodes: &[DecommissionOutcome], remaining: &[String]) {
    for outcome in nodes {
        if outcome.success {
            println!(
                "Device {} removed this controller's fabric; its primary ecosystem is untouched.",
                outcome.node_id
            );
        } else {
            println!(
                "Device {} could NOT be decommissioned: {}",
                outcome.node_id,
                outcome.error.as_deref().unwrap_or("unknown error")
            );
        }
    }
    if remaining.is_empty() {
        println!(
            "No devices remain commissioned. The local controller identity remains in the \
             storage directory; deleting it is now safe."
        );
    } else {
        println!(
            "{} device(s) remain commissioned: {}",
            remaining.len(),
            remaining.join(", ")
        );
    }
}
