//! mattertimesync: a one-shot CLI Matter controller that sets the clocks of
//! Matter devices via the standard Time Synchronization cluster.
//!
//! # CLI invariants
//!
//! Every command upholds these; new commands and options must too. Numbers
//! 1, 2 and 5 are enforced structurally by the [`output::Output`] type:
//! handlers return a value of a closed enum instead of printing, the exit
//! code is derived from that value, and both renderings consume it.
//!
//! 1. **Channels.** stdout carries command output only; all logs go to
//!    stderr. With `--json`, stdout is exactly one pretty-printed JSON
//!    object with a descriptive top-level key ({"nodes": ...},
//!    {"commissioned": ...}), on failure included ({"error": ...}).
//! 2. **Exit codes.** 0 = success, including empty-but-valid results;
//!    1 = runtime failure, including any per-node failure; 2 = usage or
//!    configuration error. Devices skipped as incompatible do not fail a
//!    run.
//! 3. **--node semantics.** The local read-only command (status) takes a
//!    [`Filter`]: an absent node yields an empty report, never an error.
//!    Device-connecting commands (inspect, sync, decommission) take a
//!    [`Target`]: the node must be commissioned, otherwise error.
//!    commission takes neither because the node ID does not exist until it
//!    assigns one.
//! 4. **Default targeting.** Device-connecting commands operate on every
//!    commissioned device when --node is omitted. On an empty registry,
//!    read-only inspect reports emptiness successfully; fabric-writing
//!    sync and decommission error, because having nothing to write to is
//!    an operator problem worth surfacing.
//! 5. **Per-node isolation.** Multi-node runs never abort the batch on one
//!    node's failure; every node gets its own outcome entry.
//! 6. **Universal options.** -c/--config and -j/--json exist everywhere;
//!    -n/--node everywhere except commission.

mod config;
mod controller;
mod host;
mod output;
mod pairing;
mod state;
mod time;
mod tz;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use jiff::Timestamp;

use crate::config::{Config, DEFAULT_CONFIG_PATH};
use crate::output::{ConfigReport, DstTransition, NodeListing, Output, StatusReport, SyncReport};
use crate::state::{NodeRegistry, ServiceState};
use crate::time::MatterMicros;

#[derive(Parser)]
#[command(
    name = "mattertimesync",
    version,
    about,
    disable_help_subcommand = true
)]
struct Cli {
    /// Configuration file
    #[arg(short = 'c', long, global = true, default_value = DEFAULT_CONFIG_PATH)]
    config: PathBuf,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Show controller and per-device state [local, read-only]
    Status {
        /// Machine-readable output (64-bit values as decimal strings)
        #[arg(short = 'j', long)]
        json: bool,
        /// Show only this device's state
        #[arg(short = 'n', long)]
        node: Option<u64>,
    },
    /// Connect to each commissioned device (or one with --node) and dump
    /// identity, time-sync capabilities, and our fabric entry
    /// [fabric interrogation, read-only]
    Inspect {
        /// Inspect only this device
        #[arg(short = 'n', long)]
        node: Option<u64>,
        /// Machine-readable output (64-bit values as decimal strings)
        #[arg(short = 'j', long)]
        json: bool,
    },
    /// Join a device as an additional Matter admin; the pairing code is
    /// used once, never logged or stored [fabric-writing]
    Commission {
        /// Pairing code from the primary ecosystem's pairing mode
        pairing_code: String,
        /// Machine-readable output (64-bit values as decimal strings)
        #[arg(short = 'j', long)]
        json: bool,
    },
    /// Set each device's clock: UTC time, time zone, DST offsets
    /// [fabric-writing]
    Sync {
        /// Target one device instead of all commissioned devices
        #[arg(short = 'n', long)]
        node: Option<u64>,
        /// Set this wall-clock time (e.g. 16:35 or 4:35pm, today in the
        /// configured time zone) instead of the current time
        #[arg(short = 't', long, value_name = "TIME")]
        time: Option<String>,
        /// Machine-readable output (64-bit values as decimal strings)
        #[arg(short = 'j', long)]
        json: bool,
    },
    /// Drop this controller's fabric from each device, or one with --node;
    /// primary ecosystems are untouched [fabric-writing]
    Decommission {
        /// Target one device instead of all commissioned devices
        #[arg(short = 'n', long)]
        node: Option<u64>,
        /// Machine-readable output (64-bit values as decimal strings)
        #[arg(short = 'j', long)]
        json: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    // No command: show the full help, not a terse error.
    let Some(command) = cli.command else {
        use clap::CommandFactory;
        let _ = Cli::command().print_help();
        return ExitCode::from(2);
    };

    let config = match Config::load(&cli.config) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("Configuration error: {error}");
            return ExitCode::from(2);
        }
    };

    env_logger::Builder::new()
        .filter_level(config.log_level.into())
        .format_timestamp_millis()
        .init();

    for warning in config.path_warnings() {
        log::warn!("{warning}");
    }

    let (json, result) = match command {
        Command::Status { json, node } => (json, run_status(&config, Filter(node))),
        Command::Inspect { json, node } => (json, run_inspect(&config, Target(node))),
        Command::Sync { json, node, time } => {
            (json, run_sync(&config, Target(node), time.as_deref()))
        }
        Command::Commission { json, pairing_code } => {
            (json, run_commission(&config, &pairing_code))
        }
        Command::Decommission { json, node } => (json, run_decommission(&config, Target(node))),
    };

    let output = result.unwrap_or_else(|error| {
        log::error!("{error:#}");
        Output::Error {
            error: format!("{error:#}"),
        }
    });
    if json {
        output.print_json();
    } else {
        output.render_human();
    }
    output.exit_code()
}

/// `--node` on a local, read-only command: filters a report. An absent node
/// yields an empty report, never an error.
struct Filter(Option<u64>);

impl Filter {
    fn retain<V>(&self, map: &mut std::collections::BTreeMap<String, V>) {
        if let Some(node) = self.0 {
            let key = node.to_string();
            map.retain(|k, _| *k == key);
        }
    }
}

/// `--node` on a device-connecting command: selects targets. A requested
/// node must be commissioned; without one, every commissioned device.
struct Target(Option<u64>);

impl Target {
    /// Targets for fabric-writing commands: an empty registry is an error
    /// (having nothing to write to is an operator problem worth surfacing).
    fn resolve(&self, config: &Config) -> anyhow::Result<Vec<u64>> {
        let targets = self.resolve_or_empty(config)?;
        if targets.is_empty() {
            anyhow::bail!("no devices are commissioned yet; run \"commission\" to add one");
        }
        Ok(targets)
    }

    /// Targets for read-only interrogation: an empty registry is a valid,
    /// empty answer. An explicitly requested unknown node is still an error.
    fn resolve_or_empty(&self, config: &Config) -> anyhow::Result<Vec<u64>> {
        let registry: NodeRegistry =
            state::load_or_default(&state::registry_path(&config.storage_path));
        let known: Vec<u64> = registry.node_ids().collect();
        match self.0 {
            None => Ok(known),
            Some(node) if known.contains(&node) => Ok(vec![node]),
            Some(node) => anyhow::bail!(
                "node {node} is not commissioned on this controller (known nodes: {})",
                if known.is_empty() {
                    "none".into()
                } else {
                    known
                        .iter()
                        .map(u64::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                }
            ),
        }
    }
}

fn run_status(config: &Config, filter: Filter) -> anyhow::Result<Output> {
    let tz = config.time_zone();
    let now = Timestamp::now();
    let state: ServiceState =
        state::load_or_default(&state::service_state_path(&config.storage_path));
    let mut registry: NodeRegistry =
        state::load_or_default(&state::registry_path(&config.storage_path));
    filter.retain(&mut registry.nodes);
    let nodes: Vec<NodeListing> = registry
        .nodes
        .into_iter()
        .filter_map(|(key, info)| {
            // Registry keys are decimal node IDs written by us; anything else
            // is file corruption and is skipped, matching the lenient loader.
            let node_id: u64 = key.parse().ok()?;
            let node = state.nodes.get(&key).cloned().unwrap_or_default();
            Some(NodeListing {
                node_id: node_id.into(),
                vendor_name: info.vendor_name,
                product_name: info.product_name,
                last_successful_connection: node.last_successful_connection,
                last_successful_sync: node.last_successful_sync,
                last_attempted_sync: node.last_attempted_sync,
                last_error: node.last_error,
            })
        })
        .collect();

    let identity = controller::identity_status(&config.storage_path).into();
    let offset_seconds = tz.to_offset(now).seconds();
    Ok(Output::Status(Box::new(StatusReport {
        config: ConfigReport {
            source: config.source.clone(),
            storage_path: config.storage_path.clone(),
            timezone: config.timezone.clone(),
            log_level: config.log_level.to_string(),
            fabric_label: config.fabric_label.clone(),
        },
        storage_initialized: config.storage_path.is_dir(),
        controller_identity: identity,
        host_ntp_synchronized: host::clock_is_ntp_synchronized(),
        current_utc_offset_seconds: offset_seconds,
        current_utc_offset: tz::format_utc_offset(offset_seconds),
        next_dst_transition: tz::next_offset_transition(&tz, now).map(|(at, before, after)| {
            DstTransition {
                at: at.to_string(),
                offset_before_seconds: before,
                offset_after_seconds: after,
            }
        }),
        matter_time_now_microseconds: MatterMicros::now().0.to_string(),
        nodes,
    })))
}

fn run_inspect(config: &Config, target: Target) -> anyhow::Result<Output> {
    let targets = target.resolve_or_empty(config)?;
    let nodes = if targets.is_empty() {
        Vec::new()
    } else {
        controller::run(config, controller::InspectOp { targets })?
    };
    Ok(Output::Inspection { nodes })
}

/// The requested wall-clock time as a concrete instant: today's date in the
/// configured zone at that time. The operator is asserting the wall clock, so
/// the result feeds `--time` directly.
fn manual_instant(config: &Config, raw: &str) -> anyhow::Result<MatterMicros> {
    let wall = crate::time::parse_wall_clock(raw).map_err(|e| anyhow::anyhow!(e))?;
    let tz = config.time_zone();
    let today = Timestamp::now().to_zoned(tz.clone()).date();
    let instant = today
        .at(wall.hour(), wall.minute(), wall.second(), 0)
        .to_zoned(tz)
        .map_err(|e| anyhow::anyhow!("cannot place {raw:?} in {}: {e}", config.timezone))?
        .timestamp();
    Ok(MatterMicros::from_timestamp(instant))
}

fn run_sync(config: &Config, target: Target, time: Option<&str>) -> anyhow::Result<Output> {
    // --time makes the operator the time source.
    let manual_time = time.map(|raw| manual_instant(config, raw)).transpose()?;

    // Fail safe: never push time from a clock that is not NTP-disciplined.
    // Not enforced with --time: the operator deliberately chose the value.
    let ntp = host::clock_is_ntp_synchronized();
    if !ntp && manual_time.is_none() {
        log::warn!("Host clock is not NTP-synchronized; refusing to set device time.");
        return Ok(Output::Sync(SyncReport {
            host_ntp_synchronized: false,
            manual_time: None,
            nodes: Vec::new(),
        }));
    }
    let targets = target.resolve(config)?;
    let nodes = controller::run(
        config,
        controller::SyncOp {
            targets,
            manual_time,
        },
    )?;
    Ok(Output::Sync(SyncReport {
        host_ntp_synchronized: ntp,
        manual_time: manual_time.map(|m| m.to_string()),
        nodes,
    }))
}

fn run_commission(config: &Config, code: &str) -> anyhow::Result<Output> {
    let onboarding = pairing::parse_manual_code(code)?;
    let commissioned = controller::run(config, controller::CommissionOp { onboarding })?;
    Ok(Output::Commissioned {
        nodes: vec![commissioned],
    })
}

fn run_decommission(config: &Config, target: Target) -> anyhow::Result<Output> {
    let targets = target.resolve(config)?;
    let nodes = controller::run(config, controller::DecommissionOp { targets })?;
    let registry: NodeRegistry =
        state::load_or_default(&state::registry_path(&config.storage_path));
    Ok(Output::Decommission {
        nodes,
        remaining_nodes: registry.nodes.into_keys().collect(),
    })
}
