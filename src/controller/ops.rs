//! The controller's on-wire operations: commission, sync, inspect,
//! decommission. Split from the harness in the parent module, whose
//! private items (Ctx, Op, MatterCtx, the identity/fabric helpers) are
//! visible here via `use super::*`.

use super::*;

use rs_matter::dm::clusters::decl::basic_information::BasicInformationClient;
use rs_matter::dm::clusters::decl::operational_credentials::OperationalCredentialsClient;
use rs_matter::dm::clusters::decl::time_synchronization::{
    GranularityEnum, TimeSourceEnum, TimeSynchronizationClient,
};
use rs_matter::dm::endpoints::ROOT_ENDPOINT_ID;
use rs_matter::onboard::{CommissionOptions, Commissioner};
use rs_matter::transport::exchange::Exchange;

use jiff::Timestamp;

use crate::pairing::Onboarding;

/// The device-registry file path for this run's storage.
fn devices_path<C: Crypto>(ctx: &Ctx<'_, C>) -> std::path::PathBuf {
    state::devices_path(&ctx.config.storage_path)
}

const BROWSE_TIMEOUT_MS: u32 = 30_000;
/// Per-phase bound for commissioning (PASE handshake + invokes, CASE + complete).
const COMMISSION_TIMEOUT_SECS: u64 = 60;
/// Bound for opening a CASE exchange to a commissioned node (mDNS resolve + handshake).
const CONNECT_TIMEOUT_SECS: u64 = 30;

/// Bounds a Matter operation that could otherwise hang (unreachable peer,
/// swallowed packets). The timeout is part of the caller's log line so an
/// operator watching a quiet log knows how long "waiting" can last.
async fn with_timeout<T>(
    what: &str,
    secs: u64,
    fut: impl Future<Output = Result<T, MatterError>>,
) -> anyhow::Result<T> {
    let mut fut = core::pin::pin!(fut);
    let mut timer = core::pin::pin!(embassy_time::Timer::after(
        embassy_time::Duration::from_secs(secs)
    ));
    match embassy_futures::select::select(&mut fut, &mut timer).await {
        embassy_futures::select::Either::First(result) => result.ctx(what),
        embassy_futures::select::Either::Second(()) => bail!("{what} timed out after {secs}s"),
    }
}

pub struct CommissionOp {
    pub onboarding: Onboarding,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CommissionOutcome {
    pub node_id: crate::output::Id64,
    pub fabric_id: crate::output::Id64,
    pub vendor_name: Option<String>,
    pub product_name: Option<String>,
}

impl Op for CommissionOp {
    type Out = CommissionOutcome;

    async fn run<C: Crypto>(self, ctx: &Ctx<'_, C>) -> anyhow::Result<CommissionOutcome> {
        let matter = ctx.matter;
        log::info!(
            "Discovering commissionable device (_matterc._udp, short discriminator {}, timeout {}s)",
            self.onboarding.short_discriminator,
            BROWSE_TIMEOUT_MS / 1000
        );
        let (peer_addr, _instance) = matter
            .transport()
            .browse_commissionable(
                &commissionable_filter(self.onboarding.short_discriminator),
                &[],
                BROWSE_TIMEOUT_MS,
            )
            .await
            .map_err(|e| {
                anyhow!("no commissionable device found (is the pairing window open?): {e:?}")
            })?;
        log::info!("Found commissionable device at {:?}", peer_addr);

        let device_node_id = ctx.identity.next_device_node_id;
        let rcac_privkey = ctx.identity.rcac_privkey()?;
        let mut noc_buf = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
        let mut noc_generator =
            NocGenerator::new(matter, rcac_privkey.reference(), ctx.fab_idx, &mut noc_buf)
                .ctx("NOC generator from persisted identity")?;

        let mut commissioner_buf = [0u8; rs_matter::cert::MAX_CERT_TLV_LEN];
        let mut commissioner = Commissioner::new(
            matter,
            ctx.crypto,
            ctx.fab_idx,
            &mut noc_generator,
            &mut commissioner_buf,
        );
        let opts = CommissionOptions {
            // Consumer devices carry vendor DACs we cannot verify without the
            // DCL; matter.js accepted these the same way.
            allow_test_attestation: true,
            ..CommissionOptions::new()
        };

        log::info!(
            "Commissioning as node {device_node_id} (PASE phase, timeout {COMMISSION_TIMEOUT_SECS}s)"
        );
        let phase1 = with_timeout(
            "commissioning over PASE",
            COMMISSION_TIMEOUT_SECS,
            commissioner.commission(
                peer_addr,
                self.onboarding.passcode,
                &opts,
                device_node_id,
                VALID_FOREVER,
            ),
        )
        .await?;
        log::info!("CASE phase: completing commissioning (timeout {COMMISSION_TIMEOUT_SECS}s)");
        with_timeout(
            "CommissioningComplete over CASE",
            COMMISSION_TIMEOUT_SECS,
            commissioner.complete_via_case(peer_addr, &phase1),
        )
        .await?;

        // Record the device: cached names plus the initial connection.
        let (vendor_name, product_name) = read_device_names(ctx, device_node_id).await;
        state::update_device(&devices_path(ctx), device_node_id, |device| {
            device.vendor_name = vendor_name.clone();
            device.product_name = product_name.clone();
            device.last_successful_connection = Some(Timestamp::now());
        })?;

        let mut identity = ctx.identity.clone();
        identity.next_device_node_id += 1;
        state::store(&identity_path(&ctx.config.storage_path), &identity)?;

        Ok(CommissionOutcome {
            node_id: device_node_id.into(),
            fabric_id: ctx.identity.fabric_id.into(),
            vendor_name,
            product_name,
        })
    }
}

/// The device's vendor and product names for the local registry, each
/// sanitized and best-effort (`None` if unreadable). Sanitizing matters:
/// these strings come off the wire from the device and are later printed to
/// the operator's terminal and journal, so a malicious device must not be
/// able to smuggle terminal escape sequences through them.
async fn read_device_names<C: Crypto>(
    ctx: &Ctx<'_, C>,
    node_id: u64,
) -> (Option<String>, Option<String>) {
    (
        read_vendor_name(ctx, node_id).await.ok(),
        read_product_name(ctx, node_id).await.ok(),
    )
}

/// Replaces control characters with '?' so a device-supplied string cannot
/// drive the operator's terminal.
fn sanitize(value: &str) -> String {
    value
        .chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

async fn read_vendor_name<C: Crypto>(ctx: &Ctx<'_, C>, node_id: u64) -> anyhow::Result<String> {
    let exchange = connect(ctx, node_id).await?;
    let mut out = String::new();
    exchange
        .basic_information()
        .vendor_name_read_with(ROOT_ENDPOINT_ID, |value| {
            out = sanitize(value?);
            Ok::<_, MatterError>(())
        })
        .await
        .ctx("read vendorName")?
        .ctx("parse vendorName")?;
    Ok(out)
}

async fn read_product_name<C: Crypto>(ctx: &Ctx<'_, C>, node_id: u64) -> anyhow::Result<String> {
    let exchange = connect(ctx, node_id).await?;
    let mut out = String::new();
    exchange
        .basic_information()
        .product_name_read_with(ROOT_ENDPOINT_ID, |value| {
            out = sanitize(value?);
            Ok::<_, MatterError>(())
        })
        .await
        .ctx("read productName")?
        .ctx("parse productName")?;
    Ok(out)
}

/// How many times to attempt an mDNS resolve + CASE connect. Resolve
/// answers can be lost per-attempt (multicast loss, macOS socket sharing),
/// so single-shot failure is not conclusive.
const CONNECT_ATTEMPTS: u32 = 3;
/// Pause between connect attempts. A failed CASE handshake can linger
/// half-open on the device, which then answers an immediate re-knock with
/// Busy; a couple of seconds lets it reap the stale session.
const CONNECT_RETRY_DELAY_SECS: u64 = 2;

/// Opens an exchange over CASE to a commissioned node (cached session when
/// available, mDNS operational resolve otherwise). One exchange = one IM
/// transaction, so every read/invoke starts here.
async fn connect<'a, C: Crypto>(ctx: &Ctx<'a, C>, node_id: u64) -> anyhow::Result<Exchange<'a>> {
    let mut last_error = None;
    for attempt in 1..=CONNECT_ATTEMPTS {
        match with_timeout(
            &format!("reaching node {node_id} (offline or unresolvable?)"),
            CONNECT_TIMEOUT_SECS,
            Exchange::initiate(ctx.matter, ctx.crypto, ctx.fab_idx, node_id),
        )
        .await
        {
            Ok(exchange) => return Ok(exchange),
            Err(error) => {
                if attempt < CONNECT_ATTEMPTS {
                    log::warn!(
                        "Node {node_id}: connect attempt {attempt}/{CONNECT_ATTEMPTS} failed \
                         ({error:#}); retrying in {CONNECT_RETRY_DELAY_SECS}s"
                    );
                    embassy_time::Timer::after(embassy_time::Duration::from_secs(
                        CONNECT_RETRY_DELAY_SECS,
                    ))
                    .await;
                }
                last_error = Some(error);
            }
        }
    }
    Err(last_error.expect("at least one attempt ran"))
}

// --- sync -----------------------------------------------------------------

use crate::time::{ClockAssessment, MatterMicros};
use crate::tz::{build_dst_offset_list, build_time_zone_list};

const VERIFY_TOLERANCE_MICROS: i64 = 5_000_000;
const FEATURE_TIME_ZONE: u32 = 1 << 0;

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
#[derive(Default)]
pub struct SyncOutcome {
    pub node_id: crate::output::Id64,
    pub success: bool,
    /// True when the device has no Time Synchronization cluster: reported
    /// with a warning, not counted as a failure, so a permanently
    /// incompatible device cannot fail every timer run.
    pub skipped: bool,
    pub error: Option<String>,
    /// Human assessment of the device clock before the write.
    pub clock_before: Option<String>,
    pub epoch_shifted: bool,
    pub utc_time_written: Option<String>,
    pub time_zone_written: Option<String>,
    pub dst_entries_written: usize,
    pub delta_after_micros: Option<i64>,
    pub verified: bool,
}

impl SyncOutcome {
    /// A node whose sync attempt errored before completing.
    fn failed(node_id: u64, error: String) -> Self {
        Self {
            node_id: node_id.into(),
            error: Some(error),
            ..Default::default()
        }
    }

    /// A node skipped because it has no Time Synchronization cluster: not a
    /// failure, so it does not affect the run's exit code.
    fn skipped(node_id: u64, reason: &str) -> Self {
        Self {
            node_id: node_id.into(),
            skipped: true,
            error: Some(reason.into()),
            ..Default::default()
        }
    }
}

pub struct SyncOp {
    pub targets: Vec<u64>,
    /// When set, write this instant instead of the current time: the
    /// operator is deliberately setting an arbitrary wall clock.
    pub manual_time: Option<MatterMicros>,
}

impl Op for SyncOp {
    type Out = Vec<SyncOutcome>;

    async fn run<C: Crypto>(self, ctx: &Ctx<'_, C>) -> anyhow::Result<Vec<SyncOutcome>> {
        let state_path = devices_path(ctx);
        let mut outcomes = Vec::with_capacity(self.targets.len());
        for node_id in self.targets {
            state::update_device(&state_path, node_id, |d| {
                d.last_attempted_sync = Some(Timestamp::now());
            })?;
            let outcome = match sync_one(ctx, node_id, self.manual_time).await {
                Ok(outcome) => outcome,
                Err(error) => SyncOutcome::failed(node_id, format!("{error:#}")),
            };
            state::update_device(&state_path, node_id, |d| {
                if outcome.success {
                    d.last_successful_sync = Some(Timestamp::now());
                    d.last_successful_connection = Some(Timestamp::now());
                    d.last_error = None;
                } else {
                    d.last_error = outcome.error.clone();
                }
            })?;
            if let Some(error) = &outcome.error {
                log::error!("Node {node_id}: sync failed: {error}");
            }
            outcomes.push(outcome);
        }
        Ok(outcomes)
    }
}

async fn sync_one<C: Crypto>(
    ctx: &Ctx<'_, C>,
    node_id: u64,
    manual_time: Option<MatterMicros>,
) -> anyhow::Result<SyncOutcome> {
    let tz = ctx.config.time_zone();
    let now_ts = Timestamp::now();

    // Capability discovery first: a device without the cluster is skipped
    // with a warning, and the TimeZone feature gates SetTimeZone/SetDSTOffset.
    let feature_map = match connect(ctx, node_id)
        .await?
        .time_synchronization()
        .feature_map_read(ROOT_ENDPOINT_ID)
        .await
    {
        Ok(map) => map,
        Err(e) if e.code() == rs_matter::error::ErrorCode::ClusterNotFound => {
            log::warn!("Node {node_id}: no Time Synchronization cluster; skipping");
            return Ok(SyncOutcome::skipped(
                node_id,
                "no Time Synchronization cluster",
            ));
        }
        Err(e) => bail!("read featureMap: {e:?}"),
    };
    let has_time_zone = feature_map & FEATURE_TIME_ZONE != 0;

    // Before: read the device clock live for the correction report.
    let before = connect(ctx, node_id)
        .await?
        .time_synchronization()
        .utc_time_read(ROOT_ENDPOINT_ID)
        .await
        .ctx("read utcTime")?;
    let device_before = before.into_option().map(MatterMicros);
    let assessment = ClockAssessment::compare(device_before, MatterMicros::now());
    log::info!("Node {node_id}: {assessment}");

    // SetUTCTime, last-moment fresh. The host clock is NTP-disciplined and
    // the timestamp microsecond-precise at send time; a device that already
    // holds good time may reject a weaker claim (TimeNotAccepted).
    let utc_write = manual_time.unwrap_or_else(MatterMicros::now);
    connect(ctx, node_id)
        .await?
        .time_synchronization()
        .set_utc_time(ROOT_ENDPOINT_ID, |b| {
            b.utc_time(utc_write.0)?
                .granularity(GranularityEnum::MicrosecondsGranularity)?
                .time_source(Some(TimeSourceEnum::NonMatterSNTP))?
                .end()
        })
        .await
        .ctx("SetUTCTime rejected")?;
    log::info!("Node {node_id}: SetUTCTime {utc_write}");

    let (time_zone_written, dst_entries_written) = if has_time_zone {
        write_zone_and_dst(ctx, node_id, &tz, now_ts).await?
    } else {
        (None, 0)
    };

    // Verify by reading the clock back.
    let after = connect(ctx, node_id)
        .await?
        .time_synchronization()
        .utc_time_read(ROOT_ENDPOINT_ID)
        .await
        .ctx("read-back utcTime")?;
    // Verify against what was WRITTEN (not against "now"): the question is
    // whether the device accepted our value, which also makes verification
    // correct when a manual time was set deliberately far from now.
    let after_assessment =
        ClockAssessment::compare(after.into_option().map(MatterMicros), utc_write);
    let delta_after = after_assessment.effective_delta_micros();
    let verified = delta_after.is_some_and(|d| d.unsigned_abs() <= VERIFY_TOLERANCE_MICROS as u64);
    if !verified {
        bail!("read-back verification failed: {after_assessment}");
    }

    ensure_fabric_label(ctx, node_id).await;

    Ok(SyncOutcome {
        node_id: node_id.into(),
        success: true,
        skipped: false,
        error: None,
        clock_before: Some(assessment.to_string()),
        epoch_shifted: assessment.is_epoch_shifted(),
        utc_time_written: Some(utc_write.to_string()),
        time_zone_written,
        dst_entries_written,
        delta_after_micros: delta_after,
        verified,
    })
}

/// Writes SetTimeZone and (when the device still needs it) SetDSTOffset,
/// returning the zone name written and the number of DST entries. Split out
/// of `sync_one` so the two writes read as one cohesive step.
async fn write_zone_and_dst<C: Crypto>(
    ctx: &Ctx<'_, C>,
    node_id: u64,
    tz: &jiff::tz::TimeZone,
    now_ts: Timestamp,
) -> anyhow::Result<(Option<String>, usize)> {
    let zone_entries = build_time_zone_list(tz, &ctx.config.timezone, now_ts);
    let response = connect(ctx, node_id)
        .await?
        .time_synchronization()
        .set_time_zone(ROOT_ENDPOINT_ID, |b| {
            let mut list = b.time_zone()?;
            for entry in &zone_entries {
                list = list
                    .push()?
                    .offset(entry.offset_seconds)?
                    .valid_at(entry.valid_at.0)?
                    .name(Some(&entry.name))?
                    .end()?;
            }
            list.end()?.end()
        })
        .await
        .ctx("SetTimeZone rejected")?;
    let dst_required = response
        .response()
        .map(|r| r.dst_offset_required().unwrap_or(true))
        .unwrap_or(true);
    response.complete().await.ctx("SetTimeZone completion")?;
    log::info!("Node {node_id}: SetTimeZone {}", ctx.config.timezone);

    if !dst_required {
        return Ok((Some(ctx.config.timezone.clone()), 0));
    }

    let max_entries = connect(ctx, node_id)
        .await?
        .time_synchronization()
        .dst_offset_list_max_size_read(ROOT_ENDPOINT_ID)
        .await
        .ctx("read dstOffsetListMaxSize")?;
    let dst_entries = build_dst_offset_list(tz, usize::from(max_entries), now_ts);
    connect(ctx, node_id)
        .await?
        .time_synchronization()
        .set_dst_offset(ROOT_ENDPOINT_ID, |b| {
            let mut list = b.dst_offset()?;
            for entry in &dst_entries {
                list = list
                    .push()?
                    .offset(entry.offset_seconds)?
                    .valid_starting(entry.valid_starting.0)?
                    .valid_until(match entry.valid_until {
                        Some(until) => rs_matter::tlv::Nullable::some(until.0),
                        None => rs_matter::tlv::Nullable::none(),
                    })?
                    .end()?;
            }
            list.end()?.end()
        })
        .await
        .ctx("SetDSTOffset rejected")?;
    log::info!(
        "Node {node_id}: SetDSTOffset with {} entries",
        dst_entries.len()
    );
    Ok((Some(ctx.config.timezone.clone()), dst_entries.len()))
}

/// Pushes the configured fabric label to the device when it differs from the
/// stored one. Best-effort: a cosmetic label must not fail a clock sync.
/// Labels are unique per device, so a conflict with another admin's label is
/// logged with guidance rather than retried.
async fn ensure_fabric_label<C: Crypto>(ctx: &Ctx<'_, C>, node_id: u64) {
    if let Err(error) = try_ensure_fabric_label(ctx, node_id).await {
        log::warn!("Node {node_id}: could not update fabric label: {error:#}");
    }
}

/// Our own entry in the device's fabric table: its label and device-side
/// fabric index. A fabric-filtered read returns only our entry, so the loop
/// keeps the last (only) row. Shared by the label, decommission, and inspect
/// paths, which each want one or both fields.
async fn read_our_fabric_entry<C: Crypto>(
    ctx: &Ctx<'_, C>,
    node_id: u64,
) -> anyhow::Result<(Option<String>, Option<u8>)> {
    let mut label = None;
    let mut index = None;
    connect(ctx, node_id)
        .await?
        .operational_credentials()
        .fabrics_read_with(ROOT_ENDPOINT_ID, |reader| {
            for item in reader? {
                let item = item?;
                label = Some(item.label()?.to_string());
                index = item.fabric_index()?;
            }
            Ok::<_, MatterError>(())
        })
        .await
        .ctx("read fabrics")?
        .ctx("parse fabrics")?;
    Ok((label, index))
}

async fn try_ensure_fabric_label<C: Crypto>(ctx: &Ctx<'_, C>, node_id: u64) -> anyhow::Result<()> {
    let wanted = ctx.config.fabric_label.clone();
    let (current, _) = read_our_fabric_entry(ctx, node_id).await?;

    if current.as_deref() == Some(wanted.as_str()) {
        return Ok(());
    }
    let response = connect(ctx, node_id)
        .await?
        .operational_credentials()
        .update_fabric_label(ROOT_ENDPOINT_ID, |b| b.label(&wanted)?.end())
        .await
        .ctx("UpdateFabricLabel")?;
    let status = response.response().map(|r| r.status_code());
    response
        .complete()
        .await
        .ctx("UpdateFabricLabel completion")?;
    log::info!("Node {node_id}: fabric label updated to {wanted:?} (status {status:?})");
    Ok(())
}

// --- decommission ----------------------------------------------------------

pub struct DecommissionOp {
    pub targets: Vec<u64>,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DecommissionOutcome {
    pub node_id: crate::output::Id64,
    pub success: bool,
    pub error: Option<String>,
}

impl Op for DecommissionOp {
    type Out = Vec<DecommissionOutcome>;

    async fn run<C: Crypto>(self, ctx: &Ctx<'_, C>) -> anyhow::Result<Vec<DecommissionOutcome>> {
        let mut outcomes = Vec::with_capacity(self.targets.len());
        for node_id in self.targets {
            let result = decommission_one(ctx, node_id).await;
            match result {
                Ok(()) => {
                    state::remove_device(&devices_path(ctx), node_id)?;
                    outcomes.push(DecommissionOutcome {
                        node_id: node_id.into(),
                        success: true,
                        error: None,
                    });
                }
                Err(error) => {
                    log::error!("Node {node_id}: decommission failed: {error:#}");
                    outcomes.push(DecommissionOutcome {
                        node_id: node_id.into(),
                        success: false,
                        error: Some(format!("{error:#}")),
                    });
                }
            }
        }
        Ok(outcomes)
    }
}

/// The device drops this controller's fabric via RemoveFabric on our own
/// entry (found through a fabric-filtered read, so no other admin's entry
/// can even be addressed), while staying paired to its primary ecosystem.
async fn decommission_one<C: Crypto>(ctx: &Ctx<'_, C>, node_id: u64) -> anyhow::Result<()> {
    let (_, our_index) = read_our_fabric_entry(ctx, node_id).await?;
    let our_index = our_index.ok_or_else(|| anyhow!("device has no entry for our fabric"))?;

    log::info!(
        "Decommissioning: removing our fabric (device index {our_index}) from node {node_id}"
    );
    let response = connect(ctx, node_id)
        .await?
        .operational_credentials()
        .remove_fabric(ROOT_ENDPOINT_ID, |b| b.fabric_index(our_index)?.end())
        .await
        .ctx("RemoveFabric")?;
    let status = response.response().map(|r| r.status_code());
    response.complete().await.ctx("RemoveFabric completion")?;
    log::info!("Node {node_id}: fabric removed (status {status:?})");
    Ok(())
}

// --- inspect ---------------------------------------------------------------

pub struct InspectOp {
    pub targets: Vec<u64>,
}

#[derive(Debug, Default, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InspectOutcome {
    pub node_id: crate::output::Id64,
    pub error: Option<String>,
    pub vendor_name: Option<String>,
    pub product_name: Option<String>,
    pub time_sync: Option<TimeSyncCaps>,
    pub our_fabric_label: Option<String>,
    pub our_fabric_index: Option<u8>,
}

impl InspectOutcome {
    /// A node whose live inspection could not complete.
    fn failed(node_id: u64, error: String) -> Self {
        Self {
            node_id: node_id.into(),
            error: Some(error),
            ..Default::default()
        }
    }
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TimeSyncCaps {
    pub feature_map: u32,
    pub time_zone_feature: bool,
    pub utc_time: Option<String>,
    pub granularity: u8,
    pub dst_offset_list_max_size: u8,
}

impl Op for InspectOp {
    type Out = Vec<InspectOutcome>;

    async fn run<C: Crypto>(self, ctx: &Ctx<'_, C>) -> anyhow::Result<Vec<InspectOutcome>> {
        let mut outcomes = Vec::with_capacity(self.targets.len());
        for node_id in self.targets {
            match inspect_one(ctx, node_id).await {
                Ok(outcome) => outcomes.push(outcome),
                Err(error) => {
                    log::error!("Node {node_id}: inspect failed: {error:#}");
                    outcomes.push(InspectOutcome::failed(node_id, format!("{error:#}")));
                }
            }
        }
        Ok(outcomes)
    }
}

async fn inspect_one<C: Crypto>(ctx: &Ctx<'_, C>, node_id: u64) -> anyhow::Result<InspectOutcome> {
    let (vendor_name, product_name) = read_device_names(ctx, node_id).await;

    let feature_map = connect(ctx, node_id)
        .await?
        .time_synchronization()
        .feature_map_read(ROOT_ENDPOINT_ID)
        .await
        .ctx("read featureMap (device may lack Time Synchronization)")?;
    let utc_time = connect(ctx, node_id)
        .await?
        .time_synchronization()
        .utc_time_read(ROOT_ENDPOINT_ID)
        .await
        .ctx("read utcTime")?
        .into_option()
        .map(|v| MatterMicros(v).to_string());
    let granularity = connect(ctx, node_id)
        .await?
        .time_synchronization()
        .granularity_read(ROOT_ENDPOINT_ID)
        .await
        .ctx("read granularity")? as u8;
    let has_tz = feature_map & FEATURE_TIME_ZONE != 0;
    let dst_max = if has_tz {
        connect(ctx, node_id)
            .await?
            .time_synchronization()
            .dst_offset_list_max_size_read(ROOT_ENDPOINT_ID)
            .await
            .unwrap_or(1)
    } else {
        0
    };

    let (label, index) = read_our_fabric_entry(ctx, node_id).await?;

    Ok(InspectOutcome {
        node_id: node_id.into(),
        error: None,
        vendor_name,
        product_name,
        time_sync: Some(TimeSyncCaps {
            feature_map,
            time_zone_feature: has_tz,
            utc_time,
            granularity,
            dst_offset_list_max_size: dst_max,
        }),
        our_fabric_label: label,
        our_fabric_index: index,
    })
}
