//! The rs-matter controller: persistent fabric, one-shot stack harness, and
//! the on-wire operations (commission, sync, decommission).
//!
//! Being a secondary Matter controller is fabric membership, not a running
//! process: every command builds the stack, races the transport and mDNS
//! pumps against the actual operation, and exits. The fabric identity
//! persists in `<storagePath>/matter/` (rs-matter's KV blobs) plus
//! `<storagePath>/identity.json` (the RCAC private key that signs device
//! NOCs, which rs-matter deliberately leaves to the caller).

use std::net::UdpSocket;
use std::num::NonZeroU8;
use std::path::Path;
use std::pin::pin;

use anyhow::{Context as _, anyhow, bail};
use embassy_futures::select::{Either3, select3};
use rs_matter::Matter;
use rs_matter::cert::MAX_CERT_TLV_AND_ASN1_LEN;
use rs_matter::cert::r#gen::VALID_FOREVER;
use rs_matter::crypto::{
    CanonAeadKey, CanonPkcSecretKey, Crypto, RngCore as _, SecretKey, SigningSecretKey,
    default_crypto,
};
use rs_matter::dm::devices::test::{DAC_PRIVKEY, TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
use rs_matter::error::Error as MatterError;
use rs_matter::fabric::FabricPersist;
use rs_matter::onboard::cac::RcacGenerator;
use rs_matter::onboard::noc::NocGenerator;
use rs_matter::transport::network::mdns::CommissionableFilter;
use rs_matter::transport::network::mdns::builtin::{BuiltinMdns, Host};
use rs_matter::transport::network::mdns::{
    MDNS_IPV6_BROADCAST_ADDR, MDNS_SOCKET_DEFAULT_BIND_ADDR,
};
use rs_matter::utils::init::InitMaybeUninit;
use serde::{Deserialize, Serialize};
use static_cell::StaticCell;

use crate::config::Config;
use crate::state;

/// Attaches context to a `MatterError`, which does not implement anyhow's
/// `Context`. Replaces the repeated `.map_err(|e| anyhow!("what: {e:?}"))`
/// at every rs-matter call site with `.ctx("what")`; the doubled form on
/// the `Result<Result<_, MatterError>, MatterError>` returned by the
/// generated `*_read_with` methods flattens with two `.ctx(..)?` in a row.
trait MatterCtx<T> {
    fn ctx(self, what: &str) -> anyhow::Result<T>;
}

impl<T> MatterCtx<T> for Result<T, MatterError> {
    fn ctx(self, what: &str) -> anyhow::Result<T> {
        self.map_err(|e| anyhow!("{what}: {e:?}"))
    }
}

/// The identity material rs-matter leaves to the caller, persisted as JSON
/// with the RCAC private key hex-encoded. Mode 0600, next to the KV blobs.
///
/// `Debug` is hand-written to redact the key: a `{identity:?}` in any future
/// log or error must never spill the root CA private key to the journal.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Identity {
    pub fabric_id: u64,
    pub controller_node_id: u64,
    pub next_device_node_id: u64,
    pub rcac_privkey_hex: String,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("fabric_id", &self.fabric_id)
            .field("controller_node_id", &self.controller_node_id)
            .field("next_device_node_id", &self.next_device_node_id)
            .field("rcac_privkey_hex", &"<redacted>")
            .finish()
    }
}

/// What `status` reports about the controller identity, derived purely from
/// the on-disk artifacts (no Matter stack startup).
#[derive(Debug)]
pub enum IdentityStatus {
    /// Neither identity.json nor a fabric blob: first commission creates it.
    NotCreated,
    Created {
        fabric_id: u64,
        controller_node_id: u64,
    },
    /// identity.json exists but cannot be read or parsed (typically
    /// permissions: it is mode 0600, owned by the service user).
    Unreadable,
    /// One half of the identity pair is missing; the fabric-writing commands
    /// will refuse or auto-recover per their guardrails.
    Inconsistent(&'static str),
}

/// Inspects the identity pair on disk. A fabric blob is any k_* file in the
/// matter/ KV directory.
pub fn identity_status(storage: &Path) -> IdentityStatus {
    let identity_exists = identity_path(storage).exists();
    let fabric_exists = std::fs::read_dir(matter_kv_path(storage))
        .map(|entries| {
            entries
                .flatten()
                .any(|e| e.file_name().to_string_lossy().starts_with("k_"))
        })
        .unwrap_or(false);
    match (identity_exists, fabric_exists) {
        (false, false) => IdentityStatus::NotCreated,
        (true, false) => {
            IdentityStatus::Inconsistent("identity.json exists but the fabric storage is missing")
        }
        (false, true) => {
            IdentityStatus::Inconsistent("fabric storage exists but identity.json is missing")
        }
        (true, true) => match std::fs::read_to_string(identity_path(storage))
            .ok()
            .and_then(|raw| serde_json::from_str::<Identity>(&raw).ok())
        {
            Some(identity) => IdentityStatus::Created {
                fabric_id: identity.fabric_id,
                controller_node_id: identity.controller_node_id,
            },
            None => IdentityStatus::Unreadable,
        },
    }
}

fn identity_path(storage: &Path) -> std::path::PathBuf {
    storage.join("identity.json")
}

fn matter_kv_path(storage: &Path) -> std::path::PathBuf {
    storage.join("matter")
}

impl Identity {
    fn generate(crypto: &impl Crypto) -> Result<Self, MatterError> {
        let mut rng = crypto.rand()?;
        let mut bytes = [0u8; 8];
        rng.fill_bytes(&mut bytes);
        // Non-zero 64-bit fabric id; operational node ids for devices are
        // small and sequential like matter.js's.
        let fabric_id = u64::from_be_bytes(bytes) | 1;
        let mut node_bytes = [0u8; 8];
        rng.fill_bytes(&mut node_bytes);
        Ok(Self {
            fabric_id,
            controller_node_id: u64::from_be_bytes(node_bytes) | 1,
            next_device_node_id: 1,
            rcac_privkey_hex: String::new(),
        })
    }

    fn rcac_privkey(&self) -> anyhow::Result<CanonPkcSecretKey> {
        let bytes = hex_decode(&self.rcac_privkey_hex).context("identity.json rcac key")?;
        let mut key = CanonPkcSecretKey::new();
        if bytes.len() != key.access_mut().len() {
            bail!(
                "identity.json rcac key has unexpected length {}",
                bytes.len()
            );
        }
        key.access_mut().copy_from_slice(&bytes);
        Ok(key)
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(hex: &str) -> anyhow::Result<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        bail!("odd-length hex");
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).context("bad hex digit"))
        .collect()
}

static MATTER: StaticCell<Matter> = StaticCell::new();

/// Flat-file KV store with atomic writes, stand-in for rs-matter's
/// `DirKvBlobStore` (whose `store()` is a plain overwrite). The fabric
/// record lives here and must never be half-written; a temp file plus
/// rename makes every update all-or-nothing. Same `k_XXXX` file naming.
struct AtomicKvBlobStore(std::path::PathBuf);

impl AtomicKvBlobStore {
    fn key_path(&self, key: u16) -> std::path::PathBuf {
        self.0.join(format!("k_{key:04x}"))
    }
}

impl rs_matter::persist::KvBlobStore for AtomicKvBlobStore {
    fn load<'a>(&mut self, key: u16, buf: &'a mut [u8]) -> Result<Option<&'a [u8]>, MatterError> {
        match std::fs::read(self.key_path(key)) {
            Ok(data) => {
                let slot = buf
                    .get_mut(..data.len())
                    .ok_or(rs_matter::error::ErrorCode::NoSpace)?;
                slot.copy_from_slice(&data);
                Ok(Some(slot))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(rs_matter::error::ErrorCode::StdIoError.into()),
        }
    }

    fn store(&mut self, key: u16, data: &[u8], _buf: &mut [u8]) -> Result<(), MatterError> {
        let path = self.key_path(key);
        let write = || -> std::io::Result<()> {
            std::fs::create_dir_all(self.0.as_path())?;
            let tmp = path.with_extension("tmp");
            state::write_private(&tmp, data)?;
            std::fs::rename(&tmp, &path)
        };
        write().map_err(|_| rs_matter::error::ErrorCode::StdIoError.into())
    }

    fn remove(&mut self, key: u16, _buf: &mut [u8]) -> Result<(), MatterError> {
        match std::fs::remove_file(self.key_path(key)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(rs_matter::error::ErrorCode::StdIoError.into()),
        }
    }
}

/// Everything an operation needs, borrowed from the harness scope.
pub struct Ctx<'a, C: Crypto> {
    pub matter: &'a Matter<'a>,
    pub crypto: &'a C,
    pub fab_idx: NonZeroU8,
    pub identity: Identity,
    pub config: &'a Config,
}

/// A controller operation, generic over the crypto backend the harness
/// picks. A trait (rather than an async closure) because Rust forbids a
/// nested `impl Trait` in closure parameters.
pub trait Op {
    type Out;
    async fn run<C: Crypto>(self, ctx: &Ctx<'_, C>) -> anyhow::Result<Self::Out>;
}

/// Builds the Matter stack, ensures the persistent controller fabric exists,
/// then races the transport and mDNS pumps against `op`. The pumps never
/// finish on their own; `op` completing ends the run.
pub fn run<O: Op>(config: &Config, op: O) -> anyhow::Result<O::Out> {
    std::fs::create_dir_all(&config.storage_path).context("create storage directory")?;
    restrict_dir_mode(&config.storage_path)?;
    // One controller process per storage directory. Held for the process
    // lifetime (flock releases on exit, so no stale-lock handling); this
    // makes the first-run identity bootstrap race-free when a manual run
    // overlaps the timer.
    let _lock = lock_storage(&config.storage_path)?;

    futures_lite::future::block_on(async {
        let crypto = default_crypto(rand::thread_rng(), DAC_PRIVKEY);
        let matter: &'static Matter =
            MATTER
                .uninit()
                .init_with(Matter::init(&TEST_DEV_DET, TEST_DEV_COMM, &TEST_DEV_ATT, 0));

        let kv_store = AtomicKvBlobStore(matter_kv_path(&config.storage_path));
        let kv = matter.kv(kv_store);
        matter
            .load_persist(&kv)
            .await
            .ctx("load persisted Matter state")?;

        let (fab_idx, identity) = ensure_fabric(config, matter, &crypto, &kv)?;
        let ctx = Ctx {
            matter,
            crypto: &crypto,
            fab_idx,
            identity,
            config,
        };

        // Matter transport on an ephemeral port.
        let socket =
            async_io::Async::<UdpSocket>::bind(([0u16; 8], 0)).context("bind Matter UDP socket")?;
        let transport = matter.run(&crypto, &socket, &socket, &socket);

        // mDNS: the builtin responder everywhere. On the deployment
        // platform (Linux) it owns port 5353 outright and behaves
        // deterministically. On a macOS dev machine it shares 5353 with
        // mDNSResponder and resolve answers occasionally race to the wrong
        // socket; the connect retries absorb most of that. (The system
        // dnssd backend was tried and is worse: its 10-item browse channel
        // deterministically drops records on Matter-dense networks.)
        let mdns_socket = bind_mdns_socket().context("bind mDNS socket")?;
        let (mdns_host_ipv4, mdns_ipv6, mdns_interface) = pick_interface()?;
        let hostname = format!(
            "{:012X}",
            ctx.identity.controller_node_id & 0xFFFF_FFFF_FFFF
        );
        let host = Host {
            hostname: &hostname,
            ip: mdns_host_ipv4,
            ipv6: mdns_ipv6,
        };
        let mut mdns_runner = BuiltinMdns::new();
        // ipv4_interface: None disables the runner's IPv4 send path
        // entirely; see bind_mdns_socket for why mDNS is IPv6-only here.
        let mdns = mdns_runner.run(
            &mdns_socket,
            &mdns_socket,
            &host,
            None,
            Some(mdns_interface),
            matter,
            &crypto,
        );

        let mut transport = pin!(transport);
        let mut mdns = pin!(mdns);
        let mut op_fut = pin!(op.run(&ctx));

        match select3(&mut transport, &mut mdns, &mut op_fut).await {
            Either3::First(r) => bail!("Matter transport exited prematurely: {r:?}"),
            Either3::Second(r) => bail!("mDNS runner exited prematurely: {r:?}"),
            Either3::Third(result) => result,
        }
    })
}

/// Loads or bootstraps the controller fabric. On first run this mints the
/// RCAC (whose private key we keep, RCAC-direct mode), our own operational
/// NOC, and the fabric IPK, then installs and persists the fabric. On later
/// runs the fabric comes back via rs-matter's KV persistence and only the
/// label is reconciled with the configuration.
fn ensure_fabric<C: Crypto>(
    config: &Config,
    matter: &Matter<'static>,
    crypto: &C,
    kv: &impl rs_matter::persist::KvBlobStoreAccess,
) -> anyhow::Result<(NonZeroU8, Identity)> {
    let identity_file = identity_path(&config.storage_path);
    let existing = matter.with_state(|state| state.fabrics.iter().map(|f| f.fab_idx()).next());

    let registry: crate::state::NodeRegistry =
        state::load_or_default(&state::registry_path(&config.storage_path));

    if let Some(fab_idx) = existing {
        match std::fs::read_to_string(&identity_file) {
            Ok(raw) => {
                let identity: Identity =
                    serde_json::from_str(&raw).context("parse identity.json")?;
                reconcile_label(matter, crypto, kv, fab_idx, &config.fabric_label)?;
                return Ok((fab_idx, identity));
            }
            // A fabric blob without identity.json is an interrupted first
            // run: identity.json is written last, and commissioning requires
            // a completed bootstrap. With an empty registry nothing can
            // reference this fabric, so discard it and bootstrap cleanly.
            // With a non-empty registry something is deeply wrong; never
            // guess.
            Err(_) if registry.nodes.is_empty() => {
                log::warn!(
                    "Discarding fabric left by an interrupted first run (no identity.json, \
                     no commissioned devices); creating a fresh controller identity"
                );
                matter
                    .with_state(|state| state.fabrics.remove(fab_idx))
                    .ctx("remove interrupted fabric")?;
                remove_persisted_fabric(kv, fab_idx)?;
            }
            Err(e) => {
                bail!(
                    "cannot read {} but the node registry lists {} commissioned device(s); \
                     refusing to touch the fabric. Restore identity.json from backup. ({e})",
                    identity_file.display(),
                    registry.nodes.len()
                );
            }
        }
    }

    // Refuse to mint a fresh identity over the remains of an old one. An
    // identity.json without a loadable fabric means the KV storage was lost
    // or damaged AFTER commissioning began; overwriting the RCAC key would
    // permanently orphan every device commissioned to it. Deleting the whole
    // storage directory (after decommissioning, or accepting the orphans) is
    // a deliberate human act, never something a run does implicitly.
    if identity_file.exists() {
        bail!(
            "{} exists but no fabric was loaded from {}; refusing to create a new controller \
             identity over an old one. Restore the matter/ KV files from backup, or delete the \
             whole storage directory to deliberately start over.",
            identity_file.display(),
            matter_kv_path(&config.storage_path).display()
        );
    }
    if !registry.nodes.is_empty() {
        bail!(
            "the node registry lists {} commissioned device(s) but no fabric was loaded; \
             refusing to create a new controller identity. Restore the storage directory from \
             backup.",
            registry.nodes.len()
        );
    }

    log::info!("First run: creating the controller fabric (persistent identity)");
    let mut identity = Identity::generate(crypto).ctx("generate controller identity")?;

    let mut rcac_buf = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
    let mut rcac_gen = RcacGenerator::new(&mut rcac_buf);
    let (rcac_priv, rcac) = rcac_gen
        .generate(crypto, identity.fabric_id, VALID_FOREVER)
        .ctx("generate RCAC")?;
    identity.rcac_privkey_hex = hex_encode(rcac_priv.reference().access());

    // Our own operational identity: keypair, CSR, NOC signed by the RCAC.
    let controller_key = crypto
        .generate_secret_key()
        .ctx("generate controller key")?;
    let mut csr_buf = [0u8; 256];
    let csr = controller_key.csr(&mut csr_buf).ctx("controller CSR")?;
    let mut controller_key_canon = CanonPkcSecretKey::new();
    controller_key
        .write_canon(&mut controller_key_canon)
        .ctx("serialize controller key")?;

    let mut noc_buf = [0u8; MAX_CERT_TLV_AND_ASN1_LEN];
    let mut noc_generator = NocGenerator::create(rcac_priv.reference(), rcac, &[], &mut noc_buf)
        .ctx("NOC generator")?;
    let controller_noc = noc_generator
        .generate(crypto, csr, identity.controller_node_id, &[], VALID_FOREVER)
        .ctx("controller NOC")?;

    let mut ipk = CanonAeadKey::new();
    crypto
        .rand()
        .ctx("seed fabric IPK")?
        .fill_bytes(ipk.access_mut());

    let fab_idx = matter
        .with_state(|state| {
            let fab_idx = state
                .fabrics
                .add(
                    crypto,
                    controller_key_canon.reference(),
                    rcac,
                    controller_noc,
                    &[],
                    Some(ipk.reference()),
                    TEST_VENDOR_ID,
                    identity.controller_node_id,
                )?
                .fab_idx();
            let _ = state.fabrics.update_label(fab_idx, &config.fabric_label);
            Ok::<_, MatterError>(fab_idx)
        })
        .ctx("install controller fabric")?;

    persist_fabric(matter, kv, fab_idx)?;

    // Identity file after the fabric: a crash in between leaves a fabric
    // without identity.json, which the next run reports loudly rather than
    // silently minting a second identity.
    state::store(&identity_file, &identity).context("write identity.json")?;
    log::info!(
        "Controller fabric created and persisted (fabric id {}, controller node id {})",
        identity.fabric_id,
        identity.controller_node_id
    );
    Ok((fab_idx, identity))
}

/// CSA test vendor id: the correct value for an uncertified controller.
const TEST_VENDOR_ID: u16 = 0xFFF1;

fn reconcile_label<C: Crypto>(
    matter: &Matter<'static>,
    _crypto: &C,
    kv: &impl rs_matter::persist::KvBlobStoreAccess,
    fab_idx: NonZeroU8,
    label: &str,
) -> anyhow::Result<()> {
    let changed = matter.with_state(|state| {
        let current = state
            .fabrics
            .get(fab_idx)
            .map(|f| f.label().to_string())
            .unwrap_or_default();
        if current == label {
            return Ok::<_, MatterError>(false);
        }
        state.fabrics.update_label(fab_idx, label)?;
        Ok(true)
    });
    match changed {
        Ok(true) => persist_fabric(matter, kv, fab_idx),
        Ok(false) => Ok(()),
        Err(e) => Err(anyhow!("update local fabric label: {e:?}")),
    }
}

fn remove_persisted_fabric(
    kv: &impl rs_matter::persist::KvBlobStoreAccess,
    fab_idx: NonZeroU8,
) -> anyhow::Result<()> {
    let mut persist = FabricPersist::new(kv);
    persist
        .remove(fab_idx)
        .and_then(|()| persist.run())
        .map_err(|e: MatterError| anyhow!("remove persisted fabric blob: {e:?}"))
}

fn persist_fabric(
    matter: &Matter<'static>,
    kv: &impl rs_matter::persist::KvBlobStoreAccess,
    fab_idx: NonZeroU8,
) -> anyhow::Result<()> {
    matter
        .with_state(|state| {
            let fabric = state
                .fabrics
                .get(fab_idx)
                .ok_or(rs_matter::error::ErrorCode::NotFound)?;
            let mut persist = FabricPersist::new(kv);
            persist.store(fabric)?;
            persist.run()
        })
        .map_err(|e: MatterError| anyhow!("persist fabric: {e:?}"))
}

#[cfg(unix)]
fn lock_storage(storage: &Path) -> anyhow::Result<std::fs::File> {
    use std::os::fd::AsRawFd;
    let path = storage.join(".lock");
    let file = std::fs::File::create(&path).context("create storage lock file")?;
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc != 0 {
        bail!(
            "another mattertimesync instance is already running against {}",
            storage.display()
        );
    }
    Ok(file)
}

#[cfg(not(unix))]
fn lock_storage(_storage: &Path) -> anyhow::Result<std::fs::File> {
    anyhow::bail!("only unix hosts are supported")
}

#[cfg(unix)]
fn restrict_dir_mode(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .context("chmod storage directory")
}

#[cfg(not(unix))]
fn restrict_dir_mode(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

fn bind_mdns_socket() -> anyhow::Result<async_io::Async<UdpSocket>> {
    use socket2::{Domain, Protocol, Socket, Type};
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    // macOS requires SO_REUSEPORT (not just SO_REUSEADDR) to share 5353
    // with the system's own mDNSResponder; Linux is lenient either way.
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    socket.set_only_v6(false)?;
    socket.bind(&MDNS_SOCKET_DEFAULT_BIND_ADDR.into())?;
    let socket = async_io::Async::<UdpSocket>::new_nonblocking(socket.into())?;

    // IPv6 only, everywhere. Matter mandates IPv6 (Thread addresses are
    // IPv6-only and every Matter device advertises over IPv6 mDNS), so the
    // IPv4 side would add nothing but platform variance: macOS refuses IPv4
    // operations on an IPv6 socket that Linux tolerates. Without the group
    // join there is no IPv4 mDNS at all, quietly and identically on every
    // host. A failed IPv6 join, by contrast, means discovery cannot work.
    let (_ipv4, _ipv6, interface) = pick_interface()?;
    socket
        .get_ref()
        .join_multicast_v6(&MDNS_IPV6_BROADCAST_ADDR, interface)
        .context("join mDNS IPv6 multicast group")?;
    Ok(socket)
}

/// Picks the LAN interface for mDNS: the first non-loopback interface with
/// both an IPv6 address (preferring link-local) and an IPv4 address.
fn pick_interface() -> anyhow::Result<(std::net::Ipv4Addr, std::net::Ipv6Addr, u32)> {
    let all = if_addrs::get_if_addrs().context("enumerate network interfaces")?;
    let candidate = |v6_filter: fn(std::net::Ipv6Addr) -> bool| {
        all.iter()
            .filter(|ia| !ia.is_loopback())
            .filter_map(|ia| match ia.addr {
                if_addrs::IfAddr::V6(ref v6) if v6_filter(v6.ip) => {
                    Some((ia.name.clone(), v6.ip, ia.index.unwrap_or(0)))
                }
                _ => None,
            })
            .find_map(|(name, ipv6, index)| {
                all.iter()
                    .filter(|ia| ia.name == name)
                    .find_map(|ia| match ia.addr {
                        if_addrs::IfAddr::V4(ref v4) => Some((v4.ip, ipv6, index)),
                        _ => None,
                    })
            })
    };
    candidate(|ip| ip.is_unicast_link_local())
        .or_else(|| candidate(|_| true))
        .ok_or_else(|| anyhow!("no network interface with IPv4 + IPv6 found for mDNS"))
}

/// Commissionable-browse filter for a manual pairing code.
pub fn commissionable_filter(short_discriminator: u8) -> CommissionableFilter {
    CommissionableFilter {
        short_discriminator: Some(short_discriminator),
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

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
use crate::state::{NodeInfo, NodeRegistry};

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
        embassy_futures::select::Either::First(result) => result.ctx("{what}"),
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

        // Cache the device identity for the local registry; best-effort.
        let vendor_name = read_vendor_name(ctx, device_node_id).await.ok();
        let product_name = read_product_name(ctx, device_node_id).await.ok();

        let registry_file = state::registry_path(&ctx.config.storage_path);
        let mut registry: NodeRegistry = state::load_or_default(&registry_file);
        registry.nodes.insert(
            device_node_id.to_string(),
            NodeInfo {
                vendor_name: vendor_name.clone(),
                product_name: product_name.clone(),
            },
        );
        state::store(&registry_file, &registry)?;

        let mut identity = ctx.identity.clone();
        identity.next_device_node_id += 1;
        state::store(&identity_path(&ctx.config.storage_path), &identity)?;

        state::update_node_state(
            &state::service_state_path(&ctx.config.storage_path),
            device_node_id,
            |node| node.last_successful_connection = Some(Timestamp::now()),
        )?;

        Ok(CommissionOutcome {
            node_id: device_node_id.into(),
            fabric_id: ctx.identity.fabric_id.into(),
            vendor_name,
            product_name,
        })
    }
}

async fn read_vendor_name<C: Crypto>(ctx: &Ctx<'_, C>, node_id: u64) -> anyhow::Result<String> {
    let exchange = connect(ctx, node_id).await?;
    let mut out = String::new();
    exchange
        .basic_information()
        .vendor_name_read_with(ROOT_ENDPOINT_ID, |value| {
            out = value?.to_string();
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
            out = value?.to_string();
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
        let state_path = state::service_state_path(&ctx.config.storage_path);
        let mut outcomes = Vec::with_capacity(self.targets.len());
        for node_id in self.targets {
            state::update_node_state(&state_path, node_id, |n| {
                n.last_attempted_sync = Some(Timestamp::now());
            })?;
            let outcome = match sync_one(ctx, node_id, self.manual_time).await {
                Ok(outcome) => outcome,
                Err(error) => SyncOutcome::failed(node_id, format!("{error:#}")),
            };
            state::update_node_state(&state_path, node_id, |n| {
                if outcome.success {
                    n.last_successful_sync = Some(Timestamp::now());
                    n.last_successful_connection = Some(Timestamp::now());
                    n.last_error = None;
                } else {
                    n.last_error = outcome.error.clone();
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

    let mut time_zone_written = None;
    let mut dst_entries_written = 0;
    if has_time_zone {
        let zone_entries = build_time_zone_list(&tz, &ctx.config.timezone, now_ts);
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
        time_zone_written = Some(ctx.config.timezone.clone());
        log::info!("Node {node_id}: SetTimeZone {}", ctx.config.timezone);

        if dst_required {
            let max_entries = connect(ctx, node_id)
                .await?
                .time_synchronization()
                .dst_offset_list_max_size_read(ROOT_ENDPOINT_ID)
                .await
                .ctx("read dstOffsetListMaxSize")?;
            let dst_entries = build_dst_offset_list(&tz, usize::from(max_entries), now_ts);
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
            dst_entries_written = dst_entries.len();
            log::info!("Node {node_id}: SetDSTOffset with {dst_entries_written} entries");
        }
    }

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
                    let registry_file = state::registry_path(&ctx.config.storage_path);
                    let mut registry: NodeRegistry = state::load_or_default(&registry_file);
                    registry.nodes.remove(&node_id.to_string());
                    state::store(&registry_file, &registry)?;
                    state::remove_node_state(
                        &state::service_state_path(&ctx.config.storage_path),
                        node_id,
                    )?;
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

#[derive(Debug, serde::Serialize)]
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
                    outcomes.push(InspectOutcome {
                        node_id: node_id.into(),
                        error: Some(format!("{error:#}")),
                        vendor_name: None,
                        product_name: None,
                        time_sync: None,
                        our_fabric_label: None,
                        our_fabric_index: None,
                    });
                }
            }
        }
        Ok(outcomes)
    }
}

async fn inspect_one<C: Crypto>(ctx: &Ctx<'_, C>, node_id: u64) -> anyhow::Result<InspectOutcome> {
    let vendor_name = read_vendor_name(ctx, node_id).await.ok();
    let product_name = read_product_name(ctx, node_id).await.ok();

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
