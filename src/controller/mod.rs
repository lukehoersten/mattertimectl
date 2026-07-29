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
    let identity_file = identity_path(storage);
    let identity_exists = identity_file.exists();
    let fabric_exists = std::fs::read_dir(matter_kv_path(storage))
        .map(|entries| {
            entries.flatten().any(|e| {
                let name = e.file_name();
                let name = name.to_string_lossy();
                // A committed blob, not a leftover k_XXXX.tmp from a crash.
                name.starts_with("k_") && !name.ends_with(".tmp")
            })
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
        (true, true) => match std::fs::read_to_string(&identity_file)
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
        // A non-zero random 64-bit id; device node ids are small and
        // sequential (assigned from next_device_node_id).
        let mut random_id = || -> Result<u64, MatterError> {
            let mut bytes = [0u8; 8];
            rng.fill_bytes(&mut bytes);
            Ok(u64::from_be_bytes(bytes) | 1)
        };
        Ok(Self {
            fabric_id: random_id()?,
            controller_node_id: random_id()?,
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
    prepare_storage_dir(&config.storage_path)?;
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
        let (mdns_host_ipv4, mdns_ipv6, mdns_interface) = pick_interface()?;
        let mdns_socket =
            bind_mdns_socket(mdns_host_ipv4, mdns_interface).context("bind mDNS socket")?;
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

    let registry: crate::state::Devices =
        state::load_or_default(&state::devices_path(&config.storage_path));

    if let Some(fab_idx) = existing {
        match std::fs::read_to_string(&identity_file) {
            Ok(raw) => {
                let identity: Identity =
                    serde_json::from_str(&raw).context("parse identity.json")?;
                reconcile_label(matter, kv, fab_idx, &config.fabric_label)?;
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

    bootstrap_fabric(config, matter, crypto, kv)
}

/// CSA test vendor id: the correct value for an uncertified controller.
const TEST_VENDOR_ID: u16 = 0xFFF1;

/// First-run fabric creation: mint the RCAC (its private key kept for
/// RCAC-direct signing), our own operational NOC, and the fabric IPK, then
/// install and persist the fabric. Called only after [`ensure_fabric`] has
/// established that the storage is virgin.
fn bootstrap_fabric<C: Crypto>(
    config: &Config,
    matter: &Matter<'static>,
    crypto: &C,
    kv: &impl rs_matter::persist::KvBlobStoreAccess,
) -> anyhow::Result<(NonZeroU8, Identity)> {
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
    state::store(&identity_path(&config.storage_path), &identity).context("write identity.json")?;
    log::info!(
        "Controller fabric created and persisted (fabric id {}, controller node id {})",
        identity.fabric_id,
        identity.controller_node_id
    );
    Ok((fab_idx, identity))
}

fn reconcile_label(
    matter: &Matter<'static>,
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
            "another mattertimectl instance is already running against {}",
            storage.display()
        );
    }
    Ok(file)
}

#[cfg(not(unix))]
fn lock_storage(_storage: &Path) -> anyhow::Result<std::fs::File> {
    anyhow::bail!("only unix hosts are supported")
}

/// Creates the storage directory (mode 0700) if absent, and tightens an
/// existing one to 0700 only when it is ours. Blindly chmod'ing an
/// operator-supplied path would wreck a misconfigured `storagePath` of, say,
/// `/tmp` when the tool runs as root, so a pre-existing directory that shows
/// no sign of belonging to this tool is left untouched with a warning.
#[cfg(unix)]
fn prepare_storage_dir(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    if !path.exists() {
        return std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
            .context("create storage directory");
    }
    if is_our_storage_dir(path) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .context("chmod storage directory")?;
    } else {
        log::warn!(
            "storagePath {} already exists and does not look like a mattertimectl storage \
             directory; leaving its permissions unchanged (it should be mode 0700, owned by the \
             service user)",
            path.display()
        );
    }
    Ok(())
}

/// Whether a directory is empty or already holds this tool's artifacts, and
/// so is safe to claim and tighten.
#[cfg(unix)]
fn is_our_storage_dir(path: &Path) -> bool {
    const MARKERS: [&str; 4] = ["identity.json", "matter", ".lock", "devices.json"];
    if MARKERS.iter().any(|m| path.join(m).exists()) {
        return true;
    }
    std::fs::read_dir(path)
        .map(|mut entries| entries.next().is_none())
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn prepare_storage_dir(path: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(path).context("create storage directory")
}

fn bind_mdns_socket(
    _ipv4: std::net::Ipv4Addr,
    interface: u32,
) -> anyhow::Result<async_io::Async<UdpSocket>> {
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

mod ops;
pub use ops::*;
