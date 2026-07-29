# mattertimectl

> Main repository: [src.nth.io/luke/mattertimectl](https://src.nth.io/luke/mattertimectl). The
> [GitHub mirror](https://github.com/lukehoersten/mattertimectl) is a backup.

A small CLI Matter controller that sets the clocks of Matter devices via the standard Time
Synchronization cluster. Rust implementation, built on [rs-matter](https://crates.io/crates/rs-matter)
(the official CSA Rust Matter stack).

Some Matter devices with clock displays (air-quality monitors, thermostats, sensor hubs) lose their
clock after a power outage, and not every ecosystem restores it reliably. This tool joins each device's
existing Matter setup as an _additional_ controller (Matter multi-admin) and pushes the correct time to
every device commissioned onto its fabric. Run it periodically from a systemd timer; the primary
ecosystem (e.g. Apple Home) keeps working unchanged.

There is no daemon: each invocation builds the Matter stack, connects, syncs, and exits.

## How it works

- The device stays commissioned to its primary ecosystem and attached to its existing Thread or Wi-Fi
  network.
- A Raspberry Pi (or any Linux host) runs this tool as a second Matter administrator on its own fabric.
- For Thread devices, the host needs no Thread radio, no OpenThread Border Router, no Thread
  credentials, and no BLE. It reaches the device over IPv6 through the existing Thread Border Routers
  (e.g. HomePod, Apple TV). A host on the same network segment as the border routers learns the route
  to the Thread network automatically from their Router Advertisements; a host on a different VLAN
  needs one static route on the gateway (see Troubleshooting).
- The host's own clock is NTP-synchronized; the tool refuses to push time from an unsynchronized clock.

## Design

The same principles as the TypeScript implementation this replaces, plus the Rust-specific ones:

- **One-shot CLI, not a daemon.** Being a secondary Matter controller is fabric membership, not a
  running process. Each invocation loads the persisted fabric identity, races the Matter transport and
  mDNS pumps against the one operation, and exits. Clock staleness is bounded by the systemd timer
  interval.
- **Capability-driven, never vendor-specific.** Any device exposing the standard Time Synchronization
  cluster (0x38) works. SetTimeZone/SetDSTOffset are gated on the device's feature map and bounded by
  its DSTOffsetListMaxSize; devices without the cluster are skipped with a warning; devices whose
  firmware encodes Unix-epoch time on the wire are detected by the exact 946,684,800s shift and
  reported corrected.
- **The fabric is created exactly once.** First run mints the controller's root CA and operational
  identity (RCAC-direct mode); every later run loads it. The identity lifecycle is guarded: runs hold
  an exclusive lock on the storage directory, a fresh identity is only ever minted over provably
  virgin storage (no fabric, no identity file, no registry entries), the one partial state an
  interrupted first run can produce is discarded automatically, and any state a commissioned device
  could depend on is refused loudly rather than overwritten. Reconnection uses Matter operational
  discovery (mDNS), never a stored IP address.
- **Fail safely.** Never recommissions automatically; never pushes time unless the host clock is
  trusted, checked by directly measuring its offset against an NTP server (one SNTP query, accepted
  under 1s; `timedatectl` as fallback when no server is reachable). Every sync is verified by reading
  the clock back and comparing against the written instant; non-zero exit lets the timer retry. CASE
  connects retry three times with backoff, since an mDNS resolve answer can be lost per-attempt.
- **Flat files, no database.** All state is plain files under `storagePath`: rs-matter's KV blobs
  (`matter/k_XXXX`, written atomically via temp+rename), `identity.json` (the root CA private key;
  mode 0600, written once and never touched by a sync), and `devices.json` (one record per
  commissioned device: cached names plus latest sync results). The config is compatible with the
  TypeScript implementation.
- **Time is jiff end to end.** Timestamps are `jiff::Timestamp`; Matter-epoch microseconds exist only
  at the wire boundary. DST transitions come directly from the IANA tzdb transition table, never from
  offset probing. Time zones are IANA names, never fixed offsets.
- **Intentionally small.** No GUI, database, cloud, QR-code pairing (the primary ecosystem always
  shows the numeric code), general Matter administration, or debugging surfaces beyond what operating
  this tool needs.

## Commands

Local, read-only (no device contact):

```bash
mattertimectl status [--node <id>] [--json]   # config, identity, and per-device sync state
```

Fabric interrogation (connects to the device, reads only):

```bash
mattertimectl inspect [--node <id>] [--json]
```

Fabric-writing:

```bash
mattertimectl commission <pairing-code>      # writes the device's fabric table + local storage
mattertimectl sync [--node <id>] [--time <hh:mm>] [--json]   # set clock, time zone, DST offsets
mattertimectl decommission [--node <id>]     # device(s) drop this controller's fabric
```

No command writes local state alone; the registry and sync results change only as part of a
fabric-writing command.

`--node <id>` targets one device; `sync` and `decommission` target all commissioned devices by
default. `sync --time 16:35` (or `4:35pm`) sets that wall-clock time, today in the configured zone,
instead of the current time; the operator is then the time source and the NTP gate is not enforced. Logs go to stderr; stdout carries only command output, so `--json` is always clean JSON.
Exit codes: 0 success, 1 runtime failure (timer retries), 2 usage/config error.

## Configuration

`/etc/mattertimectl/config.json` by default; override with `--config <path>`. Same file format as
the TypeScript implementation (see `examples/config.example.json`):

```json
{
  "storagePath": "/var/lib/mattertimectl",
  "timezone": "America/Chicago",
  "logLevel": "info",
  "fabricLabel": "My Home"
}
```

| Field         | Default            | Meaning                                                         |
| ------------- | ------------------ | --------------------------------------------------------------- |
| `storagePath` | (required)         | Directory for persistent Matter fabric state. Contains secrets. |
| `timezone`    | `America/Chicago`  | IANA time-zone name. Never a fixed UTC offset; DST is derived.  |
| `logLevel`    | `info`             | `debug`, `info`, `warn`, or `error`.                            |
| `fabricLabel` | `Matter Time Controller` | Label other ecosystems show for this controller (max 32 chars). |

Unknown fields are rejected loudly. Matter requires fabric labels to be unique per device and Apple
Home labels its own entry with the home's name, so use a variant like "Lakeside Time Sync" rather
than the home name itself; `sync` pushes label changes to each device.

## Build and deploy

```bash
cargo build --release       # target/release/mattertimectl, one self-contained binary
cargo test
```

The binary must match the target's architecture; the simplest path is building on the target itself
(a Raspberry Pi 4 handles it fine):

```bash
# on the Pi, one-time toolchain install (user-local, ~/.rustup and ~/.cargo)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
git clone <repository> && cd mattertimectl
~/.cargo/bin/cargo build --release
```

The target machine needs nothing but the binary (and a tzdb, present on any Linux). On the target:

```bash
sudo install -D -m 0755 mattertimectl /opt/mattertimectl/mattertimectl
sudo useradd --system --home /var/lib/mattertimectl --shell /usr/sbin/nologin mattertimectl
sudo mkdir -p /etc/mattertimectl /var/lib/mattertimectl
sudo chown mattertimectl:mattertimectl /var/lib/mattertimectl
sudo chmod 700 /var/lib/mattertimectl
sudo cp examples/mattertimectl.service examples/mattertimectl.timer /etc/systemd/system/
sudo systemctl daemon-reload
```

Commission (as the service user, within the pairing window opened in the primary ecosystem):

```bash
sudo -u mattertimectl /opt/mattertimectl/mattertimectl \
  --config /etc/mattertimectl/config.json commission 12345678901
```

Then `sudo systemctl enable --now mattertimectl.timer` (2 minutes after boot, hourly thereafter).

## Security notes

- **Device attestation is not verified.** Commissioning accepts any device's attestation
  certificate without checking it against the Connectivity Standards Alliance's Distributed
  Compliance Ledger (that check needs DCL access this tool does not have). Commissioning still
  requires the device's SPAKE2+ pairing passcode, so a rogue device cannot join without it, but you
  cannot cryptographically confirm that a commissioned device is genuine certified hardware.
- **Outbound network traffic** is limited to Matter (UDP to the device and its border routers),
  mDNS multicast on the local link, and the clock-trust check: one SNTP query per `sync` to
  `time.apple.com`, falling back to `pool.ntp.org`. There is no telemetry and no other outbound
  contact.
- **The root CA private key** lives unencrypted at rest in `identity.json` (mode 0600 in a 0700
  storage directory). Back it up as carefully as any private key; anyone who reads it can
  impersonate this controller to your devices. It is never logged or included in any output.

## Migrating from the TypeScript implementation

The config file carries over unchanged, but the **Matter fabric identity does
not**: matter.js and rs-matter persist fabrics in different formats, and the device is paired to a
key, not a storage path. Migration is one re-pairing:

1. Run this implementation with its own fresh `storagePath` and commission the device as an
   additional admin (Matter allows several; the fabric table has at least 5 slots). Both
   implementations can sync side by side while validating.
2. Once satisfied, `decommission` with the **old** implementation so the device drops its fabric,
   point `mattertimectl.service` at this binary, and delete the old storage directory.

## Troubleshooting

- **Sync refuses to run**: the host clock is not NTP-synchronized (`timedatectl status`). The tool
  will not push time it does not trust.
- **Commissionable device not found**: the pairing window expired, or mDNS/multicast is blocked
  between the host and the device's network.
- **Thread device discovered but unreachable**: the host has no route to the Thread network's
  `fd.../64` prefix. On the border routers' own network segment the route is learned automatically
  from their Router Advertisements; across VLANs, add one static IPv6 route on the gateway (the
  prefix via a border router's stable address). Verify with `ping` of the device's `fd...` address.
- **Clock off by one hour**: DST configuration missing or rejected; this tool always derives offsets
  from the IANA database, so check the device accepted SetDSTOffset (sync logs).
