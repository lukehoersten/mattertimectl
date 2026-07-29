# mattertimectl

> Website: [www.nth.io/mattertimectl](https://www.nth.io/mattertimectl/). Main repository:
> [src.nth.io/luke/mattertimectl](https://src.nth.io/luke/mattertimectl); the
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

## Commands

| Command | Kind | Description |
| --- | --- | --- |
| `status [-n <id>] [-j]` | local, read-only | Controller config, identity, and per-device sync state. No device contact. |
| `inspect [-n <id>] [-j]` | fabric read | Connect to each device (or one with `-n`) and dump identity, time-sync capabilities, and our fabric entry. |
| `commission <code> [-j]` | fabric write | Join a device as an additional Matter admin. The pairing code is used once, never logged or stored. |
| `sync [-n <id>] [-t <hh:mm>] [-j]` | fabric write | Set each device's clock: UTC time, time zone, DST offsets. |
| `decommission [-n <id>] [-j]` | fabric write | Drop this controller's fabric from each device (or one with `-n`). Primary ecosystems are untouched. |

| Option | Description |
| --- | --- |
| `-c, --config <path>` | Config file. Default `/etc/mattertimectl/config.json`. |
| `-n, --node <id>` | Target one device. `sync` and `decommission` default to all commissioned devices. |
| `-t, --time <hh:mm>` | `sync` only: set this wall-clock time today (e.g. `16:35`, `4:35pm`) instead of now. The operator becomes the time source and the NTP gate is skipped. |
| `-j, --json` | Machine-readable JSON on stdout (64-bit values as decimal strings). Logs stay on stderr, so `--json` is always clean. |
| `-h, --help` / `-V, --version` | Print help / version. |

No command writes local state alone; the registry and sync results change only as part of a
fabric-writing command. Exit codes: `0` success, `1` runtime failure (the timer retries), `2` usage or
config error.

## How it works

- The device stays commissioned to its primary ecosystem and attached to its existing Thread or Wi-Fi
  network.
- A Raspberry Pi (or any Linux or macOS host) runs this tool as a second Matter administrator on its
  own fabric.
- For Thread devices, the host needs no Thread radio, no OpenThread Border Router, no Thread
  credentials, and no BLE. It reaches the device over IPv6 through the existing Thread Border Routers
  (e.g. HomePod, Apple TV). A host on the same network segment as the border routers learns the route
  to the Thread network automatically from their Router Advertisements; a host on a different VLAN
  needs one static route on the gateway (see Troubleshooting).
- The host's own clock is NTP-synchronized; the tool refuses to push time from an unsynchronized clock.

## Design

- **One-shot, not a daemon.** Being a secondary controller is fabric membership, not a process. Each
  run loads the identity, does one operation, and exits; staleness is bounded by the timer interval.
- **Capability-driven.** Any device with the standard Time Synchronization cluster (0x38) works.
  Time-zone/DST writes are gated on the device's feature map; devices without the cluster are skipped.
- **One fabric, ever.** The controller identity is minted once, only over provably empty storage, under
  an exclusive lock. Partial first-run state is discarded; state a device depends on is never overwritten.
- **Fail safe.** Never recommissions on its own. Won't push time unless the host clock is NTP-trusted,
  and verifies every write by reading the clock back; a non-zero exit lets the timer retry.
- **Flat files, no database.** All state lives under `storagePath`: rs-matter KV blobs, `identity.json`
  (the root CA key, mode 0600), and `devices.json` (per-device names and last sync).
- **Time via jiff.** Timestamps are `jiff::Timestamp`; Matter-epoch microseconds live only at the wire.
  DST comes from the IANA tzdb, never offset probing; zones are IANA names, never fixed offsets.
- **Small on purpose.** No GUI, cloud, QR pairing, general Matter administration, or debug surfaces
  beyond what operating this tool needs.

## Configuration

`/etc/mattertimectl/config.json` by default; override with `--config <path>` (see
`examples/config.example.json`):

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

Builds and runs on both Linux and macOS (macOS is handy for building and for commissioning from a
laptop). The systemd unit below is the Linux deployment; on macOS run the CLI directly or from
launchd/cron.

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

Commissioning is a manual, one-time step per device: it needs a pairing window you open in the
primary ecosystem, so it cannot run from the timer. Log into the host and run it as the service user,
inside that window:

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
