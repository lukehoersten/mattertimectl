//! Host clock trust: the device must never be set from a clock we do not
//! trust.
//!
//! The primary check measures the actual clock error with a single SNTP
//! query (RFC 4330) and accepts the host when the offset is under a second.
//! That is a direct measurement, platform-independent, and stronger than
//! asking the OS whether it believes it is synchronized. When no NTP server
//! is reachable, systemd-timesyncd's verdict (`timedatectl`, Linux) is the
//! fallback; hosts with neither fail safe.

use std::net::UdpSocket;
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const NTP_SERVERS: [&str; 2] = ["time.apple.com:123", "pool.ntp.org:123"];
/// Accept the host clock when it is within this many seconds of NTP time.
/// Well inside the 5s sync read-back tolerance, far above network jitter.
const MAX_OFFSET_SECONDS: f64 = 1.0;
/// Seconds between the NTP era (1900) and the Unix epoch (1970).
const NTP_UNIX_OFFSET: f64 = 2_208_988_800.0;
/// The NTP fraction field is 32-bit fixed-point in units of 1/2^32 seconds;
/// dividing by 2^32 converts it to seconds.
const NTP_FRACTION_SCALE: f64 = (1u64 << 32) as f64;

pub fn clock_is_ntp_synchronized() -> bool {
    for server in NTP_SERVERS {
        if let Some(offset) = sntp_offset(server) {
            let ok = offset.abs() <= MAX_OFFSET_SECONDS;
            if ok {
                log::debug!("Host clock is {offset:+.3}s from {server}; trusted");
            } else {
                log::warn!("Host clock is {offset:+.3}s from {server}; not trusted");
            }
            return ok;
        }
    }
    log::debug!("No NTP server reachable; falling back to timedatectl");
    timedatectl_says_synchronized()
}

/// One SNTP client exchange: returns the approximate offset of the local
/// clock relative to the server (positive = local clock ahead). Uses the
/// request/response midpoint, so the error is bounded by half the round
/// trip, which is milliseconds against a threshold of a second.
fn sntp_offset(server: &str) -> Option<f64> {
    let socket = UdpSocket::bind(("0.0.0.0", 0)).ok()?;
    socket.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    socket.connect(server).ok()?;

    let mut request = [0u8; 48];
    request[0] = 0b00_100_011; // LI 0, version 4, mode 3 (client)
    let sent_at = unix_now();
    socket.send(&request).ok()?;

    let mut response = [0u8; 48];
    let len = socket.recv(&mut response).ok()?;
    let received_at = unix_now();
    if len < 48 || response[0] & 0x07 != 4 {
        // Not a server-mode reply.
        return None;
    }

    // Transmit timestamp: seconds since 1900 plus a 32-bit binary fraction.
    let seconds = u32::from_be_bytes(response[40..44].try_into().ok()?) as f64;
    let fraction =
        u32::from_be_bytes(response[44..48].try_into().ok()?) as f64 / NTP_FRACTION_SCALE;
    let server_time = seconds + fraction - NTP_UNIX_OFFSET;
    if server_time <= 0.0 {
        return None;
    }
    Some((sent_at + received_at) / 2.0 - server_time)
}

fn unix_now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// systemd-timesyncd's opinion; false on hosts without timedatectl.
fn timedatectl_says_synchronized() -> bool {
    Command::new("timedatectl")
        .args(["show", "-p", "NTPSynchronized", "--value"])
        .output()
        .map(|output| output.status.success() && output.stdout.trim_ascii() == b"yes")
        .unwrap_or(false)
}
