//! Matter epoch conversion and device clock assessment.
//!
//! Matter UTC time is microseconds since 2000-01-01T00:00:00Z (the "Matter
//! epoch"), not the Unix epoch. `jiff::Timestamp` is the lingua franca
//! everywhere else in this program; [`MatterMicros`] exists only at the wire
//! boundary. rs-matter passes spec values through unconverted, so no
//! Unix-epoch API shift exists here.

use std::fmt;

use jiff::Timestamp;

pub const MATTER_EPOCH_UNIX_SECONDS: i64 = 946_684_800;
const MATTER_EPOCH_UNIX_MICROS: i64 = MATTER_EPOCH_UNIX_SECONDS * 1_000_000;

/// Microseconds since the Matter epoch, as carried in Time Synchronization
/// cluster attributes and commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct MatterMicros(pub u64);

impl MatterMicros {
    pub fn now() -> Self {
        Self::from_timestamp(Timestamp::now())
    }

    /// A host clock before the Matter epoch (a Pi with no RTC reads 1970
    /// early after boot) clamps to 0 rather than panicking; the NTP gate,
    /// not this conversion, is what keeps a bad clock off a device.
    pub fn from_timestamp(at: Timestamp) -> Self {
        let micros = at.as_microsecond() - MATTER_EPOCH_UNIX_MICROS;
        Self(u64::try_from(micros).unwrap_or(0))
    }

    /// `None` when the value is outside jiff's representable range: a device
    /// is free to report any u64 as its clock, and a diagnostic read must
    /// not panic on garbage.
    pub fn to_timestamp(self) -> Option<Timestamp> {
        i64::try_from(self.0)
            .ok()
            .and_then(|micros| micros.checked_add(MATTER_EPOCH_UNIX_MICROS))
            .and_then(|micros| Timestamp::from_microsecond(micros).ok())
    }

    /// Signed delta `self - other` in microseconds, saturating so an
    /// adversarial device value cannot overflow. i128 has ample headroom
    /// for two u64 operands; the clamp only bites on nonsense inputs.
    pub fn delta_micros(self, other: Self) -> i64 {
        (self.0 as i128 - other.0 as i128).clamp(i64::MIN as i128, i64::MAX as i128) as i64
    }
}

impl fmt::Display for MatterMicros {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.to_timestamp() {
            Some(timestamp) => timestamp.fmt(f),
            // Out of representable range: show the raw value labeled, so a
            // device reporting garbage is legible rather than a crash.
            None => write!(f, "{}us-since-matter-epoch(out-of-range)", self.0),
        }
    }
}

/// A device is treated as epoch-confused when its clock delta lands within
/// this window of the exact Unix/Matter epoch distance: firmware that encodes
/// Unix-epoch values on the wire reads as ~30 years ahead after decoding. A
/// week comfortably covers any real drift while remaining astronomically far
/// from every honest delta.
const EPOCH_SHIFT_DETECTION_WINDOW_MICROS: i64 = 7 * 86_400 * 1_000_000;

/// How the device's reported clock relates to the host clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockAssessment {
    /// The device lost its clock (null utcTime, e.g. after a power outage).
    Unset,
    /// The device reported a time `delta_micros` away from the host's.
    Offset {
        /// Raw reported delta (device minus host), exact.
        delta_micros: i64,
        /// True when the delta is the Unix/Matter epoch distance: the device
        /// firmware encodes the wrong epoch on the wire (off-spec).
        epoch_shifted: bool,
    },
}

impl ClockAssessment {
    pub fn compare(device: Option<MatterMicros>, host: MatterMicros) -> Self {
        let Some(device) = device else {
            return Self::Unset;
        };
        let delta_micros = device.delta_micros(host);
        let shift_error = delta_micros.saturating_sub(MATTER_EPOCH_UNIX_MICROS);
        Self::Offset {
            delta_micros,
            epoch_shifted: shift_error.unsigned_abs() <= EPOCH_SHIFT_DETECTION_WINDOW_MICROS as u64,
        }
    }

    /// The device's real clock error: the raw delta with any detected epoch
    /// shift folded out. `None` when the clock was unset.
    pub fn effective_delta_micros(&self) -> Option<i64> {
        match *self {
            Self::Unset => None,
            Self::Offset {
                delta_micros,
                epoch_shifted,
            } => Some(if epoch_shifted {
                delta_micros.saturating_sub(MATTER_EPOCH_UNIX_MICROS)
            } else {
                delta_micros
            }),
        }
    }

    pub fn is_epoch_shifted(&self) -> bool {
        matches!(
            self,
            Self::Offset {
                epoch_shifted: true,
                ..
            }
        )
    }
}

impl fmt::Display for ClockAssessment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unset => f.write_str("device clock was unset"),
            Self::Offset { epoch_shifted, .. } => {
                let effective = self
                    .effective_delta_micros()
                    .expect("Offset always has a delta");
                if *epoch_shifted {
                    write!(
                        f,
                        "device encodes Unix-epoch time on the wire (off-spec); corrected, its clock was {}",
                        DescribeDelta(effective)
                    )
                } else {
                    write!(f, "device clock was {}", DescribeDelta(effective))
                }
            }
        }
    }
}

/// "within 1s of host time (412ms behind)" / "1m 23s ahead" for a signed delta.
struct DescribeDelta(i64);

impl fmt::Display for DescribeDelta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let magnitude = self.0.unsigned_abs();
        let direction = if self.0 < 0 { "behind" } else { "ahead" };
        if magnitude < 1_000_000 {
            write!(
                f,
                "within 1s of host time ({} {direction})",
                CompactDuration(magnitude)
            )
        } else {
            write!(f, "{} {direction}", CompactDuration(magnitude))
        }
    }
}

/// Compact human duration: 412ms, 3.2s, 1m 23s, 1d 1h 1m.
pub struct CompactDuration(pub u64);

impl fmt::Display for CompactDuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let micros = self.0;
        if micros < 1_000 {
            return write!(f, "{micros}us");
        }
        if micros < 1_000_000 {
            return write!(f, "{}ms", micros / 1_000);
        }
        let total_seconds = micros / 1_000_000;
        if total_seconds < 60 {
            let tenths = (micros % 1_000_000) / 100_000;
            return if tenths == 0 {
                write!(f, "{total_seconds}s")
            } else {
                write!(f, "{total_seconds}.{tenths}s")
            };
        }
        let days = total_seconds / 86_400;
        let hours = (total_seconds % 86_400) / 3_600;
        let minutes = (total_seconds % 3_600) / 60;
        let seconds = total_seconds % 60;
        let parts: Vec<String> = [
            (days > 0).then(|| format!("{days}d")),
            (hours > 0).then(|| format!("{hours}h")),
            (minutes > 0).then(|| format!("{minutes}m")),
            // Seconds are dropped once days appear (see the doc comment).
            (seconds > 0 && days == 0).then(|| format!("{seconds}s")),
        ]
        .into_iter()
        .flatten()
        .collect();
        f.write_str(&parts.join(" "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(s: &str) -> Timestamp {
        s.parse().unwrap()
    }

    #[test]
    fn matter_epoch_zero_is_year_2000() {
        assert_eq!(
            MatterMicros::from_timestamp(ts("2000-01-01T00:00:00Z")).0,
            0
        );
        assert_eq!(
            MatterMicros(0).to_timestamp(),
            Some(ts("2000-01-01T00:00:00Z"))
        );
        assert_eq!(
            MatterMicros(1_000_000).to_timestamp(),
            Some(ts("2000-01-01T00:00:01Z"))
        );
    }

    #[test]
    fn conversion_round_trips_current_dates() {
        let now = ts("2026-07-26T20:00:00.123456Z");
        assert_eq!(MatterMicros::from_timestamp(now).to_timestamp(), Some(now));
    }

    #[test]
    fn garbage_device_values_do_not_panic() {
        // A device may report any u64 as its clock; conversion and delta
        // arithmetic must degrade, not crash.
        let garbage = MatterMicros(u64::MAX);
        assert_eq!(garbage.to_timestamp(), None);
        assert!(garbage.to_string().contains("out-of-range"));
        let host = MatterMicros::from_timestamp(ts("2026-07-26T20:00:00Z"));
        let _ = garbage.delta_micros(host); // saturates, no overflow
        let assessment = ClockAssessment::compare(Some(garbage), host);
        let _ = assessment.effective_delta_micros();
        let _ = assessment.to_string();
    }

    #[test]
    fn pre_2000_host_clock_clamps_instead_of_panicking() {
        assert_eq!(
            MatterMicros::from_timestamp(ts("1970-01-01T00:00:00Z")).0,
            0
        );
    }

    #[test]
    fn compact_duration_scales_units() {
        let cases = [
            (0, "0us"),
            (999, "999us"),
            (412_000, "412ms"),
            (3_200_000, "3.2s"),
            (59_000_000, "59s"),
            (125_000_000, "2m 5s"),
            (3_840_000_000, "1h 4m"),
            (90_061_000_000, "1d 1h 1m"),
        ];
        for (micros, expected) in cases {
            assert_eq!(CompactDuration(micros).to_string(), expected);
        }
    }

    #[test]
    fn assessment_reports_unset_clock() {
        let host = MatterMicros::from_timestamp(ts("2026-07-26T20:00:00Z"));
        let assessment = ClockAssessment::compare(None, host);
        assert_eq!(assessment, ClockAssessment::Unset);
        assert_eq!(assessment.to_string(), "device clock was unset");
    }

    #[test]
    fn assessment_reports_direction_and_magnitude() {
        let host = MatterMicros::from_timestamp(ts("2026-07-26T20:00:00Z"));
        let behind = ClockAssessment::compare(Some(MatterMicros(host.0 - 83_000_000)), host);
        assert_eq!(behind.to_string(), "device clock was 1m 23s behind");
        assert_eq!(behind.effective_delta_micros(), Some(-83_000_000));

        let ahead = ClockAssessment::compare(Some(MatterMicros(host.0 + 5_500_000)), host);
        assert_eq!(ahead.to_string(), "device clock was 5.5s ahead");

        let close = ClockAssessment::compare(Some(MatterMicros(host.0 - 412_000)), host);
        assert_eq!(
            close.to_string(),
            "device clock was within 1s of host time (412ms behind)"
        );
    }

    #[test]
    fn assessment_detects_wrong_epoch_encoding() {
        let host = MatterMicros::from_timestamp(ts("2026-07-26T20:00:00Z"));
        let shift = (MATTER_EPOCH_UNIX_SECONDS * 1_000_000) as u64;
        let wrong = ClockAssessment::compare(Some(MatterMicros(host.0 + shift + 1_400_000)), host);
        assert!(wrong.is_epoch_shifted());
        assert_eq!(wrong.effective_delta_micros(), Some(1_400_000));
        assert_eq!(
            wrong.to_string(),
            "device encodes Unix-epoch time on the wire (off-spec); corrected, its clock was 1.4s ahead"
        );
    }

    #[test]
    fn assessment_does_not_fold_out_ordinary_large_errors() {
        let host = MatterMicros::from_timestamp(ts("2026-07-26T20:00:00Z"));
        let shift = (MATTER_EPOCH_UNIX_SECONDS * 1_000_000) as u64;
        let month = 30 * 86_400 * 1_000_000;
        let broken = ClockAssessment::compare(Some(MatterMicros(host.0 + shift + month)), host);
        assert!(!broken.is_epoch_shifted());
    }
}

/// Parses an operator-supplied wall-clock time: "16:35", "4:35p", "4:35pm",
/// each with an optional ":ss". Meridiem suffixes imply 12-hour form.
pub fn parse_wall_clock(input: &str) -> Result<jiff::civil::Time, String> {
    let lowered = input.trim().to_ascii_lowercase();
    let (digits, meridiem) = if let Some(rest) = lowered
        .strip_suffix("am")
        .or_else(|| lowered.strip_suffix('a'))
    {
        (rest.trim_end(), Some(false))
    } else if let Some(rest) = lowered
        .strip_suffix("pm")
        .or_else(|| lowered.strip_suffix('p'))
    {
        (rest.trim_end(), Some(true))
    } else {
        (lowered.as_str(), None)
    };

    let parts: Vec<&str> = digits.split(':').collect();
    if !(2..=3).contains(&parts.len()) {
        return Err(format!(
            "cannot parse {input:?} as a time (expected HH:MM or HH:MM:SS, optionally with am/pm)"
        ));
    }
    let numbers: Vec<u8> = parts
        .iter()
        .map(|p| {
            p.parse()
                .map_err(|_| format!("cannot parse {p:?} in {input:?} as a number"))
        })
        .collect::<Result<_, _>>()?;
    let (hour, minute, second) = (numbers[0], numbers[1], *numbers.get(2).unwrap_or(&0));
    let hour = match meridiem {
        Some(_) if !(1..=12).contains(&hour) => {
            return Err(format!("hour in {input:?} must be 1-12 with am/pm"));
        }
        Some(true) => hour % 12 + 12,
        Some(false) => hour % 12,
        None if hour > 23 => return Err(format!("hour in {input:?} must be 0-23")),
        None => hour,
    };
    jiff::civil::Time::new(hour as i8, minute as i8, second as i8, 0)
        .map_err(|e| format!("invalid time {input:?}: {e}"))
}

#[cfg(test)]
mod wall_clock_tests {
    use super::parse_wall_clock;

    #[test]
    fn parses_12_and_24_hour_forms() {
        let cases = [
            ("16:35", (16, 35, 0)),
            ("4:35p", (16, 35, 0)),
            ("4:35pm", (16, 35, 0)),
            ("4:35a", (4, 35, 0)),
            ("12:00am", (0, 0, 0)),
            ("12:15PM", (12, 15, 0)),
            ("16:35:20", (16, 35, 20)),
            ("07:05", (7, 5, 0)),
        ];
        for (input, (h, m, s)) in cases {
            let time = parse_wall_clock(input).unwrap();
            assert_eq!(
                (time.hour(), time.minute(), time.second()),
                (h, m, s),
                "{input}"
            );
        }
    }

    #[test]
    fn rejects_nonsense() {
        for input in ["25:00", "13:00pm", "4", "4:60", "0:00am", "banana"] {
            assert!(parse_wall_clock(input).is_err(), "accepted {input:?}");
        }
    }
}
