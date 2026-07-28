//! IANA time-zone helpers: Matter TimeZone/DSTOffset structure generation
//! and offset introspection for status output.
//!
//! jiff exposes the real tzdb transition table, so upcoming DST changes are
//! read directly instead of probed for (the TypeScript implementation had to
//! binary-search ICU offsets; here `TimeZone::following` is exact by
//! construction).

use jiff::Timestamp;
use jiff::tz::TimeZone;

use crate::time::MatterMicros;

/// Matter TimeZoneStruct: the zone's standard offset, DST carried separately.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatterTimeZoneEntry {
    /// Standard (non-DST) UTC offset in seconds.
    pub offset_seconds: i32,
    /// Matter-epoch microseconds at which the entry takes effect; 0 = always.
    pub valid_at: MatterMicros,
    pub name: String,
}

/// Matter DSTOffsetStruct: one DST period, added on top of the TimeZone offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MatterDstOffsetEntry {
    pub offset_seconds: i32,
    pub valid_starting: MatterMicros,
    /// None = valid until further notice (last entry only).
    pub valid_until: Option<MatterMicros>,
}

/// The next instant the zone's UTC offset changes, with the offsets on both
/// sides. None for fixed-offset zones.
pub fn next_offset_transition(tz: &TimeZone, from: Timestamp) -> Option<(Timestamp, i32, i32)> {
    let before = tz.to_offset(from).seconds();
    tz.following(from)
        .map(|transition| (transition.timestamp(), transition.offset().seconds()))
        .find(|&(_, offset)| offset != before)
        .map(|(at, after)| (at, before, after))
}

/// The zone's standard (non-DST) UTC offset in seconds: the smaller of the
/// mid-January and mid-July offsets of the year. DST increases the offset in
/// every zone as consumed here (including Europe/Dublin, which the tzdb
/// models with a negative SAVE but presents as +00:00 winter / +01:00 summer).
pub fn standard_offset_seconds(tz: &TimeZone, at: Timestamp) -> i32 {
    let year = at.to_zoned(TimeZone::UTC).year();
    let probe = |month: i8| -> i32 {
        let date = jiff::civil::date(year, month, 15).at(0, 0, 0, 0);
        let ts = date
            .to_zoned(TimeZone::UTC)
            .expect("UTC has no gaps")
            .timestamp();
        tz.to_offset(ts).seconds()
    };
    probe(1).min(probe(7))
}

/// The TimeZone list for SetTimeZone: a single entry carrying the zone's
/// standard offset and IANA name, valid from the beginning of time.
pub fn build_time_zone_list(tz: &TimeZone, name: &str, at: Timestamp) -> Vec<MatterTimeZoneEntry> {
    vec![MatterTimeZoneEntry {
        offset_seconds: standard_offset_seconds(tz, at),
        valid_at: MatterMicros(0),
        name: name.chars().take(64).collect(),
    }]
}

/// The DSTOffset list for SetDstOffset: the DST state in effect at `from`
/// followed by upcoming transitions, at most `max_entries` entries (the
/// device's DSTOffsetListMaxSize; spec minimum 1). Entries carry concrete
/// valid-until bounds where a next transition is known, so an unrefreshed
/// device falls back to standard time rather than trusting stale DST; the
/// periodic sync refreshes the list long before it expires. Zones without
/// transitions yield a single open-ended entry.
pub fn build_dst_offset_list(
    tz: &TimeZone,
    max_entries: usize,
    from: Timestamp,
) -> Vec<MatterDstOffsetEntry> {
    let limit = max_entries.max(1);
    let standard = standard_offset_seconds(tz, from);
    let mut entries = Vec::with_capacity(limit);

    let mut current_offset = tz.to_offset(from).seconds();
    let mut valid_starting = MatterMicros(0);
    let mut transitions = tz
        .following(from)
        .map(|transition| (transition.timestamp(), transition.offset().seconds()));

    while entries.len() < limit {
        // Skip tzdb transitions that don't change the offset (abbreviation or
        // rule bookkeeping only); they are not DST boundaries.
        let next = transitions.find(|&(_, offset)| offset != current_offset);
        match next {
            Some((at, offset_after)) => {
                let until = MatterMicros::from_timestamp(at);
                entries.push(MatterDstOffsetEntry {
                    offset_seconds: current_offset - standard,
                    valid_starting,
                    valid_until: Some(until),
                });
                valid_starting = until;
                current_offset = offset_after;
            }
            None => {
                entries.push(MatterDstOffsetEntry {
                    offset_seconds: current_offset - standard,
                    valid_starting,
                    valid_until: None,
                });
                break;
            }
        }
    }
    entries
}

/// "UTC-05:00" style rendering for logs and status output.
pub fn format_utc_offset(offset_seconds: i32) -> String {
    let sign = if offset_seconds < 0 { '-' } else { '+' };
    let magnitude = offset_seconds.unsigned_abs();
    format!(
        "UTC{sign}{:02}:{:02}",
        magnitude / 3600,
        (magnitude % 3600) / 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tz(name: &str) -> TimeZone {
        TimeZone::get(name).unwrap()
    }

    fn ts(s: &str) -> Timestamp {
        s.parse().unwrap()
    }

    fn matter(s: &str) -> MatterMicros {
        MatterMicros::from_timestamp(ts(s))
    }

    // The two Chicago transitions after 2026-07-26.
    fn fall_2026() -> MatterMicros {
        matter("2026-11-01T07:00:00Z")
    }
    fn spring_2027() -> MatterMicros {
        matter("2027-03-14T08:00:00Z")
    }

    #[test]
    fn standard_offset_ignores_season_and_hemisphere() {
        let chicago = tz("America/Chicago");
        assert_eq!(
            standard_offset_seconds(&chicago, ts("2026-07-15T00:00:00Z")),
            -6 * 3600
        );
        assert_eq!(
            standard_offset_seconds(&chicago, ts("2026-01-15T00:00:00Z")),
            -6 * 3600
        );
        // Sydney: AEST UTC+10 standard, AEDT UTC+11 in southern summer.
        assert_eq!(
            standard_offset_seconds(&tz("Australia/Sydney"), ts("2026-01-15T00:00:00Z")),
            10 * 3600
        );
        assert_eq!(
            standard_offset_seconds(&tz("UTC"), ts("2026-07-15T00:00:00Z")),
            0
        );
        assert_eq!(
            standard_offset_seconds(&tz("Asia/Kolkata"), ts("2026-07-15T00:00:00Z")),
            (5.5 * 3600.0) as i32
        );
    }

    #[test]
    fn finds_exact_chicago_transitions() {
        let chicago = tz("America/Chicago");
        let (at, before, after) =
            next_offset_transition(&chicago, ts("2026-07-15T00:00:00Z")).unwrap();
        // 2026-11-01 02:00 CDT (UTC-5) -> 01:00 CST (UTC-6): 07:00:00 UTC.
        assert_eq!(at, ts("2026-11-01T07:00:00Z"));
        assert_eq!((before, after), (-5 * 3600, -6 * 3600));
        assert!(next_offset_transition(&tz("UTC"), ts("2026-01-15T00:00:00Z")).is_none());
    }

    #[test]
    fn time_zone_list_is_single_standard_entry() {
        let list = build_time_zone_list(
            &tz("America/Chicago"),
            "America/Chicago",
            ts("2026-07-26T00:00:00Z"),
        );
        assert_eq!(
            list,
            vec![MatterTimeZoneEntry {
                offset_seconds: -6 * 3600,
                valid_at: MatterMicros(0),
                name: "America/Chicago".into(),
            }]
        );
    }

    #[test]
    fn dst_list_covers_active_period_plus_next() {
        let list = build_dst_offset_list(&tz("America/Chicago"), 2, ts("2026-07-26T00:00:00Z"));
        assert_eq!(
            list,
            vec![
                MatterDstOffsetEntry {
                    offset_seconds: 3600,
                    valid_starting: MatterMicros(0),
                    valid_until: Some(fall_2026()),
                },
                MatterDstOffsetEntry {
                    offset_seconds: 0,
                    valid_starting: fall_2026(),
                    valid_until: Some(spring_2027()),
                },
            ]
        );
    }

    #[test]
    fn dst_list_respects_device_capacity() {
        let list = build_dst_offset_list(&tz("America/Chicago"), 1, ts("2026-07-26T00:00:00Z"));
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].valid_until, Some(fall_2026()));
    }

    #[test]
    fn dst_list_is_single_open_ended_zero_for_fixed_zones() {
        for name in ["UTC", "Asia/Kolkata"] {
            let list = build_dst_offset_list(&tz(name), 2, ts("2026-07-26T00:00:00Z"));
            assert_eq!(
                list,
                vec![MatterDstOffsetEntry {
                    offset_seconds: 0,
                    valid_starting: MatterMicros(0),
                    valid_until: None,
                }],
                "zone {name}"
            );
        }
    }

    #[test]
    fn dst_list_starts_from_standard_time_in_winter() {
        let list = build_dst_offset_list(&tz("America/Chicago"), 2, ts("2026-01-15T00:00:00Z"));
        let spring_2026 = matter("2026-03-08T08:00:00Z");
        assert_eq!(list[0].offset_seconds, 0);
        assert_eq!(list[0].valid_until, Some(spring_2026));
        assert_eq!(list[1].offset_seconds, 3600);
        assert_eq!(list[1].valid_starting, spring_2026);
    }

    #[test]
    fn formats_utc_offsets() {
        assert_eq!(format_utc_offset(-6 * 3600), "UTC-06:00");
        assert_eq!(format_utc_offset(19_800), "UTC+05:30");
        assert_eq!(format_utc_offset(0), "UTC+00:00");
    }
}
