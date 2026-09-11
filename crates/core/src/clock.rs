//! Minimal UTC timestamp formatting for roster/config metadata (`added_at`,
//! `rotated_at`). Roster timestamps are cosmetic - they are part of the signed
//! members payload but carry no verification semantics - so we format them without
//! pulling in a full date/time dependency. The civil-date conversion is Howard
//! Hinnant's `days -> {y, m, d}` algorithm, valid across the proleptic Gregorian
//! calendar.

use std::time::{SystemTime, UNIX_EPOCH};

/// Current time as whole seconds since the Unix epoch. A system clock set before the
/// epoch (which should not happen) yields a negative value rather than panicking, so
/// callers that compare against it still behave sanely.
pub fn now_unix() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(e) => -(e.duration().as_secs() as i64),
    }
}

/// Current time as an RFC 3339 UTC string, e.g. `2026-07-03T12:00:00Z`. If the system
/// clock is set before the Unix epoch (which should not happen), the seconds are
/// treated as a negative offset so the output is still a valid, if surprising, date.
pub fn now_rfc3339() -> String {
    format_rfc3339(now_unix())
}

/// Format seconds-since-the-Unix-epoch as RFC 3339 UTC (`YYYY-MM-DDThh:mm:ssZ`).
pub fn format_rfc3339(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (hh, mm, ss) = (tod / 3600, (tod % 3600) / 60, tod % 60);
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// Convert days-since-1970-01-01 to a `(year, month, day)` civil date.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_epochs_format_correctly() {
        assert_eq!(format_rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_rfc3339(1_000_000_000), "2001-09-09T01:46:40Z");
        // A leap day, to exercise the calendar math.
        assert_eq!(format_rfc3339(1_582_934_400), "2020-02-29T00:00:00Z");
        // End-of-day and a far-future date (both time-of-day fields non-zero).
        assert_eq!(format_rfc3339(4_102_444_799), "2099-12-31T23:59:59Z");
        // Before the epoch: div_euclid/rem_euclid must not skew the date.
        assert_eq!(format_rfc3339(-86_400), "1969-12-31T00:00:00Z");
    }

    #[test]
    fn now_has_the_expected_shape() {
        let s = now_rfc3339();
        assert_eq!(s.len(), 20);
        assert!(s.ends_with('Z'));
        assert_eq!(&s[4..5], "-");
    }

    #[test]
    fn now_unix_is_recent() {
        // A sanity floor: well after 2026-01-01, proving the clock isn't returning 0 and
        // that `now_rfc3339` (which delegates to `now_unix`) is reading real time.
        assert!(now_unix() > 1_767_225_600);
    }
}
