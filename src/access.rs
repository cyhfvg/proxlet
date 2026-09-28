//! One-line access records for listener attempts.
//!
//! Lines go to stdout and are flushed immediately. Daemon mode redirects that
//! stdout to `--log-file`. Records never include passwords or header values.

use std::io::{self, Write};
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

/// Record one listener attempt.
///
/// # Parameters
///
/// * `client` - Source IP. The source port is omitted.
/// * `protocol` - Short protocol token such as `http` or `socks5`.
/// * `target` - Requested host and port. Userinfo before `@` is dropped.
///   `None` becomes `-`.
/// * `result` - Short outcome token such as `ok` or `auth-failed`.
///
/// # Returns
///
/// This function does not return a value. Write errors are ignored so logging
/// cannot fail the connection.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```ignore
/// record(peer, "http", Some("example.com:80"), "auth-failed");
/// ```
pub fn record(client: IpAddr, protocol: &str, target: Option<&str>, result: &str) {
    let mut stdout = io::stdout();
    let _ = writeln!(stdout, "{}", format_line(client, protocol, target, result));
    let _ = stdout.flush();
}

/// Format one access line without writing it.
///
/// # Parameters
///
/// * `client` - Source IP.
/// * `protocol` - Protocol token.
/// * `target` - Optional host:port. Userinfo is removed.
/// * `result` - Outcome token.
///
/// # Returns
///
/// Returns one line without a trailing newline:
/// `access <time> <client> <protocol> <target> <result>`.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```ignore
/// let line = format_line("127.0.0.1".parse().unwrap(), "http", None, "auth-failed");
/// ```
pub fn format_line(client: IpAddr, protocol: &str, target: Option<&str>, result: &str) -> String {
    format!(
        "access {} {client} {} {} {}",
        timestamp(),
        field(protocol),
        target_field(target),
        field(result)
    )
}

fn timestamp() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| i64::try_from(duration.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0);
    format_unix(seconds)
}

/// Format a Unix second as UTC `YYYY-MM-DDTHH:MM:SSZ`.
///
/// # Parameters
///
/// * `seconds` - Seconds since 1970-01-01T00:00:00Z. Negative values are
///   earlier dates.
///
/// # Returns
///
/// Returns a 20-character UTC timestamp for years that fit in four digits.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```ignore
/// assert_eq!(format_unix(0), "1970-01-01T00:00:00Z");
/// ```
pub fn format_unix(seconds: i64) -> String {
    let day = seconds.div_euclid(86_400);
    let tod = seconds.rem_euclid(86_400) as u32;
    let (year, month, day) = civil_from_days(day);
    let hour = tod / 3_600;
    let minute = (tod % 3_600) / 60;
    let second = tod % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Howard Hinnant `civil_from_days`, shifted so day 0 is 1970-01-01.
fn civil_from_days(days: i64) -> (i32, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    if month <= 2 {
        year += 1;
    }
    (year as i32, month as u32, day as u32)
}

fn target_field(target: Option<&str>) -> String {
    let Some(target) = target.map(str::trim).filter(|target| !target.is_empty()) else {
        return "-".to_owned();
    };
    // `user:password@host:port` must not put the password in the log.
    let host = target
        .rsplit_once('@')
        .map(|(_, host)| host)
        .unwrap_or(target);
    field(host)
}

fn field(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch.is_ascii_whitespace() || ch.is_control() {
            out.push('_');
        } else {
            out.push(ch);
        }
    }
    if out.is_empty() {
        "-".to_owned()
    } else {
        out
    }
}

/// Fold an IPv4-mapped IPv6 client address to IPv4.
///
/// # Parameters
///
/// * `ip` - Client address from an accepted socket or an allow-list entry.
///
/// # Returns
///
/// Returns the embedded IPv4 address when `ip` is `::ffff:a.b.c.d`. Other
/// addresses are returned unchanged.
///
/// # Errors
///
/// This function does not return errors.
///
/// # Examples
///
/// ```text
/// ::ffff:192.0.2.10 -> 192.0.2.10
/// 2001:db8::1 -> 2001:db8::1
/// ```
pub fn canonical_client_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(address) => address.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_known_unix_times() {
        assert_eq!(format_unix(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_unix(86_400), "1970-01-02T00:00:00Z");
        assert_eq!(format_unix(951_782_400), "2000-02-29T00:00:00Z");
    }

    #[test]
    fn drops_userinfo_and_keeps_one_line() {
        let line = format_line(
            "127.0.0.1".parse().expect("ip"),
            "http",
            Some("user:s3cret@example.com:443"),
            "auth-failed",
        );
        assert!(!line.contains("s3cret"));
        assert!(line.contains("127.0.0.1 http example.com:443 auth-failed"));
        assert!(!line.contains('\n'));
    }
}
