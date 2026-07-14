//! Resource benchmark harness (spec §4, §22).
//!
//! BAR's core promise is *target-first resources*: the monitored workload owns
//! the machine, so BAR must start model-free and stay within a small memory
//! footprint (spec §4). Section 22 requires that this be enforced as a
//! **regression test, not a documentation-only target**. This crate is the
//! measurement primitive those tests are built on.
//!
//! Phase 0 measures one thing: **peak resident set size**. A process reads its
//! own high-water mark, so the reading is race-free and needs no sampling loop —
//! the kernel already tracks the maximum. Later phases extend the harness with
//! the remaining performance rows of spec §23 (incremental-scan RAM,
//! high-volume ingestion, target-pressure suspension), which require a running
//! service loop that does not yet exist.
//!
//! ## Platform
//!
//! The reading comes from Linux `/proc/self/status`. On any platform without it
//! the functions return `None` — the caller reports "unavailable" rather than a
//! fabricated number, consistent with BAR's honest-evidence rule (spec §3).
//! The workspace forbids `unsafe`, so `getrusage`/`wait4` are deliberately not
//! used; the `/proc` high-water mark gives the same peak with safe file I/O.

/// Peak resident set size of the current process, in bytes — the maximum
/// physical memory it has held since start (Linux `VmHWM`).
///
/// Returns `None` where `/proc/self/status` is unavailable or carries no
/// `VmHWM` field. Because the kernel maintains the high-water mark, a single
/// read at any point captures the true peak up to that moment; a process that
/// reads this just before exiting reports its whole-run peak.
pub fn peak_rss_bytes() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    parse_status_kb(&status, "VmHWM:").map(|kb| kb * 1024)
}

/// Parses a `key` line of `/proc/<pid>/status` (`"VmHWM:\t   1234 kB"`) into its
/// kilobyte value. Split out so it can be tested without a live `/proc`.
fn parse_status_kb(status: &str, key: &str) -> Option<u64> {
    status
        .lines()
        .find_map(|line| line.strip_prefix(key))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|value| value.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_status_line() {
        let status = "Name:\tbar-daemon\nVmHWM:\t   40960 kB\nVmRSS:\t   40000 kB\n";
        assert_eq!(parse_status_kb(status, "VmHWM:"), Some(40960));
    }

    #[test]
    fn missing_key_is_none() {
        assert_eq!(parse_status_kb("Name:\tx\n", "VmHWM:"), None);
    }

    #[test]
    fn malformed_value_is_none() {
        assert_eq!(parse_status_kb("VmHWM:\tnot-a-number kB\n", "VmHWM:"), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reports_a_plausible_peak_on_linux() {
        // On Linux the running test process must have a non-zero peak RSS.
        let peak = peak_rss_bytes().expect("VmHWM available on Linux");
        assert!(peak > 0, "peak RSS should be positive, got {peak}");
    }
}
