//! Utility functions — hardware address formatting, hex encoding, monotonic-ish time.

use std::fmt::Write;

/// The clock of play times, in nanoseconds: CLOCK_MONOTONIC on Linux (the wall clock steps: a device without a
/// real-time clock boots in 1970 and NTP sets it once, under a stream already playing), else the wall clock. Used by
/// the AP2 audio playout scheduler and PTP timing code; an application's output compares play times with the same
/// clock.
#[cfg(feature = "ap2-core")]
pub fn now_ns() -> u64 {
    #[cfg(target_os = "linux")]
    {
        let t = nix::time::clock_gettime(nix::time::ClockId::CLOCK_MONOTONIC)
            .expect("CLOCK_MONOTONIC");
        t.tv_sec() as u64 * 1_000_000_000 + t.tv_nsec() as u64
    }
    #[cfg(not(target_os = "linux"))]
    wall_ns()
}

/// The wall clock in nanoseconds since the UNIX epoch (0 before it).
#[cfg(feature = "ap2-core")]
pub fn wall_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

/// Format a hardware address for RAOP service name: "AABBCCDDEEFF" (uppercase hex, no separators).
/// Equivalent to utils_hwaddr_raop.
pub fn hwaddr_raop(hwaddr: &[u8]) -> String {
    let mut s = String::with_capacity(hwaddr.len() * 2);
    for &b in hwaddr {
        write!(s, "{b:02X}").unwrap();
    }
    s
}

/// Format a hardware address for AirPlay device ID: "aa:bb:cc:dd:ee:ff" (lowercase hex, colon-separated).
/// Equivalent to utils_hwaddr_airplay.
pub fn hwaddr_airplay(hwaddr: &[u8]) -> String {
    let mut s = String::with_capacity(hwaddr.len() * 3);
    for (i, &b) in hwaddr.iter().enumerate() {
        if i > 0 {
            s.push(':');
        }
        write!(s, "{b:02x}").unwrap();
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hwaddr_raop_c_vector() {
        assert_eq!(
            hwaddr_raop(&[0x48, 0x5d, 0x60, 0x7c, 0xee, 0x22]),
            "485D607CEE22"
        );
    }

    #[test]
    fn hwaddr_airplay_c_vector() {
        assert_eq!(
            hwaddr_airplay(&[0x48, 0x5d, 0x60, 0x7c, 0xee, 0x22]),
            "48:5d:60:7c:ee:22"
        );
    }
}
