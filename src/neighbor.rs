// Copyright 2026 Internet Mastering & Company, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Interface facts: ifindex, MAC, default gateway, ARP-cache lookup. All from
//! /proc and std-only sockets -- no netlink dependency.

use std::fs;
use std::net::{Ipv4Addr, UdpSocket};
use std::str::FromStr;

use crate::packet::MacBytes;

pub fn ifindex_of(iface: &str) -> Option<u32> {
    fs::read_to_string(format!("/sys/class/net/{iface}/ifindex"))
        .ok()?
        .trim()
        .parse()
        .ok()
}

pub fn mac_of(iface: &str) -> Option<MacBytes> {
    let s = fs::read_to_string(format!("/sys/class/net/{iface}/address")).ok()?;
    parse_mac(s.trim())
}

pub fn parse_mac(s: &str) -> Option<MacBytes> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut mac = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(p, 16).ok()?;
    }
    Some(mac)
}

/// Default gateway for `iface` from /proc/net/route (lowest metric wins).
/// Columns: Iface Destination Gateway Flags ... Metric Mask ...
pub fn default_gateway(iface: &str) -> Option<Ipv4Addr> {
    let text = fs::read_to_string("/proc/net/route").ok()?;
    let mut best: Option<(u32, Ipv4Addr)> = None;
    for line in text.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 8 || cols[0] != iface {
            continue;
        }
        if cols[1] != "00000000" {
            continue;
        }
        let gw_hex = cols[2];
        if gw_hex.len() != 8 {
            continue;
        }
        let bytes = [
            u8::from_str_radix(&gw_hex[6..8], 16).ok()?,
            u8::from_str_radix(&gw_hex[4..6], 16).ok()?,
            u8::from_str_radix(&gw_hex[2..4], 16).ok()?,
            u8::from_str_radix(&gw_hex[0..2], 16).ok()?,
        ];
        let metric: u32 = cols[6].parse().unwrap_or(u32::MAX);
        let gw = Ipv4Addr::from(bytes);
        if best.map(|(m, _)| metric < m).unwrap_or(true) {
            best = Some((metric, gw));
        }
    }
    best.map(|(_, gw)| gw)
}

/// Our own IPv4 on `iface` as the kernel would source it toward `gw` (UDP
/// connect trick -- no packet is sent).
pub fn our_ipv4_toward(gw: Ipv4Addr) -> Option<Ipv4Addr> {
    let s = UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect(std::net::SocketAddr::from((gw, 9))).ok()?;
    match s.local_addr() {
        Ok(a) => match a.ip() {
            std::net::IpAddr::V4(v4) => Some(v4),
            _ => None,
        },
        Err(_) => None,
    }
}

/// MAC for `ip` from the system ARP cache.
pub fn arp_cache_lookup(ip: Ipv4Addr) -> Option<MacBytes> {
    let text = fs::read_to_string("/proc/net/arp").ok()?;
    let wanted = ip.to_string();
    for line in text.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() >= 4 && cols[0] == wanted {
            return parse_mac(cols[3]);
        }
    }
    None
}

pub fn ipv4_parse(s: &str) -> Option<Ipv4Addr> {
    Ipv4Addr::from_str(s).ok()
}
