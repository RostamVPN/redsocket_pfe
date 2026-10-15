// Copyright 2026 Internet Mastering & Company, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Route map: (EIP, private IP, tunnel source, tunnel destination, tunnel port)
//! tuples from a pseudo-CSV map file.

use std::collections::HashMap;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
#[cfg(target_os = "linux")]
use std::sync::{Arc, RwLock};

pub const DEFAULT_FOU_PORT: u16 = 5555;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpAddr {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

impl IpAddr {
    pub fn parse(s: &str) -> Option<Self> {
        if s.contains(':') {
            s.parse::<Ipv6Addr>().ok().map(IpAddr::V6)
        } else {
            s.parse::<Ipv4Addr>().ok().map(IpAddr::V4)
        }
    }

    pub fn is_v4(&self) -> bool {
        matches!(self, IpAddr::V4(_))
    }
}

impl fmt::Display for IpAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpAddr::V4(a) => write!(f, "{a}"),
            IpAddr::V6(a) => write!(f, "{a}"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Route {
    /// Public address the back-end spoofs as the reply source (the EIP).
    pub eip: IpAddr,
    /// Private address on the front-end's interface (the rewritten dst of arriving
    /// packets). This is the map key.
    pub private: IpAddr,
    /// Source address of the outer FoU tunnel packet.
    pub tunnel_src: IpAddr,
    /// Destination address of the outer FoU tunnel packet (the back-end).
    pub tunnel_dst: IpAddr,
    /// Destination port of the outer FoU tunnel packet.
    pub tunnel_port: u16,
}

impl Route {
    fn validate(&self) -> Result<(), String> {
        if self.tunnel_src.is_v4() != self.tunnel_dst.is_v4() {
            return Err(format!(
                "tunnel source {} and destination {} must be the same address family",
                self.tunnel_src, self.tunnel_dst
            ));
        }
        if self.eip.is_v4() != self.private.is_v4() {
            return Err(format!(
                "eip {} and private {} must be the same address family",
                self.eip, self.private
            ));
        }
        Ok(())
    }
}

/// Atomically-swappable route map.
#[derive(Debug)]
pub struct IpMap {
    routes: Vec<Route>,
    by_dst_v4: HashMap<Ipv4Addr, usize>,
    by_dst_v6: HashMap<Ipv6Addr, usize>,
}

impl IpMap {
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut routes = Vec::new();
        for (lineno, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.split(',').map(|s| s.trim()).collect();
            if parts.len() < 4 {
                return Err(format!(
                    "line {}: expected at least 4 fields (EIP, private, tunnel src, tunnel dst [, port]), got {}",
                    lineno + 1,
                    parts.len()
                ));
            }
            let eip = IpAddr::parse(parts[0])
                .ok_or_else(|| format!("line {}: invalid EIP '{}'", lineno + 1, parts[0]))?;
            let private = IpAddr::parse(parts[1])
                .ok_or_else(|| format!("line {}: invalid private IP '{}'", lineno + 1, parts[1]))?;
            let tsrc = IpAddr::parse(parts[2]).ok_or_else(|| {
                format!("line {}: invalid tunnel source '{}'", lineno + 1, parts[2])
            })?;
            let tdst = IpAddr::parse(parts[3]).ok_or_else(|| {
                format!(
                    "line {}: invalid tunnel destination '{}'",
                    lineno + 1,
                    parts[3]
                )
            })?;
            let port = if parts.len() > 4 && !parts[4].is_empty() {
                parts[4]
                    .parse::<u16>()
                    .map_err(|_| format!("line {}: invalid port '{}'", lineno + 1, parts[4]))?
            } else {
                DEFAULT_FOU_PORT
            };
            let route = Route {
                eip,
                private,
                tunnel_src: tsrc,
                tunnel_dst: tdst,
                tunnel_port: port,
            };
            route
                .validate()
                .map_err(|e| format!("line {}: {e}", lineno + 1))?;
            routes.push(route);
        }
        let mut m = IpMap {
            routes: Vec::new(),
            by_dst_v4: HashMap::new(),
            by_dst_v6: HashMap::new(),
        };
        for r in routes {
            m.insert(r);
        }
        if m.routes.is_empty() {
            return Err("no routes found in map file".to_string());
        }
        Ok(m)
    }

    fn insert(&mut self, r: Route) {
        match r.private {
            IpAddr::V4(a) => {
                if !self.by_dst_v4.contains_key(&a) {
                    self.by_dst_v4.insert(a, self.routes.len());
                    self.routes.push(r);
                }
            }
            IpAddr::V6(a) => {
                if !self.by_dst_v6.contains_key(&a) {
                    self.by_dst_v6.insert(a, self.routes.len());
                    self.routes.push(r);
                }
            }
        }
    }

    #[cfg(any(target_os = "linux", test))]
    pub fn lookup_v4(&self, dst: Ipv4Addr) -> Option<&Route> {
        self.by_dst_v4.get(&dst).map(|&i| &self.routes[i])
    }

    pub fn routes(&self) -> &[Route] {
        &self.routes
    }
}

/// Shared handle: reload swaps the whole map wholesale (never mutated in
/// place).
#[cfg(target_os = "linux")]
pub struct SharedMap {
    inner: RwLock<Arc<IpMap>>,
}

#[cfg(target_os = "linux")]
impl SharedMap {
    pub fn new(map: IpMap) -> Self {
        SharedMap {
            inner: RwLock::new(Arc::new(map)),
        }
    }

    pub fn get(&self) -> Arc<IpMap> {
        self.inner.read().unwrap().clone()
    }

    pub fn swap(&self, map: IpMap) {
        *self.inner.write().unwrap() = Arc::new(map);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_basic_map() {
        let text = "# comment\n1.2.3.4, 10.0.0.1, 10.0.0.1, 5.6.7.8, 5555\n\n1.2.3.5,10.0.0.2,10.0.0.2,8.9.10.11,4321\n";
        let m = IpMap::parse(text).unwrap();
        assert_eq!(m.routes().len(), 2);
        let r = m.lookup_v4("10.0.0.2".parse().unwrap()).unwrap();
        assert_eq!(r.eip, IpAddr::parse("1.2.3.5").unwrap());
        assert_eq!(r.tunnel_port, 4321);
    }

    #[test]
    fn default_port_and_v6() {
        let text = "2001:db8::4,2001:db8::14,2001:db8:1::10,2001:db8:2::10\n";
        let m = IpMap::parse(text).unwrap();
        let r = &m.routes()[0];
        assert_eq!(r.private, IpAddr::parse("2001:db8::14").unwrap());
        assert_eq!(r.tunnel_port, DEFAULT_FOU_PORT);
    }

    #[test]
    fn rejects_mixed_families() {
        let text = "1.2.3.4,10.0.0.1,fd8f::1,5.6.7.8\n";
        assert!(IpMap::parse(text).is_err());
    }

    #[test]
    fn rejects_short_lines() {
        assert!(IpMap::parse("1.2.3.4,10.0.0.1\n").is_err());
        assert!(IpMap::parse("").is_err());
    }
}
