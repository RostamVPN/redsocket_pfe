// Copyright 2026 Internet Mastering & Company, Inc.
// SPDX-License-Identifier: Apache-2.0

//! pfe-rs: triangle-routing (DSR) packet forwarder in Rust.

mod ipmap;
#[cfg(any(target_os = "linux", test))]
mod packet;

#[cfg(target_os = "linux")]
mod neighbor;
#[cfg(target_os = "linux")]
mod xsk;

use std::net::Ipv4Addr;
use std::process::exit;
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(target_os = "linux")]
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};

use ipmap::IpMap;
#[cfg(target_os = "linux")]
use ipmap::{IpAddr, SharedMap};
#[cfg(target_os = "linux")]
use packet::*;

const USAGE: &str = "\
pfe-rs: triangle-routing (DSR) front-end

Usage: pfe [OPTIONS]

  -i, --iface <name>       interface to take over (REQUIRED; use a secondary
                           NIC -- the interface becomes a black hole)
  -m, --mapfile <path>     CSV: EIP, private IP, tunnel src, tunnel dst [, port]
  -q, --queue <n>          NIC queue to bind (default 0)
      --mode <mode>        XDP mode: skb | driver | hw (default skb)
      --tunnel <type>      encapsulation: fou | gre (default fou). GRE is the
                           one that kernel back-ends can decapsulate natively
                           (ip link add ... type gre): fou's ipproto-4 semantic
                           expects an IPIP payload and will not deliver a bare
                           client packet
      --gateway-mac <mac>  force the next-hop MAC (skip ARP discovery)
      --gateway4 <ip>      force the IPv4 gateway IP
  -n, --configtest         validate configuration and exit
  -d, --debug              per-packet lines, client addresses masked to /24;
                           -dd hex dumps and full client addresses; -ddd
                           full frames (all of it lands in the journal)
  -h, --help               this help

Signals: SIGHUP reloads the map file atomically; SIGUSR1 dumps stats.
";

struct Args {
    iface: String,
    mapfile: String,
    queue: u32,
    mode: String,
    use_gre: bool,
    gateway_mac: Option<[u8; 6]>,
    gateway4: Option<Ipv4Addr>,
    configtest: bool,
    debug: u32,
}

fn parse_mac(s: &str) -> Option<[u8; 6]> {
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

fn parse_args(argv: &[String]) -> Result<Args, String> {
    let mut a = Args {
        iface: String::new(),
        mapfile: String::new(),
        queue: 0,
        mode: "skb".to_string(),
        use_gre: false,
        gateway_mac: None,
        gateway4: None,
        configtest: false,
        debug: 0,
    };
    let mut i = 0;
    while i < argv.len() {
        let arg = &argv[i];
        macro_rules! val {
            ($name:expr) => {
                argv.get(i + 1)
                    .ok_or_else(|| format!("missing value for {}", $name))?
                    .clone()
            };
        }
        match arg.as_str() {
            "-i" | "--iface" => {
                a.iface = val!("--iface");
                i += 1;
            }
            "-m" | "--mapfile" => {
                a.mapfile = val!("--mapfile");
                i += 1;
            }
            "-q" | "--queue" => {
                a.queue = val!("--queue").parse().map_err(|_| "invalid queue")?;
                i += 1;
            }
            "--mode" => {
                a.mode = val!("--mode");
                i += 1;
            }
            "--tunnel" => {
                a.use_gre = match val!("--tunnel").as_str() {
                    "fou" => false,
                    "gre" => true,
                    other => return Err(format!("invalid --tunnel '{other}' (fou | gre)")),
                };
                i += 1;
            }
            "--gateway-mac" => {
                let s = val!("--gateway-mac");
                a.gateway_mac =
                    Some(parse_mac(&s).ok_or_else(|| format!("invalid --gateway-mac '{s}'"))?);
                i += 1;
            }
            "--gateway4" => {
                let s = val!("--gateway4");
                a.gateway4 = Some(s.parse().map_err(|_| format!("invalid --gateway4 '{s}'"))?);
                i += 1;
            }
            "-n" | "--configtest" => a.configtest = true,
            "-d" | "--debug" => a.debug += 1,
            "-dd" => a.debug = 2,
            "-ddd" => a.debug = 3,
            "-h" | "--help" => {
                print!("{USAGE}");
                exit(0);
            }
            _ => return Err(format!("unknown argument '{arg}'")),
        }
        i += 1;
    }
    if a.iface.is_empty() {
        return Err("no interface given (--iface)".to_string());
    }
    if a.mapfile.is_empty() {
        return Err("no map file given (--mapfile)".to_string());
    }
    if !matches!(a.mode.as_str(), "skb" | "driver" | "hw") {
        return Err(format!("invalid --mode '{}' (skb | driver | hw)", a.mode));
    }
    Ok(a)
}

fn load_map(path: &str) -> Result<IpMap, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    IpMap::parse(&text).map_err(|e| format!("{path}: {e}"))
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let args = match parse_args(&argv) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {e}\n\n{USAGE}");
            exit(2);
        }
    };

    let map = match load_map(&args.mapfile) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("error: {e}");
            exit(2);
        }
    };

    println!(
        "pfe-rs starting: iface={} queue={} mode={} map={} routes={}",
        args.iface,
        args.queue,
        args.mode,
        args.mapfile,
        map.routes().len()
    );
    for r in map.routes() {
        println!(
            "  route: {} -> {} (tunnel {} -> {} port {})",
            r.private, r.eip, r.tunnel_src, r.tunnel_dst, r.tunnel_port
        );
    }

    if args.configtest {
        println!("configtest OK");
        return;
    }

    #[cfg(target_os = "linux")]
    {
        if let Err(e) = run_linux(&args, map) {
            eprintln!("fatal: {e}");
            exit(1);
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (&args, map);
        eprintln!("pfe-rs packet processing is Linux-only (AF_XDP)");
        exit(1);
    }
}

#[cfg(target_os = "linux")]
use neighbor as nb;
#[cfg(target_os = "linux")]
use xsk::*;

#[cfg(target_os = "linux")]
static RELOAD: AtomicBool = AtomicBool::new(false);
#[cfg(target_os = "linux")]
static DUMP_STATS: AtomicBool = AtomicBool::new(false);
#[cfg(target_os = "linux")]
static STOP: AtomicBool = AtomicBool::new(false);

#[cfg(target_os = "linux")]
extern "C" fn on_signal(sig: libc::c_int) {
    match sig {
        libc::SIGHUP => RELOAD.store(true, Ordering::SeqCst),
        libc::SIGUSR1 => DUMP_STATS.store(true, Ordering::SeqCst),
        _ => STOP.store(true, Ordering::SeqCst),
    }
}

#[cfg(target_os = "linux")]
fn install_signal_handlers() {
    unsafe {
        libc::signal(libc::SIGHUP, on_signal as libc::sighandler_t);
        libc::signal(libc::SIGUSR1, on_signal as libc::sighandler_t);
        libc::signal(libc::SIGTERM, on_signal as libc::sighandler_t);
        libc::signal(libc::SIGINT, on_signal as libc::sighandler_t);
    }
}

#[cfg(target_os = "linux")]
#[derive(Default)]
struct Stats {
    rx_packets: u64,
    rx_bytes: u64,
    forwarded: u64,
    arp_replied: u64,
    arp_replies_seen: u64,
    dropped: u64,
    tx_packets: u64,
    tx_bytes: u64,
    reloaded: u64,
}

#[cfg(target_os = "linux")]
const NUM_FRAMES: u32 = 8192;
#[cfg(target_os = "linux")]
const CHUNK_SIZE: u32 = 2048;
#[cfg(target_os = "linux")]
const HEADROOM: u32 = 64;
#[cfg(target_os = "linux")]
const RING_SIZE: u32 = 4096;
#[cfg(target_os = "linux")]
const CHUNK_MASK: u64 = (CHUNK_SIZE as u64) - 1;

#[cfg(target_os = "linux")]
fn run_linux(args: &Args, map: IpMap) -> Result<(), String> {
    let mode =
        XdpMode::parse(&args.mode).ok_or_else(|| format!("invalid XDP mode '{}'", args.mode))?;
    let use_gre = args.use_gre;
    let encap_len = if use_gre { GRE_HEADROOM } else { FOU_HEADROOM };
    let ifindex =
        nb::ifindex_of(&args.iface).ok_or_else(|| format!("interface {} not found", args.iface))?;
    let our_mac =
        nb::mac_of(&args.iface).ok_or_else(|| format!("cannot read MAC of {}", args.iface))?;
    println!(
        "iface {}: ifindex={} mac={}",
        args.iface,
        ifindex,
        mac_str(&our_mac)
    );

    install_signal_handlers();

    let shared = Arc::new(SharedMap::new(map));
    let mapfile = args.mapfile.clone();

    let cfg = XskConfig {
        ifindex,
        queue: args.queue,
        mode,
        num_frames: NUM_FRAMES,
        chunk_size: CHUNK_SIZE,
        headroom: HEADROOM,
        ring_size: RING_SIZE,
    };
    println!(
        "creating AF_XDP socket ({} frames x {} bytes, headroom {})",
        NUM_FRAMES, CHUNK_SIZE, HEADROOM
    );
    let mut xsk = Xsk::new(&cfg).map_err(|e| format!("AF_XDP setup failed: {e}"))?;
    println!(
        "socket up: fd={} queue {} of {} is now a black hole",
        xsk.fd, args.queue, args.iface
    );

    let gw_mac: MacBytes = match args.gateway_mac {
        Some(m) => m,
        None => {
            let gw_ip = match args.gateway4 {
                Some(ip) => ip,
                None => nb::default_gateway(&args.iface).ok_or_else(|| {
                    format!(
                        "no default route found for {}; use --gateway-mac",
                        args.iface
                    )
                })?,
            };
            println!("gateway ip: {gw_ip}");
            match nb::arp_cache_lookup(gw_ip, &args.iface) {
                Some(m) => {
                    println!("gateway mac (arp cache): {}", mac_str(&m));
                    m
                }
                None => {
                    println!("gateway mac not in arp cache; probing via xsk...");
                    unsafe { resolve_gateway_mac(&mut xsk, &our_mac, gw_ip)? }
                }
            }
        }
    };

    let mut stats = Stats::default();
    let mut pool: Vec<u64> = Vec::new();
    let mut next_ip_id: u32 = 0;
    let mut last_stats = Instant::now();
    let mut headroom_checked = false;

    println!("entering main loop (SIGHUP=reload, SIGUSR1=stats)");
    unsafe {
        loop {
            if STOP.load(Ordering::SeqCst) {
                println!("stopping");
                break;
            }
            if RELOAD.swap(false, Ordering::SeqCst) {
                match load_map(&mapfile) {
                    Ok(m) => {
                        let n = m.routes().len();
                        shared.swap(m);
                        stats.reloaded += 1;
                        println!("map reloaded: {n} routes");
                    }
                    Err(e) => eprintln!("reload failed, keeping old map: {e}"),
                }
            }
            if DUMP_STATS.swap(false, Ordering::SeqCst)
                || last_stats.elapsed() >= Duration::from_secs(60)
            {
                print_stats(&stats, &xsk);
                last_stats = Instant::now();
            }

            let avail = xsk.comp.available();
            for i in 0..avail {
                pool.push(xsk.comp.addr(i) & !CHUNK_MASK);
            }
            if avail > 0 {
                xsk.comp.release(avail);
            }
            if !pool.is_empty() {
                xsk.refill(&mut pool);
            }

            if !xsk.poll(1000) {
                continue;
            }

            let map_now = shared.get();
            let n = xsk.rx.available();
            let mut tx_count: u32 = 0;
            for i in 0..n {
                let d = xsk.rx.desc(i);
                let pkt_addr = d.addr;
                let len = d.len as usize;
                stats.rx_packets += 1;
                stats.rx_bytes += len as u64;

                if !headroom_checked && len > 0 {
                    let off = (pkt_addr & CHUNK_MASK) as u32;
                    if (off as usize) < encap_len {
                        return Err(format!(
                            "packet offset in chunk is {off}; need >= {encap_len} bytes \
                             before the packet for encap (raise HEADROOM and rebuild)"
                        ));
                    }
                    if off + len as u32 > CHUNK_SIZE {
                        return Err(format!(
                            "packet (offset {off}, len {len}) does not fit a {CHUNK_SIZE}-byte \
                             chunk; raise CHUNK_SIZE"
                        ));
                    }
                    if off != HEADROOM {
                        println!("note: kernel umem layout offset is {off} (headroom {HEADROOM} + extra)");
                    }
                    headroom_checked = true;
                }

                tx_count += handle_frame(
                    &mut xsk.umem,
                    &mut xsk.tx,
                    pkt_addr,
                    len,
                    &map_now,
                    &our_mac,
                    &gw_mac,
                    use_gre,
                    encap_len,
                    &mut stats,
                    &mut next_ip_id,
                    &mut pool,
                    args.debug,
                );
            }
            if n > 0 {
                xsk.rx.release(n);
            }
            if tx_count > 0 {
                xsk.tx.flush();
                xsk.wake_tx();
            }
        }
    }
    xsk.close();
    println!("bye");
    Ok(())
}

/// Process one RX frame.
#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
unsafe fn handle_frame(
    umem: &mut Umem,
    tx: &mut TxRing,
    pkt_addr: u64,
    len: usize,
    map: &Arc<IpMap>,
    our_mac: &MacBytes,
    gw_mac: &MacBytes,
    use_gre: bool,
    encap_len: usize,
    stats: &mut Stats,
    next_ip_id: &mut u32,
    pool: &mut Vec<u64>,
    debug: u32,
) -> u32 {
    let chunk = pkt_addr & !CHUNK_MASK;
    let recycle_now = |pool: &mut Vec<u64>| pool.push(chunk);

    {
        let pkt = umem.pkt_slice(pkt_addr, len as u32);
        let eth = match parse_eth(pkt) {
            Some(e) => e,
            None => {
                stats.dropped += 1;
                recycle_now(pool);
                return 0;
            }
        };

        match eth.ethertype {
            ETHERTYPE_ARP => {
                let arp = match parse_arp(&pkt[ETH_HDR_LEN..]) {
                    Some(a) => a,
                    None => {
                        stats.dropped += 1;
                        recycle_now(pool);
                        return 0;
                    }
                };
                if arp.op == ARP_OP_REPLY {
                    stats.arp_replies_seen += 1;
                    recycle_now(pool);
                    return 0;
                }
                let tpa = std::net::Ipv4Addr::from(arp.tpa);
                if arp.op == ARP_OP_REQUEST && map.lookup_v4(tpa).is_some() {
                    let tx_addr = pkt_addr - FOU_HEADROOM as u64;
                    {
                        let buf = umem.pkt_slice(tx_addr, (ETH_HDR_LEN + 28 + FOU_HEADROOM) as u32);
                        let n = build_arp_reply(&mut buf[..ETH_HDR_LEN + 28], &arp, our_mac);
                        if debug >= 1 {
                            println!("arp: replying for {tpa} ({} bytes)", n);
                        }
                    }
                    if tx.free() > 0 {
                        tx.submit(XdpDesc {
                            addr: tx_addr,
                            len: (ETH_HDR_LEN + 28) as u32,
                        });
                        stats.tx_packets += 1;
                        stats.tx_bytes += (ETH_HDR_LEN + 28) as u64;
                        stats.arp_replied += 1;
                        return 1;
                    }
                    stats.dropped += 1;
                } else {
                    stats.dropped += 1;
                }
                recycle_now(pool);
                0
            }
            ETHERTYPE_IPV4 => {
                let ip = &pkt[ETH_HDR_LEN..];
                let ihl = (ip.first().copied().unwrap_or(0) & 0x0f) as usize * 4;
                if ip.len() < IPV4_HDR_LEN || ihl < IPV4_HDR_LEN || ip.len() < ihl {
                    stats.dropped += 1;
                    recycle_now(pool);
                    return 0;
                }
                let dst: Ipv4Bytes = [ip[16], ip[17], ip[18], ip[19]];
                let route = match map.lookup_v4(std::net::Ipv4Addr::from(dst)) {
                    Some(r) => r,
                    None => {
                        stats.dropped += 1;
                        recycle_now(pool);
                        return 0;
                    }
                };
                let (IpAddr::V4(eip), IpAddr::V4(tsrc), IpAddr::V4(tdst)) =
                    (route.eip, route.tunnel_src, route.tunnel_dst)
                else {
                    stats.dropped += 1;
                    recycle_now(pool);
                    return 0;
                };

                let inner_len = ip.len();
                let tos = ip[1];
                let src_ip: Ipv4Bytes = [ip[12], ip[13], ip[14], ip[15]];

                if debug >= 1 {
                    println!(
                        "fwd: {} -> {} ({} bytes) tunnel {} -> {}:{}",
                        client_label(&src_ip, debug),
                        ipv4_str(&eip.octets()),
                        inner_len,
                        tsrc,
                        tdst,
                        route.tunnel_port
                    );
                }
                if debug >= 2 {
                    let cap = if debug == 2 { 64 } else { len };
                    hex_dump("rx", &pkt[..cap.min(len)]);
                }

                umem.l3_slide_back(pkt_addr, inner_len);

                let tx_addr = pkt_addr - encap_len as u64;
                let frame_len = encap_len + inner_len;
                let frame = umem.pkt_slice(tx_addr, frame_len as u32);
                rewrite_ipv4_dst(&mut frame[encap_len..], eip.octets());
                *next_ip_id = next_ip_id.wrapping_add(1);
                let outer = Outer {
                    src_mac: *our_mac,
                    dst_mac: *gw_mac,
                    src_ip: tsrc.octets(),
                    dst_ip: tdst.octets(),
                    tos,
                    ip_id: *next_ip_id as u16,
                };
                if use_gre {
                    encap_gre_v4(frame, inner_len, &outer);
                } else {
                    encap_fou_v4(frame, inner_len, &outer, route.tunnel_port);
                }

                if debug >= 2 {
                    let cap = if debug == 2 { 96 } else { frame_len };
                    hex_dump("tx", &frame[..cap.min(frame_len)]);
                }
                if tx.free() > 0 {
                    tx.submit(XdpDesc {
                        addr: tx_addr,
                        len: frame_len as u32,
                    });
                    stats.tx_packets += 1;
                    stats.tx_bytes += frame_len as u64;
                    stats.forwarded += 1;
                    return 1;
                }
                stats.dropped += 1;
                recycle_now(pool);
                0
            }
            _ => {
                stats.dropped += 1;
                recycle_now(pool);
                0
            }
        }
    }
}

/// Send an ARP request for the gateway over the xsk and wait for the reply.
#[cfg(target_os = "linux")]
unsafe fn resolve_gateway_mac(
    xsk: &mut Xsk,
    our_mac: &MacBytes,
    gw_ip: std::net::Ipv4Addr,
) -> Result<MacBytes, String> {
    let our_ip = nb::our_ipv4_toward(gw_ip).unwrap_or(std::net::Ipv4Addr::UNSPECIFIED);

    let chunk = (NUM_FRAMES as u64 - 1) * CHUNK_SIZE as u64;
    {
        let buf = xsk.umem.pkt_slice(chunk, 64);
        let n = build_arp_request(buf, our_mac, &our_ip.octets(), &gw_ip.octets());
        xsk.tx.submit(XdpDesc {
            addr: chunk,
            len: n as u32,
        });
    }
    xsk.tx.flush();
    xsk.wake_tx();

    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if !xsk.poll(200) {
            continue;
        }
        let n = xsk.rx.available();
        let mut found: Option<MacBytes> = None;
        let mut junk: Vec<u64> = Vec::with_capacity(n as usize);
        for i in 0..n {
            let d = xsk.rx.desc(i);
            junk.push(d.addr & !CHUNK_MASK);
            let pkt = xsk.umem.pkt_slice(d.addr, d.len);
            let arp = match parse_eth(pkt) {
                Some(eth) if eth.ethertype == ETHERTYPE_ARP => parse_arp(&pkt[ETH_HDR_LEN..]),
                _ => None,
            };
            if let Some(arp) = arp {
                if found.is_none() && arp.op == ARP_OP_REPLY && arp.spa == gw_ip.octets() {
                    found = Some(arp.sha);
                }
            }
        }
        xsk.rx.release(n);
        xsk.refill(&mut junk);
        if let Some(mac) = found {
            println!("gateway mac (probe): {}", mac_str(&mac));
            return Ok(mac);
        }
    }
    Err(format!(
        "gateway {gw_ip} did not answer ARP within 3s; set --gateway-mac explicitly"
    ))
}

#[cfg(target_os = "linux")]
fn print_stats(s: &Stats, xsk: &Xsk) {
    let xs = xsk.stats();
    println!(
        "stats: rx={} rxB={} fwd={} arpReply={} arpRx={} drop={} tx={} txB={} | xdp: rxDrop={} rxInvalid={} txInvalid={} rxRingFull={} fillEmpty={} txEmpty={}",
        s.rx_packets,
        s.rx_bytes,
        s.forwarded,
        s.arp_replied,
        s.arp_replies_seen,
        s.dropped,
        s.tx_packets,
        s.tx_bytes,
        xs.rx_dropped,
        xs.rx_invalid_descs,
        xs.tx_invalid_descs,
        xs.rx_ring_full,
        xs.rx_fill_ring_empty_descs,
        xs.tx_ring_empty_descs
    );
}

#[cfg(target_os = "linux")]
fn mac_str(m: &[u8]) -> String {
    m.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(any(target_os = "linux", test))]
fn ipv4_str(b: &[u8]) -> String {
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}

/// Client address for the per-packet line: its /24 at -d, the full address
/// from -dd on.
#[cfg(any(target_os = "linux", test))]
fn client_label(src: &[u8; 4], debug: u32) -> String {
    if debug >= 2 {
        ipv4_str(src)
    } else {
        format!("{}.{}.{}.0/24", src[0], src[1], src[2])
    }
}

#[cfg(target_os = "linux")]
fn hex_dump(label: &str, data: &[u8]) {
    let mut line = String::new();
    for (i, b) in data.iter().enumerate() {
        if i.is_multiple_of(16) && !line.is_empty() {
            println!("{label} {:04x}  {line}", i - 16);
            line.clear();
        }
        line.push_str(&format!("{b:02x} "));
    }
    if !line.is_empty() {
        println!("{label} ----  {line}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(argv: &[&str]) -> Result<Args, String> {
        parse_args(&argv.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn parse_args_rejects_bogus_mode_tunnel_and_gateway_values() {
        let base = ["-i", "eth1", "-m", "map.csv"];
        assert!(parse(&base).is_ok());
        for bad in [
            ["--mode", "bogus"],
            ["--tunnel", "bogus"],
            ["--gateway-mac", "zz:zz"],
            ["--gateway4", "999.1.1.1"],
        ] {
            let argv: Vec<&str> = base.iter().chain(bad.iter()).copied().collect();
            let err = parse(&argv).err().expect("rejected");
            assert!(err.contains(bad[0]), "{err}");
        }
        let ok = parse(&[
            "-i",
            "eth1",
            "-m",
            "map.csv",
            "--tunnel",
            "gre",
            "--gateway-mac",
            "00:00:5e:00:53:01",
            "--gateway4",
            "192.0.2.1",
        ])
        .unwrap();
        assert!(ok.use_gre);
        assert_eq!(ok.gateway_mac, Some([0, 0, 0x5e, 0, 0x53, 1]));
        assert_eq!(ok.gateway4, Some(Ipv4Addr::new(192, 0, 2, 1)));
    }

    #[test]
    fn debug_level_one_masks_the_client_address() {
        let src = [198, 51, 100, 77];
        assert_eq!(client_label(&src, 1), "198.51.100.0/24");
        assert_eq!(client_label(&src, 2), "198.51.100.77");
    }
}
