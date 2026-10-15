// Copyright 2026 Internet Mastering & Company, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Pure packet manipulation: parse, EIP rewrite with incremental checksum
//! updates, and FoU (IP-in-UDP) encapsulation into headroom. No syscalls, so
//! this module is unit-testable on any platform.

pub const ETH_HDR_LEN: usize = 14;
pub const IPV4_HDR_LEN: usize = 20;
pub const UDP_HDR_LEN: usize = 8;
/// Ethernet + outer IPv4 + outer UDP.
pub const FOU_HEADROOM: usize = ETH_HDR_LEN + IPV4_HDR_LEN + UDP_HDR_LEN;
/// Ethernet + outer IPv4 + 4-byte GRE header.
pub const GRE_HDR_LEN: usize = 4;
pub const GRE_HEADROOM: usize = ETH_HDR_LEN + IPV4_HDR_LEN + GRE_HDR_LEN;

pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;

pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;
pub const IPPROTO_GRE: u8 = 47;

pub const ARP_OP_REQUEST: u16 = 1;
pub const ARP_OP_REPLY: u16 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EthHdr<'a> {
    pub dst: &'a [u8],
    pub src: &'a [u8],
    pub ethertype: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArpPacket {
    pub op: u16,
    pub sha: MacBytes,
    pub spa: Ipv4Bytes,
    pub tha: MacBytes,
    pub tpa: Ipv4Bytes,
}

/// Outer (tunnel) header parameters shared by the FoU and GRE encapsulators.
#[derive(Clone, Copy, Debug)]
pub struct Outer {
    pub src_mac: MacBytes,
    pub dst_mac: MacBytes,
    pub src_ip: Ipv4Bytes,
    pub dst_ip: Ipv4Bytes,
    pub tos: u8,
    pub ip_id: u16,
}

pub type Ipv4Bytes = [u8; 4];
pub type MacBytes = [u8; 6];

/// Parse the Ethernet header of a frame. Returns None if too short.
pub fn parse_eth(frame: &[u8]) -> Option<EthHdr<'_>> {
    if frame.len() < ETH_HDR_LEN {
        return None;
    }
    Some(EthHdr {
        dst: &frame[0..6],
        src: &frame[6..12],
        ethertype: u16::from_be_bytes([frame[12], frame[13]]),
    })
}

/// Parse an ARP packet (after the Ethernet header). Only supports the
/// Ethernet/IPv4 hardware/protocol combination, which is all pfe answers.
pub fn parse_arp(pkt: &[u8]) -> Option<ArpPacket> {
    if pkt.len() < 28 {
        return None;
    }
    let htype = u16::from_be_bytes([pkt[0], pkt[1]]);
    let ptype = u16::from_be_bytes([pkt[2], pkt[3]]);
    if htype != 1 || ptype != ETHERTYPE_IPV4 || pkt[4] != 6 || pkt[5] != 4 {
        return None;
    }
    Some(ArpPacket {
        op: u16::from_be_bytes([pkt[6], pkt[7]]),
        sha: pkt[8..14].try_into().ok()?,
        spa: [pkt[14], pkt[15], pkt[16], pkt[17]],
        tha: pkt[18..24].try_into().ok()?,
        tpa: [pkt[24], pkt[25], pkt[26], pkt[27]],
    })
}

/// Build an ARP reply frame in `buf` for a request we received. `buf` must be
/// at least ETH_HDR_LEN + 28 bytes; returns the total length written.
pub fn build_arp_reply(buf: &mut [u8], req: &ArpPacket, our_mac: &MacBytes) -> usize {
    let total = ETH_HDR_LEN + 28;
    buf[..6].copy_from_slice(&req.sha);
    buf[6..12].copy_from_slice(our_mac);
    buf[12..14].copy_from_slice(&ETHERTYPE_ARP.to_be_bytes());
    let arp = &mut buf[ETH_HDR_LEN..total];
    arp[0..2].copy_from_slice(&1u16.to_be_bytes());
    arp[2..4].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
    arp[4] = 6;
    arp[5] = 4;
    arp[6..8].copy_from_slice(&ARP_OP_REPLY.to_be_bytes());
    arp[8..14].copy_from_slice(our_mac);
    arp[14..18].copy_from_slice(&req.tpa);
    arp[18..24].copy_from_slice(&req.sha);
    arp[24..28].copy_from_slice(&req.spa);
    total
}

pub fn build_arp_request(
    buf: &mut [u8],
    our_mac: &MacBytes,
    our_ip: &Ipv4Bytes,
    query: &Ipv4Bytes,
) -> usize {
    let total = ETH_HDR_LEN + 28;
    buf[..6].copy_from_slice(&[0xff; 6]);
    buf[6..12].copy_from_slice(our_mac);
    buf[12..14].copy_from_slice(&ETHERTYPE_ARP.to_be_bytes());
    let arp = &mut buf[ETH_HDR_LEN..total];
    arp[0..2].copy_from_slice(&1u16.to_be_bytes());
    arp[2..4].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
    arp[4] = 6;
    arp[5] = 4;
    arp[6..8].copy_from_slice(&ARP_OP_REQUEST.to_be_bytes());
    arp[8..14].copy_from_slice(our_mac);
    arp[14..18].copy_from_slice(our_ip);
    arp[18..24].copy_from_slice(&[0x00; 6]);
    arp[24..28].copy_from_slice(query);
    total
}

/// Fold a 32-bit partial sum to 16 bits (one's complement).
#[inline]
fn fold32(mut n: u32) -> u16 {
    while n >> 16 != 0 {
        n = (n & 0xffff) + (n >> 16);
    }
    n as u16
}

/// Incremental checksum update (RFC 1624, HC' = ~(~HC + ~m + m')) for one
/// changed 16-bit word. Returns the updated field value.
#[inline]
fn adjust_word(old_field: u16, old: u16, new: u16) -> u16 {
    let mut sum = (!old_field) as u32;
    sum = sum + (!old) as u32 + new as u32;
    let folded = fold32(sum);
    !folded
}

/// Adjust a checksum field in place for a changed 16-bit half-word.
#[inline]
fn adjust_field(field: &mut [u8], old: u16, new: u16) {
    let hc = u16::from_be_bytes([field[0], field[1]]);
    let h = adjust_word(hc, old, new);
    field[..2].copy_from_slice(&h.to_be_bytes());
}

/// Ones-complement sum over a byte range (big-endian words), returned folded.
pub fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 2 <= data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    !fold32(sum)
}

/// Where the L4 checksum lives, given the IP header start and protocol.
/// None for a non-first fragment, whose bytes after the header are payload.
#[inline]
fn l4_offset(ip: &[u8]) -> Option<usize> {
    if ip.len() < IPV4_HDR_LEN {
        return None;
    }
    let ihl = (ip[0] & 0x0f) as usize * 4;
    if ihl < IPV4_HDR_LEN || ip.len() < ihl + 2 {
        return None;
    }
    if u16::from_be_bytes([ip[6], ip[7]]) & 0x1fff != 0 {
        return None;
    }
    Some(match ip[9] {
        IPPROTO_TCP => ihl + 16,
        IPPROTO_UDP => ihl + 6,
        _ => return None,
    })
}

/// Rewrite the destination address of an IPv4 packet from `old` to `new`,
/// updating the IP header checksum (full recompute) and the L4 checksum
/// (incremental). UDP checksum 0 (none) is left alone. A header length
/// field that is below 20 or beyond the bytes present leaves the packet
/// untouched; the caller drops such frames before calling.
pub fn rewrite_ipv4_dst(ip: &mut [u8], new: Ipv4Bytes) {
    let ihl = (ip[0] & 0x0f) as usize * 4;
    if ihl < IPV4_HDR_LEN || ip.len() < ihl {
        return;
    }
    let old: Ipv4Bytes = [ip[16], ip[17], ip[18], ip[19]];
    ip[16..20].copy_from_slice(&new);

    ip[10] = 0;
    ip[11] = 0;
    let hc = checksum(&ip[..ihl]);
    ip[10..12].copy_from_slice(&hc.to_be_bytes());

    if let Some(l4off) = l4_offset(ip) {
        if ip.len() < l4off + 2 {
            return;
        }
        let is_udp = ip[9] == IPPROTO_UDP;
        let has_cksum = if is_udp {
            ip[l4off] != 0 || ip[l4off + 1] != 0
        } else {
            true
        };
        if has_cksum {
            let field = &mut ip[l4off..l4off + 2];
            let old_hw: [u16; 2] = [
                u16::from_be_bytes([old[0], old[1]]),
                u16::from_be_bytes([old[2], old[3]]),
            ];
            let new_hw: [u16; 2] = [
                u16::from_be_bytes([new[0], new[1]]),
                u16::from_be_bytes([new[2], new[3]]),
            ];
            adjust_field(field, old_hw[0], new_hw[0]);
            adjust_field(field, old_hw[1], new_hw[1]);

            if is_udp && (field[0] == 0 && field[1] == 0) {
                field[..2].copy_from_slice(&0xffffu16.to_be_bytes());
            }
        }
    }
}

/// Write the Ethernet header and the outer IPv4 header (proto `proto`,
/// total length `total_len`) at the start of `buf`.
fn write_outer_v4(buf: &mut [u8], outer: &Outer, proto: u8, total_len: u16) {
    buf[..6].copy_from_slice(&outer.dst_mac);
    buf[6..12].copy_from_slice(&outer.src_mac);
    buf[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());

    let ip = &mut buf[ETH_HDR_LEN..ETH_HDR_LEN + IPV4_HDR_LEN];
    ip[0] = 0x45;
    ip[1] = outer.tos;
    ip[2..4].copy_from_slice(&total_len.to_be_bytes());
    ip[4..6].copy_from_slice(&outer.ip_id.to_be_bytes());
    ip[6] = 0x00;
    ip[7] = 0;
    ip[8] = 64;
    ip[9] = proto;
    ip[10] = 0;
    ip[11] = 0;
    ip[12..16].copy_from_slice(&outer.src_ip);
    ip[16..20].copy_from_slice(&outer.dst_ip);
    let hc = checksum(ip);
    ip[10..12].copy_from_slice(&hc.to_be_bytes());
}

/// Encapsulate `inner` (a complete IP packet) in FoU inside `buf`, where
/// `buf.len() >= FOU_HEADROOM + inner.len()` and the inner packet must be
/// placed at `&buf[FOU_HEADROOM..]` beforehand.
pub fn encap_fou_v4(buf: &mut [u8], inner_len: usize, outer: &Outer, port: u16) {
    debug_assert!(buf.len() >= FOU_HEADROOM + inner_len);

    let total_len = (IPV4_HDR_LEN + UDP_HDR_LEN + inner_len) as u16;
    write_outer_v4(buf, outer, IPPROTO_UDP, total_len);

    let udp = &mut buf[ETH_HDR_LEN + IPV4_HDR_LEN..FOU_HEADROOM];
    udp[0..2].copy_from_slice(&port.to_be_bytes());
    udp[2..4].copy_from_slice(&port.to_be_bytes());
    let ulen = (UDP_HDR_LEN + inner_len) as u16;
    udp[4..6].copy_from_slice(&ulen.to_be_bytes());
    udp[6] = 0;
    udp[7] = 0;
}

/// Encapsulate `inner` (a complete L3 IPv4 packet) in GRE inside `buf`:
/// [eth][outer IPv4 proto 47][GRE flags=0 proto=0x0800][inner]. The inner
/// packet must already sit at `&buf[GRE_HEADROOM..]`.
pub fn encap_gre_v4(buf: &mut [u8], inner_len: usize, outer: &Outer) {
    debug_assert!(buf.len() >= GRE_HEADROOM + inner_len);

    let total_len = (IPV4_HDR_LEN + GRE_HDR_LEN + inner_len) as u16;
    write_outer_v4(buf, outer, IPPROTO_GRE, total_len);

    let gre = &mut buf[ETH_HDR_LEN + IPV4_HDR_LEN..GRE_HEADROOM];
    gre[0] = 0;
    gre[1] = 0;
    gre[2..4].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_tcp_packet() -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&[0xaa; 6]);
        f.extend_from_slice(&[0xbb; 6]);
        f.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45;
        ip[1] = 0x00;
        ip[2..4].copy_from_slice(&40u16.to_be_bytes());
        ip[8] = 64;
        ip[9] = IPPROTO_TCP;
        ip[12..16].copy_from_slice(&[192, 168, 1, 9]);
        ip[16..20].copy_from_slice(&[10, 0, 0, 1]);
        let hc = checksum(&ip);
        ip[10..12].copy_from_slice(&hc.to_be_bytes());
        f.extend_from_slice(&ip);
        let mut tcp = vec![0u8; 20];
        tcp[0..2].copy_from_slice(&12345u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&80u16.to_be_bytes());

        tcp[16..18].copy_from_slice(&0x1234u16.to_be_bytes());
        f.extend_from_slice(&tcp);
        f
    }

    #[test]
    fn rewrite_updates_header_and_tcp_checksums() {
        let mut frame = sample_tcp_packet();
        let ip_start = ETH_HDR_LEN;

        let fix = |f: &mut [u8], dst: [u8; 4]| {
            let ip = &f[ip_start..];
            let mut pseudo = Vec::new();
            pseudo.extend_from_slice(&ip[12..16]);
            pseudo.extend_from_slice(&dst);
            pseudo.extend_from_slice(&[0, 6, 0, 20]);
            let mut tcp = f[ip_start + 20..ip_start + 40].to_vec();
            tcp[16..18].copy_from_slice(&[0, 0]);
            pseudo.extend_from_slice(&tcp);
            let c = checksum(&pseudo);
            f[ip_start + 20 + 16..ip_start + 20 + 18].copy_from_slice(&c.to_be_bytes());
        };
        fix(&mut frame, [10, 0, 0, 1]);
        assert_eq!(checksum(&frame[ip_start..ip_start + 20]), 0);

        rewrite_ipv4_dst(&mut frame[ip_start..], [1, 2, 3, 4]);

        let ip = &frame[ip_start..];
        assert_eq!(&ip[16..20], &[1, 2, 3, 4]);
        assert_eq!(
            checksum(&ip[..20]),
            0,
            "IP header checksum must still validate"
        );

        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&ip[12..16]);
        pseudo.extend_from_slice(&ip[16..20]);
        pseudo.extend_from_slice(&[0, 6, 0, 20]);
        pseudo.extend_from_slice(&ip[20..40]);

        assert_eq!(
            checksum(&pseudo),
            0,
            "TCP checksum must validate after rewrite"
        );
    }

    #[test]
    fn rewrite_updates_udp_checksum_at_its_offset() {
        let mut ip = vec![0u8; 20 + 8];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&28u16.to_be_bytes());
        ip[9] = IPPROTO_UDP;
        ip[12..16].copy_from_slice(&[1, 1, 1, 1]);
        ip[16..20].copy_from_slice(&[10, 0, 0, 1]);
        let hc = checksum(&ip[..20]);
        ip[10..12].copy_from_slice(&hc.to_be_bytes());
        ip[20..22].copy_from_slice(&4000u16.to_be_bytes());
        ip[22..24].copy_from_slice(&53u16.to_be_bytes());
        ip[24..26].copy_from_slice(&8u16.to_be_bytes());
        let pseudo = |ip: &[u8]| {
            let mut v = Vec::new();
            v.extend_from_slice(&ip[12..20]);
            v.extend_from_slice(&[0, IPPROTO_UDP, 0, 8]);
            v.extend_from_slice(&ip[20..28]);
            v
        };
        let c = checksum(&pseudo(&ip));
        ip[26..28].copy_from_slice(&c.to_be_bytes());
        assert_eq!(checksum(&pseudo(&ip)), 0);

        rewrite_ipv4_dst(&mut ip, [9, 9, 9, 9]);

        assert_eq!(&ip[20..26], &[0x0f, 0xa0, 0, 53, 0, 8], "ports and length untouched");
        assert_eq!(checksum(&ip[..20]), 0);
        assert_eq!(checksum(&pseudo(&ip)), 0, "UDP checksum must validate after rewrite");
    }

    #[test]
    fn rewrite_leaves_fragment_payload_alone() {
        let fragment = |proto: u8, frag_field: u16| {
            let mut ip = vec![0x11u8; 60];
            ip[..20].fill(0);
            ip[0] = 0x45;
            ip[2..4].copy_from_slice(&60u16.to_be_bytes());
            ip[6..8].copy_from_slice(&frag_field.to_be_bytes());
            ip[9] = proto;
            ip[12..16].copy_from_slice(&[198, 51, 100, 77]);
            ip[16..20].copy_from_slice(&[10, 0, 0, 1]);
            let hc = checksum(&ip[..20]);
            ip[10..12].copy_from_slice(&hc.to_be_bytes());
            ip
        };
        for proto in [IPPROTO_TCP, IPPROTO_UDP] {
            let mut ip = fragment(proto, 185);
            let payload = ip[20..].to_vec();
            rewrite_ipv4_dst(&mut ip, [203, 0, 113, 10]);
            assert_eq!(&ip[16..20], &[203, 0, 113, 10]);
            assert_eq!(checksum(&ip[..20]), 0);
            assert_eq!(&ip[20..], &payload[..], "proto {proto}: non-first fragment payload");
        }
        let mut first = fragment(IPPROTO_TCP, 0x2000);
        rewrite_ipv4_dst(&mut first, [203, 0, 113, 10]);
        assert_ne!(&first[36..38], &[0x11, 0x11], "first fragment carries the TCP checksum");
    }

    #[test]
    fn rewrite_ignores_a_header_length_beyond_the_packet() {
        let mut ip = vec![0u8; 20];
        ip[0] = 0x4f;
        ip[9] = IPPROTO_TCP;
        let before = ip.clone();
        rewrite_ipv4_dst(&mut ip, [9, 9, 9, 9]);
        assert_eq!(ip, before);
    }

    #[test]
    fn rewrite_leaves_udp_none_checksum_alone() {
        let mut ip = vec![0u8; 20 + 8];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&28u16.to_be_bytes());
        ip[9] = IPPROTO_UDP;
        ip[12..16].copy_from_slice(&[1, 1, 1, 1]);
        ip[16..20].copy_from_slice(&[10, 0, 0, 1]);
        let hc = checksum(&ip[..20]);
        ip[10..12].copy_from_slice(&hc.to_be_bytes());
        ip[26] = 0;
        ip[27] = 0;
        rewrite_ipv4_dst(&mut ip, [9, 9, 9, 9]);
        assert_eq!(&ip[26..28], &[0, 0], "UDP none-checksum must stay 0");
        assert_eq!(checksum(&ip[..20]), 0);
    }

    #[test]
    fn fou_encap_layout() {
        let inner_len = 20;
        let mut buf = vec![0u8; FOU_HEADROOM + inner_len];
        let inner: Vec<u8> = (0..inner_len as u8).collect();
        buf[FOU_HEADROOM..].copy_from_slice(&inner);
        let outer = Outer {
            src_mac: [0x11; 6],
            dst_mac: [0x22; 6],
            src_ip: [10, 0, 0, 1],
            dst_ip: [5, 6, 7, 8],
            tos: 0x10,
            ip_id: 7,
        };
        encap_fou_v4(&mut buf, inner_len, &outer, 5555);
        let eth = parse_eth(&buf).unwrap();
        assert_eq!(eth.ethertype, ETHERTYPE_IPV4);
        assert_eq!(eth.src, &[0x11; 6]);
        assert_eq!(eth.dst, &[0x22; 6]);
        let ip = &buf[ETH_HDR_LEN..];
        assert_eq!(ip[0] >> 4, 4);
        assert_eq!(ip[9], IPPROTO_UDP);
        assert_eq!(&ip[12..16], &[10, 0, 0, 1]);
        assert_eq!(&ip[16..20], &[5, 6, 7, 8]);
        let ihl = 20;
        assert_eq!(checksum(&ip[..ihl]), 0);
        let udp = &buf[ETH_HDR_LEN + ihl..];
        let sport = u16::from_be_bytes([udp[0], udp[1]]);
        let dport = u16::from_be_bytes([udp[2], udp[3]]);
        let ulen = u16::from_be_bytes([udp[4], udp[5]]);
        assert_eq!(sport, 5555);
        assert_eq!(dport, 5555);
        assert_eq!(ulen, 8 + inner_len as u16);
        assert_eq!(&buf[FOU_HEADROOM..], &inner[..]);
    }

    #[test]
    fn gre_encap_layout() {
        let inner_len = 20;
        let mut buf = vec![0u8; GRE_HEADROOM + inner_len];
        let inner: Vec<u8> = (0..inner_len as u8).collect();
        buf[GRE_HEADROOM..].copy_from_slice(&inner);
        let outer = Outer {
            src_mac: [0x11; 6],
            dst_mac: [0x22; 6],
            src_ip: [10, 0, 0, 1],
            dst_ip: [5, 6, 7, 8],
            tos: 0x10,
            ip_id: 7,
        };
        encap_gre_v4(&mut buf, inner_len, &outer);
        let eth = parse_eth(&buf).unwrap();
        assert_eq!(eth.ethertype, ETHERTYPE_IPV4);
        assert_eq!(eth.src, &[0x11; 6]);
        assert_eq!(eth.dst, &[0x22; 6]);
        let ip = &buf[ETH_HDR_LEN..];
        assert_eq!(ip[0] >> 4, 4);
        assert_eq!(ip[1], 0x10);
        assert_eq!(ip[9], IPPROTO_GRE);
        assert_eq!(
            u16::from_be_bytes([ip[2], ip[3]]),
            (IPV4_HDR_LEN + GRE_HDR_LEN + inner_len) as u16
        );
        assert_eq!(&ip[12..16], &[10, 0, 0, 1]);
        assert_eq!(&ip[16..20], &[5, 6, 7, 8]);
        assert_eq!(checksum(&ip[..IPV4_HDR_LEN]), 0);
        let gre = &buf[ETH_HDR_LEN + IPV4_HDR_LEN..GRE_HEADROOM];
        assert_eq!(gre, &[0, 0, 0x08, 0x00]);
        assert_eq!(&buf[GRE_HEADROOM..], &inner[..]);
    }

    #[test]
    fn arp_roundtrip() {
        let mut req = vec![0u8; ETH_HDR_LEN + 28];
        let our_mac: MacBytes = [1, 2, 3, 4, 5, 6];
        build_arp_request(&mut req, &our_mac, &[10, 0, 0, 5], &[10, 0, 0, 1]);
        let eth = parse_eth(&req).unwrap();
        assert_eq!(eth.ethertype, ETHERTYPE_ARP);
        let arp = parse_arp(&req[ETH_HDR_LEN..]).unwrap();
        assert_eq!(arp.op, ARP_OP_REQUEST);
        assert_eq!(arp.tpa, [10, 0, 0, 1]);

        let mut reply = vec![0u8; 64];
        let n = build_arp_reply(&mut reply, &arp, &our_mac);
        let r = parse_arp(&reply[ETH_HDR_LEN..n]).unwrap();
        assert_eq!(r.op, ARP_OP_REPLY);
        assert_eq!(r.spa, arp.tpa);
        assert_eq!(r.tpa, arp.spa);
        assert_eq!(r.sha, our_mac);
    }
}
