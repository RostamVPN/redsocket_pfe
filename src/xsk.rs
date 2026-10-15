// Copyright 2026 Internet Mastering & Company, Inc.
// SPDX-License-Identifier: Apache-2.0

//! AF_XDP socket + XSKMAP redirect program, built on raw syscalls (no libbpf).

use std::fmt;
use std::io;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicU32, Ordering};

use crate::packet::{ETH_HDR_LEN, FOU_HEADROOM};

pub const AF_XDP: libc::c_int = 44;
pub const SOL_XDP: libc::c_int = 283;

const XDP_MMAP_OFFSETS: libc::c_int = 1;
const XDP_RX_RING: libc::c_int = 2;
const XDP_TX_RING: libc::c_int = 3;
const XDP_UMEM_REG: libc::c_int = 4;
const XDP_UMEM_FILL_RING: libc::c_int = 5;
const XDP_UMEM_COMPLETION_RING: libc::c_int = 6;
const XDP_STATISTICS: libc::c_int = 7;

const XDP_COPY: u16 = 1 << 1;

const XDP_PGOFF_RX_RING: libc::off_t = 0;
const XDP_PGOFF_TX_RING: libc::off_t = 0x80000000;
const XDP_UMEM_PGOFF_FILL_RING: libc::off_t = 0x100000000;
const XDP_UMEM_PGOFF_COMPLETION_RING: libc::off_t = 0x180000000;

const BPF_MAP_CREATE: libc::c_int = 0;
const BPF_MAP_UPDATE_ELEM: libc::c_int = 2;
const BPF_PROG_LOAD: libc::c_int = 5;

const BPF_MAP_TYPE_XSKMAP: u32 = 17;
const BPF_PROG_TYPE_XDP: u32 = 6;
const BPF_FUNC_REDIRECT_MAP: i32 = 51;
const XDP_PASS: i32 = 2;

const XDP_FLAGS_SKB_MODE: u32 = 1 << 1;
const XDP_FLAGS_DRV_MODE: u32 = 1 << 2;
const XDP_FLAGS_HW_MODE: u32 = 1 << 3;
const IFLA_XDP: u16 = 43;
const IFLA_XDP_FD: u16 = 1;
const IFLA_XDP_FLAGS: u16 = 3;

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct XdpRingOffset {
    producer: u64,
    consumer: u64,
    desc: u64,
    flags: u64,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct XdpMmapOffsets {
    rx: XdpRingOffset,
    tx: XdpRingOffset,
    fr: XdpRingOffset,
    cr: XdpRingOffset,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct XdpUmemReg {
    addr: u64,
    len: u64,
    chunk_size: u32,
    headroom: u32,
    flags: u32,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct SockaddrXdp {
    family: u16,
    flags: u16,
    ifindex: u32,
    queue_id: u32,
    shared_umem_fd: u32,
}

#[repr(C, packed)]
#[derive(Default, Clone, Copy)]
struct BpfInsn {
    code: u8,
    regs: u8,
    off: i16,
    imm: i32,
}

impl BpfInsn {
    const fn new(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> Self {
        BpfInsn {
            code,
            regs: (src << 4) | dst,
            off,
            imm,
        }
    }
}

const BPF_LD_IMM64_DW: u8 = 0x18;
const BPF_PSEUDO_MAP_FD: u8 = 1;
const BPF_MOV64_IMM: u8 = 0xb7;
const BPF_JMP_CALL: u8 = 0x85;
const BPF_EXIT: u8 = 0x95;

#[repr(C)]
#[derive(Default)]
struct BpfAttrMapCreate {
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
}

#[repr(C)]
#[derive(Default)]
struct BpfAttrMapUpdate {
    map_fd: u32,
    _pad: u32,
    key: u64,
    value: u64,
    flags: u64,
}

#[repr(C)]
#[derive(Default)]
struct BpfAttrProgLoad {
    prog_type: u32,
    insn_cnt: u32,
    insns: u64,
    license: u64,
    log_level: u32,
    log_size: u32,
    log_buf: u64,
    kern_version: u32,
    prog_flags: u32,
    prog_name: [u8; 16],
    prog_ifindex: u32,
    _tail: [u32; 8],
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct Ifinfomsg {
    family: u8,
    _pad1: u8,
    type_: u16,
    index: i32,
    flags: u32,
    change: u32,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct RtAttr {
    len: u16,
    type_: u16,
}

fn sys_bpf(cmd: libc::c_int, attr: *const u8, size: usize) -> io::Result<libc::c_int> {
    let r = unsafe { libc::syscall(libc::SYS_bpf, cmd, attr, size) } as libc::c_int;
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(r)
    }
}

struct Ring {
    mask: u32,
    producer: *mut AtomicU32,
    consumer: *mut AtomicU32,
    flags: *mut AtomicU32,
    desc: *mut u8,
    cached_prod: u32,
    cached_cons: u32,
}

unsafe impl Send for Ring {}

impl Ring {
    unsafe fn mmap_ring(
        fd: RawFd,
        pgoff: libc::off_t,
        n_desc: u32,
        desc_size: usize,
        off: &XdpRingOffset,
    ) -> io::Result<Ring> {
        let len = off.desc as usize + n_desc as usize * desc_size;
        let map = libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_POPULATE,
            fd,
            pgoff,
        );
        if map == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(Ring {
            mask: n_desc - 1,
            producer: map.add(off.producer as usize) as *mut AtomicU32,
            consumer: map.add(off.consumer as usize) as *mut AtomicU32,
            flags: map.add(off.flags as usize) as *mut AtomicU32,
            desc: map.add(off.desc as usize) as *mut u8,
            cached_prod: 0,
            cached_cons: 0,
        })
    }

    #[inline]
    fn need_wakeup(&self) -> bool {
        unsafe { (*self.flags).load(Ordering::Relaxed) & 1 != 0 }
    }
}

/// Kernel `struct xdp_desc`; `options` must be zero on submission.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct XdpDesc {
    pub addr: u64,
    pub len: u32,
    pub options: u32,
}

const _: () = assert!(std::mem::size_of::<XdpDesc>() == 16);

/// RX ring (kernel produces, we consume).
pub struct RxRing {
    r: Ring,
}

impl RxRing {
    /// Number of descriptors available to consume right now.
    #[inline]
    pub fn available(&mut self) -> u32 {
        let prod = unsafe { (*self.r.producer).load(Ordering::Acquire) };
        let n = prod.wrapping_sub(self.r.cached_cons);
        n.min(self.r.mask + 1)
    }

    /// Get descriptor `i` of the current batch (0 <= i < available()).
    #[inline]
    pub unsafe fn desc(&self, i: u32) -> XdpDesc {
        let idx = (self.r.cached_cons + i) & self.r.mask;
        let p = self.r.desc.add(idx as usize * 16) as *const XdpDesc;
        *p
    }

    /// Release a batch of `n` consumed descriptors to the kernel.
    #[inline]
    pub fn release(&mut self, n: u32) {
        self.r.cached_cons = self.r.cached_cons.wrapping_add(n);
        unsafe { (*self.r.consumer).store(self.r.cached_cons, Ordering::Release) };
    }
}

/// TX ring (we produce, kernel consumes).
pub struct TxRing {
    r: Ring,
}

impl TxRing {
    /// Free slots usable right now (without seeing kernel completions).
    #[inline]
    pub fn free(&mut self) -> u32 {
        let cons = unsafe { (*self.r.consumer).load(Ordering::Acquire) };
        let used = self.r.cached_prod.wrapping_sub(cons);
        (self.r.mask + 1) - used
    }

    /// Submit one descriptor. Caller must have checked free() > 0.
    #[inline]
    pub unsafe fn submit(&mut self, d: XdpDesc) {
        let idx = self.r.cached_prod & self.r.mask;
        let p = self.r.desc.add(idx as usize * 16) as *mut XdpDesc;
        *p = d;
        self.r.cached_prod = self.r.cached_prod.wrapping_add(1);
    }

    /// Make submitted descriptors visible to the kernel.
    #[inline]
    pub fn flush(&mut self) -> bool {
        std::sync::atomic::compiler_fence(Ordering::SeqCst);
        unsafe { (*self.r.producer).store(self.r.cached_prod, Ordering::Release) };
        self.r.need_wakeup()
    }
}

/// Fill ring (we produce chunk addresses, kernel consumes them for RX).
pub struct FillRing {
    r: Ring,
}

impl FillRing {
    #[inline]
    pub fn free(&mut self) -> u32 {
        let cons = unsafe { (*self.r.consumer).load(Ordering::Acquire) };
        let used = self.r.cached_prod.wrapping_sub(cons);
        (self.r.mask + 1) - used
    }

    #[inline]
    pub unsafe fn submit(&mut self, addr: u64) {
        let idx = self.r.cached_prod & self.r.mask;
        let p = self.r.desc.add(idx as usize * 8) as *mut u64;
        *p = addr;
        self.r.cached_prod = self.r.cached_prod.wrapping_add(1);
    }

    #[inline]
    pub fn flush(&mut self) -> bool {
        std::sync::atomic::compiler_fence(Ordering::SeqCst);
        unsafe { (*self.r.producer).store(self.r.cached_prod, Ordering::Release) };
        self.r.need_wakeup()
    }
}

/// Completion ring (kernel produces addresses of transmitted frames).
pub struct CompRing {
    r: Ring,
}

impl CompRing {
    #[inline]
    pub fn available(&mut self) -> u32 {
        let prod = unsafe { (*self.r.producer).load(Ordering::Acquire) };
        prod.wrapping_sub(self.r.cached_cons).min(self.r.mask + 1)
    }

    #[inline]
    pub unsafe fn addr(&self, i: u32) -> u64 {
        let idx = (self.r.cached_cons + i) & self.r.mask;
        let p = self.r.desc.add(idx as usize * 8) as *const u64;
        *p
    }

    #[inline]
    pub fn release(&mut self, n: u32) {
        self.r.cached_cons = self.r.cached_cons.wrapping_add(n);
        unsafe { (*self.r.consumer).store(self.r.cached_cons, Ordering::Release) };
    }
}

pub struct Umem {
    pub base: *mut u8,
    len: usize,
}

unsafe impl Send for Umem {}

impl Umem {
    /// Frame bytes at `pkt_addr`; the range must lie inside the umem.
    #[inline]
    pub unsafe fn pkt_slice(&mut self, pkt_addr: u64, len: u32) -> &mut [u8] {
        let inside = (pkt_addr as usize)
            .checked_add(len as usize)
            .is_some_and(|end| end <= self.len);
        assert!(inside, "umem range {pkt_addr}+{len} is outside {} bytes", self.len);
        let p = self.base.add(pkt_addr as usize);
        std::slice::from_raw_parts_mut(p, len as usize)
    }

    /// Slide an L3 packet (currently at chunk offset pkt_addr + ETH_HDR_LEN, i.e.
    /// behind its Ethernet header) back to pkt_addr. memmove handles the overlap.
    #[inline]
    pub unsafe fn l3_slide_back(&self, pkt_addr: u64, inner_len: usize) {
        let src = self.base.add(pkt_addr as usize + ETH_HDR_LEN);
        let dst = self.base.add(pkt_addr as usize);
        std::ptr::copy(src, dst, inner_len);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XdpMode {
    Skb,
    Driver,
    Hw,
}

impl XdpMode {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "skb" => Some(XdpMode::Skb),
            "driver" => Some(XdpMode::Driver),
            "hw" => Some(XdpMode::Hw),
            _ => None,
        }
    }

    fn netlink_flag(&self) -> u32 {
        match self {
            XdpMode::Skb => XDP_FLAGS_SKB_MODE,
            XdpMode::Driver => XDP_FLAGS_DRV_MODE,
            XdpMode::Hw => XDP_FLAGS_HW_MODE,
        }
    }
}

pub struct Xsk {
    pub fd: RawFd,
    pub ifindex: u32,
    pub queue: u32,
    pub mode: XdpMode,
    pub umem: Umem,
    pub rx: RxRing,
    pub tx: TxRing,
    pub fill: FillRing,
    pub comp: CompRing,
    map_fd: RawFd,
    prog_fd: RawFd,
    attached: bool,
}

pub struct XskConfig {
    pub ifindex: u32,
    pub queue: u32,
    pub mode: XdpMode,
    pub num_frames: u32,
    pub chunk_size: u32,
    pub headroom: u32,
    pub ring_size: u32,
}

#[derive(Default, Clone, Copy, Debug)]
pub struct XdpSockStats {
    pub rx_dropped: u64,
    pub rx_invalid_descs: u64,
    pub tx_invalid_descs: u64,
    pub rx_ring_full: u64,
    pub rx_fill_ring_empty_descs: u64,
    pub tx_ring_empty_descs: u64,
}

impl Xsk {
    pub fn new(cfg: &XskConfig) -> io::Result<Xsk> {
        if cfg.headroom as usize + 1514 > cfg.chunk_size as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "chunk_size too small for headroom + max frame",
            ));
        }
        if (cfg.headroom as usize) < FOU_HEADROOM {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("headroom must be >= {FOU_HEADROOM} for FoU encap"),
            ));
        }
        if !cfg.ring_size.is_power_of_two() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ring_size must be a power of two",
            ));
        }

        unsafe {
            let len = cfg.num_frames as usize * cfg.chunk_size as usize;
            let base = libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_POPULATE,
                -1,
                0,
            );
            if base == libc::MAP_FAILED {
                return Err(io::Error::last_os_error());
            }
            let umem = Umem {
                base: base as *mut u8,
                len,
            };

            let fd = libc::socket(AF_XDP, libc::SOCK_RAW | libc::SOCK_CLOEXEC, 0);
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let res: io::Result<Xsk> = (|| {
                let mut reg = XdpUmemReg {
                    addr: base as u64,
                    len: len as u64,
                    chunk_size: cfg.chunk_size,
                    headroom: cfg.headroom,
                    flags: 0,
                };
                setsockopt(
                    fd,
                    XDP_UMEM_REG,
                    &mut reg as *mut _ as *const u8,
                    std::mem::size_of::<XdpUmemReg>(),
                )?;

                setsockopt_u32(fd, XDP_UMEM_FILL_RING, cfg.ring_size)?;
                setsockopt_u32(fd, XDP_UMEM_COMPLETION_RING, cfg.ring_size)?;
                setsockopt_u32(fd, XDP_RX_RING, cfg.ring_size)?;
                setsockopt_u32(fd, XDP_TX_RING, cfg.ring_size)?;

                let mut offs = XdpMmapOffsets::default();
                let mut optlen = std::mem::size_of::<XdpMmapOffsets>() as u32;
                let rc = libc::getsockopt(
                    fd,
                    SOL_XDP,
                    XDP_MMAP_OFFSETS,
                    &mut offs as *mut _ as *mut libc::c_void,
                    &mut optlen,
                );
                if rc != 0 {
                    return Err(io::Error::last_os_error());
                }

                let fill =
                    Ring::mmap_ring(fd, XDP_UMEM_PGOFF_FILL_RING, cfg.ring_size, 8, &offs.fr)?;
                let comp = Ring::mmap_ring(
                    fd,
                    XDP_UMEM_PGOFF_COMPLETION_RING,
                    cfg.ring_size,
                    8,
                    &offs.cr,
                )?;
                let rx = Ring::mmap_ring(fd, XDP_PGOFF_RX_RING, cfg.ring_size, 16, &offs.rx)?;
                let tx = Ring::mmap_ring(fd, XDP_PGOFF_TX_RING, cfg.ring_size, 16, &offs.tx)?;

                let sa = SockaddrXdp {
                    family: AF_XDP as u16,
                    flags: XDP_COPY,
                    ifindex: cfg.ifindex,
                    queue_id: cfg.queue,
                    shared_umem_fd: 0,
                };
                let rc = libc::bind(
                    fd,
                    &sa as *const SockaddrXdp as *const libc::sockaddr,
                    std::mem::size_of::<SockaddrXdp>() as u32,
                );
                if rc != 0 {
                    return Err(io::Error::last_os_error());
                }

                let map_entries = 64.max(cfg.queue + 1);
                let map_fd = create_xskmap(map_entries)?;
                let prog_fd = load_xdp_redirect_prog(map_fd, cfg.queue)?;
                for slot in 0..map_entries {
                    bpf_update_elem_u32(map_fd, slot, fd as u32)?;
                }
                attach_xdp_prog(cfg.ifindex, prog_fd, cfg.mode)?;

                let mut xsk = Xsk {
                    fd,
                    ifindex: cfg.ifindex,
                    queue: cfg.queue,
                    mode: cfg.mode,
                    umem,
                    rx: RxRing { r: rx },
                    tx: TxRing { r: tx },
                    fill: FillRing { r: fill },
                    comp: CompRing { r: comp },
                    map_fd,
                    prog_fd,
                    attached: true,
                };

                let chunks = cfg.num_frames.min(xsk.fill.free());
                for i in 0..chunks {
                    xsk.fill.submit((i as u64) * cfg.chunk_size as u64);
                }
                xsk.fill.flush();
                Ok(xsk)
            })();
            if res.is_err() {
                libc::close(fd);
            }
            res
        }
    }

    /// Add more chunk addresses to the fill ring (returns how many were actually
    /// accepted; the rest stay in the caller's pool).
    pub unsafe fn refill(&mut self, addrs: &mut Vec<u64>) -> usize {
        let n = addrs.len().min(self.fill.free() as usize);
        for &a in &addrs[..n] {
            self.fill.submit(a);
        }
        let need_kick = self.fill.flush();
        if need_kick {
            self.wake_rx();
        }
        addrs.drain(..n);
        n
    }

    /// Kick the TX path (skb mode: sendto with null buffer flushes the ring).
    pub unsafe fn wake_tx(&self) {
        libc::sendto(
            self.fd,
            std::ptr::null(),
            0,
            libc::MSG_DONTWAIT,
            std::ptr::null(),
            0,
        );
    }

    pub unsafe fn wake_rx(&self) {
        let mut pfd = libc::pollfd {
            fd: self.fd,
            events: libc::POLLIN,
            revents: 0,
        };
        libc::poll(&mut pfd, 1, 0);
    }

    /// Poll for RX readiness (timeout ms).
    pub unsafe fn poll(&self, timeout_ms: i32) -> bool {
        let mut pfd = libc::pollfd {
            fd: self.fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let rc = libc::poll(&mut pfd, 1, timeout_ms);
        rc > 0 && (pfd.revents & libc::POLLIN) != 0
    }

    pub fn stats(&self) -> XdpSockStats {
        unsafe {
            let mut st = XdpSockStats::default();
            let mut optlen = std::mem::size_of::<XdpSockStats>() as u32;
            let rc = libc::getsockopt(
                self.fd,
                SOL_XDP,
                XDP_STATISTICS,
                &mut st as *mut _ as *mut libc::c_void,
                &mut optlen,
            );
            if rc != 0 {
                return XdpSockStats::default();
            }
            st
        }
    }

    /// Detach everything (idempotent).
    pub fn close(&mut self) {
        unsafe {
            if self.attached {
                detach_xdp_prog(self.ifindex, self.mode);
                self.attached = false;
            }
            libc::close(self.prog_fd);
            libc::close(self.map_fd);
            libc::close(self.fd);
            self.fd = -1;
        }
    }
}

impl Drop for Xsk {
    fn drop(&mut self) {
        self.close();
    }
}

impl fmt::Debug for Xsk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Xsk(fd={}, ifindex={}, queue={}, mode={:?})",
            self.fd, self.ifindex, self.queue, self.mode
        )
    }
}

unsafe fn setsockopt(fd: RawFd, opt: libc::c_int, val: *const u8, len: usize) -> io::Result<()> {
    let rc = libc::setsockopt(fd, SOL_XDP, opt, val as *const libc::c_void, len as u32);
    if rc != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

unsafe fn setsockopt_u32(fd: RawFd, opt: libc::c_int, v: u32) -> io::Result<()> {
    setsockopt(fd, opt, &v as *const u32 as *const u8, 4)
}

fn create_xskmap(max_entries: u32) -> io::Result<RawFd> {
    let attr = BpfAttrMapCreate {
        map_type: BPF_MAP_TYPE_XSKMAP,
        key_size: 4,
        value_size: 4,
        max_entries,
        map_flags: 0,
    };
    sys_bpf(
        BPF_MAP_CREATE,
        &attr as *const _ as *const u8,
        std::mem::size_of::<BpfAttrMapCreate>(),
    )
}

fn bpf_update_elem_u32(map_fd: RawFd, key: u32, value: u32) -> io::Result<()> {
    let attr = BpfAttrMapUpdate {
        map_fd: map_fd as u32,
        _pad: 0,
        key: &key as *const u32 as u64,
        value: &value as *const u32 as u64,
        flags: 0,
    };
    sys_bpf(
        BPF_MAP_UPDATE_ELEM,
        &attr as *const _ as *const u8,
        std::mem::size_of::<BpfAttrMapUpdate>(),
    )?;
    Ok(())
}

/// XSKMAP redirect program.
fn load_xdp_redirect_prog(map_fd: RawFd, queue: u32) -> io::Result<RawFd> {
    let insns: Vec<BpfInsn> = vec![
        BpfInsn::new(BPF_LD_IMM64_DW, 1, BPF_PSEUDO_MAP_FD, 0, map_fd),
        BpfInsn::default(),
        BpfInsn::new(BPF_MOV64_IMM, 2, 0, 0, queue as i32),
        BpfInsn::new(BPF_MOV64_IMM, 3, 0, 0, XDP_PASS),
        BpfInsn::new(BPF_JMP_CALL, 0, 0, 0, BPF_FUNC_REDIRECT_MAP),
        BpfInsn::new(BPF_EXIT, 0, 0, 0, 0),
    ];
    let license = b"GPL\0";
    let mut log_buf = [0u8; 4096];
    let attr = BpfAttrProgLoad {
        prog_type: BPF_PROG_TYPE_XDP,
        insn_cnt: insns.len() as u32,
        insns: insns.as_ptr() as u64,
        license: license.as_ptr() as u64,
        log_level: 1,
        log_size: log_buf.len() as u32,
        log_buf: log_buf.as_mut_ptr() as u64,
        ..Default::default()
    };
    let r = sys_bpf(
        BPF_PROG_LOAD,
        &attr as *const _ as *const u8,
        std::mem::size_of::<BpfAttrProgLoad>(),
    );
    match r {
        Ok(fd) => Ok(fd),
        Err(e) => {
            let log = String::from_utf8_lossy(&log_buf)
                .trim_end_matches('\0')
                .to_string();
            let mut s = format!("BPF_PROG_LOAD failed: {e}");
            if !log.is_empty() {
                s.push_str("\nverifier: ");
                s.push_str(&log);
            }
            Err(io::Error::other(s))
        }
    }
}

fn build_rta(buf: &mut Vec<u8>, type_: u16, payload: &[u8]) {
    let len = 4 + payload.len();
    let ra = RtAttr {
        len: len as u16,
        type_,
    };
    buf.extend_from_slice(unsafe { std::slice::from_raw_parts(&ra as *const _ as *const u8, 4) });
    buf.extend_from_slice(payload);
    while !buf.len().is_multiple_of(4) {
        buf.push(0);
    }
}

fn xdp_nl_msg(ifindex: u32, prog_fd: RawFd, flags: u32) -> Vec<u8> {
    let mut msg = Vec::with_capacity(128);

    let hdr_len = 16;

    let ifi = Ifinfomsg {
        family: 0,
        _pad1: 0,
        type_: 0,
        index: ifindex as i32,
        flags: 0,
        change: 0,
    };
    msg.extend_from_slice(unsafe {
        std::slice::from_raw_parts(
            &ifi as *const _ as *const u8,
            std::mem::size_of::<Ifinfomsg>(),
        )
    });

    let mut nested = Vec::with_capacity(32);
    let fd_bytes = prog_fd.to_ne_bytes();
    build_rta(&mut nested, IFLA_XDP_FD, &fd_bytes);
    let flags_bytes = flags.to_ne_bytes();
    build_rta(&mut nested, IFLA_XDP_FLAGS, &flags_bytes);
    build_rta(&mut msg, IFLA_XDP, &nested);
    let len = msg.len() + hdr_len;

    let mut full = Vec::with_capacity(len);
    let nlmsg_flags: u16 = (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16;
    full.extend_from_slice(&(len as u32).to_ne_bytes());
    full.extend_from_slice(&libc::RTM_SETLINK.to_ne_bytes());
    full.extend_from_slice(&nlmsg_flags.to_ne_bytes());
    full.extend_from_slice(&1u32.to_ne_bytes());
    full.extend_from_slice(&0u32.to_ne_bytes());
    full.extend_from_slice(&msg);
    full
}

fn xdp_nl_msg_remove(ifindex: u32, flags: u32) -> Vec<u8> {
    xdp_nl_msg(ifindex, -1, flags)
}

fn send_nl(msg: &[u8]) -> io::Result<()> {
    unsafe {
        let fd = libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        );
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let rc = libc::send(fd, msg.as_ptr() as *const libc::c_void, msg.len(), 0);
        if rc < 0 {
            let e = io::Error::last_os_error();
            libc::close(fd);
            return Err(e);
        }

        let mut buf = [0u8; 4096];
        let n = libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0);
        libc::close(fd);
        if n < 0 {
            return Err(io::Error::last_os_error());
        }

        if n as usize >= 16 {
            let t = u16::from_ne_bytes([buf[4], buf[5]]);
            if t == libc::NLMSG_ERROR as u16 {
                let err = i32::from_ne_bytes([buf[16], buf[17], buf[18], buf[19]]);
                if err != 0 {
                    return Err(io::Error::from_raw_os_error(-err));
                }
            }
        }
        Ok(())
    }
}

fn attach_xdp_prog(ifindex: u32, prog_fd: RawFd, mode: XdpMode) -> io::Result<()> {
    let msg = xdp_nl_msg(ifindex, prog_fd, mode.netlink_flag());
    send_nl(&msg)
        .map_err(|e| io::Error::new(e.kind(), format!("XDP attach failed ({:?}): {}", mode, e)))
}

fn detach_xdp_prog(ifindex: u32, mode: XdpMode) {
    let msg = xdp_nl_msg_remove(ifindex, mode.netlink_flag());
    let _ = send_nl(&msg);
}
