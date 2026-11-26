//! Rust WireGuard backend for wireguard-android (`libwg-rs.so`).
//!
//! Drop-in JNI replacement for `libwg-go.so` / `GoBackend`, using
//! Mullvad's `gotatun` (Rust WireGuard, fork of Cloudflare's BoringTun)
//! instead of `wireguard-go`.
//!
//! The Kotlin side (`RustBackend.java`, a copy of the old `GoBackend.java`
//! with the class and library name changed) calls exactly six natives:
//!
//! * `wgTurnOn(ifName, tunFd, settings)` -> handle, or -1 on error
//! * `wgTurnOff(handle)`
//! * `wgGetSocketV4(handle)` / `wgGetSocketV6(handle)` -> UDP fd, or -1
//! * `wgGetConfig(handle)` -> UAPI-format dump (parsed by
//!   `RustBackend.getStatistics()` for rx/tx/handshake per peer)
//! * `wgVersion()` -> version string
//!
//! `settings` is the UAPI string produced by `Config.toWgUserspaceString()`:
//! `private_key=<hex>`, optional `listen_port=<n>`, `replace_peers=true`,
//! then per peer `public_key=<hex>`, `allowed_ip=<ip>/<prefix>`,
//! optional `endpoint=<ip>:<port>`, `persistent_keepalive_interval=<n>`,
//! `preshared_key=<hex>`.
//!
//! Differences from the Go backend, by design:
//!
//! * No UAPI unix socket is served (`wireguard-go` opened one under the
//!   app cache dir). Nothing in the app talks to it; `wg`/`wg-quick`
//!   (`WgQuickBackend`, kernel path) is untouched.
//! * No `DisableSomeRoamingForBrokenMobileSemantics` equivalent: gotatun
//!   rebinds its UDP socket on `Device::resume()` / rebuild, and the
//!   app recreates the tunnel on network change like before.
//! * Socket protection: gotatun does not expose its UDP fd. Instead the
//!   [`CapturingUdpFactory`] records the fd at `bind()` time, and
//!   `wgGetSocketV4/V6` return the recorded fd, which Kotlin then passes
//!   to `VpnService.protect(fd)` exactly as it did for Go. The socket is
//!   dual-stack, so both calls return the same fd; on an IPv4-only
//!   fallback `wgGetSocketV6` returns -1 (which `protect()` tolerates
//!   the same way it tolerated Go's -1).

use std::collections::HashMap;
#[cfg(target_os = "android")]
use std::ffi::CString;
use std::io;
use std::net::SocketAddr;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use gotatun::device::{Device, DeviceBuilder, Peer};
use gotatun::packet::{Ip, Packet, PacketBufPool};
use gotatun::tun::{IpRecv, IpSend, MtuWatcher};
use gotatun::udp::socket::{UdpSocket, UdpSocketFactory};
use gotatun::udp::{UdpTransportFactory, UdpTransportFactoryParams};
use ipnetwork::IpNetwork;
use jni::JNIEnv;
use jni::objects::{JClass, JString};
use jni::sys::{jint, jstring};
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tokio::runtime::{Builder, Runtime};
use x25519_dalek::{PublicKey, StaticSecret};

// ---------------------------------------------------------------------------
// Android logging (best effort; no-op on host builds)
// ---------------------------------------------------------------------------

#[cfg(target_os = "android")]
#[link(name = "log")]
unsafe extern "C" {
    fn __android_log_write(
        prio: std::os::raw::c_int,
        tag: *const std::os::raw::c_char,
        text: *const std::os::raw::c_char,
    ) -> std::os::raw::c_int;
}

#[cfg(target_os = "android")]
fn log_android(level: i32, tag: &str, msg: &str) {
    // __android_log_write(level, tag, text)
    let tag = CString::new(tag).unwrap_or_else(|_| CString::new("wg-rs").unwrap());
    let msg = CString::new(msg).unwrap_or_else(|_| CString::new("?").unwrap());
    unsafe {
        __android_log_write(level, tag.as_ptr(), msg.as_ptr());
    }
}

#[cfg(not(target_os = "android"))]
fn log_android(_level: i32, _tag: &str, msg: &str) {
    eprintln!("[wg-rs] {msg}");
}

fn log_error(msg: &str) {
    // ANDROID_LOG_ERROR = 6
    log_android(6, "WireGuard/RustBackend", msg);
}

// ---------------------------------------------------------------------------
// Tokio runtime (one global runtime; gotatun devices live on it)
// ---------------------------------------------------------------------------

fn runtime() -> &'static Runtime {
    static RT: OnceLock<Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        // One worker thread instead of one per CPU core: a VPN is mostly
        // idle and the device's background tasks are async, so a single
        // worker drives them fine. Fewer threads = less RAM (stacks) and
        // fewer wakeups. A current_thread runtime would be even lighter,
        // but its tasks only run while block_on is active, so it would
        // need a dedicated driver thread; one worker keeps the exact
        // same semantics as the default multi-thread runtime, including
        // block_on from any JNI thread.
        Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .expect("failed to create Tokio runtime for wg-rs")
    })
}

// ---------------------------------------------------------------------------
// TUN transport over the fd handed over by VpnService (detachFd)
// ---------------------------------------------------------------------------

/// Put `fd` in non-blocking mode. `AsyncFd` polls the fd with epoll and
/// never blocks the worker thread, so the fd must already be non-blocking
/// before registration.
fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    // SAFETY: `fd` is a valid, open fd we own (the TUN fd from VpnService).
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    let ret = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// One raw syscall, retried in place on EINTR so the readiness state is
/// never cleared for a spurious interruption.
fn read_once(raw: RawFd, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        let ret = unsafe { libc::read(raw, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if ret < 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(e);
        }
        return Ok(ret as usize);
    }
}

fn write_once(raw: RawFd, buf: &[u8]) -> io::Result<usize> {
    loop {
        let ret = unsafe { libc::write(raw, buf.as_ptr() as *const libc::c_void, buf.len()) };
        if ret < 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(e);
        }
        return Ok(ret as usize);
    }
}

/// Writer half of the TUN fd, driven by epoll on the runtime worker.
/// No blocking-pool thread is spawned per packet: `tokio::fs::File` used
/// to dispatch every read/write through `spawn_blocking`, which grew a
/// thread per concurrent op under load (11 extra threads measured
/// on-device 2026-11-26, worker peak 46% of one core).
struct FdTunTx {
    fd: AsyncFd<OwnedFd>,
}

impl FdTunTx {
    fn new(fd: OwnedFd) -> io::Result<Self> {
        // SAFETY: `fd` is a valid, open, non-blocking fd owned by us; it
        // stays open and refers to the same file description for the
        // whole lifetime of the AsyncFd (we never swap it out).
        let fd = unsafe { AsyncFd::register(fd) }.map_err(|e| e.into_parts().1)?;
        Ok(Self { fd })
    }
}

impl IpSend for FdTunTx {
    async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
        let bytes: Packet<[u8]> = packet.into_bytes();
        let buf = bytes.as_ref();
        let mut written = 0;
        while written < buf.len() {
            let off = written;
            let n = self
                .fd
                .async_io(Interest::WRITABLE, |fd| {
                    write_once(fd.as_raw_fd(), &buf[off..])
                })
                .await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "tun write returned 0",
                ));
            }
            written += n;
        }
        Ok(())
    }
}

/// Reader half of the TUN fd, same epoll mechanism as the writer.
struct FdTunRx {
    fd: AsyncFd<OwnedFd>,
    mtu: MtuWatcher,
}

impl FdTunRx {
    fn new(fd: OwnedFd) -> io::Result<Self> {
        // SAFETY: same contract as FdTunTx::new.
        let fd = unsafe { AsyncFd::register(fd) }.map_err(|e| e.into_parts().1)?;
        Ok(Self {
            fd,
            mtu: MtuWatcher::new(1280),
        })
    }
}

/// Max packets returned by one `IpRecv::recv` call. One reactor wakeup is
/// amortized over up to this many packets under load; the cap bounds the
/// latency one batch can add (32 x 1280 B ≈ 41 KB).
const MAX_TUN_RECV_BATCH: usize = 32;

impl IpRecv for FdTunRx {
    async fn recv<'a>(
        &'a mut self,
        pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
        // First packet: wait for readability, exactly as before. The fd is
        // non-blocking, so the raw reads after this can never block.
        let mut first = pool.get();
        let buf: &mut [u8] = &mut first;
        let n = self
            .fd
            .async_io(Interest::READABLE, |fd| read_once(fd.as_raw_fd(), buf))
            .await?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "tun closed"));
        }
        first.truncate(n);
        let mut packets = Vec::with_capacity(MAX_TUN_RECV_BATCH);
        if let Ok(packet) = first.try_into_ip() {
            packets.push(packet);
        }
        // Drain the fd: keep reading without awaiting until it is empty or
        // the batch is full. A malformed packet is dropped, never fatal:
        // the old code returned Err here and killed the whole device.
        // Raw reads outside `async_io` are sound: the fd is non-blocking,
        // and `async_io` retries its closure first on the next call, so no
        // readiness is lost.
        let raw = self.fd.get_ref().as_raw_fd();
        while packets.len() < MAX_TUN_RECV_BATCH {
            let mut next = pool.get();
            let buf: &mut [u8] = &mut next;
            match read_once(raw, buf) {
                Ok(0) => break,
                Ok(n) => {
                    next.truncate(n);
                    if let Ok(packet) = next.try_into_ip() {
                        packets.push(packet);
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }
        Ok(packets.into_iter())
    }

    fn mtu(&self) -> MtuWatcher {
        self.mtu.clone()
    }
}

// ---------------------------------------------------------------------------
// UDP factory that records the bound socket fd (for VpnService.protect)
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Clone, Copy)]
struct SocketFds {
    v4: i32,
    v6: i32,
}

#[derive(Debug, Default)]
struct CapturingUdpFactory {
    inner: UdpSocketFactory,
    fds: Arc<Mutex<SocketFds>>,
}

impl UdpTransportFactory for CapturingUdpFactory {
    type Send = UdpSocket;
    type Recv = UdpSocket;

    async fn bind(
        &mut self,
        params: &UdpTransportFactoryParams,
    ) -> io::Result<(Self::Send, Self::Recv)> {
        let (send, recv) = self.inner.bind(params).await?;
        let fd = send.as_fd().as_raw_fd();
        let is_v6 = send.local_addr().map(|a| a.is_ipv6()).unwrap_or(false);
        let mut fds = self.fds.lock().unwrap_or_else(|e| e.into_inner());
        if is_v6 {
            // Dual-stack socket: the same fd serves v4 and v6.
            fds.v4 = fd;
            fds.v6 = fd;
        } else {
            fds.v4 = fd;
        }
        Ok((send, recv))
    }
}

// ---------------------------------------------------------------------------
// Tunnel handles
// ---------------------------------------------------------------------------

type RsDevice = Device<(CapturingUdpFactory, FdTunTx, FdTunRx)>;

struct Handle {
    device: RsDevice,
    fds: Arc<Mutex<SocketFds>>,
}

fn handles() -> &'static Mutex<HashMap<i32, Handle>> {
    static HANDLES: OnceLock<Mutex<HashMap<i32, Handle>>> = OnceLock::new();
    HANDLES.get_or_init(|| Mutex::new(HashMap::new()))
}

fn alloc_handle(handle: Handle) -> i32 {
    let mut map = handles().lock().unwrap_or_else(|e| e.into_inner());
    let mut id: i32 = 0;
    while map.contains_key(&id) {
        id = id.saturating_add(1);
        if id == i32::MAX {
            return -1;
        }
    }
    map.insert(id, handle);
    id
}

// ---------------------------------------------------------------------------
// UAPI settings parsing (Config.toWgUserspaceString format)
// ---------------------------------------------------------------------------

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16)?;
        let lo = (bytes[i + 1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    Some(out)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn key32(hex: &str) -> Option<[u8; 32]> {
    let v = hex_decode(hex)?;
    v.try_into().ok()
}

struct ParsedConfig {
    private_key: StaticSecret,
    listen_port: Option<u16>,
    peers: Vec<Peer>,
}

fn parse_uapi(settings: &str) -> Result<ParsedConfig, String> {
    let mut private_key: Option<StaticSecret> = None;
    let mut listen_port: Option<u16> = None;
    let mut peers: Vec<Peer> = Vec::new();
    let mut current: Option<Peer> = None;

    let finish_peer = |current: &mut Option<Peer>, peers: &mut Vec<Peer>| {
        if let Some(peer) = current.take() {
            peers.push(peer);
        }
    };

    for line in settings.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key {
            "private_key" => {
                let bytes = key32(value).ok_or("bad private_key")?;
                private_key = Some(StaticSecret::from(bytes));
            }
            "listen_port" => {
                listen_port = value.parse::<u16>().ok();
            }
            "replace_peers" => {}
            "public_key" => {
                finish_peer(&mut current, &mut peers);
                let bytes = key32(value).ok_or("bad public_key")?;
                current = Some(Peer::new(PublicKey::from(bytes)));
            }
            "allowed_ip" => {
                let Some(peer) = current.as_mut() else {
                    continue;
                };
                let net: IpNetwork = value
                    .parse()
                    .map_err(|_| format!("bad allowed_ip: {value}"))?;
                peer.allowed_ips.push(net);
            }
            "endpoint" => {
                let Some(peer) = current.as_mut() else {
                    continue;
                };
                let addr: SocketAddr = value
                    .parse()
                    .map_err(|_| format!("bad endpoint: {value}"))?;
                peer.endpoint = Some(addr);
            }
            "persistent_keepalive_interval" => {
                let Some(peer) = current.as_mut() else {
                    continue;
                };
                if let Ok(secs) = value.parse::<u16>() {
                    peer.keepalive = if secs == 0 { None } else { Some(secs) };
                }
            }
            "preshared_key" => {
                let Some(peer) = current.as_mut() else {
                    continue;
                };
                if let Some(bytes) = key32(value) {
                    peer.preshared_key = Some(bytes);
                }
            }
            _ => {
                // Unknown UAPI keys (e.g. fwmark) are ignored: the app
                // never sends them in toWgUserspaceString().
            }
        }
    }
    finish_peer(&mut current, &mut peers);

    let private_key = private_key.ok_or("missing private_key")?;
    Ok(ParsedConfig {
        private_key,
        listen_port,
        peers,
    })
}

// ---------------------------------------------------------------------------
// Core operations (called from the JNI wrappers below)
// ---------------------------------------------------------------------------

fn turn_on(_ifname: &str, tun_fd: i32, settings: &str) -> i32 {
    let parsed = match parse_uapi(settings) {
        Ok(parsed) => parsed,
        Err(e) => {
            log_error(&format!("wgTurnOn: parse settings: {e}"));
            return -1;
        }
    };

    // take ownership of the fd Kotlin detached for us (as Go did)
    let owned = unsafe { OwnedFd::from_raw_fd(tun_fd) };
    let read_owned = match owned.try_clone() {
        Ok(fd) => fd,
        Err(e) => {
            log_error(&format!("wgTurnOn: dup tun fd: {e}"));
            return -1;
        }
    };
    // AsyncFd polls with epoll, so both dups must be non-blocking first.
    // O_NONBLOCK lives on the open file description, so one set covers
    // both; set on both anyway so neither depends on the other.
    for fd in [owned.as_raw_fd(), read_owned.as_raw_fd()] {
        if let Err(e) = set_nonblocking(fd) {
            log_error(&format!("wgTurnOn: set tun fd non-blocking: {e}"));
            return -1;
        }
    }

    let fds = Arc::new(Mutex::new(SocketFds { v4: -1, v6: -1 }));
    let factory = CapturingUdpFactory {
        inner: UdpSocketFactory::default(),
        fds: Arc::clone(&fds),
    };

    let mut builder = DeviceBuilder::new()
        .with_udp(factory)
        .with_private_key(parsed.private_key)
        .with_peers(parsed.peers);
    if let Some(port) = parsed.listen_port {
        builder = builder.with_listen_port(port);
    }

    // AsyncFd::register panics without a reactor, so the TUN halves are
    // built inside block_on; on failure the OwnedFds just drop (fd closed).
    let device = match runtime().block_on(async {
        let tx = match FdTunTx::new(owned) {
            Ok(tx) => tx,
            Err(e) => return Err(format!("register tun tx fd: {e}")),
        };
        let rx = match FdTunRx::new(read_owned) {
            Ok(rx) => rx,
            Err(e) => return Err(format!("register tun rx fd: {e}")),
        };
        builder
            .with_ip_pair(tx, rx)
            .build()
            .await
            .map_err(|e| format!("build gotatun device: {e:?}"))
    }) {
        Ok(device) => device,
        Err(e) => {
            log_error(&format!("wgTurnOn: {e}"));
            return -1;
        }
    };

    alloc_handle(Handle { device, fds })
}

fn turn_off(handle_id: i32) {
    let device = {
        let mut map = handles().lock().unwrap_or_else(|e| e.into_inner());
        map.remove(&handle_id).map(|h| h.device)
    };
    if let Some(device) = device {
        runtime().block_on(device.stop());
    }
}

fn socket_fd(handle_id: i32, v6: bool) -> i32 {
    let map = handles().lock().unwrap_or_else(|e| e.into_inner());
    let Some(handle) = map.get(&handle_id) else {
        return -1;
    };
    let fds = handle.fds.lock().unwrap_or_else(|e| e.into_inner());
    if v6 { fds.v6 } else { fds.v4 }
}

fn get_config(handle_id: i32) -> String {
    // Hold the handles lock across the read: Device is not Clone, and
    // the read is short (stats only). Turn-on/off wait briefly.
    let map = handles().lock().unwrap_or_else(|e| e.into_inner());
    let Some(handle) = map.get(&handle_id) else {
        return String::new();
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    runtime().block_on(handle.device.read(async |device| {
        let mut out = String::new();
        if let Some(key) = device.private_key() {
            out.push_str(&format!("private_key={}\n", hex_encode(&key.to_bytes())));
        }
        out.push_str(&format!("listen_port={}\n", device.listen_port()));
        for peer in device.peers().await {
            out.push_str(&format!(
                "public_key={}\n",
                hex_encode(peer.peer.public_key.as_bytes())
            ));
            if let Some(endpoint) = peer.peer.endpoint {
                out.push_str(&format!("endpoint={endpoint}\n"));
            }
            for net in &peer.peer.allowed_ips {
                out.push_str(&format!("allowed_ip={net}\n"));
            }
            out.push_str(&format!("rx_bytes={}\n", peer.stats.rx_bytes));
            out.push_str(&format!("tx_bytes={}\n", peer.stats.tx_bytes));
            let last = peer
                .stats
                .last_handshake
                .map(|ago| now.saturating_sub(ago))
                .unwrap_or(Duration::ZERO);
            out.push_str(&format!("last_handshake_time_sec={}\n", last.as_secs()));
            out.push_str(&format!(
                "last_handshake_time_nsec={}\n",
                last.subsec_nanos()
            ));
        }
        out
    }))
}

// ---------------------------------------------------------------------------
// JNI exports: Java_com_wireguard_android_backend_RustBackend_*
// ---------------------------------------------------------------------------

fn jstring_to_rust(env: &mut JNIEnv, s: &JString) -> String {
    env.get_string(s).map(|v| v.into()).unwrap_or_default()
}

fn rust_to_jstring<'a>(env: &mut JNIEnv<'a>, s: &str) -> jstring {
    match env.new_string(s) {
        Ok(v) => v.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_wireguard_android_backend_RustBackend_wgTurnOn(
    mut env: JNIEnv,
    _class: JClass,
    ifname: JString,
    tun_fd: jint,
    settings: JString,
) -> jint {
    let ifname = jstring_to_rust(&mut env, &ifname);
    let settings = jstring_to_rust(&mut env, &settings);
    let result = std::panic::catch_unwind(move || turn_on(&ifname, tun_fd, &settings));
    match result {
        Ok(handle) => handle,
        Err(_) => {
            log_error("wgTurnOn: panic");
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_wireguard_android_backend_RustBackend_wgTurnOff(
    _env: JNIEnv,
    _class: JClass,
    handle: jint,
) {
    let _ = std::panic::catch_unwind(|| turn_off(handle));
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_wireguard_android_backend_RustBackend_wgGetSocketV4(
    _env: JNIEnv,
    _class: JClass,
    handle: jint,
) -> jint {
    socket_fd(handle, false)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_wireguard_android_backend_RustBackend_wgGetSocketV6(
    _env: JNIEnv,
    _class: JClass,
    handle: jint,
) -> jint {
    socket_fd(handle, true)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_wireguard_android_backend_RustBackend_wgGetConfig(
    mut env: JNIEnv,
    _class: JClass,
    handle: jint,
) -> jstring {
    let config = std::panic::catch_unwind(|| get_config(handle)).unwrap_or_default();
    rust_to_jstring(&mut env, &config)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_wireguard_android_backend_RustBackend_wgVersion(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    rust_to_jstring(&mut env, "gotatun 0.10.3 (rust)")
}

// Keep the linker from discarding the JNI symbols, and give `cargo check`
// on the host a trivial entry point check.
#[allow(dead_code)]
fn _unused_os_str_ext(fd: &std::ffi::OsStr) -> usize {
    fd.as_bytes().len()
}
