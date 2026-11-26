# libwg-rs — Rust WireGuard backend (gotatun)

Drop-in replacement for the old `libwg-go.so` / `GoBackend`, for the
official wireguard-android app. Only the engine changed: the Kotlin UI,
`VpnService` setup, routes/DNS/MTU, and the kernel `WgQuickBackend` path
are untouched.

## What it is

- Rust crate `wg-rs` (`cdylib` → `libwg_rs.so`, shipped as `libwg-rs.so`)
- Engine: Mullvad `gotatun` 0.10.3 (same rev as wpmulti:
  `e95ba9693c15c9063a8c0293d9cbc67aef15eb1d`), feature `device`,
  crypto `aws-lc-rs` (gotatun default)
- JNI: `jni` 0.21, six natives on `RustBackend`
  (`wgTurnOn`, `wgTurnOff`, `wgGetSocketV4`, `wgGetSocketV6`,
  `wgGetConfig`, `wgVersion`) — same contract as the Go backend.
- Kotlin: `GoBackend.java` → `RustBackend.java` (same code, class and
  library name changed), `Application.kt` and the `is GoBackend` checks
  now use `RustBackend`, manifest service renamed, string
  `type_name_go_userspace` → `type_name_rust_userspace`.

## How the engine is wired

- `wgTurnOn` parses the UAPI string from `Config.toWgUserspaceString()`
  (`private_key`, `listen_port`, per-peer `public_key` / `allowed_ip` /
  `endpoint` / `persistent_keepalive_interval` / `preshared_key`),
  takes ownership of the TUN fd Kotlin detached, and builds a
  `gotatun::device::Device` on a global Tokio runtime (1 worker thread;
  see Optimizations below).
- TUN: a small `FdTunTx` / `FdTunRx` pair over the fd
  (`tokio::io::unix::AsyncFd`, dup'd once for read/write; fd set
  `O_NONBLOCK` first), MTU watcher constant
  1280 (the MTU Kotlin set on the `VpnService.Builder`).
- Socket protect: gotatun does not expose its UDP fd, so
  `CapturingUdpFactory` records the fd at `bind()` time;
  `wgGetSocketV4/V6` return it and Kotlin calls
  `VpnService.protect(fd)` as before. The socket is dual-stack, so
  both return the same fd; on an IPv4-only fallback V6 returns -1.
- `wgGetConfig` formats the UAPI dump from `Device::read().peers()`
  (`public_key`, `rx_bytes`, `tx_bytes`, `last_handshake_time_sec/nsec`
  as absolute epoch seconds, computed from gotatun's
  "time since last handshake"), which `RustBackend.getStatistics()`
  parses exactly as it parsed the Go dump.
- Panics unwind, never abort: `panic = "unwind"` in release profile.

## Intentional differences from Go

- No UAPI unix socket (Go served one under the app cache dir; nothing
  in the app uses it).
- No `DisableSomeRoamingForBrokenMobileSemantics` equivalent; the app
  recreates the tunnel on network change as before.

## Build

Prerequisites (once): `rustup target add aarch64-linux-android
armv7-linux-androideabi i686-linux-android x86_64-linux-android`
and `cargo-ndk` on PATH (`~/.cargo/bin`).

The Gradle build drives it via `tunnel/tools/CMakeLists.txt`
(`libwg_rs.so` custom target → `cargo ndk --target <abi>
--platform <api> -- build --release`, copied to
`libwg_rs.so` in the library output dir). The output name must stay
`libwg_rs.so` (underscore): `RustBackend` loads `"wg_rs"`, and
`System.mapLibraryName` turns that into `libwg_rs.so`; a dash-named
file is never found (`dlopen failed: library "libwg_rs.so" not
found`). `libwg.so` / `libwg-quick.so` (C wireguard-tools) are unchanged.

Manual check (host, no Android): `cargo check` in this directory.
Manual Android build (arm64): `cargo ndk -t arm64-v8a -P 24 -- build --release` (needs `ANDROID_NDK_HOME` set).

## Optimizations (2026-11-26)

- Tokio runtime: one worker thread instead of one per CPU core. A VPN
  is mostly idle and the device tasks are async, so one worker drives
  them fine; fewer threads = less RAM (stacks) and fewer wakeups. A
  `current_thread` runtime was considered and rejected: its tasks only
  run while `block_on` is active, so it would need a dedicated driver
  thread; one worker keeps the exact same semantics as the default
  multi-thread runtime, including `block_on` from any JNI thread.
- Tokio features trimmed from `full` to
  `rt-multi-thread, time, net` (gotatun enables its own set on top).
  `full` also pulls in `process`/`signal`/`io-std`/`macros`, which
  nothing here needs. `fs`/`sync`/`io-util` were dropped when the TUN
  halves moved from `tokio::fs::File` to `AsyncFd` (below).
- TUN I/O via `tokio::io::unix::AsyncFd` (epoll on the worker thread),
  not `tokio::fs::File`: the file version dispatches every read/write
  through `spawn_blocking`, and under load the blocking pool grew a
  thread per concurrent op — 12 `tokio-rt-worker` threads measured
  on-device 2026-11-26 (worker peak 46% of one core, total tokio peak
  ~114%), vs 2 threads at idle (1 worker + 1 blocking). With
  `AsyncFd` the TUN read/write run on the single worker thread and
  the blocking pool is never touched: back to 1 tokio thread total
  plus the gotatun UDP tasks on the same worker. `AsyncFd::register`
  is `unsafe` (fd must stay open, non-blocking, same description —
  upheld: we own both dups, set `O_NONBLOCK` via `fcntl` before
  registering, never swap them) and panics without a reactor, so the
  halves are built inside `block_on` in `turn_on`. Measured peak
  (30 snapshots, `top -H`): worker 46% of one core, all tokio
  threads ~114% (~1.14 cores) under load — the fix removes the 11
  blocking threads, it does not change the crypto work itself.
- Release profile: `lto = true`, `codegen-units = 1`, `opt-level = 3`,
  `panic = "unwind"` (a panic at the JNI boundary must unwind into a
  Java exception, never abort the app). Unstripped arm64 `.so` went
  from 6.8 MB to 3.4 MB; the APK ships the Gradle-stripped ~1.17 MB.
- Crypto backend is `aws-lc-rs` (the fast option: hand-written ARMv8
  NEON assembly for ChaCha20-Poly1305, `chacha-armv8.pl` /
  `chacha20_poly1305_armv8.pl` in aws-lc-sys 0.47.0), verified:
  `cargo tree -e features -p gotatun-crypto` shows it enabled, and
  the built `.so` contains `aws_lc` symbols.
  (`default-features = false` on gotatun only drops gotatun's own
  default; `gotatun-crypto` still enables its own default.)
  Note: because the hot path is that assembly, the crate's own
  `opt-level = 3` matters only for the glue code around it (packet
  handling, TUN/UDP I/O), not for crypto speed; 2 vs 3 was never
  measured here.
- Batching (2026-11-26, not yet measured on-device): two changes, both
  aimed at the per-packet syscall/reactor overhead, not crypto.
  (1) TUN read batches in this crate: `FdTunRx::recv` waits once for
  readability, then drains the fd with raw non-blocking reads until
  `WouldBlock` (max 32 packets), returning them all as one iterator —
  one reactor wakeup per batch instead of one per packet. A malformed
  packet is dropped, never fatal (the old code returned `Err` and
  killed the device). (2) UDP receive batches in the forked gotatun
  (`tunnel/tools/gotatun`, pkok1099 fork of mullvad/gotatun at
  e95ba96): `DeviceState::handle_incoming` now calls `recv_many_from`
  instead of `recv_from`, so the Linux socket's `recvmmsg` + GRO path
  (up to 100 datagrams per syscall) is actually used. UDP *send*
  batching (`send_many_to`/`sendmmsg`) exists in gotatun too, but the
  device loop still sends one packet per `send_to` call — the next
  candidate if measurements show the upload direction is the
  bottleneck. MTU stays 1280 (the wgcf profile's value; raising it
  risks blackholes) and no big-core affinity is set (needs measurement
  first).
- Gotatun-specific knobs checked (2026-11-26): `PacketBufPool::new_lazy`
  is already used inside gotatun's `Device`; our code only calls
  `pool.get()`. UDP GRO exists on Linux too
  (`gotatun/src/udp/socket/linux.rs`, enabled by `UdpSocketFactory::bind`
  on every socket) — it was idle before because the device loop called
  single-packet `recv_from`; see the batching bullet above.
  `mimalloc`/`jemalloc` are `gotatun-cli`-only
  features, not exposed by the library. `udp_recv_buffer_size` /
  `udp_send_buffer_size` exist only on the default-UDP-factory
  builder; this crate uses a custom `CapturingUdpFactory`, so the
  OS-default socket buffers apply. No other performance knobs exist
  on `DeviceBuilder`.
- Not yet measured on-device: CPU/RAM vs the official app. Measure
  with `adb shell dumpsys meminfo com.wireguard.android` (tunnel up,
  idle and under traffic) before claiming a win.
