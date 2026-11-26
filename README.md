# Android GUI for [WireGuard](https://www.wireguard.com/)

> **Fork notice:** this is a fork of the official WireGuard Android app by Jason A. Donenfeld ([git.zx2c4.com/wireguard-android](https://git.zx2c4.com/wireguard-android)), with the Go userspace engine replaced by a Rust engine ([Mullvad gotatun](https://github.com/mullvad/gotatun)). The original work remains copyright of its authors; see [COPYING](COPYING) for the license. Prebuilt APKs are in [GitHub Releases](https://github.com/pkok1099/wireguard-rs/releases).

This is an Android GUI for [WireGuard](https://www.wireguard.com/). It [opportunistically uses the kernel implementation](https://git.zx2c4.com/android_kernel_wireguard/about/), and falls back to using the non-root [Rust userspace implementation](https://github.com/mullvad/gotatun) (gotatun).

## Building

```
$ git clone --recurse-submodules https://github.com/pkok1099/wireguard-rs
$ cd wireguard-rs
$ ./gradlew assembleRelease
```

macOS users may need [flock(1)](https://github.com/discoteq/flock).

## Embedding

The tunnel library is [on Maven Central](https://search.maven.org/artifact/com.wireguard.android/tunnel), alongside [extensive class library documentation](https://javadoc.io/doc/com.wireguard.android/tunnel).

```
implementation 'com.wireguard.android:tunnel:$wireguardTunnelVersion'
```

The library makes use of Java 8 features, so be sure to support those in your gradle configuration with [desugaring](https://developer.android.com/studio/write/java8-support#library-desugaring):

```
compileOptions {
    sourceCompatibility JavaVersion.VERSION_17
    targetCompatibility JavaVersion.VERSION_17
    coreLibraryDesugaringEnabled = true
}
dependencies {
    coreLibraryDesugaring "com.android.tools:desugar_jdk_libs:2.0.3"
}
```

## Translating

Please help us translate the app into several languages on [our translation platform](https://crowdin.com/project/WireGuard).
