# SPDX-License-Identifier: Apache-2.0
#
# Copyright © 2017-2025 WireGuard LLC. All Rights Reserved.

cmake_minimum_required(VERSION 3.4.1)
project("WireGuard")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}")
add_link_options(LINKER:--build-id=none)
add_compile_options(-Wall -Werror)

add_executable(libwg-quick.so wireguard-tools/src/wg-quick/android.c ndk-compat/compat.c)
target_compile_options(libwg-quick.so PUBLIC -std=gnu11 -include ${CMAKE_CURRENT_SOURCE_DIR}/ndk-compat/compat.h -DWG_PACKAGE_NAME=\"${ANDROID_PACKAGE_NAME}\")
target_link_libraries(libwg-quick.so -ldl)

file(GLOB WG_SOURCES wireguard-tools/src/*.c ndk-compat/compat.c)
add_executable(libwg.so ${WG_SOURCES})
target_include_directories(libwg.so PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/wireguard-tools/src/uapi/linux/" "${CMAKE_CURRENT_SOURCE_DIR}/wireguard-tools/src/")
target_compile_options(libwg.so PUBLIC -std=gnu11 -include ${CMAKE_CURRENT_SOURCE_DIR}/ndk-compat/compat.h -DRUNSTATEDIR=\"/data/data/${ANDROID_PACKAGE_NAME}/cache\")

# libwg_rs.so: Rust backend (gotatun) replacing wireguard-go.
# Built with cargo-ndk, which needs the Rust Android target for the ABI
# installed (`rustup target add aarch64-linux-android armv7-linux-androideabi
# i686-linux-android x86_64-linux-android`) and cargo-ndk on PATH
# (~/.cargo/bin). The .so is copied into the Gradle library output dir
# under the exact name Kotlin loads: libwg_rs.so (loadLibrary "wg_rs" —
# System.mapLibraryName turns "wg_rs" into "libwg_rs.so", underscore, not
# a dash; a dash-named file is never found and the backend fails to start).
if(ANDROID_ABI STREQUAL "arm64-v8a")
    set(WG_RS_TARGET "aarch64-linux-android")
elseif(ANDROID_ABI STREQUAL "armeabi-v7a")
    set(WG_RS_TARGET "armv7-linux-androideabi")
elseif(ANDROID_ABI STREQUAL "x86")
    set(WG_RS_TARGET "i686-linux-android")
elseif(ANDROID_ABI STREQUAL "x86_64")
    set(WG_RS_TARGET "x86_64-linux-android")
else()
    message(FATAL_ERROR "libwg_rs: unsupported ANDROID_ABI ${ANDROID_ABI}")
endif()

add_custom_target(libwg_rs.so WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/libwg-rs" COMMENT "Building libwg-rs (gotatun)" VERBATIM COMMAND ${CMAKE_COMMAND} -E env "PATH=$ENV{HOME}/.cargo/bin:$ENV{PATH}" "ANDROID_NDK_HOME=${CMAKE_ANDROID_NDK}" cargo ndk --target ${ANDROID_ABI} --platform ${ANDROID_NATIVE_API_LEVEL} -- build --release
    COMMAND ${CMAKE_COMMAND} -E copy_if_different "${CMAKE_CURRENT_SOURCE_DIR}/libwg-rs/target/${WG_RS_TARGET}/release/libwg_rs.so" "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libwg_rs.so"
)

# Strip unwanted ELF sections to prevent DT_FLAGS_1 warnings on old Android versions
file(GLOB ELF_CLEANER_SOURCES elf-cleaner/*.c elf-cleaner/*.cpp)
add_custom_target(elf-cleaner COMMENT "Building elf-cleaner" VERBATIM COMMAND cc
        -O2 -DPACKAGE_NAME="elf-cleaner" -DPACKAGE_VERSION="" -DCOPYRIGHT=""
        -o "${CMAKE_CURRENT_BINARY_DIR}/elf-cleaner" ${ELF_CLEANER_SOURCES}
)
add_custom_command(TARGET libwg.so POST_BUILD VERBATIM COMMAND "${CMAKE_CURRENT_BINARY_DIR}/elf-cleaner"
        --api-level "${ANDROID_NATIVE_API_LEVEL}" "$<TARGET_FILE:libwg.so>")
add_dependencies(libwg.so elf-cleaner)
add_custom_command(TARGET libwg-quick.so POST_BUILD VERBATIM COMMAND "${CMAKE_CURRENT_BINARY_DIR}/elf-cleaner"
        --api-level "${ANDROID_NATIVE_API_LEVEL}" "$<TARGET_FILE:libwg-quick.so>")
add_dependencies(libwg-quick.so elf-cleaner)
