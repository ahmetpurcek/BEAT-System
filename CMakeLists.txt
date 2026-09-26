cmake_minimum_required(VERSION 3.16)
project(BEAT_System C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Build tipi belirtilmediyse Release kullan
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Kaynak dosyalar
set(SOURCES
    src/main.c
    src/platform.c
    src/utils.c
    src/arp_scanner.c
    src/network_monitor.c
    src/network_ids.c
    src/arp_block.c
    src/port_scanner.c
    src/gui.c
    src/filter_engine.c
    src/raw_inject.c
    src/quic_sni.c
    src/site_block.c
)

# Hedef
add_executable(beat_system ${SOURCES})

# Header dizinleri (yalnizca bu hedef icin)
target_include_directories(beat_system PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/lib
)

# GNU uzantilari (raw soket, getifaddrs vb.)
target_compile_definitions(beat_system PRIVATE _GNU_SOURCE)

# OpenSSL (QUIC Initial SNI cozumleme; yoksa quic_sni.c fallback'e duser)
find_package(OpenSSL)
if(OpenSSL_FOUND)
    target_compile_definitions(beat_system PRIVATE HAVE_OPENSSL)
    target_link_libraries(beat_system PRIVATE OpenSSL::Crypto)
    message(STATUS "OpenSSL bulundu: QUIC SNI cozumleme aktif")
else()
    message(STATUS "OpenSSL yok: QUIC SNI cozulemez, ICMP fallback kullanilir")
endif()

# Derleme bayraklari
target_compile_options(beat_system PRIVATE
    -Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers
)

# --- Bagimliliklar ---
find_package(PkgConfig REQUIRED)

# raylib (pkg-config uzerinden)
pkg_check_modules(RAYLIB REQUIRED IMPORTED_TARGET raylib)
target_link_libraries(beat_system PRIVATE PkgConfig::RAYLIB)

# libpcap
pkg_check_modules(PCAP REQUIRED IMPORTED_TARGET libpcap)
target_link_libraries(beat_system PRIVATE PkgConfig::PCAP)

# Threads (pthread)
find_package(Threads REQUIRED)
target_link_libraries(beat_system PRIVATE Threads::Threads)

# OpenGL (raylib icin zorunlu)
find_package(OpenGL REQUIRED)
target_link_libraries(beat_system PRIVATE OpenGL::GL)

# X11 (raylib statik derlendiyse gerekli olabilir)
find_package(X11)
if(X11_FOUND)
    target_link_libraries(beat_system PRIVATE ${X11_LIBRARIES})
endif()

# m (math) ve dl (dynamic loading)
target_link_libraries(beat_system PRIVATE m dl)

message(STATUS "Platform: ${CMAKE_SYSTEM_NAME}")
message(STATUS "Derleyici: ${CMAKE_C_COMPILER}")
