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
    src/camera_discovery.c
    src/camera_access.c
    src/video_stream.c
    src/cam_net.c
    src/camera_vuln.c
    src/sentinel_core.c
    src/sentinel_fw.c
    src/sentinel_proto.c
    src/sentinel_fuzz.c
    src/sentinel_exploit.c
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

# Derleme bayraklari
target_compile_options(beat_system PRIVATE
    -Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers
)

# --- Derleme bagimliliklari ---
find_package(PkgConfig REQUIRED)

# raylib (pkg-config). Paylasilan kutuphane libglfw3'e NEEDED ile baglidir;
# statik raylib ise glfw3'u dogrudan bu hedefe ister (raylib.pc Requires.private).
pkg_check_modules(RAYLIB REQUIRED IMPORTED_TARGET raylib)
target_link_libraries(beat_system PRIVATE PkgConfig::RAYLIB)

pkg_check_modules(GLFW3 REQUIRED IMPORTED_TARGET glfw3)
target_link_libraries(beat_system PRIVATE PkgConfig::GLFW3)
message(STATUS "GLFW bulundu: ${GLFW3_VERSION} (raylib pencere arka ucu)")

# libpcap
pkg_check_modules(PCAP REQUIRED IMPORTED_TARGET libpcap)
target_link_libraries(beat_system PRIVATE PkgConfig::PCAP)

# OpenSSL (QUIC Initial SNI + kamera TLS). Yoksa quic_sni.c yine derlenir;
# HAVE_OPENSSL tanimsiz kalir ve o kod yollari kapanir.
find_package(OpenSSL)
if(OpenSSL_FOUND)
    target_compile_definitions(beat_system PRIVATE HAVE_OPENSSL)
    target_link_libraries(beat_system PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    message(STATUS "OpenSSL bulundu: QUIC SNI cozumleme + kamera TLS sondasi aktif")
else()
    message(STATUS "OpenSSL yok: QUIC SNI + kamera HTTPS sondasi devre disi (Basic/Digest yine calisir)")
endif()

# libcrypt / libxcrypt. sentinel_fw.c crypt(3) ve crypt.h kullanir;
# modern glibc crypt() saglamaz, bu yuzden eksikse link kirilir.
find_path(CRYPT_INCLUDE_DIR crypt.h)
find_library(CRYPT_LIB crypt)
if(NOT CRYPT_INCLUDE_DIR OR NOT CRYPT_LIB)
    message(FATAL_ERROR
        "libcrypt bulunamadi (crypt.h + liblibcrypt).\n"
        "  Debian/Kali: sudo apt install libcrypt-dev")
endif()
target_include_directories(beat_system PRIVATE ${CRYPT_INCLUDE_DIR})
target_link_libraries(beat_system PRIVATE ${CRYPT_LIB})
message(STATUS "libcrypt bulundu: ${CRYPT_LIB}")

# Threads (pthread) — build-essential icindeki libc ile gelir
find_package(Threads REQUIRED)
target_link_libraries(beat_system PRIVATE Threads::Threads)

# OpenGL (raylib icin zorunlu; libgl1-mesa-dev / libgl-dev)
find_package(OpenGL REQUIRED)
target_link_libraries(beat_system PRIVATE OpenGL::GL)

# X11 (raylib veya glfw statik derlendiyse semboller burada cozulur)
find_package(X11)
if(X11_FOUND)
    target_link_libraries(beat_system PRIVATE ${X11_LIBRARIES})
    message(STATUS "X11 bulundu: statik raylib/glfw baglantisi icin eklendi")
else()
    message(STATUS "X11 basliklari yok: paylasilan raylib/glfw ile derleme surer")
endif()

# m (math) ve dl (dynamic loading)
target_link_libraries(beat_system PRIVATE m dl)

# --- Calisma zamani araclari (derlemeyi durdurmaz) ---
find_program(FFMPEG_BIN ffmpeg)
if(FFMPEG_BIN)
    message(STATUS "ffmpeg bulundu: ${FFMPEG_BIN} (canli izleme / kayit / snapshot)")
else()
    message(STATUS "ffmpeg yok: derleme surer; canli kamera goruntusu acilamaz")
endif()

find_program(IPTABLES_BIN iptables)
if(IPTABLES_BIN)
    message(STATUS "iptables bulundu: ${IPTABLES_BIN} (site karartma BEAT_SB zinciri)")
else()
    message(STATUS "iptables yok: DNS/RST karartma calisir; cekirdek DROP katmani devre disi")
endif()

find_program(IP_BIN ip)
if(IP_BIN)
    message(STATUS "ip bulundu: ${IP_BIN} (ip route / ip neigh)")
else()
    message(STATUS "ip yok: varsayilan rota ve komsu tablosu cozumlenemeyebilir (iproute2)")
endif()

message(STATUS "Platform: ${CMAKE_SYSTEM_NAME}")
message(STATUS "Derleyici: ${CMAKE_C_COMPILER}")

