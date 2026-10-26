/*
 * camera_discovery.c — Kamera Keşif Motoru Uygulaması
 *
 * Pasif/aktif keşif hattı:
 *   ARP tablosu (MAC) -> hedef listesi -> paralel port taraması ->
 *   genişletilmiş port turu (MAC'i çözülen hostlarda) ->
 *   RTSP/HTTP derin sonda -> TLS sertifika sondası (443/8443) ->
 *   ONVIF WS-Discovery (iki tur: multicast + broadcast) -> skorlama.
 *
 * Harici bağımlılık yok: POSIX soketleri + standart C kütüphanesi.
 */
#include "camera_discovery.h"
#include "camera_vuln.h"
#include "camera_access.h"
#include "utils.h"

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>

#ifdef HAVE_OPENSSL
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#endif

/* ========== Global State ========== */
static CameraScanResults  g_results;
static platform_mutex_t   g_lock;
static char               g_log[CAM_MAX_LOG_LINES][256];
static int                g_log_count = 0;
static int                g_log_write = 0;
static platform_mutex_t   g_log_lock;
static int                g_initialized = 0;
static volatile int       g_cancel = 0;
static platform_thread_t  g_scan_thread;
static volatile int       g_thread_running = 0;

/* ========== Log ========== */
void camera_discovery_log(const char *fmt, ...) {
    platform_mutex_lock(&g_log_lock);
    char buf[256];
    char ts[16];
    time_now_hms(ts, sizeof(ts));
    int prefix = snprintf(buf, sizeof(buf), "[%s] ", ts);
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf + prefix, sizeof(buf) - prefix, fmt, ap);
    va_end(ap);
    int idx = g_log_write % CAM_MAX_LOG_LINES;
    strncpy(g_log[idx], buf, 255);
    g_log[idx][255] = '\0';
    g_log_write++;
    if (g_log_count < CAM_MAX_LOG_LINES) g_log_count++;
    platform_mutex_unlock(&g_log_lock);
}

int camera_discovery_get_log(char lines[][256], int max_lines) {
    platform_mutex_lock(&g_log_lock);
    int n = 0;
    int total = g_log_count;
    int start = (g_log_write - total + CAM_MAX_LOG_LINES * 8) % CAM_MAX_LOG_LINES;
    for (int i = 0; i < total && n < max_lines; i++) {
        int idx = (start + i) % CAM_MAX_LOG_LINES;
        strncpy(lines[n], g_log[idx], 255);
        lines[n][255] = '\0';
        n++;
    }
    platform_mutex_unlock(&g_log_lock);
    return n;
}

/* ========== MAC OUI Veritabanı (bilinen kamera üreticileri) ========== */
typedef struct { const char *prefix; const char *vendor; } OuiEntry;

static const OuiEntry k_cam_oui[] = {
    /* Hikvision / Ezviz / Amcrest-Hik */
    {"44:19:B6", "Hikvision"}, {"4C:BD:8F", "Hikvision"}, {"BC:AD:28", "Hikvision"},
    {"C0:56:E3", "Hikvision"}, {"28:57:BE", "Hikvision"}, {"54:C4:15", "Hikvision"},
    {"8C:E7:48", "Hikvision"}, {"A4:14:37", "Hikvision"}, {"44:47:CC", "Hikvision"},
    {"E0:CA:3C", "Hikvision"}, {"BC:9B:5E", "Hikvision"}, {"C4:2F:90", "Hikvision"},
    /* Dahua / Amcrest / Lorex */
    {"3C:EF:8C", "Dahua"}, {"90:02:A9", "Dahua"}, {"4C:11:BF", "Dahua"},
    {"8C:E9:B4", "Dahua"}, {"6C:1C:71", "Dahua"}, {"9C:14:63", "Dahua"},
    {"E0:50:8B", "Dahua"}, {"38:AF:29", "Dahua"},
    /* Axis */
    {"00:40:8C", "Axis"}, {"AC:CC:8E", "Axis"}, {"B8:A4:4F", "Axis"},
    {"00:0A:C5", "Axis"},
    /* Hanwha / Samsung Techwin */
    {"00:16:6C", "Hanwha"}, {"00:09:18", "Hanwha"}, {"00:1C:F0", "Hanwha"},
    /* Vivotek */
    {"00:02:D1", "Vivotek"}, {"00:22:2B", "Vivotek"},
    /* Foscam */
    {"00:62:6E", "Foscam"}, {"9C:8E:CD", "Foscam"}, {"C4:D6:55", "Foscam"},
    /* Reolink */
    {"EC:71:DB", "Reolink"}, {"40:7C:7D", "Reolink"},
    /* Bosch */
    {"00:07:5F", "Bosch"}, {"00:1C:44", "Bosch"},
    /* Pelco */
    {"00:04:7D", "Pelco"},
    /* Uniview (UNV) */
    {"48:EA:63", "Uniview"}, {"9C:8E:99", "Uniview"}, {"AC:64:17", "Uniview"},
    /* TP-Link / Tapo / Kasa */
    {"30:DE:4B", "TP-Link"}, {"9C:53:22", "TP-Link"}, {"60:32:B1", "TP-Link"},
    {"B0:4E:26", "TP-Link"},
    /* D-Link cameras */
    {"00:1B:11", "D-Link"}, {"28:10:7B", "D-Link"}, {"00:80:C8", "D-Link"},
    /* Panasonic */
    {"00:80:F0", "Panasonic"}, {"00:1B:2E", "Panasonic"},
    /* Mobotix / Arecont / GeoVision / Grandstream */
    {"00:03:C5", "Mobotix"}, {"00:1A:07", "Arecont"}, {"00:13:E2", "GeoVision"},
    {"00:0B:82", "Grandstream"},
    /* Wyze / Xiaomi / XiongMai (XMEye) */
    {"2C:AA:8E", "Wyze"}, {"7C:78:B2", "Wyze"},
    {"78:11:DC", "Xiaomi"}, {"34:CE:00", "Xiaomi"},
    {"38:AA:3C", "XiongMai"}, {"48:EA:63", "XiongMai"},
    /* Others */
    {"00:1A:8C", "Sony"}, {"00:1D:BA", "Sony"},
    {"00:0F:7C", "ACTi"}, {"00:1E:06", "Wibrain"},
    {NULL, NULL}
};

/* Normalize MAC -> "AA:BB:CC:DD:EE:FF" büyük harf (girdi kopyalanır). */
static void mac_normalize(const char *in, char *out, int len) {
    char tmp[MAX_MAC_LEN];
    int j = 0;
    for (int i = 0; in[i] && j < (int)sizeof(tmp) - 1; i++) {
        if (isxdigit((unsigned char)in[i])) tmp[j++] = (char)toupper((unsigned char)in[i]);
    }
    tmp[j] = '\0';
    if (j == 12) {
        snprintf(out, len, "%c%c:%c%c:%c%c:%c%c:%c%c:%c%c",
                 tmp[0],tmp[1],tmp[2],tmp[3],tmp[4],tmp[5],
                 tmp[6],tmp[7],tmp[8],tmp[9],tmp[10],tmp[11]);
    } else {
        strncpy(out, in, len - 1);
        out[len - 1] = '\0';
    }
}

int camera_discovery_oui_is_camera(const char *mac, char *vendor_out, int len) {
    if (vendor_out && len > 0) vendor_out[0] = '\0';
    if (!mac || !mac[0]) return 0;
    char norm[MAX_MAC_LEN];
    mac_normalize(mac, norm, sizeof(norm));
    for (int i = 0; k_cam_oui[i].prefix; i++) {
        if (strncmp(norm, k_cam_oui[i].prefix, 8) == 0) {
            if (vendor_out) { strncpy(vendor_out, k_cam_oui[i].vendor, len - 1); vendor_out[len - 1] = '\0'; }
            return 1;
        }
    }
    return 0;
}

/* ========== Metin / XML yardımcıları ========== */
/* <tag>deger</tag> içinden değeri çıkarır (namespace önekini yok sayar). */
static int xml_tag_text(const char *buf, const char *tag, char *out, int len) {
    out[0] = '\0';
    char needle[64];
    snprintf(needle, sizeof(needle), ":%s>", tag);
    const char *p = strstr(buf, needle);
    if (!p) {
        snprintf(needle, sizeof(needle), "<%s>", tag);
        p = strstr(buf, needle);
        if (!p) return 0;
    }
    p = strchr(p, '>');
    if (!p) return 0;
    p++;
    const char *e = strchr(p, '<');
    if (!e) return 0;
    int n = (int)(e - p);
    if (n <= 0 || n >= len) { if (n >= len) n = len - 1; }
    memcpy(out, p, n);
    out[n] = '\0';
    str_trim(out);
    return out[0] ? 1 : 0;
}

/* Metinden bilinen kamera üreticisini tahmin eder. */
static int guess_manufacturer(const char *text, char *out, int len) {
    if (!text || !text[0]) return 0;
    struct { const char *key; const char *vendor; } map[] = {
        {"hikvision", "Hikvision"}, {"ezviz", "Hikvision"}, {"dahua", "Dahua"},
        {"amcrest", "Amcrest"}, {"lorex", "Dahua"}, {"axis", "Axis"},
        {"hanwha", "Hanwha"}, {"samsung", "Hanwha"}, {"vivotek", "Vivotek"},
        {"foscam", "Foscam"}, {"reolink", "Reolink"}, {"bosch", "Bosch"},
        {"pelco", "Pelco"}, {"uniview", "Uniview"}, {"tp-link", "TP-Link"},
        {"tapo", "TP-Link"}, {"d-link", "D-Link"}, {"panasonic", "Panasonic"},
        {"mobotix", "Mobotix"}, {"grandstream", "Grandstream"}, {"wyze", "Wyze"},
        {"xiaomi", "Xiaomi"}, {"xmeye", "XiongMai"}, {"netsurveillance", "XiongMai"},
        {"geovision", "GeoVision"}, {"sony", "Sony"}, {"acti", "ACTi"},
        {"netwave", "Netwave"}, {"vstarcam", "VStarcam"}, {"havision", "Havision"},
        {"mediamtx", "MediaMTX"}, {"gstreamer", "GStreamer"}, {"live555", "Live555"},
        {"rtsp", "RTSP Sunucu"}, {"boa", "Boa (gömülü)"}, {"goahead", "GoAhead (gömülü)"},
        {"lighttpd", "Lighttpd"},
    };
    for (unsigned i = 0; i < sizeof(map)/sizeof(map[0]); i++) {
        if (str_contains_ci(text, map[i].key)) {
            strncpy(out, map[i].vendor, len - 1);
            out[len - 1] = '\0';
            return 1;
        }
    }
    return 0;
}

/* ========== ARP Tablosu (IP -> MAC) ========== */
#define ARP_MAP_MAX 512
static char arp_map_ip[ARP_MAP_MAX][MAX_IP_LEN];
static char arp_map_mac[ARP_MAP_MAX][MAX_MAC_LEN];
static int  arp_map_count = 0;

static void load_arp_table(void) {
    arp_map_count = 0;
    FILE *fp = fopen("/proc/net/arp", "r");
    if (fp) {
        char line[256];
        fgets(line, sizeof(line), fp); /* başlık */
        while (fgets(line, sizeof(line), fp) && arp_map_count < ARP_MAP_MAX) {
            /* alan sırası: IP HWtype Flags HWaddr Mask Device */
            char ipa[64], hwt[16], flg[16], hwa[32];
            if (sscanf(line, "%63s %15s %15s %31s", ipa, hwt, flg, hwa) == 4) {
                if (strcmp(hwa, "00:00:00:00:00:00") != 0 && strchr(hwa, ':')) {
                    strncpy(arp_map_ip[arp_map_count], ipa, MAX_IP_LEN - 1);
                    mac_normalize(hwa, arp_map_mac[arp_map_count], MAX_MAC_LEN);
                    arp_map_count++;
                }
            }
        }
        fclose(fp);
    }
    /* `ip neigh` ile takviye */
    char out[4096];
    if (platform_run_command("ip -4 neigh show 2>/dev/null", out, sizeof(out)) >= 0 && out[0]) {
        char *line = strtok(out, "\n");
        while (line && arp_map_count < ARP_MAP_MAX) {
            char ip[64], mac[32];
            char *ll = strstr(line, "lladdr ");
            if (ll && sscanf(line, "%63s", ip) == 1) {
                if (sscanf(ll + 7, "%31s", mac) == 1 && strchr(mac, ':')) {
                    int dup = 0;
                    for (int i = 0; i < arp_map_count; i++)
                        if (strcmp(arp_map_ip[i], ip) == 0) { dup = 1; break; }
                    if (!dup) {
                        strncpy(arp_map_ip[arp_map_count], ip, MAX_IP_LEN - 1);
                        mac_normalize(mac, arp_map_mac[arp_map_count], MAX_MAC_LEN);
                        arp_map_count++;
                    }
                }
            }
            line = strtok(NULL, "\n");
        }
    }
}

static const char *arp_lookup(const char *ip) {
    for (int i = 0; i < arp_map_count; i++)
        if (strcmp(arp_map_ip[i], ip) == 0) return arp_map_mac[i];
    return NULL;
}

/* ============================================================
 * Kendi ag kimligimiz / dislama (self, gateway, broadcast...)
 * ============================================================ */
#define EXCL_MAX 64
static char g_self_ips[EXCL_MAX][MAX_IP_LEN];
static int  g_self_ip_count = 0;
static char g_gateway_ip[MAX_IP_LEN];
static char g_net_range[64];

static void gather_self_info(void) {
    g_self_ip_count = 0;
    g_gateway_ip[0] = '\0';
    g_net_range[0] = '\0';

    struct ifaddrs *ifa = NULL;
    if (getifaddrs(&ifa) == 0) {
        for (struct ifaddrs *p = ifa; p; p = p->ifa_next) {
            if (!p->ifa_addr || p->ifa_addr->sa_family != AF_INET) continue;
            struct sockaddr_in *sin = (struct sockaddr_in *)p->ifa_addr;
            char ip[MAX_IP_LEN];
            if (!inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip))) continue;
            if (strcmp(ip, "127.0.0.1") == 0 || strcmp(ip, "0.0.0.0") == 0) continue;
            if (g_self_ip_count < EXCL_MAX)
                snprintf(g_self_ips[g_self_ip_count++], MAX_IP_LEN, "%s", ip);
        }
        freeifaddrs(ifa);
    }

    platform_get_gateway(g_gateway_ip, sizeof(g_gateway_ip), NULL, 0);

    char iface[MAX_IFACE_LEN] = {0}, lip[MAX_IP_LEN] = {0};
    platform_get_default_interface(iface, sizeof(iface));
    platform_get_local_ip(iface, lip, sizeof(lip));
    platform_get_network_range(iface, lip, g_net_range, sizeof(g_net_range));

    camera_discovery_log("Kendi ag: %s %s (gateway %s, %d yerel IP dislanacak)",
        g_net_range[0] ? g_net_range : "(?)", iface,
        g_gateway_ip[0] ? g_gateway_ip : "-", g_self_ip_count);
}

static int is_self_ip(const char *ip) {
    for (int i = 0; i < g_self_ip_count; i++)
        if (strcmp(g_self_ips[i], ip) == 0) return 1;
    return 0;
}

/* Kullanici acikca bir hedef (IP/CIDR) verdiginde, otomatik taramadaki
 * "kendi makinem + gateway + loopback" dislamasi devre disi kalir; boylece
 * yerel testbed (127.0.0.1) ve kendi alt agindaki kameralar da bulunur.
 * Otomatik taramada (hedef bos) ise dislama aynen korunur. */
static int g_explicit_target = 0;

/* Dislanacak hostlar: kendi IP'leri, gateway, ag adresi, broadcast,
 * multicast, 0.0.0.0/8 ve 169.254/16 (link-local). */
static int is_excluded_host(const char *ip) {
    if (!ip || !ip[0]) return 1;
    if (!g_explicit_target) {
        if (is_self_ip(ip)) return 1;
        if (g_gateway_ip[0] && strcmp(ip, g_gateway_ip) == 0) return 1;
        if (strcmp(ip, "127.0.0.1") == 0) return 1;
    }
    if (strcmp(ip, "0.0.0.0") == 0) return 1;
    if (strcmp(ip, "255.255.255.255") == 0) return 1;
    unsigned a = 0, b = 0, c = 0, d = 0;
    if (sscanf(ip, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return 1;
    if (a == 0 || a >= 224) return 1;      /* 0.x, multicast, rezerve */
    if (d == 255) return 1;                 /* .255 broadcast */
    if (a == 169 && b == 254) return 1;     /* link-local */
    return 0;
}

/* ========== Aktif ARP/neighbor supurme ========== */
/* Her hosta kucuk bir UDP datagrami gondererek katman-2 ARP cozumlemesini
 * tetikler; boylece kamera MAC/OUI bilgisi port taramasindan ONCE dolabilir. */
static void arp_sweep(char hosts[][MAX_IP_LEN], int count) {
    if (count <= 0) return;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return;
    int fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    unsigned char knock = 0;
    for (int i = 0; i < count; i++) {
        if (g_cancel) break;
        struct sockaddr_in a;
        memset(&a, 0, sizeof(a));
        a.sin_family = AF_INET;
        a.sin_port = htons(9);   /* discard: yalniz ARP tetikleme amacli */
        if (inet_pton(AF_INET, hosts[i], &a.sin_addr) == 1)
            sendto(fd, &knock, 1, 0, (struct sockaddr *)&a, sizeof(a));
    }
    close(fd);
    platform_sleep_ms(250);
}

/* ========== Multicast kesif (SSDP/UPnP + mDNS) ========== */
/* DNS yanitindaki A (tip 1) kayitlarindan IPv4 adreslerini toplar. */
static void dns_collect_a(const unsigned char *p, int len,
                          char out[][MAX_IP_LEN], int *n, int max) {
    if (len < 12) return;
    int qd = (p[4] << 8) | p[5];
    int an = (p[6] << 8) | p[7];
    int off = 12;
    for (int i = 0; i < qd && off < len; i++) {
        int stop = 0;
        while (off < len && p[off] != 0 && !stop) {
            if ((p[off] & 0xC0) == 0xC0) { off += 2; stop = 1; }
            else off += 1 + p[off];
        }
        if (!stop && off < len && p[off] == 0) off += 1;
        off += 4; /* qtype + qclass */
    }
    for (int i = 0; i < an && off + 10 <= len; i++) {
        while (off < len && p[off] != 0) {
            if ((p[off] & 0xC0) == 0xC0) { off += 2; break; }
            off += 1 + p[off];
        }
        if (off < len && p[off] == 0) off += 1;
        if (off + 10 > len) break;
        int type = (p[off] << 8) | p[off + 1];
        int rdlen = (p[off + 8] << 8) | p[off + 9];
        off += 10;
        if (off + rdlen > len) break;
        if (type == 1 && rdlen == 4) {
            char ip[MAX_IP_LEN];
            snprintf(ip, sizeof(ip), "%u.%u.%u.%u", p[off], p[off+1], p[off+2], p[off+3]);
            if (!is_excluded_host(ip)) {
                int dup = 0;
                for (int k = 0; k < *n; k++) if (strcmp(out[k], ip) == 0) { dup = 1; break; }
                if (!dup && *n < max) snprintf(out[(*n)++], MAX_IP_LEN, "%s", ip);
            }
        }
        off += rdlen;
    }
}

static void add_found(char out[][MAX_IP_LEN], int *n, int max, const char *ip) {
    if (is_excluded_host(ip)) return;
    for (int i = 0; i < *n; i++) if (strcmp(out[i], ip) == 0) return;
    if (*n < max) snprintf(out[(*n)++], MAX_IP_LEN, "%s", ip);
}

/* SSDP (UPnP) + mDNS ile port taramasinin kacirabilecegi hostlari bulur ve
 * mevcut hedef listesine ekler. Doner: eklenen yeni host sayisi. */
static int ssdp_mdns_discover(char hosts[][MAX_IP_LEN], int *total, int max) {
    static char found[CAM_MAX_HOSTS][MAX_IP_LEN];
    int nf = 0;
    int added = 0;

    /* --- SSDP M-SEARCH --- */
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd >= 0) {
        unsigned char ttl = 2;
        setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));
        struct timeval tv = {1, 200000};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        const char *msearch =
            "M-SEARCH * HTTP/1.1\r\n"
            "HOST: 239.255.255.250:1900\r\n"
            "MAN: \"ssdp:discover\"\r\n"
            "MX: 1\r\n"
            "ST: ssdp:all\r\n\r\n";
        struct sockaddr_in dst;
        memset(&dst, 0, sizeof(dst));
        dst.sin_family = AF_INET;
        dst.sin_port = htons(1900);
        inet_pton(AF_INET, "239.255.255.250", &dst.sin_addr);
        sendto(fd, msearch, strlen(msearch), 0, (struct sockaddr *)&dst, sizeof(dst));

        char buf[4096];
        for (int k = 0; k < 48; k++) {
            struct sockaddr_in from;
            socklen_t fl = sizeof(from);
            int r = (int)recvfrom(fd, buf, sizeof(buf) - 1, 0, (struct sockaddr *)&from, &fl);
            if (r <= 0) break;
            char ip[MAX_IP_LEN];
            if (inet_ntop(AF_INET, &from.sin_addr, ip, sizeof(ip)))
                add_found(found, &nf, CAM_MAX_HOSTS, ip);
        }
        close(fd);
    }

    /* --- mDNS PTR sorgulari (kamera servis tipleri) --- */
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd >= 0) {
        unsigned char ttl = 1;
        setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));
        struct timeval tv = {1, 200000};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        const char *qnames[] = {
            "_rtsp._tcp.local", "_onvif._tcp.local",
            "_http._tcp.local", "_nvr._tcp.local"
        };
        struct sockaddr_in dst;
        memset(&dst, 0, sizeof(dst));
        dst.sin_family = AF_INET;
        dst.sin_port = htons(5353);
        inet_pton(AF_INET, "224.0.0.251", &dst.sin_addr);
        for (unsigned qi = 0; qi < sizeof(qnames) / sizeof(qnames[0]); qi++) {
            unsigned char q[512];
            memset(q, 0, 12);
            q[5] = 1;  /* qdcount = 1 */
            int o = 12;
            const char *nm = qnames[qi];
            while (*nm) {
                const char *dot = strchr(nm, '.');
                int l = dot ? (int)(dot - nm) : (int)strlen(nm);
                if (o + 1 + l >= (int)sizeof(q) - 5) break;
                q[o++] = (unsigned char)l;
                memcpy(q + o, nm, l); o += l;
                nm = dot ? dot + 1 : nm + l;
            }
            q[o++] = 0;
            q[o++] = 0; q[o++] = 12;  /* PTR */
            q[o++] = 0; q[o++] = 1;   /* IN */
            sendto(fd, q, o, 0, (struct sockaddr *)&dst, sizeof(dst));
        }
        char buf[4096];
        for (int k = 0; k < 64; k++) {
            struct sockaddr_in from;
            socklen_t fl = sizeof(from);
            int r = (int)recvfrom(fd, buf, sizeof(buf) - 1, 0, (struct sockaddr *)&from, &fl);
            if (r <= 0) break;
            dns_collect_a((const unsigned char *)buf, r, found, &nf, CAM_MAX_HOSTS);
            char sip[MAX_IP_LEN];
            if (inet_ntop(AF_INET, &from.sin_addr, sip, sizeof(sip)))
                add_found(found, &nf, CAM_MAX_HOSTS, sip);
        }
        close(fd);
    }

    for (int i = 0; i < nf; i++) {
        int dup = 0;
        for (int j = 0; j < *total; j++) if (strcmp(hosts[j], found[i]) == 0) { dup = 1; break; }
        if (!dup && *total < max) {
            snprintf(hosts[(*total)++], MAX_IP_LEN, "%s", found[i]);
            added++;
        }
    }
    return added;
}

/* ========== Zaman yardımcısı ========== */
/* Monotonik saat (ms). Duvarsaati siçramalarindan ve saat dilimi
 * degisimlerinden etkilenmez; bekleme pencereleri icin kullanilir. */
static long long mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* ========== Soket yardımcıları ========== */
static int sock_send_all(int fd, const char *buf, int len, int timeout_ms) {
    int sent = 0;
    while (sent < len) {
        int n = (int)send(fd, buf + sent, len - sent, MSG_NOSIGNAL);
        if (n > 0) { sent += n; continue; }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            struct pollfd pfd = { .fd = fd, .events = POLLOUT };
            if (poll(&pfd, 1, timeout_ms) <= 0) break;
            continue;
        }
        break;
    }
    return sent;
}

static int sock_recv_str(int fd, char *out, int outlen, int first_timeout_ms) {
    int total = 0;
    int timeout = first_timeout_ms;
    while (total < outlen - 1) {
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        if (poll(&pfd, 1, timeout) <= 0) break;
        int n = (int)recv(fd, out + total, outlen - 1 - total, 0);
        if (n <= 0) break;
        total += n;
        timeout = 250; /* ilk veri geldi: kısa boşlukta dur */
    }
    out[total] = '\0';
    return total;
}

/* ========== Port probe (nonblocking connect) ========== */
static int tcp_open(const char *ip, int port, int timeout_ms) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, ip, &a.sin_addr) != 1) { close(fd); return -1; }

    int fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);

    int r = connect(fd, (struct sockaddr *)&a, sizeof(a));
    if (r == 0) return fd;
    if (errno != EINPROGRESS) { close(fd); return -1; }

    struct pollfd pfd = { .fd = fd, .events = POLLOUT };
    if (poll(&pfd, 1, timeout_ms) <= 0) { close(fd); return -1; }

    int err = 0;
    socklen_t el = sizeof(err);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el) < 0 || err != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* ========== Genişletilmiş port turu (fan-out) ========== */
/* Ayni host uzerindeki cok sayida portu tek poll penceresinde dener.
 * Bloklamayan connect + SO_ERROR ile acik portlar toplanir.
 * Donus: acik port sayisi (open_out'a yazilir). */
static int tcp_sweep_fanout(const char *ip, const int *ports, int count,
                            int *open_out, int max_open, int timeout_ms) {
    if (!ip || !ports || count <= 0 || !open_out || max_open <= 0) return 0;
    int cap = count < 128 ? count : 128;
    int fds[128];
    int prt[128];
    int nfd = 0;
    int opened = 0;

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1) return 0;

    for (int i = 0; i < cap; i++) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) continue;
        int fl = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, fl | O_NONBLOCK);
        sa.sin_port = htons((unsigned short)ports[i]);
        int r = connect(fd, (struct sockaddr *)&sa, sizeof(sa));
        if (r == 0) {
            if (opened < max_open) open_out[opened++] = ports[i];
            close(fd);
            continue;
        }
        if (errno != EINPROGRESS) { close(fd); continue; }
        fds[nfd] = fd;
        prt[nfd] = ports[i];
        nfd++;
    }
    if (nfd == 0) return opened;

    struct pollfd pfds[128];
    char done[128];
    memset(done, 0, sizeof(done));
    for (int i = 0; i < nfd; i++) {
        pfds[i].fd = fds[i];
        pfds[i].events = POLLOUT;
        pfds[i].revents = 0;
    }

    long long deadline = mono_ms() + (timeout_ms > 0 ? timeout_ms : 250);
    int pending = nfd;
    while (pending > 0) {
        long long left = deadline - mono_ms();
        if (left <= 0) break;
        int pr = poll(pfds, (nfds_t)nfd, (int)left);
        if (pr <= 0) {
            if (pr < 0 && errno == EINTR) continue;
            break;
        }
        for (int i = 0; i < nfd; i++) {
            if (done[i] || pfds[i].revents == 0) continue;
            int err = 0;
            socklen_t el = sizeof(err);
            if (getsockopt(fds[i], SOL_SOCKET, SO_ERROR, &err, &el) == 0 && err == 0) {
                if (opened < max_open) open_out[opened++] = prt[i];
            }
            done[i] = 1;
            pfds[i].fd = -1;
            pending--;
        }
    }
    for (int i = 0; i < nfd; i++) if (fds[i] >= 0) close(fds[i]);
    return opened;
}

/* ========== RTSP sondası ========== */
static int rtsp_probe(const char *ip, int port, CameraDevice *cam) {
    int fd = tcp_open(ip, port, 350);
    if (fd < 0) return 0;

    char req[256];
    snprintf(req, sizeof(req),
             "OPTIONS rtsp://%s:%d/ RTSP/1.0\r\nCSeq: 1\r\n"
             "User-Agent: BEAT-System/1.0\r\n\r\n", ip, port);
    sock_send_all(fd, req, (int)strlen(req), 350);

    char buf[3072];
    int n = sock_recv_str(fd, buf, sizeof(buf), 1500);
    int found = 0, auth = 0, code = 0;
    if (n > 0 && strstr(buf, "RTSP/")) {
        found = 1;
        sscanf(buf, "%*s %d", &code);
        if (code == 401 || str_contains_ci(buf, "WWW-Authenticate")) auth = 1;
    /* Bazi RTSP sunuculari OPTIONS istegine kimlik sormaz (or. mediamtx);
       DESCRIBE ile ikinci kez dogrula. Root path bazi sunucularda
       400/404 donebildiginden birkac aday yol denenir. */
    if (found && !auth) {
        static const char *auth_paths[] = { "/", "/x", "/live" };
        for (size_t ap = 0; ap < sizeof(auth_paths) / sizeof(auth_paths[0]) && !auth; ap++) {
            int dfd = (ap == 0) ? fd : tcp_open(ip, port, 350);
            if (dfd < 0) continue;
            snprintf(req, sizeof(req),
                     "DESCRIBE rtsp://%s:%d%s RTSP/1.0\r\nCSeq: 2\r\n"
                     "Accept: application/sdp\r\n"
                     "User-Agent: BEAT-System/1.0\r\n\r\n", ip, port, auth_paths[ap]);
            sock_send_all(dfd, req, (int)strlen(req), 350);
            char dbuf[2048];
            int dn = sock_recv_str(dfd, dbuf, sizeof(dbuf), 1500);
            if (ap != 0) close(dfd);
            if (dn > 0 && (strstr(dbuf, " 401 ") || str_contains_ci(dbuf, "WWW-Authenticate"))) {
                auth = 1;
                char *re2 = strstr(dbuf, "realm=");
                if (re2 && !cam->rtsp_realm[0]) {
                    re2 += 6;
                    if (*re2 == '"') re2++;
                    char rt[CAM_REALM_LEN];
                    int j = 0;
                    while (re2[j] && re2[j] != '"' && re2[j] != '\r' && re2[j] != '\n' && j < (int)sizeof(rt) - 1) { rt[j] = re2[j]; j++; }
                    rt[j] = '\0';
                    if (rt[0]) strncpy(cam->rtsp_realm, rt, CAM_REALM_LEN - 1);
                }
            }
        }
    }
    }

    if (found) {
        /* Server başlığı */
        char *sv = strstr(buf, "erver:"); /* "Server:" veya "server:" */
        if (sv) {
            sv += 7;
            while (*sv == ' ') sv++;
            char tmp[CAM_SERVER_LEN];
            int i = 0;
            while (sv[i] && sv[i] != '\r' && sv[i] != '\n' && i < (int)sizeof(tmp) - 1) {
                tmp[i] = sv[i]; i++;
            }
            tmp[i] = '\0';
            str_trim(tmp);
            if (tmp[0] && !cam->server_header[0])
                strncpy(cam->server_header, tmp, CAM_SERVER_LEN - 1);
        }
        /* realm */
        char *re = strstr(buf, "realm=");
        if (re) {
            re += 6;
            if (*re == '"') re++;
            char tmp[CAM_REALM_LEN];
            int i = 0;
            while (re[i] && re[i] != '"' && re[i] != '\r' && re[i] != '\n' && i < (int)sizeof(tmp) - 1) {
                tmp[i] = re[i]; i++;
            }
            tmp[i] = '\0';
            if (tmp[0]) strncpy(cam->rtsp_realm, tmp, CAM_REALM_LEN - 1);
        }
        if (auth) cam->rtsp_auth_required = 1;
    }
    close(fd);
    return found;
}

/* ========== HTTP sondası ========== */
static int http_probe(const char *ip, int port, CameraDevice *cam) {
    int fd = tcp_open(ip, port, 350);
    if (fd < 0) return 0;

    char req[256];
    snprintf(req, sizeof(req),
             "GET / HTTP/1.0\r\nHost: %s\r\nUser-Agent: BEAT-System/1.0\r\n"
             "Connection: close\r\n\r\n", ip);
    sock_send_all(fd, req, (int)strlen(req), 350);

    char buf[4096];
    int n = sock_recv_str(fd, buf, sizeof(buf), 1500);
    int found = (n > 0);
    int is_camera_ui = 0;

    if (found) {
        char *sv = strstr(buf, "erver:");
        if (sv) {
            sv += 7;
            while (*sv == ' ') sv++;
            char tmp[CAM_SERVER_LEN];
            int i = 0;
            while (sv[i] && sv[i] != '\r' && sv[i] != '\n' && i < (int)sizeof(tmp) - 1) { tmp[i] = sv[i]; i++; }
            tmp[i] = '\0';
            str_trim(tmp);
            if (tmp[0] && !cam->server_header[0])
                strncpy(cam->server_header, tmp, CAM_SERVER_LEN - 1);
            if (guess_manufacturer(tmp, cam->manufacturer, CAM_MODEL_LEN)) is_camera_ui = 1;
        }
        /* 401 realm */
        char *re = strstr(buf, "realm=");
        if (re) {
            re += 6;
            if (*re == '"') re++;
            char tmp[CAM_REALM_LEN];
            int i = 0;
            while (re[i] && re[i] != '"' && re[i] != '\r' && re[i] != '\n' && i < (int)sizeof(tmp) - 1) { tmp[i] = re[i]; i++; }
            tmp[i] = '\0';
            if (tmp[0]) strncpy(cam->rtsp_realm, tmp, CAM_REALM_LEN - 1);
        }
        if (str_contains_ci(buf, "realm") && str_contains_ci(buf, "401")) {
            guess_manufacturer(buf, cam->manufacturer, CAM_MODEL_LEN);
        }

        /* Kamera UI imza kelimeleri */
        const char *kws[] = {
            "hikvision", "dahua", "netsurveillance", "ip camera", "network camera",
            "webcam", "onvif", "streaming/channels", "isapi", "cgi-bin",
            "mjpeg", "dnvrs", "mjson", "dvrdvs", "vstarcam", "foscam", "reolink",
            "amcrest", "axis", "goahead", "web/admin", "dvr", "nvr", "video.cgi",
            NULL
        };
        for (int i = 0; kws[i]; i++) {
            if (str_contains_ci(buf, kws[i])) { is_camera_ui = 1; break; }
        }
        if (!is_camera_ui && (str_contains_ci(buf, "camera") && str_contains_ci(buf, "<title")))
            is_camera_ui = 1;
    }
    close(fd);
    return is_camera_ui ? 2 : (found ? 1 : 0);
}

/* ========== TLS sertifika sondası (443/8443) ========== */
#ifdef HAVE_OPENSSL
/* Sertifika adindaki O / CN / OU alanlarini tek metinde toplar. */
static void name_fields(X509_NAME *nm, char *out, int len) {
    if (!out || len <= 0) return;
    out[0] = '\0';
    if (!nm) return;
    static const int nids[] = { NID_organizationName, NID_commonName, NID_organizationalUnitName };
    for (int i = 0; i < 3; i++) {
        char buf[256];
        buf[0] = '\0';
        if (X509_NAME_get_text_by_NID(nm, nids[i], buf, sizeof(buf)) <= 0) continue;
        if (!buf[0]) continue;
        size_t used = strlen(out);
        if (used && used + 3 >= (size_t)len) continue;
        if (used) snprintf(out + used, (size_t)len - used, " | %s", buf);
        else snprintf(out, (size_t)len, "%s", buf);
    }
}

/* TLS el sikismasi yapip sertifika konu/veren alanlarini okur.
 * Sadece okuma amacli; sertifika dogrulanmaz (kamera kendinden imzali). */
static int tls_cert_probe(const char *ip, int port, char *subj, int sublen,
                          char *iss, int isslen) {
    if (subj && sublen > 0) subj[0] = '\0';
    if (iss && isslen > 0) iss[0] = '\0';
    if (!ip || !ip[0] || port <= 0) return 0;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_library_init();
    SSL_load_error_strings();
#else
    OPENSSL_init_ssl(0, NULL);
#endif

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) return 0;
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    SSL *ssl = SSL_new(ctx);
    if (!ssl) { SSL_CTX_free(ctx); return 0; }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { SSL_free(ssl); SSL_CTX_free(ctx); return 0; }

    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((unsigned short)port);
    if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1 ||
        connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        close(fd);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return 0;
    }

    SSL_set_fd(ssl, fd);
    int got = 0;
    if (SSL_connect(ssl) == 1) {
        X509 *cert;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        cert = SSL_get1_peer_certificate(ssl);
#else
        cert = SSL_get_peer_certificate(ssl);
#endif
        if (cert) {
            name_fields(X509_get_subject_name(cert), subj, sublen);
            name_fields(X509_get_issuer_name(cert), iss, isslen);
            X509_free(cert);
            got = 1;
        }
    }
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(fd);
    SSL_CTX_free(ctx);
    return got;
}
#else
/* OpenSSL yoksa TLS sondasi sessizce devre disi kalir. */
static int tls_cert_probe(const char *ip, int port, char *subj, int sublen,
                          char *iss, int isslen) {
    (void)ip; (void)port; (void)subj; (void)sublen; (void)iss; (void)isslen;
    return 0;
}
#endif

/* ========== ONVIF WS-Discovery ========== */
typedef struct {
    char ip[MAX_IP_LEN];
    char manufacturer[CAM_MODEL_LEN];
    char model[CAM_MODEL_LEN];
    char xaddr[CAM_URL_LEN];
} OnvifHit;

static const char *WS_PROBE =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<e:Envelope xmlns:e=\"http://www.w3.org/2003/05/soap-envelope\" "
    "xmlns:w=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" "
    "xmlns:d=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\" "
    "xmlns:dn=\"http://www.onvif.org/ver10/network/wsdl\">"
    "<e:Header><w:MessageID>%s</w:MessageID>"
    "<w:To e:mustUnderstand=\"true\">urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>"
    "<w:Action e:mustUnderstand=\"true\">"
    "http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action></e:Header>"
    "<e:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe>"
    "</e:Body></e:Envelope>";

/* Bir tur icin yanitlari toplar; bulunan toplam hit sayisini doner. */
static int ws_collect(int fd, OnvifHit *hits, int max_hits, int found, int wait_ms) {

    long long deadline = mono_ms() + wait_ms;
    while (found < max_hits) {
        long long left = deadline - mono_ms();
        if (left <= 0) break;
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        if (poll(&pfd, 1, (int)left) <= 0) break;

        unsigned char rbuf[8192];
        struct sockaddr_in from;
        socklen_t fl = sizeof(from);
        int n = (int)recvfrom(fd, rbuf, sizeof(rbuf) - 1, 0,
                              (struct sockaddr *)&from, &fl);
        if (n <= 0) continue;
        rbuf[n] = '\0';
        const char *body = (const char *)rbuf;
        if (!str_contains_ci(body, "ProbeMatch") && !str_contains_ci(body, "XAddrs"))
            continue;

        char ip[MAX_IP_LEN];
        inet_ntop(AF_INET, &from.sin_addr, ip, sizeof(ip));
        int dup = 0;
        for (int i = 0; i < found; i++)
            if (strcmp(hits[i].ip, ip) == 0) { dup = 1; break; }
        if (dup) continue;

        OnvifHit *h = &hits[found];
        memset(h, 0, sizeof(*h));
        strncpy(h->ip, ip, MAX_IP_LEN - 1);
        xml_tag_text(body, "Manufacturer", h->manufacturer, CAM_MODEL_LEN);
        xml_tag_text(body, "Model", h->model, CAM_MODEL_LEN);
        if (!xml_tag_text(body, "XAddrs", h->xaddr, CAM_URL_LEN)) {
            const char *xa = strstr(body, "XAddrs");
            if (xa) {
                const char *gt = strchr(xa, '>');
                if (gt) {
                    gt++;
                    const char *lt = strchr(gt, '<');
                    if (lt) {
                        int len = (int)(lt - gt);
                        if (len > 0 && len < CAM_URL_LEN) { memcpy(h->xaddr, gt, len); h->xaddr[len] = '\0'; }
                    }
                }
            }
        }
        found++;
    }
    return found;
}

/* Her turda benzersiz MessageID uretir. Cihazlar ayni MessageID ile gelen
 * tekrarlanan Probe'lara yanit vermeyebiliyor. */
static void ws_msgid(char *out, int len) {
    static unsigned int seq = 0;
    unsigned int r1 = (unsigned int)rand();
    unsigned int r2 = (unsigned int)rand();
    unsigned int r3 = (unsigned int)time(NULL);
    unsigned int s = __sync_add_and_fetch(&seq, 1);
    snprintf(out, len, "uuid:%08x-%04x-4%03x-%04x-%08x%04x",
             r1,
             (r2 >> 16) & 0xFFFF,
             (r3 + s) & 0x0FFF,
             ((r3 >> 4) & 0x3FFF) | 0x8000,
             (s * 2654435761u) ^ r2,
             r1 & 0xFFFF);
}

/* g_net_range'ten (orn. "192.168.1.0/24") alt ag broadcast adresini uretir. */
static int net_broadcast_addr(char *out, int len) {
    if (!out || len <= 0 || !g_net_range[0]) return 0;
    char spec[64];
    strncpy(spec, g_net_range, sizeof(spec) - 1);
    spec[sizeof(spec) - 1] = '\0';
    int prefix = 24;
    char *slash = strchr(spec, '/');
    if (slash) { *slash = '\0'; prefix = atoi(slash + 1); }
    unsigned int a = 0, b = 0, c = 0, d = 0;
    if (sscanf(spec, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return 0;
    unsigned int ip = (a << 24) | (b << 16) | (c << 8) | d;
    unsigned int mask;
    if (prefix <= 0) mask = 0u;
    else if (prefix >= 32) mask = 0xFFFFFFFFu;
    else mask = 0xFFFFFFFFu << (32 - prefix);
    unsigned int bc = (ip & mask) | ~mask;
    snprintf(out, len, "%u.%u.%u.%u",
             (bc >> 24) & 0xFF, (bc >> 16) & 0xFF, (bc >> 8) & 0xFF, bc & 0xFF);
    return 1;
}

/* Probe'u multicast + alt ag broadcast + sinirli broadcast uzerinden yollar.
 * Broadcast, multicast grup uyeligine girmeyen cihazlari da kapsar. */
static void ws_send_probe(int fd, const char *msgid) {
    char msg[2048];
    snprintf(msg, sizeof(msg), WS_PROBE, msgid);
    size_t mlen = strlen(msg);
    if (mlen == 0 || mlen >= sizeof(msg)) return;

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(3702);

    if (inet_pton(AF_INET, "239.255.255.250", &dst.sin_addr) == 1)
        sendto(fd, msg, mlen, 0, (struct sockaddr *)&dst, sizeof(dst));

    char bc[32];
    if (net_broadcast_addr(bc, sizeof(bc)) && inet_pton(AF_INET, bc, &dst.sin_addr) == 1)
        sendto(fd, msg, mlen, 0, (struct sockaddr *)&dst, sizeof(dst));

    dst.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    sendto(fd, msg, mlen, 0, (struct sockaddr *)&dst, sizeof(dst));
}

/* Iki turlu toplama: 1) standart multicast Probe, 2) yeni MessageID ile
 * multicast + broadcast. Ilk turu kaciran veya multicast grubuna girmeyen
 * cihazlar ikinci turda yakalanir. */
static int ws_discovery_gather(OnvifHit *hits, int max_hits, int wait_ms) {
    if (!hits || max_hits <= 0) return 0;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return 0;

    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &one, sizeof(one));

    struct sockaddr_in local;
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    local.sin_port = 0;
    if (bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0) { close(fd); return 0; }

    struct ip_mreq mreq;
    memset(&mreq, 0, sizeof(mreq));
    inet_pton(AF_INET, "239.255.255.250", &mreq.imr_multiaddr);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));

    unsigned char ttl = 2;
    setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));

    int r1_wait = (wait_ms * 2) / 5;
    if (r1_wait < 600) r1_wait = 600;
    if (r1_wait > wait_ms) r1_wait = wait_ms;

    char mid[64];
    ws_msgid(mid, sizeof(mid));
    ws_send_probe(fd, mid);
    int found = ws_collect(fd, hits, max_hits, 0, r1_wait);

    if (found < max_hits) {
        ws_msgid(mid, sizeof(mid));
        ws_send_probe(fd, mid);
        found = ws_collect(fd, hits, max_hits, found, wait_ms);
    }

    close(fd);
    return found;
}

/* ========== Hedef (host) listesi ========== */
static int build_host_list(const char *target, char hosts[][MAX_IP_LEN],
                           int max_hosts, char *range_out, int rlen) {
    char spec[64] = {0};
    if (target && target[0]) {
        strncpy(spec, target, sizeof(spec) - 1);
    } else {
        char iface[MAX_IFACE_LEN] = {0}, lip[MAX_IP_LEN] = {0};
        platform_get_default_interface(iface, sizeof(iface));
        platform_get_local_ip(iface, lip, sizeof(lip));
        platform_get_network_range(iface, lip, spec, sizeof(spec));
    }
    if (!spec[0]) return 0;

    char base[64];
    int prefix = 32;
    char *slash = strchr(spec, '/');
    if (slash) {
        *slash = '\0';
        prefix = atoi(slash + 1);
        if (prefix < 0) prefix = 0;
        if (prefix > 32) prefix = 32;
    }
    strncpy(base, spec, sizeof(base) - 1);

    int a = 0, b = 0, c = 0, d = 0;
    if (sscanf(base, "%d.%d.%d.%d", &a, &b, &c, &d) != 4) return 0;

    unsigned int ip = (a << 24) | (b << 16) | (c << 8) | d;
    unsigned int mask = (prefix == 0) ? 0u : (0xFFFFFFFFu << (32 - prefix));
    unsigned int net = ip & mask;
    unsigned int bcast = net | ~mask;

    unsigned int start = net, end = bcast;
    if (prefix <= 30) { start = net + 1; end = bcast - 1; }
    if (start > end) { start = net; end = bcast; }

    snprintf(range_out, rlen, "%u.%u.%u.%u/%d",
             (net >> 24) & 0xFF, (net >> 16) & 0xFF, (net >> 8) & 0xFF, net & 0xFF, prefix);

    int count = 0;
    for (unsigned int x = start; x <= end && count < max_hosts; x++) {
        char ip[MAX_IP_LEN];
        snprintf(ip, sizeof(ip), "%u.%u.%u.%u",
                 (x >> 24) & 0xFF, (x >> 16) & 0xFF, (x >> 8) & 0xFF, x & 0xFF);
        /* Kendi makine, gateway, broadcast, multicast ve link-local
         * adresleri hedef listesine HIC girmez (kullanici istegi). */
        if (is_excluded_host(ip)) { if (end - x > 0xFFFFFFFFu) break; continue; }
        snprintf(hosts[count], MAX_IP_LEN, "%s", ip);
        count++;
        if (end - x > 0xFFFFFFFFu) break;
    }
    return count;
}

/* ========== Servis portları ========== */
static const int k_probe_ports[] = {
    554, 8554, 8555, 80, 8080, 81, 88, 8000, 8081, 37777, 34567, 8899, 9000,
    443, 8443, 1024, 5000
};
#define PROBE_PORT_COUNT ((int)(sizeof(k_probe_ports)/sizeof(k_probe_ports[0])))

/* Genisletilmis port turu: standart disi porta tasinmis RTSP/HTTP arayuzleri.
 * Yalnizca MAC'i cozulen (agda gercekten var olan) hostlarda kosar. */
static const int k_ext_ports[] = {
    82, 83, 84, 85, 86, 87, 89,
    555, 1054, 1554, 5544, 5554, 6554,
    7070, 8556, 1935,
    8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090,
    8181, 8282, 8888,
    9001, 9002, 9008,
    9999, 10000, 10001,
    34568, 34599, 37778,
    8200, 8300, 9527, 3388, 3000, 5001, 65001
};
#define EXT_PORT_COUNT ((int)(sizeof(k_ext_ports)/sizeof(k_ext_ports[0])))

static int is_rtsp_port(int p) { return p == 554 || p == 8554 || p == 8555 || p == 10554; }
static int is_http_port(int p) { return p == 80 || p == 8080 || p == 81 || p == 88 || p == 8081 || p == 8000 || p == 443 || p == 8443 || p == 5000 || p == 1024 || p == 9000; }
static int is_https_port(int p) { return p == 443 || p == 8443; }
static int is_vendor_port(int p) { return p == 37777 || p == 34567 || p == 8899 || p == 8000; }

/* ========== Sonuç dizisine ekleme (kilitli) ========== */
static void append_camera(const CameraDevice *cam) {
    platform_mutex_lock(&g_lock);
    if (g_results.count < CAM_MAX_DEVICES) {
        g_results.cameras[g_results.count++] = *cam;
    }
    platform_mutex_unlock(&g_lock);
}

/* ========== Tek host sondası ========== */
static void probe_host(const char *ip) {
    CameraDevice cam;
    memset(&cam, 0, sizeof(cam));
    strncpy(cam.ip, ip, MAX_IP_LEN - 1);

    if (is_excluded_host(ip)) return;   /* self/gateway/broadcast taranmaz */

    const char *mac = arp_lookup(ip);
    int oui_cam = 0;
    if (mac) {
        strncpy(cam.mac, mac, MAX_MAC_LEN - 1);
        oui_cam = camera_discovery_oui_is_camera(mac, cam.vendor, MAX_VENDOR_LEN);
    }

    int open_any = 0;
    int opened[PROBE_PORT_COUNT + EXT_PORT_COUNT];
    int opened_count = 0;

    for (int i = 0; i < PROBE_PORT_COUNT; i++) {
        if (g_cancel) return;
        int port = k_probe_ports[i];
        int fd = tcp_open(ip, port, 250);
        if (fd >= 0) {
            close(fd);
            open_any = 1;
            if (opened_count < PROBE_PORT_COUNT) opened[opened_count++] = port;
            if (cam.port_count < CAM_MAX_PORTS) cam.ports[cam.port_count++] = port;
        }
    }

    /* Genisletilmis port turu: yalnizca MAC'i cozulen (agda var olan) hostlarda.
     * Standart disi porta tasinmis RTSP/HTTP arayuzlerini yakalar. */
    int ext_n = 0;
    int ext_opened[EXT_PORT_COUNT];
    if (mac && !g_cancel) {
        ext_n = tcp_sweep_fanout(ip, k_ext_ports, EXT_PORT_COUNT,
                                 ext_opened, EXT_PORT_COUNT, 250);
        if (ext_n > 0) {
            open_any = 1;
            for (int i = 0; i < ext_n; i++) {
                if (opened_count < (int)(sizeof(opened) / sizeof(opened[0])))
                    opened[opened_count++] = ext_opened[i];
                if (cam.port_count < CAM_MAX_PORTS)
                    cam.ports[cam.port_count++] = ext_opened[i];
            }
        }
    }

    if (!open_any && !oui_cam) return; /* ilgisiz host */

    if (open_any) cam.evidence |= CAM_EV_PORT;

    /* Derin sondalar: RTSP ve HTTP portları üzerinde */
    for (int i = 0; i < opened_count; i++) {
        int port = opened[i];
        if (is_rtsp_port(port)) {
            CameraDevice tmp;
            memset(&tmp, 0, sizeof(tmp));
            if (rtsp_probe(ip, port, &tmp)) {
                cam.evidence |= CAM_EV_RTSP;
                if (cam.server_header[0] == '\0' && tmp.server_header[0])
                    strncpy(cam.server_header, tmp.server_header, CAM_SERVER_LEN - 1);
                if (cam.rtsp_port == 0) {
                    cam.rtsp_port = port;
                    cam.rtsp_auth_required = tmp.rtsp_auth_required;
                    if (tmp.rtsp_realm[0])
                        strncpy(cam.rtsp_realm, tmp.rtsp_realm, CAM_REALM_LEN - 1);
                } else if (cam.rtsp_auth_required && !tmp.rtsp_auth_required) {
                    /* Ayni hostta daha acik bir akis varsa onu tercih et */
                    cam.rtsp_port = port;
                    cam.rtsp_auth_required = 0;
                    cam.rtsp_realm[0] = '\0';
                }
                if (cam.rtsp_auth_required) cam.evidence |= CAM_EV_RTSP_AUTH;
                else cam.evidence &= ~CAM_EV_RTSP_AUTH;
                guess_manufacturer(cam.server_header, cam.manufacturer, CAM_MODEL_LEN);
                guess_manufacturer(cam.rtsp_realm, cam.manufacturer, CAM_MODEL_LEN);
            }
        }
    }
    for (int i = 0; i < opened_count; i++) {
        int port = opened[i];
        if (is_http_port(port)) {
            int r = http_probe(ip, port, &cam);
            if (r == 2) {
                cam.evidence |= CAM_EV_HTTP;
                if (cam.http_port == 0) cam.http_port = port;
            } else if (r == 1 && cam.http_port == 0) {
                cam.http_port = port;
            }
        }
    }
    for (int i = 0; i < opened_count; i++) {
        if (is_vendor_port(opened[i])) { cam.evidence |= CAM_EV_VPORT; break; }
    }

    /* Genisletilmis turda bulunan portlari siniflandir (RTSP -> HTTP sirasiyla) */
    for (int i = 0; i < ext_n; i++) {
        if (g_cancel) break;
        int port = ext_opened[i];
        if (is_rtsp_port(port) || is_http_port(port)) continue; /* standart turda islendi */
        CameraDevice tmp;
        memset(&tmp, 0, sizeof(tmp));
        if (rtsp_probe(ip, port, &tmp)) {
            cam.evidence |= CAM_EV_RTSP;
            if (cam.rtsp_port == 0) {
                cam.rtsp_port = port;
                cam.rtsp_auth_required = tmp.rtsp_auth_required;
                if (tmp.rtsp_realm[0])
                    strncpy(cam.rtsp_realm, tmp.rtsp_realm, CAM_REALM_LEN - 1);
            }
            if (cam.rtsp_auth_required) cam.evidence |= CAM_EV_RTSP_AUTH;
            if (cam.server_header[0] == '\0' && tmp.server_header[0])
                strncpy(cam.server_header, tmp.server_header, CAM_SERVER_LEN - 1);
            continue;
        }
        int r = http_probe(ip, port, &cam);
        if (r == 2) {
            cam.evidence |= CAM_EV_HTTP;
            if (cam.http_port == 0) cam.http_port = port;
        } else if (r == 1 && cam.http_port == 0) {
            cam.http_port = port;
        }
    }

    /* TLS sertifika sondasi (443/8443): sertifika O/CN/OU alanlarinda uretici izi */
    for (int i = 0; i < opened_count; i++) {
        int port = opened[i];
        if (!is_https_port(port)) continue;
        char subj[CAM_MODEL_LEN * 2] = {0};
        char istr[CAM_MODEL_LEN * 2] = {0};
        if (!tls_cert_probe(ip, port, subj, sizeof(subj), istr, sizeof(istr))) continue;
        if (subj[0]) camera_discovery_log("TLS sertifikasi %s:%d - konu: %s", ip, port, subj);
        if (cam.http_port == 0) cam.http_port = port;
        char man[CAM_MODEL_LEN] = {0};
        int thit = guess_manufacturer(subj, man, sizeof(man));
        if (!thit) thit = guess_manufacturer(istr, man, sizeof(man));
        if (thit) {
            cam.evidence |= CAM_EV_TLS;
            if (!cam.manufacturer[0] && man[0])
                strncpy(cam.manufacturer, man, CAM_MODEL_LEN - 1);
        }
    }

    if (oui_cam) cam.evidence |= CAM_EV_OUI;

    /* HTTP device-info parmak izi (uretici/model/firmware) */
    if (cam.http_port) {
        char ven[CAM_MODEL_LEN] = {0}, mdl[CAM_MODEL_LEN] = {0};
        char fw[128] = {0}, sn[128] = {0};
        int fm = camera_vuln_fingerprint_http(ip, cam.http_port,
                     is_https_port(cam.http_port),
                     ven, sizeof(ven), mdl, sizeof(mdl),
                     fw, sizeof(fw), sn, sizeof(sn));
        if (fm > 0) {
            cam.evidence |= CAM_EV_HTTP;
            if (ven[0]) strncpy(cam.manufacturer, ven, CAM_MODEL_LEN - 1);
            if (mdl[0]) strncpy(cam.model, mdl, CAM_MODEL_LEN - 1);
        }
    }

    /* ONVIF device-service zenginlestirme (GetDeviceInformation/GetStreamUri) */
    if (cam.http_port) {
        OnvifDeviceInfo odi;
        if (onvif_probe_device(ip, cam.http_port, is_https_port(cam.http_port),
                               NULL, NULL, &odi) == 0) {
            cam.has_onvif = 1;
            cam.evidence |= CAM_EV_ONVIF;
            if (odi.manufacturer[0]) strncpy(cam.manufacturer, odi.manufacturer, CAM_MODEL_LEN - 1);
            if (odi.model[0]) strncpy(cam.model, odi.model, CAM_MODEL_LEN - 1);
            if (odi.stream_uri[0]) strncpy(cam.rtsp_url, odi.stream_uri, CAM_URL_LEN - 1);
            if (odi.media_xaddr[0]) strncpy(cam.onvif_xaddr, odi.media_xaddr, CAM_URL_LEN - 1);
        }
    }

    /* URL tahminleri */
    if (cam.rtsp_port)
        snprintf(cam.rtsp_url, CAM_URL_LEN, "rtsp://%s:%d/", ip, cam.rtsp_port);
    else if (cam.http_port)
        snprintf(cam.http_url, CAM_URL_LEN, "http://%s:%d/", ip, cam.http_port);
    if (cam.http_port && !cam.http_url[0])
        snprintf(cam.http_url, CAM_URL_LEN, "http://%s:%d/", ip, cam.http_port);

    /* Skorlama */
    int score = 0;
    if (cam.evidence & CAM_EV_RTSP)   score += 40;
    else if (cam.rtsp_port)           score += 25;
    if (cam.evidence & CAM_EV_ONVIF)  score += 20;
    if (cam.evidence & CAM_EV_HTTP)   score += 20;
    if (cam.evidence & CAM_EV_OUI)    score += 15;
    if (cam.evidence & CAM_EV_VPORT)  score += 10;
    if (cam.evidence & CAM_EV_RTSP_AUTH) score += 5;
    if (cam.evidence & CAM_EV_TLS)    score += 8;
    if (score > 100) score = 100;
    cam.confidence = score;

    /* Kamera sayılmak için asgari kanıt: RTSP, ONVIF, HTTP imza, OUI veya üretici port */
    unsigned cam_evidence = CAM_EV_RTSP | CAM_EV_ONVIF | CAM_EV_HTTP | CAM_EV_OUI |
                            CAM_EV_VPORT | CAM_EV_TLS;
    if ((cam.evidence & cam_evidence) == 0) return; /* yalnız rastgele açık port: kamera değil */

    /* Kanıt metni */
    char ev[CAM_EVIDENCE_LEN] = {0};
    if (cam.evidence & CAM_EV_PORT)      strcat(ev, "acik-port,");
    if (cam.evidence & CAM_EV_RTSP)      strcat(ev, "rtsp-yanit,");
    if (cam.evidence & CAM_EV_RTSP_AUTH) strcat(ev, "kimlik-gerekli,");
    if (cam.evidence & CAM_EV_HTTP)      strcat(ev, "http-kamera-ui,");
    if (cam.evidence & CAM_EV_ONVIF)     strcat(ev, "onvif,");
    if (cam.evidence & CAM_EV_OUI)       strcat(ev, "oui-uretici,");
    if (cam.evidence & CAM_EV_VPORT)     strcat(ev, "uretici-port,");
    if (cam.evidence & CAM_EV_TLS)       strcat(ev, "tls-sertifika,");
    int el = (int)strlen(ev);
    if (el > 0 && ev[el-1] == ',') ev[el-1] = '\0';
    strncpy(cam.evidence_text, ev, CAM_EVIDENCE_LEN - 1);

    cam.discovered_at = time(NULL);

    platform_mutex_lock(&g_lock);
    g_results.responded_hosts++;
    platform_mutex_unlock(&g_lock);

    camera_discovery_log("Kamera adayi: %s (skor %d) [%s]", ip, cam.confidence, cam.evidence_text);

    /* Erişim motoruna HTTP bağlamını (bypass/ONVIF/snapshot için) bildir */
    {
        const char *vhint = cam.vendor[0] ? cam.vendor : cam.manufacturer;
        camera_access_set_context(ip, cam.http_port, vhint);
    }

    append_camera(&cam);
}

/* ========== Worker ========== */
typedef struct {
    char (*hosts)[MAX_IP_LEN];
    int host_count;
    int next;
    platform_mutex_t *mtx;
} ScanCtx;

static void *scan_worker(void *arg) {
    ScanCtx *ctx = (ScanCtx *)arg;
    for (;;) {
        platform_mutex_lock(ctx->mtx);
        int i = ctx->next++;
        platform_mutex_unlock(ctx->mtx);
        if (i >= ctx->host_count) break;
        if (g_cancel) break;
        probe_host(ctx->hosts[i]);

        platform_mutex_lock(&g_lock);
        g_results.scanned_hosts++;
        if (g_results.total_hosts > 0)
            g_results.progress = (g_results.scanned_hosts * 100) / g_results.total_hosts;
        platform_mutex_unlock(&g_lock);
    }
    return NULL;
}

/* ========== Ana tarama ========== */
static int do_scan(const char *cidr);

int camera_discovery_scan(const char *cidr) {
    return do_scan(cidr);
}

static int do_scan(const char *cidr) {
    static char hosts[CAM_MAX_HOSTS][MAX_IP_LEN];
    char range[64] = {0};

    platform_mutex_lock(&g_lock);
    if (g_results.is_scanning) { platform_mutex_unlock(&g_lock); return -1; }
    memset(g_results.cameras, 0, sizeof(g_results.cameras));
    g_results.count = 0;
    g_results.is_scanning = 1;
    g_results.scan_complete = 0;
    g_results.progress = 0;
    g_results.scanned_hosts = 0;
    g_results.responded_hosts = 0;
    strncpy(g_results.phase, "Hedef liste olusturuluyor", sizeof(g_results.phase) - 1);
    platform_mutex_unlock(&g_lock);

    g_cancel = 0;
    g_explicit_target = (cidr && cidr[0]) ? 1 : 0;
    gather_self_info();
    load_arp_table();
    camera_discovery_log("ARP tablosu: %d kayit", arp_map_count);

    int total = build_host_list(cidr, hosts, CAM_MAX_HOSTS, range, sizeof(range));
    if (total <= 0) {
        camera_discovery_log("Gecersiz hedef: '%s'", cidr ? cidr : "(yerel)");
        platform_mutex_lock(&g_lock);
        g_results.is_scanning = 0;
        g_results.scan_complete = 1;
        platform_mutex_unlock(&g_lock);
        return -1;
    }

    platform_mutex_lock(&g_lock);
    g_results.total_hosts = total;
    strncpy(g_results.target, range, sizeof(g_results.target) - 1);
    strncpy(g_results.phase, "Port + servis taramasi", sizeof(g_results.phase) - 1);
    platform_mutex_unlock(&g_lock);
    camera_discovery_log("Tarama hedefi: %s (%d host)", range, total);

    /* Aktif ARP/MAC supurme: OUI bilgisini port taramasindan once topla */
    platform_mutex_lock(&g_lock);
    strncpy(g_results.phase, "ARP/MAC supurme", sizeof(g_results.phase) - 1);
    platform_mutex_unlock(&g_lock);
    arp_sweep(hosts, total);
    load_arp_table();

    /* SSDP (UPnP) + mDNS: port taramasinin kacirabilecegi hostlari ekle */
    if (!g_cancel) {
        platform_mutex_lock(&g_lock);
        strncpy(g_results.phase, "SSDP/mDNS kesif", sizeof(g_results.phase) - 1);
        platform_mutex_unlock(&g_lock);
        int extra = ssdp_mdns_discover(hosts, &total, CAM_MAX_HOSTS);
        if (extra > 0) {
            camera_discovery_log("SSDP/mDNS: %d ek host bulundu (toplam %d)", extra, total);
            platform_mutex_lock(&g_lock);
            g_results.total_hosts = total;
            platform_mutex_unlock(&g_lock);
        }
    }

    /* Paralel port taraması */
    ScanCtx ctx;
    ctx.hosts = hosts;
    ctx.host_count = total;
    ctx.next = 0;
    platform_mutex_t idx_mtx;
    platform_mutex_init(&idx_mtx);
    ctx.mtx = &idx_mtx;

    int workers = CAM_MAX_WORKERS;
    if (workers > total) workers = total;
    if (workers < 1) workers = 1;
    platform_thread_t th[CAM_MAX_WORKERS];
    int created = 0;
    for (int i = 0; i < workers; i++) {
        if (platform_thread_create(&th[i], scan_worker, &ctx) == 0) created++;
    }
    for (int i = 0; i < created; i++) pthread_join(th[i], NULL);
    platform_mutex_destroy(&idx_mtx);

    /* ONVIF WS-Discovery birleştirme */
    if (!g_cancel) {
        platform_mutex_lock(&g_lock);
        strncpy(g_results.phase, "ONVIF WS-Discovery", sizeof(g_results.phase) - 1);
        platform_mutex_unlock(&g_lock);
        OnvifHit hits[64];
        int nh = ws_discovery_gather(hits, 64, 2500);
        camera_discovery_log("ONVIF WS-Discovery: %d yanit", nh);
        for (int i = 0; i < nh; i++) {
            platform_mutex_lock(&g_lock);
            int at = -1;
            for (int j = 0; j < g_results.count; j++)
                if (strcmp(g_results.cameras[j].ip, hits[i].ip) == 0) { at = j; break; }
            platform_mutex_unlock(&g_lock);

            if (at >= 0) {
                platform_mutex_lock(&g_lock);
                CameraDevice *c = &g_results.cameras[at];
                c->evidence |= CAM_EV_ONVIF;
                c->has_onvif = 1;
                if (hits[i].manufacturer[0]) strncpy(c->manufacturer, hits[i].manufacturer, CAM_MODEL_LEN - 1);
                if (hits[i].model[0]) strncpy(c->model, hits[i].model, CAM_MODEL_LEN - 1);
                if (hits[i].xaddr[0]) strncpy(c->onvif_xaddr, hits[i].xaddr, CAM_URL_LEN - 1);
                if (c->confidence < 100) c->confidence += 20;
                if (c->confidence > 100) c->confidence = 100;
                platform_mutex_unlock(&g_lock);
            } else {
                CameraDevice c;
                memset(&c, 0, sizeof(c));
                strncpy(c.ip, hits[i].ip, MAX_IP_LEN - 1);
                const char *m = arp_lookup(hits[i].ip);
                if (m) { strncpy(c.mac, m, MAX_MAC_LEN - 1); camera_discovery_oui_is_camera(m, c.vendor, MAX_VENDOR_LEN); }
                strncpy(c.manufacturer, hits[i].manufacturer, CAM_MODEL_LEN - 1);
                strncpy(c.model, hits[i].model, CAM_MODEL_LEN - 1);
                strncpy(c.onvif_xaddr, hits[i].xaddr, CAM_URL_LEN - 1);
                c.evidence = CAM_EV_ONVIF;
                c.has_onvif = 1;
                c.confidence = 50;
                strncpy(c.evidence_text, "onvif", CAM_EVIDENCE_LEN - 1);
                c.discovered_at = time(NULL);
                camera_discovery_log("ONVIF cihazi: %s (%s %s)", c.ip, c.manufacturer, c.model);
                camera_access_set_context(c.ip, 0, c.manufacturer[0] ? c.manufacturer : c.vendor);
                append_camera(&c);
            }
        }
    }

    platform_mutex_lock(&g_lock);
    int count = g_results.count;
    g_results.is_scanning = 0;
    g_results.scan_complete = 1;
    g_results.progress = 100;
    g_results.last_scan_time = time(NULL);
    strncpy(g_results.phase, "Tamamlandi", sizeof(g_results.phase) - 1);
    platform_mutex_unlock(&g_lock);

    camera_discovery_log("Tarama bitti: %d kamera, %d yanitli host", count, g_results.responded_hosts);
    return count;
}

/* ========== Asenkron sarma ========== */
static char g_async_target[64];
static void *async_thread(void *arg) {
    (void)arg;
    do_scan(g_async_target[0] ? g_async_target : NULL);
    g_thread_running = 0;
    return NULL;
}

void camera_discovery_start_async(const char *cidr) {
    if (g_thread_running || g_results.is_scanning) { camera_discovery_log("Tarama zaten calisiyor"); return; }
    if (cidr && cidr[0]) strncpy(g_async_target, cidr, sizeof(g_async_target) - 1);
    else g_async_target[0] = '\0';
    g_thread_running = 1;
    if (platform_thread_create(&g_scan_thread, async_thread, NULL) == 0) {
        platform_thread_detach(g_scan_thread);
    } else {
        g_thread_running = 0;
        camera_discovery_log("Tarama thread'i baslatilamadi");
    }
}

void camera_discovery_cancel(void) {
    g_cancel = 1;
    camera_discovery_log("Tarama iptal istendi");
}

int camera_discovery_is_scanning(void) {
    return g_results.is_scanning;
}

/* ========== Sonuç alma ========== */
void camera_discovery_get_results(CameraScanResults *out) {
    if (!out) return;
    platform_mutex_lock(&g_lock);
    memcpy(out, &g_results, sizeof(CameraScanResults));
    platform_mutex_unlock(&g_lock);
}

int camera_discovery_get_cameras(CameraDevice *out, int max_count) {
    if (!out || max_count <= 0) return 0;
    platform_mutex_lock(&g_lock);
    int n = g_results.count;
    if (n > max_count) n = max_count;
    memcpy(out, g_results.cameras, sizeof(CameraDevice) * n);
    platform_mutex_unlock(&g_lock);
    return n;
}

/* ========== Yardımcılar ========== */
const char *camera_discovery_rtsp_url(const CameraDevice *cam, char *buf, int len) {
    if (cam->rtsp_url[0]) { strncpy(buf, cam->rtsp_url, len - 1); buf[len-1] = '\0'; return buf; }
    int port = cam->rtsp_port ? cam->rtsp_port : 554;
    snprintf(buf, len, "rtsp://%s:%d/", cam->ip, port);
    return buf;
}

static const char *k_common_rtsp_paths[] = {
    "/", "/stream", "/stream1", "/live", "/live/ch0", "/video", "/video1",
    "/11", "/12", "/1", "/2", "/h264", "/h265",
    "/Streaming/Channels/101", "/Streaming/Channels/102",
    "/cam/realmonitor?channel=1&subtype=0",
    "/user=admin_password=_channel=1_stream=0.sdp",
    "/onvif1", "/onvif2", "/media/video1", "/axis-media/media.amp",
    "/live.sdp", "/mpeg4", "/mjpeg", "/av0_0",
    NULL
};

const char *const *camera_discovery_common_rtsp_paths(int *count_out) {
    int n = 0;
    while (k_common_rtsp_paths[n]) n++;
    if (count_out) *count_out = n;
    return k_common_rtsp_paths;
}

/* ========== Yaşam döngüsü ========== */
void camera_discovery_init(void) {
    if (g_initialized) return;
    memset(&g_results, 0, sizeof(g_results));
    memset(g_log, 0, sizeof(g_log));
    platform_mutex_init(&g_lock);
    platform_mutex_init(&g_log_lock);
    g_initialized = 1;
    camera_discovery_log("Kamera kesif motoru hazir");
}

void camera_discovery_cleanup(void) {
    g_cancel = 1;
    platform_sleep_ms(200);
    platform_mutex_destroy(&g_lock);
    platform_mutex_destroy(&g_log_lock);
    g_initialized = 0;
}
