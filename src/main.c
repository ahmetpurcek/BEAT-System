/*
 * main.c — Ana Giriş Noktası
 * BEAT System — C Native Desktop Uygulaması
 *
 * İki çalışma modu:
 *   1) GUI modu (varsayılan): raylib penceresi ile normal masaüstü deneyimi.
 *   2) HEADLESS modu (--headless): GUI/raylib olmadan paket yakalar, IDS
 *      motoruna besler ve üretilen uyarıları stdout'a + opsiyonel JSONL
 *      dosyasına yazar. Gerçek trafikle FP ölçümü ve SIEM entegrasyonu için.
 */
#include "platform.h"
#include "utils.h"
#include "arp_scanner.h"
#include "network_monitor.h"
#include "network_ids.h"
#include "arp_block.h"
#include "port_scanner.h"
#include "gui.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>

/* ==================== HEADLESS MODU ==================== */

static volatile sig_atomic_t g_headless_stop = 0;

static void headless_on_sigint(int sig) {
    (void)sig;
    g_headless_stop = 1;
}

static void usage(const char *argv0) {
    printf(
        "Kullanim:\n"
        "  %s                            (GUI modu)\n"
        "  %s --headless [SECENEKLER]    (GUI'siz IDS modu)\n"
        "\n"
        "Headless secenekleri:\n"
        "  --iface <ad>          Yakalama arayuzu (varsayilan: otomatik)\n"
        "  --scope <ip,ip,...>   Izleme listesi (virgulle ayrilmis IP'ler)\n"
        "  --scope-cidr <CIDR>   Izleme listesini CIDR'den uret (orn. 192.168.0.0/24)\n"
        "  --local-ip <ip>       Bu makinenin IP'si (self-traffic filtresi)\n"
        "  --local-mac <mac>     Bu makinenin MAC'i (ARP spoof tespiti)\n"
        "  --gateway-ip <ip>     Ag gecidi IP (varsayilan: otomatik)\n"
        "  --gateway-mac <mac>   Ag gecidi MAC (varsayilan: otomatik)\n"
        "  --duration <sn>       Calisma suresi (0 = sonsuz, Ctrl+C ile dur)\n"
        "  --out <dosya>         Uyarilari JSONL olarak bu dosyaya da yaz\n"
        "  --quiet               Uyari basliklarini stdout'a yazma (sadece sayac)\n"
        "\n",
        argv0, argv0);
}

/* CIDR'i IDS_SCOPE_MAX sinirina kadar genisletip diziye doldurur. */
static int expand_cidr(const char *cidr, const char **out, int max_out) {
    unsigned a = 0, b = 0, c = 0, d = 0, bits = 32;
    if (sscanf(cidr, "%u.%u.%u.%u/%u", &a, &b, &c, &d, &bits) != 5) return 0;
    if (a > 255 || b > 255 || c > 255 || d > 255 || bits > 32) return 0;
    uint32_t base = (a << 24) | (b << 16) | (c << 8) | d;
    uint32_t mask = (bits == 0) ? 0u : (0xFFFFFFFFu << (32 - bits));
    uint32_t net  = base & mask;
    uint32_t bcast = net | ~mask;
    int n = 0;
    for (uint32_t ip = net + 1; ip < bcast && n < max_out; ip++) {
        static char buf[IDS_SCOPE_MAX][16];
        snprintf(buf[n], 16, "%u.%u.%u.%u",
                 (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
                 (ip >> 8) & 0xFF, ip & 0xFF);
        out[n] = buf[n];
        n++;
    }
    return n;
}

/* /proc/net/route'tan varsayilan ag gecidi IP'sini okur (0 = bulunamadi). */
static uint32_t read_default_gateway(void) {
    FILE *fp = fopen("/proc/net/route", "r");
    if (!fp) return 0;
    char line[256];
    fgets(line, sizeof(line), fp);
    uint32_t gw = 0;
    while (fgets(line, sizeof(line), fp)) {
        char iface[64];
        unsigned dest, gateway, flags;
        if (sscanf(line, "%63s %x %x %x", iface, &dest, &gateway, &flags) == 4) {
            if (dest == 0 && (flags & 0x2)) { gw = gateway; break; }
        }
    }
    fclose(fp);
    /* /proc/net/route little-endian hex verir: ters cevirmek gerekir. */
    uint32_t le = gw;
    return ((le & 0xFF) << 24) | ((le & 0xFF00) << 8) |
           ((le >> 8) & 0xFF00) | ((le >> 24) & 0xFF);
}

static void json_escape(const char *in, char *out, int outlen) {
    int j = 0;
    for (int i = 0; in && in[i] && j < outlen - 2; i++) {
        char ch = in[i];
        if (ch == '"' || ch == '\\') { out[j++] = '\\'; out[j++] = ch; }
        else if (ch == '\n' || ch == '\r') { out[j++] = ' '; }
        else out[j++] = ch;
    }
    out[j] = '\0';
}

static int headless_run(int argc, char *argv[]) {
    const char *iface = NULL;
    const char *scope_arg = NULL;
    const char *cidr_arg = NULL;
    const char *local_ip = NULL;
    const char *local_mac = NULL;
    const char *gateway_ip = NULL;
    const char *gateway_mac = NULL;
    const char *out_path = NULL;
    int duration = 0;
    int quiet = 0;

    for (int i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "--headless")) continue;
        else if (!strcmp(argv[i], "--iface") && i + 1 < argc) iface = argv[++i];
        else if (!strcmp(argv[i], "--scope") && i + 1 < argc) scope_arg = argv[++i];
        else if (!strcmp(argv[i], "--scope-cidr") && i + 1 < argc) cidr_arg = argv[++i];
        else if (!strcmp(argv[i], "--local-ip") && i + 1 < argc) local_ip = argv[++i];
        else if (!strcmp(argv[i], "--local-mac") && i + 1 < argc) local_mac = argv[++i];
        else if (!strcmp(argv[i], "--gateway-ip") && i + 1 < argc) gateway_ip = argv[++i];
        else if (!strcmp(argv[i], "--gateway-mac") && i + 1 < argc) gateway_mac = argv[++i];
        else if (!strcmp(argv[i], "--duration") && i + 1 < argc) duration = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--out") && i + 1 < argc) out_path = argv[++i];
        else if (!strcmp(argv[i], "--quiet")) quiet = 1;
        else if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
            usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Bilinmeyen secenek: %s\n", argv[i]);
            usage(argv[0]);
            return 2;
        }
    }

    if (geteuid() != 0) {
        fprintf(stderr,
                "UYARI: Root degilsiniz; pcap yakalama basarisiz olursa "
                "procfs fallback (yalniz yerel soketler) kullanilir.\n");
    }

    if (platform_init() != 0) {
        fprintf(stderr, "Platform baslatilamadi!\n");
        return 1;
    }

    /* Moduller */
    full_monitor_init();
    ids_init();

    /* Izleme kapsami: --scope (liste) oncelikli, yoksa --scope-cidr. */
    static const char *ips[IDS_SCOPE_MAX];
    int nscope = 0;
    if (scope_arg && scope_arg[0]) {
        static char store[IDS_SCOPE_MAX][16];
        char *copy = strdup(scope_arg);
        char *tok = strtok(copy, ",");
        while (tok && nscope < IDS_SCOPE_MAX) {
            while (*tok == ' ') tok++;
            snprintf(store[nscope], 16, "%s", tok);
            ips[nscope] = store[nscope];
            nscope++;
            tok = strtok(NULL, ",");
        }
        free(copy);
    } else if (cidr_arg && cidr_arg[0]) {
        nscope = expand_cidr(cidr_arg, ips, IDS_SCOPE_MAX);
        ids_set_network_range(cidr_arg);
    }
    ids_scope_set(ips, nscope);
    printf("[HEADLESS] Izleme kapsami: %d IP\n", nscope);

    /* MAC/IP baglami (self-traffic filtresi + ARP spoof tespiti) */
    char own_mac[MAX_MAC_LEN] = {0};
    if (!local_mac && full_monitor_own_mac(own_mac, sizeof(own_mac)) == 0 &&
        own_mac[0])
        local_mac = own_mac;
    if (!gateway_ip) {
        uint32_t gw = read_default_gateway();
        if (gw) {
            static char gwbuf[16];
            snprintf(gwbuf, sizeof(gwbuf), "%u.%u.%u.%u",
                     (gw >> 24) & 0xFF, (gw >> 16) & 0xFF,
                     (gw >> 8) & 0xFF, gw & 0xFF);
            gateway_ip = gwbuf;
        }
    }
    ids_set_mac_context(local_mac, gateway_mac, gateway_ip, local_ip);
    printf("[HEADLESS] local_ip=%s local_mac=%s gw_ip=%s gw_mac=%s\n",
           local_ip ? local_ip : "-", local_mac ? local_mac : "-",
           gateway_ip ? gateway_ip : "-", gateway_mac ? gateway_mac : "-");

    signal(SIGINT, headless_on_sigint);
    signal(SIGTERM, headless_on_sigint);

    full_monitor_start(iface);
    platform_sleep_ms(500);

    /* MAC baglamini yakalama basladiktan SONRA tekrar ayarla: kendi NIC
     * MAC'imiz ancak capture baslayinca ogrenilir. local_mac bos kalirsa
     * self-origin filtresi ve ARP spoof tespiti yanlis calisir (kendi
     * ARP'imiz KRITIK 'ARP IP Cakismasi' FP'si uretir - dogrulandi). */
    if (!local_mac || !local_mac[0]) {
        char late_mac[MAX_MAC_LEN] = {0};
        if (full_monitor_own_mac(late_mac, sizeof(late_mac)) == 0 &&
            late_mac[0]) {
            local_mac = late_mac;
            ids_set_mac_context(local_mac, gateway_mac, gateway_ip, local_ip);
            printf("[HEADLESS] Gec ogrenilen local_mac=%s\n", local_mac);
        }
    }

    int mode = full_monitor_get_mode();
    printf("[HEADLESS] Yakalama modu: %s\n",
           mode == 2 ? "pcap (canli)" : (mode == 1 ? "procfs fallback" : "kapali"));
    fflush(stdout);

    FILE *outf = NULL;
    if (out_path) {
        outf = fopen(out_path, "w");
        if (!outf) fprintf(stderr, "[HEADLESS] --out dosyasi acilamadi: %s\n", out_path);
    }

    /* Daha once gorulen uyarilari izlemek icin: alert sayaci + imza */
    static char seen[IDS_MAX_GUI_ALERTS][160];
    int seen_n = 0;

    time_t start = time(NULL);
    printf("[HEADLESS] Calisiyor... (Ctrl+C ile dur)\n");
    fflush(stdout);

    while (!g_headless_stop) {
        platform_sleep_ms(500);
        IdsGuiAlert snap[IDS_MAX_GUI_ALERTS];
        int n = ids_get_alerts_snapshot(snap, IDS_MAX_GUI_ALERTS);
        for (int i = 0; i < n && seen_n < IDS_MAX_GUI_ALERTS; i++) {
            char id[160];
            snprintf(id, sizeof(id), "%s|%s|%s|%s",
                     snap[i].timestamp, snap[i].sig_name,
                     snap[i].src_ip, snap[i].dst_ip);
            int dup = 0;
            for (int k = 0; k < seen_n; k++)
                if (!strcmp(seen[k], id)) { dup = 1; break; }
            if (dup) continue;
            snprintf(seen[seen_n], sizeof(seen[seen_n]), "%s", id);
            seen_n++;

            if (!quiet) {
                printf("[ALERT] %s | %s | %s -> %s:%u | skor=%.2f knf=%u | %s\n",
                       snap[i].timestamp, snap[i].sig_name, snap[i].src_ip,
                       snap[i].dst_ip, snap[i].dst_port, snap[i].score,
                       snap[i].confidence, snap[i].description);
                fflush(stdout);
            }
            if (outf) {
                char en[256], ed[256];
                json_escape(snap[i].sig_name, en, sizeof(en));
                json_escape(snap[i].description, ed, sizeof(ed));
                fprintf(outf,
                        "{\"ts\":\"%s\",\"sig\":\"%s\",\"src\":\"%s\","
                        "\"dst\":\"%s\",\"dport\":%u,\"score\":%.2f,"
                        "\"sev\":\"%s\",\"conf\":%u,\"ev\":%u,\"desc\":\"%s\"}\n",
                        snap[i].timestamp, en, snap[i].src_ip, snap[i].dst_ip,
                        snap[i].dst_port, snap[i].score, snap[i].severity,
                        snap[i].confidence, snap[i].evidence_bits, ed);
                fflush(outf);
            }
        }
        if (duration > 0 && (time(NULL) - start) >= duration) break;
    }

    printf("\n[HEADLESS] === OZET ===\n");
    printf("[HEADLESS] islenen paket : %llu\n",
           (unsigned long long)g_ids.total_pkts_processed);
    printf("[HEADLESS] toplam uyari : %llu\n",
           (unsigned long long)g_ids.total_alerts);
    printf("[HEADLESS] bastirilan FP: %llu\n",
           (unsigned long long)g_ids.suppressed_fps);
    printf("[HEADLESS] aktif tracker: %d\n", g_ids.active_trackers);
    printf("[HEADLESS] gorulen benzersiz uyari: %d\n", seen_n);
    fflush(stdout);

    if (outf) fclose(outf);
    full_monitor_stop();
    full_monitor_cleanup();
    ids_cleanup();
    platform_cleanup();
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc > 1 && !strcmp(argv[1], "--headless"))
        return headless_run(argc, argv);

    printf("=== BEAT System ===\n");
    printf("Platform: %s\n", PLATFORM_NAME);

    /* Paket yakalama (pcap), ARP spoof ve NDP zehirleme root gerektirir */
    if (geteuid() != 0) {
        fprintf(stderr,
                "UYARI: Root olarak calismiyorsunuz!\n"
                "Paket yakalama, ARP spoof ve NDP islemleri root yetkisi "
                "ister.\n"
                "Tum ozellikler icin: sudo ./build/beat_system\n");
    }

    /* Platform başlat */
    if (platform_init() != 0) {
        fprintf(stderr, "Platform baslatilamadi!\n");
        return 1;
    }

    /* Modüller başlat */
    scanner_init();
    full_monitor_init();
    ids_init();
    arp_block_init();
    portscan_init();

    /* Otonom ağ taramasını başlat */
    scanner_start_auto_scan(15);

    /* GUI başlat */
    gui_init(1280, 720);

    /* Ana döngü */
    while (!gui_should_close()) {
        gui_draw();
    }

    /* Temizlik */
    gui_cleanup();
    arp_spoof_stop();
    arp_block_cleanup();
    portscan_cleanup();
    full_monitor_cleanup();
    ids_cleanup();
    scanner_cleanup();
    platform_cleanup();

    printf("BEAT System kapatildi.\n");
    return 0;
}
