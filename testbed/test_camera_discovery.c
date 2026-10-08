/*
 * test_camera_discovery.c — Kamera keşif motoru bağımsız doğrulama koşucusu.
 *
 * Derleme:
 *   gcc -I include testbed/test_camera_discovery.c \
 *       src/camera_discovery.c src/platform.c src/utils.c \
 *       -o /tmp/test_camera_discovery -lpthread
 *
 * Kullanım:
 *   /tmp/test_camera_discovery 127.0.0.1
 *   /tmp/test_camera_discovery 192.168.0.0/24
 */
#include "camera_discovery.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    const char *target = (argc > 1) ? argv[1] : "127.0.0.1";

    camera_discovery_init();
    printf("=== Kamera kesif testi: hedef=%s ===\n", target);

    int n = camera_discovery_scan(target);
    printf("Bulunan kamera sayisi: %d\n\n", n);

    CameraScanResults res;
    camera_discovery_get_results(&res);
    printf("Hedef: %s | host: %d | yanitli: %d | cihaz: %d\n\n",
           res.target, res.total_hosts, res.responded_hosts, res.count);

    for (int i = 0; i < res.count; i++) {
        CameraDevice *c = &res.cameras[i];
        printf("[%d] %s  mac=%s\n", i + 1, c->ip, c->mac[0] ? c->mac : "-");
        printf("    marka=%s  vendor=%s  model=%s  guven=%d\n",
               c->manufacturer[0] ? c->manufacturer : "-",
               c->vendor[0] ? c->vendor : "-",
               c->model[0] ? c->model : "-",
               c->confidence);
        printf("    rtsp=%s (auth=%d realm=%s)\n",
               c->rtsp_url[0] ? c->rtsp_url : "-",
               c->rtsp_auth_required,
               c->rtsp_realm[0] ? c->rtsp_realm : "-");
        printf("    http=%s  server=%s  onvif=%d\n",
               c->http_url[0] ? c->http_url : "-",
               c->server_header[0] ? c->server_header : "-",
               c->has_onvif);
        printf("    portlar:");
        for (int j = 0; j < c->port_count; j++) printf(" %d", c->ports[j]);
        printf("\n    kanit: %s\n\n", c->evidence_text);
    }

    char logbuf[64][256];
    int ln = camera_discovery_get_log(logbuf, 64);
    printf("=== Motor logu (%d satir) ===\n", ln);
    for (int i = 0; i < ln; i++) printf("  %s\n", logbuf[i]);

    camera_discovery_cleanup();
    return 0;
}
