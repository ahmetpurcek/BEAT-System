/* test_camscan_live.c — gecici canli dogrulama kosucusu
 * (gorev tarafindan uretildi; is sonunda silinir)
 *
 * Kesif -> otomatik erisim (RTSP + HTTP kimlik) zincirini GUI olmadan
 * uctan uca surer ve sonuclari basar. */
#include "camera_discovery.h"
#include "camera_access.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv) {
    const char *cidr = (argc > 1) ? argv[1] : NULL;

    camera_discovery_init();
    camera_access_init();

    printf("=== Otonom kamera testi baslatiliyor (hedef: %s) ===\n",
           cidr ? cidr : "(yerel ag)");
    fflush(stdout);

    int n = camera_discovery_scan(cidr);
    printf("\nKESIF: %d kamera bulundu\n", n);

    CameraScanResults res;
    camera_discovery_get_results(&res);
    for (int i = 0; i < res.count; i++) {
        CameraDevice *c = &res.cameras[i];
        printf("  - %s skor=%d tur=%s vendor=%s rtsp_port=%d http_port=%d onvif=%d [%s]\n",
               c->ip, c->confidence, c->kind_text,
               c->vendor[0] ? c->vendor : c->manufacturer,
               c->rtsp_port, c->http_port, c->has_onvif, c->evidence_text);
    }

    /* Siniflandirma sonucu ayiklanan (kamera OLMAYAN) cihazlar */
    {
        char lines[200][256];
        int nl = camera_discovery_get_log(lines, 200);
        int shown = 0;
        for (int i = 0; i < nl; i++) {
            if (strstr(lines[i], "Kamera DEGIL")) {
                if (!shown) printf("\nKamera OLMAYAN cihazlar (ag cihazi olarak ayiklandi):\n");
                printf("  %s\n", lines[i]);
                shown++;
            }
        }
    }

    printf("\nOtonom erisim (RTSP + HTTP kimlik saldirisi) bekleniyor...\n");
    fflush(stdout);

    /* Erisim iscileri bitene kadar bekle (ust sinir 300 sn). */
    int busy_total = 0;
    for (int t = 0; t < 300; t += 2) {
        int busy = 0;
        for (int i = 0; i < res.count; i++)
            if (camera_access_busy(res.cameras[i].ip)) busy++;
        if (busy == 0) break;
        busy_total = busy;
        if ((t % 10) == 0) {
            printf("  ... %d erisim isi hala calisiyor (%d sn)\n", busy, t);
            fflush(stdout);
        }
        sleep(2);
    }
    (void)busy_total;

    printf("\n=== ERISIM SONUCLARI ===\n");
    int found = 0;
    for (int i = 0; i < res.count; i++) {
        CameraAccessJob j;
        if (!camera_access_get(res.cameras[i].ip, &j)) continue;
        const char *st =
            j.state == CA_FOUND ? "FOUND" :
            j.state == CA_FAILED ? "FAILED" :
            j.state == CA_RUNNING ? "RUNNING" :
            j.state == CA_QUEUED ? "QUEUED" : "?";
        printf("  %s -> [%s] user='%s' pass='%s'\n",
               res.cameras[i].ip, st, j.found_user, j.found_pass);
        printf("        url=%s\n", j.found_url);
        printf("        err=%s snap=%s\n", j.last_error, j.snapshot_path);
        if (j.state == CA_FOUND) found++;
    }
    printf("\nTOPLAM ERISIM: %d / %d\n", found, res.count);

    camera_access_shutdown();
    camera_discovery_cleanup();
    return 0;
}
