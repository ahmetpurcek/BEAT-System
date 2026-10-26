/*
 * sentinel_fw.c — Faz 3: Firmware istihbarati
 *
 *   indirme (libcurl) -> konteyner tanima -> katmanli unpack ->
 *   secret mining (kimlik/anahtar/cloud) -> ELF yuzey analizi ->
 *   pre-auth kod yolu adaylari
 *
 * Unpack gercek araclarla yapilir (binwalk 3, unsquashfs, debugfs, tar,
 * gunzip, cpio). Arac yoksa katman "atlandi" olarak RAPORLANIR; sessizce
 * basari varsayilmaz. Sifreli imaj tespit edilirse analiz durdurulmaz;
 * bulgu olarak isaretlenir ve alt katmanlar denenmez.
 */
#include "sentinel.h"
#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <math.h>
#include <regex.h>
#include <crypt.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>

#define FW_MAX_FILES      20000
#define FW_MAX_DEPTH      14
#define FW_MAX_TEXT       (6u * 1024u * 1024u)   /* tek dosyada taranan bayt */
#define FW_MAX_STRINGS    4000

typedef struct {
    SnFwResult *res;
    int   add_findings;
    char  evidence[SN_PATH_LEN];
    int   ev_open;
    int   files;
    int   binaries;
    int   secrets;
    int   unsafe_calls;
    int   preauth;
    int   findings;          /* toplam eklenen bulgu (tum siniflar) */
    int   unique_cred;
    char  seen_cred[64][96];
    int   seen_cred_n;
} FwCtx;

/* ==================== Surec yardimcilari ==================== */

/* Komutu sh -c '...' icine koyarken icerideki tek tirnaklari kacir.
 * Kacirmadan yazmak iki sorun uretiyordu: (1) debugfs rdump gibi tirnak
 * iceren komutlar bozuk calisiyordu, (2) firmware icinden gelen dosya
 * adlari kabuk yorumlamasina giriyordu (enjeksiyon yuzeyi). */
static void sh_quote_escape(const char *in, char *out, size_t outlen) {
    size_t w = 0;
    for (const char *p = in; *p && w + 5 < outlen; p++) {
        if (*p == '\'') {
            out[w++] = '\'';
            out[w++] = '\\';
            out[w++] = '\'';
            out[w++] = '\'';
        } else {
            out[w++] = *p;
        }
    }
    out[w] = '\0';
}

static int run_cmd(const char *cmd, char *out, int outlen, int timeout_s) {
    char esc[4096];
    char full[4300];
    sh_quote_escape(cmd, esc, sizeof(esc));
    snprintf(full, sizeof(full), "timeout %d sh -c '%s' 2>&1", timeout_s, esc);
    FILE *p = popen(full, "r");
    if (!p) return -1;
    int n = 0;
    if (out && outlen > 0) {
        size_t r = fread(out, 1, (size_t)(outlen - 1), p);
        n = (int)r;
        out[n] = '\0';
    } else {
        char tmp[256];
        while (fgets(tmp, sizeof(tmp), p)) n += (int)strlen(tmp);
    }
    int rc = pclose(p);
    if (rc == -1) return -1;
    if (WIFEXITED(rc)) return WEXITSTATUS(rc);
    return -1;
}

/* Basliklar icin yolu kisalt: ayni onek paylasan yuzlerce binary ayni
 * basligi uretince dedupe bunlari tek bulguya indiriyordu. Yolun
 * sonunu koruyarak ayirt edici hale getir. */
static void short_rel(const char *rel, char *out, size_t outlen) {
    size_t n = strlen(rel);
    if (n + 1 <= outlen) {
        snprintf(out, outlen, "%s", rel);
        return;
    }
    size_t keep = outlen - 5;
    snprintf(out, outlen, "...%s", rel + (n - keep));
}

static int have_tool(const char *name) {
    char cmd[128], out[64];
    snprintf(cmd, sizeof(cmd), "command -v %s", name);
    if (run_cmd(cmd, out, sizeof(out), 5) == 0 && out[0]) return 1;
    return 0;
}

static void mkdir_p(const char *path) {
    char tmp[SN_PATH_LEN];
    snprintf(tmp, sizeof(tmp), "%s", path);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') { *p = '\0'; mkdir(tmp, 0755); *p = '/'; }
    }
    mkdir(tmp, 0755);
}

static int is_text_ext(const char *name) {
    static const char *exts[] = {
        ".conf", ".cfg", ".ini", ".sh", ".js", ".html", ".htm", ".asp", ".xml",
        ".json", ".txt", ".lua", ".py", ".php", ".cgi", ".properties", ".env",
        ".pem", ".key", ".crt", ".cnf", ".yaml", ".yml", ".sql", ".pl", NULL };
    const char *dot = strrchr(name, '.');
    if (!dot) return 1;          /* uzantisiz: metin olabilir */
    for (int i = 0; exts[i]; i++)
        if (!strcasecmp(dot, exts[i])) return 1;
    return 0;
}

/* ==================== Konteyner tanima ==================== */

typedef enum {
    FW_T_UNKNOWN = 0, FW_T_ELF, FW_T_TAR, FW_T_GZIP, FW_T_XZ, FW_T_ZIP,
    FW_T_SQUASHFS, FW_T_CRAMFS, FW_T_JFFS2, FW_T_UBI, FW_T_EXT, FW_T_CPIO,
    FW_T_SCRIPT_TAIL, FW_T_SCRIPT, FW_T_HIKVISION_ENC, FW_T_DAV
} FwType;

static FwType fw_type_of(const char *path, char *detail, int dlen) {
    FILE *f = fopen(path, "rb");
    if (!f) return FW_T_UNKNOWN;
    /* 2048 bayt: ext2/3/4 superblock sihri 1024+56 = 1080 ofsetinde;
     * 600 baytlik tampon bu kontrolu hicbir zaman dogru calistiramiyordu. */
    unsigned char b[2048];
    size_t n = fread(b, 1, sizeof(b), f);
    fclose(f);
    if (detail && dlen) detail[0] = '\0';
    if (n < 4) return FW_T_UNKNOWN;

    if (n >= 4 && b[0] == 0x7f && b[1] == 'E' && b[2] == 'L' && b[3] == 'F') return FW_T_ELF;
    if (n >= 4 && b[0] == 'P' && b[1] == 'K' && b[2] == 3 && b[3] == 4) return FW_T_ZIP;
    if (n >= 2 && b[0] == 0x1f && b[1] == 0x8b) return FW_T_GZIP;
    if (n >= 6 && b[0] == 0xfd && b[1] == '7' && b[2] == 'z' && b[3] == 'X') return FW_T_XZ;
    if (n >= 4 && !memcmp(b, "hsqs", 4)) return FW_T_SQUASHFS;
    if (n >= 4 && !memcmp(b, "sqsh", 4)) return FW_T_SQUASHFS;
    if (n >= 4 && b[0] == 0x45 && b[1] == 0x3d && b[2] == 0xcd && b[3] == 0x28) return FW_T_CRAMFS;
    if (n >= 2 && b[0] == 0x85 && b[1] == 0x19) return FW_T_JFFS2;
    if (n >= 4 && !memcmp(b, "UBI#", 4)) return FW_T_UBI;
    if (n >= 6 && (!memcmp(b, "070701", 6) || !memcmp(b, "070702", 6))) return FW_T_CPIO;
    /* Hikvision/Trendnet DAV konteyner basligi (ozel/obfuskeli bicim).
     * Sifreli demek degil: govde binwalk ile acilabiliyor. */
    if (n >= 4 && ((b[0] == 0x8a && b[1] == 0xff && b[2] == 0xf7 && b[3] == 0xb6) ||
                   (b[0] == 0xe9 && b[1] == 0x9a && b[2] == 0xf7 && b[3] == 0xb6))) {
        if (detail) snprintf(detail, (size_t)dlen, "Hikvision DAV konteyner (ozel bicim)");
        return FW_T_DAV;
    }
    if (n >= 512 && !memcmp(b + 257, "ustar", 5)) return FW_T_TAR;
    /* ext2/3/4 superblock sihri 0xEF53, ofset 1080 */
    if (n > 1088 && b[1080] == 0x53 && b[1081] == 0xEF) return FW_T_EXT;
    /* Hikvision digicap: sifreli baslik (8a ff f7 b6) veya duz "digicap" */
    if (n >= 4 && b[0] == 0x8a && b[1] == 0xff && b[2] == 0xf7 && b[3] == 0xb6) {
        if (detail) snprintf(detail, (size_t)dlen, "Hikvision/Davinci sifreli konteyner (AES)");
        return FW_T_HIKVISION_ENC;
    }
    /* Duzeltme: memcmp(...,0) her zaman dogru donuyordu; boylece 4 bayttan
     * buyuk HER imaj "kabuk betigi" olarak siniflaniyordu. */
    if (n >= 8 && !memcmp(b, "digicap", 7)) {
        if (detail) snprintf(detail, (size_t)dlen, "Hikvision digicap konteyner");
        return FW_T_HIKVISION_ENC;
    }
    if (n >= 2 && b[0] == '#' && b[1] == '!') {
        /* self-extracting script: "tail -n +N" ile govde cikarir */
        FILE *g = fopen(path, "r");
        if (g) {
            char line[512];
            int lines = 0;
            while (fgets(line, sizeof(line), g) && lines < 400) {
                lines++;
                if (strstr(line, "tail -n +")) {
                    if (detail) snprintf(detail, (size_t)dlen,
                                         "self-extracting sh (tail -n +N govde)");
                    fclose(g);
                    return FW_T_SCRIPT_TAIL;
                }
            }
            fclose(g);
        }
        if (detail) snprintf(detail, (size_t)dlen, "kabuk betigi");
        return FW_T_SCRIPT;
    }
    return FW_T_UNKNOWN;
}

/* ==================== Entropi / sifreleme tespiti ==================== */

static double block_entropy(const unsigned char *buf, size_t n) {
    if (!n) return 0.0;
    int hist[256] = {0};
    for (size_t i = 0; i < n; i++) hist[buf[i]]++;
    double H = 0.0, tot = (double)n;
    for (int i = 0; i < 256; i++) {
        if (!hist[i]) continue;
        double p = hist[i] / tot;
        H -= p * (log2(p));
    }
    return H;
}

static int looks_encrypted(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    unsigned char buf[65536];
    size_t n = fread(buf, 1, sizeof(buf), f);
    fclose(f);
    if (n < 4096) return 0;
    double h = block_entropy(buf, n);
    /* Yalnizca yuksek entropi tek basina yeterli kanit degil; sihir
     * taramasi zaten basarisiz oldugunda cagrilir. */
    return h > 7.85;
}

/* ==================== Unpack ==================== */

static char g_layer_note[2048];

static int unpack_layer(const char *path, const char *outdir, int depth,
                        SnFwResult *res, int add_findings);

/* Alt katmanlari kesfet: binwalk ciktisindan bagimsiz olarak dosya
 * tipine gore yeniden dener (tar/ext/squashfs katmanlari binwalk 3
 * tarafindan her zaman acilmaz). */
static int unpack_children(const char *dir, int depth, SnFwResult *res, int add_findings) {
    DIR *d = opendir(dir);
    if (!d) return 0;
    struct dirent *de;
    int opened = 0;
    while ((de = readdir(d))) {
        if (de->d_name[0] == '.') continue;
        char p[SN_PATH_LEN];
        snprintf(p, sizeof(p), "%s/%s", dir, de->d_name);
        struct stat sb;
        if (stat(p, &sb) != 0 || !S_ISREG(sb.st_mode)) continue;
        if (sb.st_size < 512) continue;
        char detail[128];
        FwType t = fw_type_of(p, detail, sizeof(detail));
        if (t == FW_T_TAR || t == FW_T_EXT || t == FW_T_SQUASHFS || t == FW_T_CPIO) {
            char sub[SN_PATH_LEN];
            snprintf(sub, sizeof(sub), "%s.x", p);
            mkdir_p(sub);
            if (unpack_layer(p, sub, depth + 1, res, add_findings) == 0) opened++;
        }
    }
    closedir(d);
    return opened;
}

static int unpack_layer(const char *path, const char *outdir, int depth,
                        SnFwResult *res, int add_findings) {
    if (depth > FW_MAX_DEPTH) return -1;
    char detail[160];
    FwType t = fw_type_of(path, detail, sizeof(detail));
    char cmd[2048];
    int rc = -1;

    sn_logf("fw: katman %d tip=%d (%s) %s", depth, (int)t,
            detail[0] ? detail : "bilinmiyor", path);

    switch (t) {
    case FW_T_SCRIPT_TAIL: {
        /* tail -n +N ile govdeyi cikar, sonra yeniden tanimla */
        FILE *f = fopen(path, "r");
        if (!f) return -1;
        char line[512];
        int N = 0;
        while (fgets(line, sizeof(line), f)) {
            char *p = strstr(line, "tail -n +");
            if (p) { N = atoi(p + 9); if (N <= 0) N = 1; break; }
        }
        fclose(f);
        char body[SN_PATH_LEN];
        snprintf(body, sizeof(body), "%s/body_%d.bin", outdir, depth);
        snprintf(cmd, sizeof(cmd), "tail -n +%d '%s' > '%s'", N, path, body);
        if (run_cmd(cmd, NULL, 0, 120) != 0) return -1;
        sn_logf("fw: self-extract govde cikarildi (satir %d)", N);
        return unpack_layer(body, outdir, depth + 1, res, add_findings);
    }
    case FW_T_TAR:
        snprintf(cmd, sizeof(cmd), "tar -xf '%s' -C '%s'", path, outdir);
        rc = run_cmd(cmd, NULL, 0, 300);
        if (rc == 0) snprintf(res->filesystem, sizeof(res->filesystem), "tar");
        break;
    case FW_T_GZIP: {
        char outp[SN_PATH_LEN];
        snprintf(outp, sizeof(outp), "%s/decompressed.bin", outdir);
        snprintf(cmd, sizeof(cmd), "gzip -dc '%s' > '%s'", path, outp);
        rc = run_cmd(cmd, NULL, 0, 300);
        if (rc == 0) {
            snprintf(res->filesystem, sizeof(res->filesystem), "gzip");
            unpack_layer(outp, outdir, depth + 1, res, add_findings);
        }
        break;
    }
    case FW_T_XZ: {
        char outp[SN_PATH_LEN];
        snprintf(outp, sizeof(outp), "%s/decompressed.bin", outdir);
        snprintf(cmd, sizeof(cmd), "xz -dc '%s' > '%s'", path, outp);
        rc = run_cmd(cmd, NULL, 0, 300);
        if (rc == 0) {
            snprintf(res->filesystem, sizeof(res->filesystem), "xz");
            unpack_layer(outp, outdir, depth + 1, res, add_findings);
        }
        break;
    }
    case FW_T_ZIP:
        snprintf(cmd, sizeof(cmd), "unzip -q -o '%s' -d '%s'", path, outdir);
        rc = run_cmd(cmd, NULL, 0, 300);
        break;
    case FW_T_SQUASHFS:
        if (have_tool("unsquashfs")) {
            snprintf(cmd, sizeof(cmd),
                     "unsquashfs -f -no-progress -d '%s/rootfs' '%s'", outdir, path);
            rc = run_cmd(cmd, NULL, 0, 420);
            if (rc == 0) snprintf(res->filesystem, sizeof(res->filesystem), "squashfs");
        } else {
            sn_logf("fw: unsquashfs yok - squashfs katmani acilmadi");
        }
        break;
    case FW_T_CRAMFS:
        if (have_tool("sasquatch")) {
            snprintf(cmd, sizeof(cmd), "sasquatch -d '%s/rootfs' '%s'", outdir, path);
            rc = run_cmd(cmd, NULL, 0, 300);
            if (rc == 0) snprintf(res->filesystem, sizeof(res->filesystem), "cramfs");
        } else {
            sn_logf("fw: cramfs araci yok (sasquatch) - katman atlandi, "
                    "binwalk denemesi yapilacak");
            rc = -1;
        }
        break;
    case FW_T_EXT: {
        char rf[SN_PATH_LEN];
        snprintf(rf, sizeof(rf), "%s/rootfs", outdir);
        mkdir_p(rf);
        if (have_tool("debugfs")) {
            snprintf(cmd, sizeof(cmd),
                     "debugfs -R 'rdump / \"%s\"' '%s'", rf, path);
            rc = run_cmd(cmd, NULL, 0, 420);
            if (rc == 0) snprintf(res->filesystem, sizeof(res->filesystem), "ext2/3/4");
        } else {
            sn_logf("fw: debugfs yok - ext katmani acilmadi");
        }
        break;
    }
    case FW_T_CPIO: {
        snprintf(cmd, sizeof(cmd),
                 "cd '%s' && cpio -idm --no-absolute-filenames < '%s'", outdir, path);
        rc = run_cmd(cmd, NULL, 0, 300);
        if (rc == 0) snprintf(res->filesystem, sizeof(res->filesystem), "cpio");
        break;
    }
    case FW_T_JFFS2:
    case FW_T_UBI:
    case FW_T_UNKNOWN:
    default: {
        /* Son care: binwalk (varsa) */
        if (have_tool("binwalk")) {
            snprintf(cmd, sizeof(cmd), "binwalk -eM -C '%s/bw' '%s'", outdir, path);
            rc = run_cmd(cmd, NULL, 0, 600);
            if (rc == 0) sn_logf("fw: binwalk katmani islendi");
        }
        break;
    }
    }
    if (rc != 0) {
        snprintf(g_layer_note, sizeof(g_layer_note),
                 "katman acilamadi (tip=%d, rc=%d) %s", (int)t, rc, path);
    } else if (depth + 1 > res->depth) {
        /* Raporda "cikarim derinligi" olarak gosterilir: gercekten acilan
         * katman sayisi (ust imaj = 1). Once sabit 0 basiliyordu. */
        res->depth = depth + 1;
    }
    return rc;
}

/* ==================== Secret mining ==================== */

static void ev_write(FwCtx *ctx, const char *fmt, ...) {
    if (!ctx->ev_open) return;
    FILE *f = fopen(ctx->evidence, "a");
    if (!f) return;
    va_list ap;
    va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);
    fputc('\n', f);
    fclose(f);
}

static void add_finding(FwCtx *ctx, const char *cls, const char *title,
                        const char *vector, const char *cwe, const char *vec_cvss,
                        int confidence, const char *status, const char *detail) {
    if (!ctx->add_findings) return;
    SnFinding f;
    memset(&f, 0, sizeof(f));
    snprintf(f.cls, sizeof(f.cls), "%s", cls);
    snprintf(f.title, sizeof(f.title), "%s", title);
    /* Rapor "Vektor" alanini dogrudan basiyor; CVSS vektoru varsa onu yaz,
     * etiket (or. elf_unsafe_calls) yalnizca vektor yoksa gorunsun. */
    if (vec_cvss && *vec_cvss)
        snprintf(f.vector, sizeof(f.vector), "%s", vec_cvss);
    else
        snprintf(f.vector, sizeof(f.vector), "%s", vector ? vector : "");
    snprintf(f.cwe, sizeof(f.cwe), "%s", cwe ? cwe : "");
    snprintf(f.status, sizeof(f.status), "%s", status ? status : "candidate");
    snprintf(f.detail, sizeof(f.detail), "%s", detail ? detail : "");
    snprintf(f.evidence, sizeof(f.evidence), "%s", ctx->evidence);
    f.cvss = sn_cvss_base(vec_cvss);
    f.confidence = confidence;
    sn_severity_from_cvss(f.cvss, f.severity, sizeof(f.severity));
    sn_finding_add(&f);
    ctx->findings++;
    if (!strcmp(cls, "firmware_secret")) ctx->secrets++;
}

static int cred_seen(FwCtx *ctx, const char *s) {
    for (int i = 0; i < ctx->seen_cred_n; i++)
        if (!strcmp(ctx->seen_cred[i], s)) return 1;
    if (ctx->seen_cred_n < 64)
        snprintf(ctx->seen_cred[ctx->seen_cred_n++], 96, "%s", s);
    return 0;
}

/* Bulunan DES/MD5/SHA hash'ini sozluk ile dener (crypt(3)). */
static int crack_hash(const char *hash, const char *wordlist, char *plain, int plen) {
    static const char *builtin[] = {
        "admin", "12345", "123456", "1234", "password", "root", "toor",
        "hikvision", "dahua", "888888", "666666", "12345678", "admin123",
        "vstarcam", "ipcam", "camera", "system", "support", "service",
        "123456789", "111111", "000000", "abc123", "qwerty", "P@ssw0rd", NULL };
    for (int i = 0; builtin[i]; i++) {
        char got[128];
        snprintf(got, sizeof(got), "%s", crypt(builtin[i], hash));
        if (got[0] && !strcmp(got, hash)) {
            snprintf(plain, (size_t)plen, "%s", builtin[i]);
            return 0;
        }
    }
    if (wordlist && *wordlist) {
        FILE *f = fopen(wordlist, "r");
        if (f) {
            char w[128];
            int n = 0;
            while (fgets(w, sizeof(w), f) && n < 200000) {
                n++;
                str_trim(w);
                if (!w[0] || w[0] == '#') continue;
                char got[128];
                snprintf(got, sizeof(got), "%s", crypt(w, hash));
                if (got[0] && !strcmp(got, hash)) {
                    snprintf(plain, (size_t)plen, "%s", w);
                    fclose(f);
                    return 0;
                }
            }
            fclose(f);
        }
    }
    return -1;
}

static int hash_like(const char *s) {
    size_t n = strlen(s);
    if (n == 13 && s[0] != '!' && s[0] != '*') return 1;           /* DES */
    if (n > 20 && s[0] == '$' && strchr(s, '$')) return 1;         /* md5/sha/bcrypt */
    return 0;
}

static void scan_passwd_file(FwCtx *ctx, const char *path, const char *rel) {
    FILE *f = fopen(path, "r");
    if (!f) return;
    char line[512];
    int found = 0;
    while (fgets(line, sizeof(line), f) && found < 8) {
        str_trim(line);
        if (!line[0] || line[0] == '#') continue;
        char *c1 = strchr(line, ':');
        if (!c1) continue;
        *c1 = '\0';
        char *rest = c1 + 1;
        char *hash = rest;
        char *c2 = strchr(rest, ':');
        if (c2) *c2 = '\0';

        if (!hash_like(hash)) continue;
        found++;
        char plain[128] = "";
        int cracked = (crack_hash(hash, NULL, plain, sizeof(plain)) == 0);
        char detail[SN_DETAIL_LEN];
        char title[SN_TITLE_LEN];
        if (cracked) {
            snprintf(title, sizeof(title), "Gomulu sistem hesabi zayif parolali: %s", line);
            snprintf(detail, sizeof(detail),
                     "%s icinde %s hesabi icin hash %s; sozluk denemesinde duz metin "
                     "\"%s\" olarak cozuldu. Bu hesap cihazda telnet/SSH/serial "
                     "erisimi icin kullanilabilir.", rel, line, hash, plain);
            ev_write(ctx, "[passwd] %s -> %s:%s (cozuldu: %s)", rel, line, hash, plain);
            add_finding(ctx, "firmware_secret", title, "passwd_hash_crack",
                        "CWE-798", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        92, "confirmed", detail);
        } else {
            snprintf(title, sizeof(title), "Gomulu sistem hesabi hash'i: %s", line);
            snprintf(detail, sizeof(detail),
                     "%s icinde %s hesabi icin geri donuslu parola hash'i (%s) "
                     "bulundu; sozluk denemesi sonuc vermedi. Cevrimdisi kirma "
                     "denenmelidir.", rel, line, hash);
            ev_write(ctx, "[passwd] %s -> %s:%s (cozulmedi)", rel, line, hash);
            add_finding(ctx, "firmware_secret", title, "passwd_hash",
                        "CWE-522", "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        70, "candidate", detail);
        }
    }
    fclose(f);
}

/* Kimlik/parola kurali eslesmesinde "deger" tarafinin gercekten bir sirl
 * olup olmadigini kabaca suz. Gozlemlenen yanlis pozitifler:
 *   - yerellestirme etiketleri: "Passwd:Local:", "Passwd:Локально:"
 *   - JS/XML API adlari: "Root = xmlDoc.createElement"
 *   - dosya yollari ve sablon ifadeleri
 * Bunlar rapora "kritik gomulu parola" olarak dusmemeli. */
/* Web arayuzu / yerellestirme varliklari: kimlik avinda surekli yanlis
 * pozitif uretiyorlar (jquery.min.js, Log.xml, dispatch.asp). Bu
 * dosyalarda yalnizca ozel anahtar/cloud/anahtar kurallari calisir. */
static int is_ui_asset(const char *rel) {
    static const char *ext[] = { ".js", ".css", ".html", ".htm", ".asp",
                                 ".aspx", ".jsp", ".php", ".po", ".mo",
                                 ".svg", ".map", NULL };
    const char *dot = strrchr(rel, '.');
    if (!dot) return 0;
    for (int i = 0; ext[i]; i++)
        if (!strcasecmp(dot, ext[i])) return 1;
    return 0;
}

static int cred_value_plausible(const char *val, char after) {
    static const char *labels[] = {
        "passwd", "password", "pass", "pwd", "secret", "local", "localized",
        "locale", "root", "admin", "support", "user", "group", "mode",
        "info", "enable", "disable", "true", "false", "yes", "no", "none",
        "null", "default", "value", "string", "input", "label", "function",
        "var", "let", "const", "return", "this", "new", "undefined", "typeof",
        "document", "window", "case", "break", "switch", "else", NULL };
    size_t n = strlen(val);
    if (n < 4 || n > 32) return 0;
    if (after == ':') return 0;                 /* etiket: "...:Local:" */
    if (val[n - 1] == ':' || val[n - 1] == ',' || val[n - 1] == ';') return 0;
    for (const unsigned char *p = (const unsigned char *)val; *p; p++)
        if (*p >= 0x80) return 0;               /* ASCII disi etiket metni */
    /* Deger yalnizca kimlik/parola karakter kumesinden olussun. Boylece
     * "null,", ")!=-1)", "Local:Restaurar" gibi kod/etiket parcalari elenir. */
    for (const char *p = val; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (!(isalnum(c) || strchr("!@#$%^&*._-", c))) return 0;
    }
    for (int i = 0; labels[i]; i++)
        if (!strcasecmp(val, labels[i])) return 0;
    return 1;
}

static void regex_scan(FwCtx *ctx, const char *text, size_t len,
                       const char *path, const char *rel) {
    struct { const char *re; const char *label; const char *cls;
             const char *cwe; const char *cvss; int conf; const char *status; } rules[] = {
        { "(pass(word|wd)?|pwd|secret)[\"']?[ \t]*[=:][ \t]*[\"']?([^\"' \t;]{3,64})",
          "Parola atamasi", "firmware_secret", "CWE-798",
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 80, "candidate" },
        { "-----BEGIN [A-Z ]*PRIVATE KEY-----",
          "Gomulu ozel anahtar", "firmware_secret", "CWE-321",
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 85, "confirmed" },
        { "([a-z0-9-]+\\.)*(tutk|ppcs|ezviz|tuya|hik-connect|dahua|meari|vstarcam|yoosee|gwelltimes)\\.[a-z]{2,4}",
          "Cloud/P2P endpoint", "cloud_p2p", "CWE-201",
          "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", 60, "candidate" },
        { "(AES|aes)[-_ ]?(key|KEY)[ \t]*[=:][ \t]*[\"']?([0-9a-fA-F]{16,64})",
          "Sabit simetrik anahtar", "firmware_secret", "CWE-321",
          "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 75, "candidate" },
        { "(^|[^A-Za-z0-9_])(admin|root|support)[\"']?[ \t]*[:=][ \t]*[\"']?([A-Za-z0-9!@#$%^&*._-]{4,32})",
          "Varsayilan/gomulu kimlik cifti", "firmware_secret", "CWE-798",
          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 65, "candidate" },
    };
    const int nrules = (int)(sizeof(rules) / sizeof(rules[0]));

    for (int r = 0; r < nrules; r++) {
        regex_t rx;
        /* REG_NOSUB KULLANILMAZ: pmatch dizisini doldurmaz, m[] stack'te
         * cop degerle kalir -> yanlis ornek metin ve tampon disi ilerleme
         * (SIGSEGV). Eslesme ofsetleri icin pmatch sart. */
        if (regcomp(&rx, rules[r].re, REG_EXTENDED | REG_ICASE) != 0)
            continue;
        regmatch_t m[4];
        const char *cur = text;
        int hits = 0;
        while (hits < 4 && regexec(&rx, cur, 4, m, 0) == 0) {
            /* glibc, ikili/gecersiz coklu bayt icerikte rm_eo < rm_so veya
             * rm_eo == 0 dondurebiliyor (gozlemlendi: rm_so=1, rm_eo=0).
             * Dogrulanmamis ofsetle memcpy yapmak tasma demek; eslesmeyi
             * gecersiz say ve donguden cik. */
            if (m[0].rm_so < 0 || m[0].rm_eo <= m[0].rm_so) break;
            size_t remain = strlen(cur);
            size_t off = (size_t)m[0].rm_so;
            if (off >= remain) break;
            /* pmatch artik gercek (REG_NOSUB kaldirildi): kimlik/parola
             * kurallarinda TUM eslesme yerine deger grubunu (m[3]) kullan;
             * aksi halde baslik "Passwd:Local" gibi etiketle kirleniyordu. */
            int is_cred = !strcmp(rules[r].cls, "firmware_secret") &&
                          (strstr(rules[r].label, "Parola") ||
                           strstr(rules[r].label, "kimlik"));
            if (is_cred && is_ui_asset(rel)) break;
            const regmatch_t *mv = &m[0];
            if (is_cred && m[3].rm_so >= 0 && m[3].rm_eo > m[3].rm_so)
                mv = &m[3];
            size_t voff = (size_t)mv->rm_so;
            if (voff >= remain) break;
            size_t len2 = (size_t)mv->rm_eo - voff;
            if (len2 > remain - voff) len2 = remain - voff;
            char sample[160];
            size_t cp = len2 < sizeof(sample) - 1 ? len2 : sizeof(sample) - 1;
            memcpy(sample, cur + voff, cp);
            sample[cp] = '\0';
            char after = ((size_t)mv->rm_eo < remain) ? cur[mv->rm_eo] : '\0';
            int plausible = !is_cred || cred_value_plausible(sample, after);
            /* parola benzeri metinlerde degeri logla ama kirp */
            char uniq[96];
            snprintf(uniq, sizeof(uniq), "%s|%.80s", rules[r].label, sample);
            if (plausible && !cred_seen(ctx, uniq)) {
                char title[SN_TITLE_LEN];
                snprintf(title, sizeof(title), "%s: %.70s", rules[r].label, sample);
                char detail[SN_DETAIL_LEN];
                snprintf(detail, sizeof(detail),
                         "%s dosyasinda \"%s\" eslesti. Baglam: firmware icinde "
                         "gomulu kimlik/anahtar materyali.", rel, sample);
                ev_write(ctx, "[%s] %s :: %s", rules[r].cls, rel, sample);
                add_finding(ctx, rules[r].cls, title, "firmware_grep",
                            rules[r].cwe, rules[r].cvss, rules[r].conf,
                            rules[r].status, detail);
            }
            hits++;
            /* rm_eo strlen(cur)'dan buyuk donebiliyor (gecersiz coklu bayt).
             * Dogrulanmamis ofsetle ilerlemek cur'u tampon disina tasiyordu
             * -> SIGSEGV. Sinirda dur. */
            if ((size_t)m[0].rm_eo >= remain) break;
            cur += m[0].rm_eo;
            if (!*cur) break;
        }
        regfree(&rx);
    }
}

static void scan_file(FwCtx *ctx, const char *path, const char *rel) {
    struct stat sb;
    if (stat(path, &sb) != 0 || !S_ISREG(sb.st_mode)) return;
    if (sb.st_size == 0) return;
    ctx->files++;
    if (ctx->files > FW_MAX_FILES) return;

    char detail[160];
    FwType t = fw_type_of(path, detail, sizeof(detail));

    if (t == FW_T_ELF) {
        ctx->binaries++;
        char cmd[1024], out[16384];
        snprintf(cmd, sizeof(cmd), "rabin2 -qq -i '%s' 2>/dev/null | head -400", path);
        int unsafe = 0;
        if (run_cmd(cmd, out, sizeof(out), 30) == 0) {
            const char *bad[] = { "strcpy", "strcat", "sprintf", "system",
                                  "popen", "gets", "memcpy", NULL };
            for (int i = 0; bad[i]; i++)
                if (strstr(out, bad[i])) unsafe++;
        }
        if (unsafe > 0) {
            ctx->unsafe_calls += unsafe;
            char title[SN_TITLE_LEN];
            char srel[SN_TITLE_LEN];
            short_rel(rel, srel, 110);
            snprintf(title, sizeof(title), "Bellek/komut riski tasiyan binary: %.100s", srel);
            char det[SN_DETAIL_LEN];
            snprintf(det, sizeof(det),
                     "%s icinde %d tehlikeli cagri ailesi (strcpy/sprintf/system/"
                     "popen) goruldu. Pre-auth kod yolu bulunursa RCE adayi.", rel, unsafe);
            ev_write(ctx, "[elf] %s unsafe_families=%d", rel, unsafe);
            add_finding(ctx, "firmware_binary", title, "elf_unsafe_calls",
                        "CWE-120", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        55, "candidate", det);
        }
        /* pre-auth adayi: ag protokolu isleyen daemon */
        snprintf(cmd, sizeof(cmd), "strings -n 8 '%s' 2>/dev/null | head -3000", path);
        if (run_cmd(cmd, out, sizeof(out), 30) == 0) {
            int net = (strstr(out, "HTTP/1.") || strstr(out, "RTSP/1.0") ||
                       strstr(out, "SOAP") || strstr(out, "onvif"));
            int auth = (strstr(out, "Authorization") || strstr(out, "WWW-Authenticate"));
            if (net) {
                ctx->preauth++;
                char title[SN_TITLE_LEN];
                char srel[SN_TITLE_LEN];
                short_rel(rel, srel, 110);
                snprintf(title, sizeof(title), "Ag protokolu isleyen daemon: %.100s", srel);
                char det[SN_DETAIL_LEN];
                snprintf(det, sizeof(det),
                         "%s HTTP/RTSP/SOAP isliyor (auth semasi: %s). Bu binary "
                         "auth kontrolunden ONCE parse eden handler'lar icin tersine "
                         "muhendislik hedefi; Ghidra/radare2 ile cagri grafigi "
                         "cikarilmalidir.", rel, auth ? "goruldu" : "gorulmedi");
                ev_write(ctx, "[elf] %s network_daemon auth_strings=%d", rel, auth);
                add_finding(ctx, "firmware_binary", title, "preauth_surface",
                            "CWE-306", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            50, "candidate", det);
            }
        }
        return;
    }

    if (!is_text_ext(rel) && sb.st_size > 262144) return;

    FILE *f = fopen(path, "rb");
    if (!f) return;
    size_t take = (size_t)sb.st_size < FW_MAX_TEXT ? (size_t)sb.st_size : FW_MAX_TEXT;
    char *buf = malloc(take + 1);
    if (!buf) { fclose(f); return; }
    size_t got = fread(buf, 1, take, f);
    fclose(f);
    buf[got] = '\0';

    /* binary icerikte NUL varsa yalnizca ilk bolumu tara */
    size_t scan_len = got;
    for (size_t i = 0; i < got; i++)
        if (buf[i] == '\0') { scan_len = i; break; }

    regex_scan(ctx, buf, scan_len, path, rel);
    free(buf);
}

static int name_has_suffix(const char *s, const char *suf) {
    size_t ls = strlen(s), lf = strlen(suf);
    return ls >= lf && !strcmp(s + ls - lf, suf);
}

/* binwalk 3 imajlari cikarir ama icindeki dosya sistemini her zaman acmaz
 * (ext2/3/4 icin extractor yoksa imaj dosyasi olarak kalir). Agacta kalan
 * dosya sistemi imajlarini gercek araclarla ac; aksi halde /etc/passwd,
 * telnetd gibi kanitlar taranmadan analiz "temiz" gorunur. */
static int unpack_tree_images(const char *dir, int depth, int *budget, SnFwResult *res) {
    if (depth > 6 || *budget <= 0) return 0;
    DIR *d = opendir(dir);
    if (!d) return 0;
    struct dirent *de;
    int opened = 0;
    while ((de = readdir(d)) && *budget > 0) {
        if (de->d_name[0] == '.') continue;
        if (name_has_suffix(de->d_name, ".rootfs") ||
            name_has_suffix(de->d_name, ".x")) continue;
        char p[SN_PATH_LEN];
        snprintf(p, sizeof(p), "%s/%s", dir, de->d_name);
        struct stat sb;
        if (lstat(p, &sb) != 0) continue;
        if (S_ISDIR(sb.st_mode)) {
            opened += unpack_tree_images(p, depth + 1, budget, res);
            continue;
        }
        if (!S_ISREG(sb.st_mode) || sb.st_size < 4096) continue;

        char detail[128] = "";
        FwType t = fw_type_of(p, detail, sizeof(detail));
        if (t != FW_T_EXT && t != FW_T_SQUASHFS && t != FW_T_CRAMFS &&
            t != FW_T_CPIO && t != FW_T_GZIP) continue;

        char sub[SN_PATH_LEN];
        snprintf(sub, sizeof(sub), "%s.rootfs", p);
        mkdir_p(sub);
        if (unpack_layer(p, sub, 1, res, 0) == 0) {
            (*budget)--;
            opened++;
            sn_logf("fw: gomulu imaj acildi (tip=%d): %.140s", (int)t, p);
        }
    }
    closedir(d);
    return opened;
}

static void walk_tree(FwCtx *ctx, const char *dir, const char *relbase, int depth) {
    if (depth > FW_MAX_DEPTH || ctx->files > FW_MAX_FILES) return;
    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *de;
    while ((de = readdir(d))) {
        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
        char p[SN_PATH_LEN], rel[SN_PATH_LEN];
        snprintf(p, sizeof(p), "%s/%s", dir, de->d_name);
        if (relbase[0]) snprintf(rel, sizeof(rel), "%s/%s", relbase, de->d_name);
        else snprintf(rel, sizeof(rel), "%s", de->d_name);

        struct stat sb;
        if (lstat(p, &sb) != 0) continue;
        if (S_ISLNK(sb.st_mode)) continue;         /* symlink takibi yok */
        if (S_ISDIR(sb.st_mode)) {
            /* etc/passwd ve benzeri kritik dosyalar */
            walk_tree(ctx, p, rel, depth + 1);
            continue;
        }
        if (!S_ISREG(sb.st_mode)) continue;

        if (!strcmp(de->d_name, "passwd") && strstr(rel, "etc"))
            scan_passwd_file(ctx, p, rel);
        else if (!strcmp(de->d_name, "shadow") && strstr(rel, "etc"))
            scan_passwd_file(ctx, p, rel);
        scan_file(ctx, p, rel);
    }
    closedir(d);
}

/* ==================== Ana giris ==================== */

int sn_fw_analyze(const char *path, SnFwResult *res, int add_findings) {
    if (!path || !*path) return -1;
    struct stat sb;
    if (stat(path, &sb) != 0 || !S_ISREG(sb.st_mode)) {
        sn_logf("fw: dosya yok: %s", path);
        return -1;
    }

    memset(res, 0, sizeof(*res));
    snprintf(res->path, sizeof(res->path), "%s", path);
    sn_sha256_file(path, res->sha256, sizeof(res->sha256));

    char detail[160] = "";
    FwType t = fw_type_of(path, detail, sizeof(detail));
    /* Kapsayici alanini okunabilir tut: GUI/rapor bunu dogrudan basiyor. */
    if (detail[0]) snprintf(res->container, sizeof(res->container), "%s", detail);
    else snprintf(res->container, sizeof(res->container), "bilinmiyor (tip=%d)", (int)t);
    res->encrypted = (t == FW_T_HIKVISION_ENC) ? 1 : 0;
    if (!res->encrypted) res->encrypted = looks_encrypted(path);

    char base_dir[SN_PATH_LEN];
    snprintf(base_dir, sizeof(base_dir), "sentinel_fw/%.16s",
             res->sha256[0] ? res->sha256 : "nohash");
    mkdir_p(base_dir);
    snprintf(res->extract_dir, sizeof(res->extract_dir), "%s", base_dir);

    sn_logf("fw: %s (%lld bayt, sha256=%.16s...)", path, (long long)sb.st_size,
            res->sha256[0] ? res->sha256 : "yok");
    sn_logf("fw: konteyner=%s %s", detail[0] ? detail : "bilinmiyor",
            res->encrypted ? "[YUKSEK ENTROPI: sifreli olabilir]" : "");

    FwCtx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.res = res;
    ctx.add_findings = add_findings;
    snprintf(ctx.evidence, sizeof(ctx.evidence), "%s/evidence.txt", base_dir);

    FILE *ev = fopen(ctx.evidence, "w");
    if (ev) {
        fprintf(ev, "# SENTINEL firmware kanit dosyasi\n# imaj: %s\n# sha256: %s\n",
                path, res->sha256);
        fclose(ev);
        ctx.ev_open = 1;
    }

    int unpacked = 0;
    if (res->encrypted) {
        sn_logf("fw: imaj sifreli gorunuyor - statik unpack denenecek ama "
                "anahtar/updater binary'si olmadan basari beklenmiyor");
        if (add_findings)
            add_finding(&ctx, "firmware_crypto",
                        "Firmware imaji sifreli (statik analiz blokeli)",
                        "entropy_analysis", "CWE-311",
                        "CVSS:3.1/AV:P/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                        60, "candidate",
                        "Imaj yuksek entropili ve bilinen dosya sistemi sihri "
                        "icermiyor. Vendor updater binary'sinden anahtar cikarilmadan "
                        "rootfs analiz edilemez; Faz 4-5 bu hedef icin firmware "
                        "istihbarati olmadan calisacak.");
    }

    char rootfs[SN_PATH_LEN];
    snprintf(rootfs, sizeof(rootfs), "%s/rootfs", base_dir);
    mkdir_p(rootfs);

    if (unpack_layer(path, rootfs, 0, res, add_findings) == 0) unpacked = 1;
    unpack_children(rootfs, 0, res, add_findings);

    /* binwalk agacinda imaj olarak kalan dosya sistemlerini ac */
    int img_budget = 24;
    int imgs = unpack_tree_images(rootfs, 0, &img_budget, res);
    if (imgs > 0) {
        sn_logf("fw: %d gomulu dosya sistemi acildi", imgs);
        unpacked = 1;
    }

    /* Acilan her seyi tara */
    walk_tree(&ctx, rootfs, "", 0);

    /* telnetd / sshd gibi servis izleri (persistence ve varsayilan kimlik) */
    if (have_tool("find")) {
        char cmd[1024], out[4096];
        snprintf(cmd, sizeof(cmd),
                 "find '%s' -type f \\( -name telnetd -o -name dropbear -o "
                 "-name sshd -o -name busybox \\) 2>/dev/null | head -8", rootfs);
        if (run_cmd(cmd, out, sizeof(out), 30) == 0 && out[0] && add_findings) {
            char det[SN_DETAIL_LEN];
            snprintf(det, sizeof(det),
                     "Imajda uzaktan kabuk servisi ikilisi bulundu: %s. "
                     "Kimlik dogrulama zayifsa kalici erisim vektoru.", out);
            ev_write(&ctx, "[service] %s", out);
            /* Kanit yalnizca "imajda boyle bir ikili var". Portun acik oldugu,
             * zayif kimlik dogrulama veya anonim erisim oldugu GOSTERILMEDI;
             * bu yuzden 9.8 degil, kosullu/orta siddet. */
            add_finding(&ctx, "firmware_service",
                        "Imajda uzaktan kabuk servisi ikilisi mevcut",
                        "service_inventory", "CWE-284",
                        "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
                        45, "candidate", det);
        }
    }

    res->files = ctx.files;
    res->binaries = ctx.binaries;
    res->secrets = ctx.secrets;
    res->unsafe_calls = ctx.unsafe_calls;
    res->preauth_candidates = ctx.preauth;

    if (ctx.ev_open) {
        FILE *f = fopen(ctx.evidence, "a");
        if (f) {
            fprintf(f, "# ozet: dosya=%d binary=%d bulgu=%d sir=%d tehlikeli_cagri=%d preauth=%d\n",
                    ctx.files, ctx.binaries, ctx.findings, ctx.secrets,
                    ctx.unsafe_calls, ctx.preauth);
            fclose(f);
        }
    }

    sn_logf("fw: analiz bitti - %d dosya, %d binary, %d bulgu (%d sirl), "
            "%d pre-auth aday (unpack=%s)", ctx.files, ctx.binaries,
            ctx.findings, ctx.secrets, ctx.preauth,
            unpacked ? "kismen/evet" : "hayir");
    return 0;
}
