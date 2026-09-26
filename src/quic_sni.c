/*
 * quic_sni.c — QUIC Initial paketinden istemci TLS SNI cikarimi.
 *
 * RFC 9001 geregi QUIC Initial paketleri, paketin DCID'sinden turetilen
 * SABIT tuz (salt) ile sifrelenir. Bu yuzden anahtar/IV/HP degerleri
 * elle turetilebilir; sunucu ile oturum kurmaya gerek yoktur.
 *
 * Akis:
 *   1. Uzun baslik (long header) + Initial tipi dogrula
 *   2. DCID -> HKDF-Extract(salt, DCID)
 *   3. "client in" (olmazsa "server in") -> quic key/iv/hp
 *   4. Header protection kaldir (hp ile AES-128-ECB maske)
 *   5. Nonce = iv XOR pn, AES-128-GCM coz (AAD = baslik, tag dogrulanmaz)
 *   6. Frame taramasi: CRYPTO (0x06) -> TLS ClientHello -> SNI
 *
 * OpenSSL yoksa derleme cikarim yapamaz: quic_sni_available() 0 doner ve
 * site_block motoru ICMP fallback'e duser.
 */
#include "quic_sni.h"

#include <string.h>

#ifdef HAVE_OPENSSL
#include <openssl/evp.h>
#include <openssl/hmac.h>

/* RFC 9001 v1 Initial salt: 38762cf7f55934b34d179ae6a4c80cadccbb7f0a */
static const unsigned char QUIC_SALT[20] = {
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a
};

int quic_sni_available(void) { return 1; }

/* ---- HKDF-Expand (RFC 5869) ---- */
static int hkdf_expand(const unsigned char *prk, int prk_len,
                       const unsigned char *info, int info_len,
                       unsigned char *out, int out_len) {
    unsigned char t[32];
    int tlen = 0, done = 0;
    unsigned char counter = 1;
    while (done < out_len) {
        unsigned char buf[256];
        int bl = 0;
        if (tlen > 0) { memcpy(buf, t, (size_t)tlen); bl = tlen; }
        if (bl + info_len + 1 > (int)sizeof(buf)) return -1;
        memcpy(buf + bl, info, (size_t)info_len); bl += info_len;
        buf[bl++] = counter;
        unsigned int outl = 0;
        if (!HMAC(EVP_sha256(), prk, prk_len, buf, bl, t, &outl)) return -1;
        tlen = (int)outl;
        int take = (out_len - done) < tlen ? (out_len - done) : tlen;
        memcpy(out + done, t, (size_t)take);
        done += take;
        counter++;
    }
    return 0;
}

/* ---- HKDF-Expand-Label (TLS 1.3 yapisi) ---- */
static int expand_label(const unsigned char *secret, int secret_len,
                        const char *label, unsigned char *out, int out_len) {
    unsigned char info[96];
    int p = 0;
    info[p++] = (unsigned char)((out_len >> 8) & 0xFF);
    info[p++] = (unsigned char)(out_len & 0xFF);
    static const char prefix[] = "tls13 ";
    int pl = (int)(sizeof(prefix) - 1);
    int ll = (int)strlen(label);
    info[p++] = (unsigned char)(pl + ll);
    memcpy(info + p, prefix, (size_t)pl); p += pl;
    memcpy(info + p, label, (size_t)ll); p += ll;
    info[p++] = 0x00;   /* context length = 0 */
    return hkdf_expand(secret, secret_len, info, p, out, out_len);
}

/* DCID + yon ("client in"/"server in") -> key(16)/iv(12)/hp(16) */
static int quic_derive(const unsigned char *dcid, int dcid_len, const char *dir,
                       unsigned char key[16], unsigned char iv[12], unsigned char hp[16]) {
    unsigned char prk[32];
    unsigned int prk_len = 0;
    if (!HMAC(EVP_sha256(), QUIC_SALT, (int)sizeof(QUIC_SALT), dcid, dcid_len, prk, &prk_len))
        return -1;
    unsigned char secret[32];
    if (expand_label(prk, (int)prk_len, dir, secret, 32) != 0) return -1;
    if (expand_label(secret, 32, "quic key", key, 16) != 0) return -1;
    if (expand_label(secret, 32, "quic iv", iv, 12) != 0) return -1;
    if (expand_label(secret, 32, "quic hp", hp, 16) != 0) return -1;
    return 0;
}

/* Tek AES-128-ECB blogu (header protection maskesi icin) */
static int aes_ecb_block(const unsigned char key[16],
                         const unsigned char in[16], unsigned char out[16]) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int outl = 0, fl = 0;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL) != 1 ||
        EVP_CIPHER_CTX_set_padding(ctx, 0) != 1 ||
        EVP_EncryptUpdate(ctx, out, &outl, in, 16) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    EVP_EncryptFinal_ex(ctx, out + outl, &fl);
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

/* ---- QUIC varint (RFC 9000 §16) ---- */
static int qv_decode(const unsigned char *p, int len, int *used, unsigned long long *val) {
    if (len < 1) return -1;
    int prefix = p[0] >> 6;
    int n = 1 << prefix;   /* 1,2,4,8 */
    if (len < n) return -1;
    unsigned long long v = (unsigned long long)(p[0] & 0x3f);
    for (int i = 1; i < n; i++) v = (v << 8) | p[i];
    *used = n;
    *val = v;
    return 0;
}

/* ---- TLS ClientHello icinden SNI (kucuk harfe cevirerek) ---- */
static int parse_sni(const unsigned char *d, int len, char *out, int out_len) {
    if (len < 4 || d[0] != 0x01) return 0;   /* HandshakeType = ClientHello */
    int hlen = (d[1] << 16) | (d[2] << 8) | d[3];
    int hend = 4 + hlen;
    if (hend > len) hend = len;

    int p = 4;
    p += 2;   /* legacy_version */
    p += 32;  /* random */
    if (p + 1 > hend) return 0;
    int sid = d[p]; p += 1 + sid;
    if (p + 2 > hend) return 0;
    int cs = (d[p] << 8) | d[p + 1]; p += 2 + cs;
    if (p + 1 > hend) return 0;
    int comp = d[p]; p += 1 + comp;
    if (p + 2 > hend) return 0;
    int ext_len = (d[p] << 8) | d[p + 1]; p += 2;
    int ext_end = p + ext_len;
    if (ext_end > hend) ext_end = hend;

    while (p + 4 <= ext_end) {
        int et = (d[p] << 8) | d[p + 1];
        int el = (d[p + 2] << 8) | d[p + 3];
        p += 4;
        if (p + el > ext_end) break;
        if (et == 0x0000) {   /* server_name */
            int q = p;
            if (q + 2 > p + el) return 0;
            int list_len = (d[q] << 8) | d[q + 1]; q += 2;
            int list_end = q + list_len;
            if (list_end > p + el) list_end = p + el;
            while (q + 3 <= list_end) {
                int ntype = d[q]; q++;
                int nlen = (d[q] << 8) | d[q + 1]; q += 2;
                if (q + nlen > list_end) break;
                if (ntype == 0 && nlen > 0) {
                    int c = nlen < out_len - 1 ? nlen : out_len - 1;
                    for (int i = 0; i < c; i++) {
                        char ch = (char)d[q + i];
                        out[i] = (ch >= 'A' && ch <= 'Z') ? (char)(ch - 'A' + 'a') : ch;
                    }
                    out[c] = '\0';
                    return 1;
                }
                q += nlen;
            }
            return 0;
        }
        p += el;
    }
    return 0;
}

/* Cozulen yukteki QUIC frame'lerini tara; CRYPTO -> ClientHello -> SNI */
static int scan_frames(const unsigned char *pt, int len, char *out, int out_len) {
    int p = 0;
    while (p < len) {
        unsigned char t = pt[p];
        if (t == 0x00 || t == 0x01) { p++; continue; }   /* PADDING / PING */
        if (t == 0x06) {                                  /* CRYPTO */
            int u;
            unsigned long long off, ln;
            p++;
            if (qv_decode(pt + p, len - p, &u, &off) < 0) return 0;
            p += u;
            if (qv_decode(pt + p, len - p, &u, &ln) < 0) return 0;
            p += u;
            if (ln > (unsigned long long)(len - p)) return 0;
            if (parse_sni(pt + p, (int)ln, out, out_len)) return 1;
            p += (int)ln;
            continue;
        }
        break;   /* ACK vb. karmasik frame: birak */
    }
    /* Yedek: dogrudan ClientHello imzasi ara */
    for (int i = 0; i + 4 <= len; i++) {
        if (pt[i] == 0x01) {
            int hl = (pt[i + 1] << 16) | (pt[i + 2] << 8) | pt[i + 3];
            if (hl > 0 && hl < 4096 && i + 4 + hl <= len) {
                if (parse_sni(pt + i, 4 + hl, out, out_len)) return 1;
            }
        }
    }
    return 0;
}

/* Tek yonu (client/server) cozmeyi dene */
static int try_side(const unsigned char *data, int len, int pn_offset,
                    unsigned long long plen, const unsigned char *dcid, int dcid_len,
                    const char *dir, char *out, int out_len) {
    unsigned char key[16], iv[12], hp[16];
    if (quic_derive(dcid, dcid_len, dir, key, iv, hp) != 0) return 0;

    /* sample = pn_offset + 4 .. +20 */
    if (pn_offset + 4 + 16 > len) return 0;
    unsigned char sample[16], mask[16];
    memcpy(sample, data + pn_offset + 4, 16);
    if (aes_ecb_block(hp, sample, mask) != 0) return 0;

    unsigned char b0 = (unsigned char)(data[0] ^ (mask[0] & 0x0f));
    int pnlen = (b0 & 0x03) + 1;
    if (pn_offset + pnlen > len) return 0;

    unsigned int pn = 0;
    for (int i = 0; i < pnlen; i++) {
        unsigned char pb = (unsigned char)(data[pn_offset + i] ^ mask[1 + i]);
        pn = (pn << 8) | pb;
    }

    int ct_off = pn_offset + pnlen;
    int ct_len = (int)plen - pnlen - 16;   /* tag 16 bayt */
    if (ct_len < 1 || ct_len > 4096) return 0;
    if (ct_off + ct_len > len) return 0;

    unsigned char aad[64];
    int aad_len = pn_offset + pnlen;
    if (aad_len > (int)sizeof(aad)) return 0;
    memcpy(aad, data, (size_t)aad_len);
    aad[0] = b0;

    unsigned char nonce[12];
    memcpy(nonce, iv, 12);
    for (int i = 0; i < 4; i++)
        nonce[11 - i] ^= (unsigned char)((pn >> (8 * i)) & 0xFF);

    unsigned char pt[4096];
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;
    int ok = 0, outl = 0, pt_len = 0;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) == 1 &&
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) == 1 &&
        EVP_DecryptUpdate(ctx, NULL, &outl, aad, aad_len) == 1 &&
        EVP_DecryptUpdate(ctx, pt, &outl, data + ct_off, ct_len) == 1) {
        pt_len = outl;
        ok = 1;
    }
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) return 0;   /* tag dogrulanmaz; sadece cozum */

    return scan_frames(pt, pt_len, out, out_len);
}

int quic_sni_extract(const unsigned char *data, int len, char *out, int out_len) {
    if (!data || !out || out_len <= 1 || len < 40) return 0;
    out[0] = '\0';

    if (!(data[0] & 0x80)) return 0;                 /* long header degil */
    if (((data[0] >> 4) & 0x03) != 0x00) return 0;   /* Initial degil */
    /* fixed bit = 1 beklenir */
    if (!(data[0] & 0x40)) return 0;

    int p = 5;   /* byte0 + version(4) */
    if (p >= len) return 0;
    int dcid_len = data[p++];
    if (dcid_len < 8 || dcid_len > 20 || p + dcid_len > len) return 0;
    const unsigned char *dcid = data + p;
    p += dcid_len;

    if (p >= len) return 0;
    int scid_len = data[p++];
    if (p + scid_len > len) return 0;
    p += scid_len;

    int u;
    unsigned long long toklen;
    if (qv_decode(data + p, len - p, &u, &toklen) < 0) return 0;
    p += u;
    if (toklen > (unsigned long long)(len - p)) return 0;
    p += (int)toklen;

    unsigned long long plen;
    if (qv_decode(data + p, len - p, &u, &plen) < 0) return 0;
    p += u;
    int pn_offset = p;
    if (pn_offset >= len) return 0;
    if (plen > (unsigned long long)(len - pn_offset)) return 0;   /* kesik yakalama */

    /* Once istemci yonu (giden ClientHello), sonra sunucu yonu */
    if (try_side(data, len, pn_offset, plen, dcid, dcid_len, "client in", out, out_len))
        return 1;
    if (try_side(data, len, pn_offset, plen, dcid, dcid_len, "server in", out, out_len))
        return 1;
    return 0;
}

#else  /* !HAVE_OPENSSL */

int quic_sni_available(void) { return 0; }

int quic_sni_extract(const unsigned char *data, int len, char *out, int out_len) {
    (void)data; (void)len; (void)out; (void)out_len;
    if (out && out_len > 0) out[0] = '\0';
    return 0;
}

#endif /* HAVE_OPENSSL */
