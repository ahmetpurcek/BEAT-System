/*
 * cam_net.c — Kamera modulu paylasilan ag + kripto altyapisi (uygulama)
 */
#include "cam_net.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <poll.h>

#ifdef HAVE_OPENSSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

/* =====================================================================
 * TCP / TLS baglanti
 * ===================================================================== */

#ifdef HAVE_OPENSSL
static void cam_tls_init_once(void) {
    static int done = 0;
    if (done) return;
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    done = 1;
}
#endif


static int cam_tcp_connect(const char *ip, int port, int timeout_ms) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, ip, &a.sin_addr) != 1) { close(fd); return -1; }

    struct timeval tv = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    int one = 1; setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    int fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    int r = connect(fd, (struct sockaddr *)&a, sizeof(a));
    if (r == 0) { fcntl(fd, F_SETFL, fl); return fd; }
    if (errno != EINPROGRESS) { close(fd); return -1; }

    struct pollfd pfd = { .fd = fd, .events = POLLOUT };
    if (poll(&pfd, 1, timeout_ms) <= 0) { close(fd); return -1; }
    int err = 0; socklen_t el = sizeof(err);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el) < 0 || err != 0) {
        close(fd); return -1;
    }
    fcntl(fd, F_SETFL, fl);
    return fd;
}

int cam_conn_open(CamConn *c, const char *ip, int port, int timeout_ms, int tls) {
    if (!c) return -1;
    c->fd = -1; c->ssl = NULL; c->is_tls = 0;
    int fd = cam_tcp_connect(ip, port, timeout_ms);
    if (fd < 0) return -1;
    c->fd = fd;

#ifdef HAVE_OPENSSL
    if (tls) {
        cam_tls_init_once();
        SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx) { close(fd); c->fd = -1; return -2; }
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
        SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
        SSL *ssl = SSL_new(ctx);
        if (!ssl) { SSL_CTX_free(ctx); close(fd); c->fd = -1; return -2; }
        SSL_set_fd(ssl, fd);
        int r = SSL_connect(ssl);
        /* ctx'i SSL'e bagli tutariz; SSL_free'ta ayri serbest birakilir. */
        if (r != 1) { SSL_free(ssl); SSL_CTX_free(ctx); close(fd); c->fd = -1; return -2; }
        c->ssl = ssl;
        c->is_tls = 1;
        return 0;
    }
#else
    if (tls) { close(fd); c->fd = -1; return -2; }
#endif
    return 0;
}

int cam_conn_write(CamConn *c, const void *buf, int len, int timeout_ms) {
    if (!c || c->fd < 0) return -1;
#ifdef HAVE_OPENSSL
    if (c->is_tls) {
        SSL *ssl = (SSL *)c->ssl;
        int sent = 0;
        while (sent < len) {
            int n = SSL_write(ssl, (const char *)buf + sent, len - sent);
            if (n > 0) { sent += n; continue; }
            int e = SSL_get_error(ssl, n);
            if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
                struct pollfd pfd = { .fd = c->fd, .events = (e == SSL_ERROR_WANT_READ) ? POLLIN : POLLOUT };
                if (poll(&pfd, 1, timeout_ms) <= 0) break;
                continue;
            }
            break;
        }
        return sent;
    }
#endif
    int sent = 0;
    while (sent < len) {
        int n = (int)send(c->fd, (const char *)buf + sent, len - sent, MSG_NOSIGNAL);
        if (n > 0) { sent += n; continue; }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            struct pollfd pfd = { .fd = c->fd, .events = POLLOUT };
            if (poll(&pfd, 1, timeout_ms) <= 0) break;
            continue;
        }
        break;
    }
    return sent;
}

int cam_conn_read(CamConn *c, void *buf, int len, int timeout_ms) {
    if (!c || c->fd < 0) return -1;
#ifdef HAVE_OPENSSL
    if (c->is_tls) {
        SSL *ssl = (SSL *)c->ssl;
        for (;;) {
            int n = SSL_read(ssl, buf, len);
            if (n > 0) return n;
            int e = SSL_get_error(ssl, n);
            if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
                struct pollfd pfd = { .fd = c->fd, .events = (e == SSL_ERROR_WANT_READ) ? POLLIN : POLLOUT };
                if (poll(&pfd, 1, timeout_ms) <= 0) return 0;
                continue;
            }
            return 0;   /* kapanis / hata */
        }
    }
#endif
    struct pollfd pfd = { .fd = c->fd, .events = POLLIN };
    if (poll(&pfd, 1, timeout_ms) <= 0) return 0;
    int n = (int)recv(c->fd, buf, len, 0);
    return n < 0 ? 0 : n;
}

void cam_conn_close(CamConn *c) {
    if (!c) return;
#ifdef HAVE_OPENSSL
    if (c->is_tls && c->ssl) {
        SSL *ssl = (SSL *)c->ssl;
        SSL_CTX *ctx = SSL_get_SSL_CTX(ssl);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        if (ctx) SSL_CTX_free(ctx);
        c->ssl = NULL;
    }
#endif
    if (c->fd >= 0) { close(c->fd); c->fd = -1; }
    c->is_tls = 0;
}

/* =====================================================================
 * Base64
 * ===================================================================== */
void cam_b64_encode(const unsigned char *in, int len, char *out, int outlen) {
    static const char *t =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int i = 0, o = 0;
    while (i < len && o + 5 < outlen) {
        int n = len - i;
        unsigned v = (unsigned)in[i] << 16;
        if (n > 1) v |= (unsigned)in[i + 1] << 8;
        if (n > 2) v |= (unsigned)in[i + 2];
        out[o++] = t[(v >> 18) & 63];
        out[o++] = t[(v >> 12) & 63];
        out[o++] = (n > 1) ? t[(v >> 6) & 63] : '=';
        out[o++] = (n > 2) ? t[v & 63] : '=';
        i += 3;
    }
    out[o] = '\0';
}

/* =====================================================================
 * MD5 (RFC 1321, saf C)
 * ===================================================================== */
typedef struct { uint32_t h[4]; uint64_t len; unsigned char b[64]; size_t bl; } cam_md5_ctx;

static const uint32_t MD5_K[64] = {
    0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
    0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
    0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
    0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
    0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
    0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
    0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
    0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
};
static const int MD5_S[64] = {
    7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
    5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
    4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
    6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21
};

static uint32_t rol32(uint32_t x, int c){ return (x << c) | (x >> (32 - c)); }

static void md5_block(cam_md5_ctx *ctx, const unsigned char *p) {
    uint32_t m[16];
    for (int i = 0; i < 16; i++)
        m[i] = (uint32_t)p[i*4] | ((uint32_t)p[i*4+1] << 8) |
               ((uint32_t)p[i*4+2] << 16) | ((uint32_t)p[i*4+3] << 24);
    uint32_t a = ctx->h[0], b = ctx->h[1], c = ctx->h[2], d = ctx->h[3];
    for (int i = 0; i < 64; i++) {
        uint32_t f; int g;
        if (i < 16)      { f = (b & c) | (~b & d);      g = i; }
        else if (i < 32) { f = (d & b) | (~d & c);      g = (5*i + 1) % 16; }
        else if (i < 48) { f = b ^ c ^ d;               g = (3*i + 5) % 16; }
        else             { f = c ^ (b | ~d);            g = (7*i) % 16; }
        uint32_t tmp = d;
        d = c; c = b;
        b = b + rol32(a + f + MD5_K[i] + m[g], MD5_S[i]);
        a = tmp;
    }
    ctx->h[0] += a; ctx->h[1] += b; ctx->h[2] += c; ctx->h[3] += d;
}

void cam_md5(const unsigned char *in, size_t len, unsigned char out[16]) {
    cam_md5_ctx ctx;
    ctx.h[0]=0x67452301; ctx.h[1]=0xefcdab89; ctx.h[2]=0x98badcfe; ctx.h[3]=0x10325476;
    ctx.len = 0; ctx.bl = 0;
    size_t i = 0;
    while (i < len) {
        ctx.b[ctx.bl++] = in[i++];
        if (ctx.bl == 64) { md5_block(&ctx, ctx.b); ctx.len += 64; ctx.bl = 0; }
    }
    uint64_t bits = (uint64_t)len * 8;
    ctx.b[ctx.bl++] = 0x80;
    if (ctx.bl > 56) { while (ctx.bl < 64) ctx.b[ctx.bl++] = 0; md5_block(&ctx, ctx.b); ctx.bl = 0; }
    while (ctx.bl < 56) ctx.b[ctx.bl++] = 0;
    for (int k = 0; k < 8; k++) ctx.b[56 + k] = (unsigned char)(bits >> (8 * k));
    md5_block(&ctx, ctx.b);
    for (int k = 0; k < 4; k++) {
        out[k*4]   = (unsigned char)(ctx.h[k]);
        out[k*4+1] = (unsigned char)(ctx.h[k] >> 8);
        out[k*4+2] = (unsigned char)(ctx.h[k] >> 16);
        out[k*4+3] = (unsigned char)(ctx.h[k] >> 24);
    }
}

static void hex32(const unsigned char *in, int n, char *out) {
    static const char *h = "0123456789abcdef";
    for (int i = 0; i < n; i++) { out[i*2] = h[in[i] >> 4]; out[i*2+1] = h[in[i] & 15]; }
    out[n*2] = '\0';
}
void cam_md5_hex(const void *in, size_t len, char out[33]) {
    unsigned char d[16];
    cam_md5((const unsigned char *)in, len, d);
    hex32(d, 16, out);
}

/* =====================================================================
 * SHA1 (RFC 3174, saf C)
 * ===================================================================== */
typedef struct { uint32_t h[5]; uint64_t len; unsigned char b[64]; size_t bl; } cam_sha1_ctx;

static void sha1_block(cam_sha1_ctx *ctx, const unsigned char *p) {
    uint32_t w[80];
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[i*4] << 24) | ((uint32_t)p[i*4+1] << 16) |
               ((uint32_t)p[i*4+2] << 8) | (uint32_t)p[i*4+3];
    for (int i = 16; i < 80; i++)
        w[i] = rol32(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
    uint32_t a=ctx->h[0], b=ctx->h[1], c=ctx->h[2], d=ctx->h[3], e=ctx->h[4];
    for (int i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20)      { f = (b & c) | (~b & d);              k = 0x5a827999; }
        else if (i < 40) { f = b ^ c ^ d;                        k = 0x6ed9eba1; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d);      k = 0x8f1bbcdc; }
        else             { f = b ^ c ^ d;                        k = 0xca62c1d6; }
        uint32_t tmp = rol32(a, 5) + f + e + k + w[i];
        e = d; d = c; c = rol32(b, 30); b = a; a = tmp;
    }
    ctx->h[0]+=a; ctx->h[1]+=b; ctx->h[2]+=c; ctx->h[3]+=d; ctx->h[4]+=e;
}

void cam_sha1(const unsigned char *in, size_t len, unsigned char out[20]) {
    cam_sha1_ctx ctx;
    ctx.h[0]=0x67452301; ctx.h[1]=0xEFCDAB89; ctx.h[2]=0x98BADCFE; ctx.h[3]=0x10325476; ctx.h[4]=0xC3D2E1F0;
    ctx.len = 0; ctx.bl = 0;
    size_t i = 0;
    while (i < len) {
        ctx.b[ctx.bl++] = in[i++];
        if (ctx.bl == 64) { sha1_block(&ctx, ctx.b); ctx.len += 64; ctx.bl = 0; }
    }
    uint64_t bits = (uint64_t)len * 8;
    ctx.b[ctx.bl++] = 0x80;
    if (ctx.bl > 56) { while (ctx.bl < 64) ctx.b[ctx.bl++] = 0; sha1_block(&ctx, ctx.b); ctx.bl = 0; }
    while (ctx.bl < 56) ctx.b[ctx.bl++] = 0;
    for (int k = 0; k < 8; k++) ctx.b[56 + k] = (unsigned char)(bits >> (8 * (7 - k)));
    sha1_block(&ctx, ctx.b);
    for (int k = 0; k < 5; k++) {
        out[k*4]   = (unsigned char)(ctx.h[k] >> 24);
        out[k*4+1] = (unsigned char)(ctx.h[k] >> 16);
        out[k*4+2] = (unsigned char)(ctx.h[k] >> 8);
        out[k*4+3] = (unsigned char)(ctx.h[k]);
    }
}

void cam_sha1_b64(const void *in, size_t len, char *out, int outlen) {
    unsigned char d[20];
    cam_sha1((const unsigned char *)in, len, d);
    cam_b64_encode(d, 20, out, outlen);
}


void cam_make_nonce(char *out, int outlen) {
    unsigned char rnd[16];
    int got = 0;
    FILE *fp = fopen("/dev/urandom", "rb");
    if (fp) { got = (int)fread(rnd, 1, sizeof(rnd), fp); fclose(fp); }
    if (got < 16) {
        unsigned long seed = (unsigned long)time(NULL) ^ ((unsigned long)getpid() << 16) ^ (unsigned long)(uintptr_t)out;
        for (int i = got; i < 16; i++) { seed = seed * 6364136223846793005UL + 1442695040888963407UL; rnd[i] = (unsigned char)(seed >> 33); }
    }
    /* hex */
    static const char *h = "0123456789abcdef";
    int n = 16;
    if (outlen < n*2 + 1) n = (outlen - 1) / 2;
    for (int i = 0; i < n; i++) { out[i*2] = h[rnd[i] >> 4]; out[i*2+1] = h[rnd[i] & 15]; }
    out[n*2] = '\0';
}

/* =====================================================================
 * HTTP istemcisi
 * ===================================================================== */
static void parse_header_line(CamHttpResp *r, const char *line) {
    const char *c = strchr(line, ':');
    if (!c) return;
    const char *v = c + 1;
    while (*v == ' ' || *v == '\t') v++;
    int keylen = (int)(c - line);
    int vlen = 0;
    while (v[vlen] && v[vlen] != '\r' && v[vlen] != '\n') vlen++;

    if (keylen == 6 && !strncasecmp(line, "Server", 6)) {
        int n = vlen < (int)sizeof(r->server)-1 ? vlen : (int)sizeof(r->server)-1;
        memcpy(r->server, v, n); r->server[n] = '\0';
    } else if (keylen == 8 && !strncasecmp(line, "Location", 8)) {
        int n = vlen < (int)sizeof(r->location)-1 ? vlen : (int)sizeof(r->location)-1;
        memcpy(r->location, v, n); r->location[n] = '\0';
    } else if (keylen == 12 && !strncasecmp(line, "Content-Type", 12)) {
        int n = vlen < (int)sizeof(r->content_type)-1 ? vlen : (int)sizeof(r->content_type)-1;
        memcpy(r->content_type, v, n); r->content_type[n] = '\0';
    } else if (keylen == 16 && !strncasecmp(line, "WWW-Authenticate", 16)) {
        int n = vlen < (int)sizeof(r->www_auth)-1 ? vlen : (int)sizeof(r->www_auth)-1;
        memcpy(r->www_auth, v, n); r->www_auth[n] = '\0';
    } else if (keylen == 10 && !strncasecmp(line, "Set-Cookie", 10)) {
        if (!r->set_cookie[0]) {
            int n = vlen < (int)sizeof(r->set_cookie)-1 ? vlen : (int)sizeof(r->set_cookie)-1;
            memcpy(r->set_cookie, v, n); r->set_cookie[n] = '\0';
        }
    }
}

/*
 * Bir yaniti okur: basliklar + govde.
 *  - Baslik blogu kapali buffer'da biriktirilir.
 *  - Govde Content-Length'e gore (varsa) veya baglanti kapanana kadar (sinirli) okunur.
 */
static int read_response(CamConn *c, char *body, int bodylen, CamHttpResp *resp) {
    char raw[16384];
    int total = 0;
    int header_end = -1;
    int idle_ms = 1200;

    /* Basliklari topla */
    while (total < (int)sizeof(raw) - 1) {
        char tmp[4096];
        int n = cam_conn_read(c, tmp, sizeof(tmp), idle_ms);
        if (n <= 0) break;
        if (total + n > (int)sizeof(raw) - 1) n = (int)sizeof(raw) - 1 - total;
        memcpy(raw + total, tmp, n);
        total += n;
        raw[total] = '\0';
        char *he = strstr(raw, "\r\n\r\n");
        if (he) { header_end = (int)(he - raw) + 4; break; }
    }
    if (total <= 0) return -1;
    if (header_end < 0) header_end = total;

    /* Durum satiri */
    int status = 0;
    {
        char *sp = strchr(raw, ' ');
        if (sp) status = atoi(sp + 1);
    }
    if (resp) {
        resp->status = status;
        int hlen = header_end < (int)sizeof(resp->headers) ? header_end : (int)sizeof(resp->headers)-1;
        memcpy(resp->headers, raw, hlen);
        resp->headers[hlen] = '\0';
        /* Satir satir baslik ayristir */
        char *p = raw;
        char *line_end;
        while (p < raw + header_end && (line_end = strstr(p, "\r\n")) != NULL) {
            if (line_end == p) break;           /* bos satir: baslik sonu */
            parse_header_line(resp, p);
            p = line_end + 2;
        }
    }

    /* Govde */
    int body_have = total - header_end;
    if (body && bodylen > 0) {
        int bn = body_have < bodylen - 1 ? body_have : bodylen - 1;
        if (bn > 0) memcpy(body, raw + header_end, bn);
        body[bn] = '\0';

        /* Content-Length varsa eksik kismi tamamla (sinirli) */
        long cl = -1;
        if (resp && resp->headers[0]) {
            const char *clh = NULL;
            /* basliklari kucuk/buyuk harf duyarsiz ara */
            const char *s = resp->headers;
            while ((s = strchr(s, '\n')) != NULL) {
                s++;
                if (!strncasecmp(s, "Content-Length:", 15)) { clh = s + 15; break; }
            }
            if (clh) cl = atol(clh);
        }
        if (cl > 0 && bn < cl && bn < bodylen - 1) {
            while (bn < (int)cl && bn < bodylen - 1) {
                int n = cam_conn_read(c, body + bn, bodylen - 1 - bn, idle_ms);
                if (n <= 0) break;
                bn += n;
            }
            body[bn] = '\0';
        }
    }
    return 0;
}

int cam_http_request(const char *ip, int port, int tls,
                     const char *method, const char *path,
                     const char *host_header, const char *extra_headers,
                     int timeout_ms, char *body, int bodylen, CamHttpResp *resp) {
    if (body && bodylen > 0) body[0] = '\0';
    if (resp) memset(resp, 0, sizeof(*resp));

    CamConn c;
    if (cam_conn_open(&c, ip, port, timeout_ms, tls) != 0) return -1;

    char req[2048];
    int host_port = (tls && port == 443) || (!tls && port == 80) ? 0 : 1;
    char hostbuf[160];
    if (host_header && host_header[0]) snprintf(hostbuf, sizeof(hostbuf), "%s", host_header);
    else if (host_port) snprintf(hostbuf, sizeof(hostbuf), "%s:%d", ip, port);
    else snprintf(hostbuf, sizeof(hostbuf), "%s", ip);

    snprintf(req, sizeof(req),
             "%s %s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "User-Agent: Mozilla/5.0\r\n"
             "Accept: */*\r\n"
             "Connection: close\r\n"
             "%s"
             "\r\n",
             method ? method : "GET", (path && path[0]) ? path : "/",
             hostbuf, extra_headers ? extra_headers : "");

    if (cam_conn_write(&c, req, (int)strlen(req), timeout_ms) <= 0) {
        cam_conn_close(&c);
        return -1;
    }
    int r = read_response(&c, body, bodylen, resp);
    cam_conn_close(&c);
    return r;
}

int cam_wwwauth_is_digest(const char *www_auth) {
    return www_auth && strcasestr(www_auth, "digest") != NULL;
}

/* www_auth icinden parametre degerini cikar (tirnakli veya degil). */
static void digest_param(const char *hdr, const char *key, char *out, int outlen) {
    out[0] = '\0';
    const char *p = hdr;
    int kl = (int)strlen(key);
    while ((p = strcasestr(p, key)) != NULL) {
        const char *q = p + kl;
        while (*q == ' ' || *q == '=') q++;
        if (*q == '"') {
            q++;
            const char *e = strchr(q, '"');
            if (e) {
                int n = (int)(e - q);
                if (n >= outlen) n = outlen - 1;
                memcpy(out, q, n); out[n] = '\0';
                return;
            }
        } else {
            int n = 0;
            while (q[n] && q[n] != ',' && q[n] != ' ' && q[n] != '\r' && q[n] != '\n' && n < outlen - 1) { out[n] = q[n]; n++; }
            out[n] = '\0';
            if (n) return;
        }
        p = q;
    }
}

void cam_http_digest_header(const char *user, const char *pass,
                            const char *www_auth,
                            const char *method, const char *uri,
                            char *out, int outlen) {
    char realm[128], nonce[128], qop[64], opaque[128], algorithm[32];
    digest_param(www_auth, "realm", realm, sizeof(realm));
    digest_param(www_auth, "nonce", nonce, sizeof(nonce));
    digest_param(www_auth, "qop", qop, sizeof(qop));
    digest_param(www_auth, "opaque", opaque, sizeof(opaque));
    digest_param(www_auth, "algorithm", algorithm, sizeof(algorithm));

    char ha1[33], ha2[33], nc[16], cnonce[40];
    cam_make_nonce(cnonce, 24);
    snprintf(nc, sizeof(nc), "00000001");

    {
        char buf[512];
        snprintf(buf, sizeof(buf), "%s:%s:%s", user ? user : "", realm, pass ? pass : "");
        cam_md5_hex(buf, strlen(buf), ha1);
    }
    {
        char buf[512];
        snprintf(buf, sizeof(buf), "%s:%s", method ? method : "GET", uri ? uri : "/");
        cam_md5_hex(buf, strlen(buf), ha2);
    }

    char response[33];
    if (qop[0] && strcasestr(qop, "auth")) {
        char buf[1024];
        snprintf(buf, sizeof(buf), "%s:%s:%s:%s:%s:%s",
                 ha1, nonce, nc, cnonce, "auth", ha2);
        cam_md5_hex(buf, strlen(buf), response);
        snprintf(out, outlen,
                 "Authorization: Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", "
                 "uri=\"%s\", qop=auth, nc=%s, cnonce=\"%s\", response=\"%s\"%s%s%s\r\n",
                 user ? user : "", realm, nonce, uri ? uri : "/", nc, cnonce, response,
                 opaque[0] ? ", opaque=\"" : "", opaque[0] ? opaque : "",
                 opaque[0] ? "\"" : "");
    } else {
        char buf[1024];
        snprintf(buf, sizeof(buf), "%s:%s:%s", ha1, nonce, ha2);
        cam_md5_hex(buf, strlen(buf), response);
        snprintf(out, outlen,
                 "Authorization: Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", "
                 "uri=\"%s\", response=\"%s\"%s%s%s\r\n",
                 user ? user : "", realm, nonce, uri ? uri : "/", response,
                 opaque[0] ? ", opaque=\"" : "", opaque[0] ? opaque : "",
                 opaque[0] ? "\"" : "");
    }
}

