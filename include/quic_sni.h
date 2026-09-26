/*
 * quic_sni.h — QUIC Initial paketinden istemci TLS SNI cikarimi.
 *
 * Site karartma motoru, UDP/443 trafiginde (HTTP/3) hangi siteye
 * gidildigini gormek icin QUIC Initial paketini cozer: RFC 9001 geregi
 * Initial paketler, DCID turevli sabit tuz ile sifrelenir; bu yuzden
 * anahtar/IV/HP degerleri elle turetilebilir.
 *
 * OpenSSL (libcrypto) yoksa cikarim yapilamaz; quic_sni_available() 0 doner
 * ve motor ICMP fallback'e duser (istemciyi TCP/TLS'e zorlar).
 */
#ifndef QUIC_SNI_H
#define QUIC_SNI_H

/* data = UDP yuku basi (QUIC long header). Basariliysa 1 + out'a kucuk
 * harfli SNI yazilir, aksi halde 0. */
int quic_sni_extract(const unsigned char *data, int len, char *out, int out_len);

/* OpenSSL destegi derlenmis mi? 0 = yok. */
int quic_sni_available(void);

#endif /* QUIC_SNI_H */
