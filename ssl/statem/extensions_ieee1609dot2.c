#include <openssl/ocsp.h>
#include "../ssl_local.h"
#include "statem_local.h"
#include "../ieee1609dot2.h"
#include <openssl/ssl.h>


/* Parse extension sent from client to server */
static int tls_parse_ctos_cert_type_ext(SSL *s, PACKET *pkt, unsigned int context, X509 *x,
                  size_t chainidx, int ext_idx)
{
    size_t list_len;
    RFC8902_CERT_TYPE * cert_type_data;

    if (!SSL_is_RFC8902_supported(s)) {
        return 0;
    }

    cert_type_data = SSL_get_RFC8902_CERT_TYPE(s, ext_idx);

    // packet contains array of the supported types
    if (!PACKET_get_1_len(pkt, &list_len)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    /* Consistency check */
    if (PACKET_remaining(pkt) != list_len) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    // loop through cert types
    int client_allows_x509 = 0;
    int client_allows_1609 = 0;
    for (size_t i = 0; i < list_len; i++) {
        unsigned int cert_type;
        if (!PACKET_get_1(pkt, &cert_type)) {
            SSLfatal(s, SSL_AD_DECODE_ERROR, ERR_R_INTERNAL_ERROR);
            return 0;
        }
        if (cert_type == CertificateTypeX509) {
            client_allows_x509 = 1;
        }
        if (cert_type == CertificateType1609Dot2) {
            client_allows_1609 = 1;
        }
    }
    // prefer 1609;
    if ((cert_type_data->support & SSL_RFC8902_1609) && client_allows_1609) {
        cert_type_data->type_decided = CertificateType1609Dot2;
    } else if ((cert_type_data->support & SSL_RFC8902_X509) && client_allows_x509){
        cert_type_data->type_decided = CertificateTypeX509;
    } else {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_UNSUPPORTED_CERT_TYPE);
        return 0;
    }

    return 1;
}

/* Parse extension sent from server to client */
static int tls_parse_stoc_cert_type_ext(SSL *s, PACKET *pkt, unsigned int context, X509 *x,
                size_t chainidx, int ext_idx)
{
    unsigned int cert_type;
    RFC8902_CERT_TYPE * cert_type_data;

    if (!SSL_is_RFC8902_supported(s)) {
        return 0;
    }

    cert_type_data = SSL_get_RFC8902_CERT_TYPE(s, ext_idx);

    // packet contains single chosen type
    /* Consistency check */
    if (PACKET_remaining(pkt) != 1) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (!PACKET_get_1(pkt, &cert_type)) {
        SSLfatal(s, SSL_AD_DECODE_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if ((cert_type_data->support & SSL_RFC8902_1609)
            && cert_type == CertificateType1609Dot2) {
        cert_type_data->type_decided = cert_type;
    } else if ((cert_type_data->support & SSL_RFC8902_X509)
            && cert_type == CertificateTypeX509) {
        cert_type_data->type_decided = cert_type;
    } else {
        SSLfatal(s, SSL_AD_DECODE_ERROR, SSL_R_UNSUPPORTED_CERT_TYPE);
        return 0;
    }

    return 1;
}

/* Construct extension sent from server to client */
static EXT_RETURN tls_construct_stoc_cert_type_ext(SSL *s, WPACKET *pkt, unsigned int context,
                           X509 *x, size_t chainidx, int ext_idx)
{
    RFC8902_CERT_TYPE * cert_type_data;

    if (!SSL_is_RFC8902_supported(s)) {
        return EXT_RETURN_NOT_SENT;
    }

    cert_type_data = SSL_get_RFC8902_CERT_TYPE(s, ext_idx);

    // if nothing is agreed something went very wrong
    if (cert_type_data->type_decided == -1) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return EXT_RETURN_FAIL;
    }

    // send single type supported by the client
    if (!WPACKET_put_bytes_u16(pkt, ext_idx)
        || !WPACKET_start_sub_packet_u16(pkt)
        || !WPACKET_put_bytes_u8(pkt, cert_type_data->type_decided)
        || !WPACKET_close(pkt)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return EXT_RETURN_FAIL;
        }
    return EXT_RETURN_SENT;
}

/* Construct extension sent from client to server */
static int tls_construct_ctos_cert_type_ext(SSL *s, WPACKET *pkt, unsigned int context,
                           X509 *x, size_t chainidx, int ext_idx)
{
    RFC8902_CERT_TYPE * cert_type_data;

    if (!SSL_is_RFC8902_supported(s)) {
        return 2;
    }

    cert_type_data = SSL_get_RFC8902_CERT_TYPE(s, ext_idx);

    if (!WPACKET_put_bytes_u16(pkt, ext_idx)
        || !WPACKET_start_sub_packet_u16(pkt)
        || !WPACKET_start_sub_packet_u8(pkt)
        || ((cert_type_data->support & SSL_RFC8902_X509)
                ? !WPACKET_put_bytes_u8(pkt, CertificateTypeX509)
                : 0)
        || ((cert_type_data->support & SSL_RFC8902_1609)
                ? !WPACKET_put_bytes_u8(pkt, CertificateType1609Dot2)
                : 0)
        || !WPACKET_close(pkt)
        || !WPACKET_close(pkt)) {
            SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return 0;
        }
    return 1;
}

/* Parse extension sent from client to server */
int tls_parse_ctos_srv_type_ext(SSL *s, PACKET *pkt, unsigned int context, X509 *x,
                  size_t chainidx)
{
    return tls_parse_ctos_cert_type_ext(s, pkt, context, x, chainidx,
        TLSEXT_TYPE_server_certificate_type);
}

/* Parse extension sent from server to client */
int tls_parse_stoc_srv_type_ext(SSL *s, PACKET *pkt, unsigned int context, X509 *x,
                size_t chainidx)
{
    return tls_parse_stoc_cert_type_ext(s, pkt, context, x, chainidx,
        TLSEXT_TYPE_server_certificate_type);
}

/* Construct extension sent from server to client */
EXT_RETURN tls_construct_stoc_srv_type_ext(SSL *s, WPACKET *pkt, unsigned int context,
                           X509 *x, size_t chainidx)
{
    return tls_construct_stoc_cert_type_ext(s, pkt, context, x, chainidx,
            TLSEXT_TYPE_server_certificate_type);
}

/* Construct extension sent from client to server */
EXT_RETURN tls_construct_ctos_srv_type_ext(SSL *s, WPACKET *pkt, unsigned int context,
                           X509 *x, size_t chainidx)
{
    return tls_construct_ctos_cert_type_ext(s, pkt, context, x, chainidx,
            TLSEXT_TYPE_server_certificate_type);
}

/* Parse extension sent from client to server */
int tls_parse_ctos_clnt_type_ext(SSL *s, PACKET *pkt, unsigned int context, X509 *x,
                  size_t chainidx)
{
    //RFC7250: The server MUST also include a certificate_request payload in the server hello message
    // is this the correct way?
    SSL_set_verify(s, SSL_VERIFY_PEER, NULL);
    return tls_parse_ctos_cert_type_ext(s, pkt, context, x, chainidx,
            TLSEXT_TYPE_client_certificate_type);
}

/* Parse extension sent from server to client */
int tls_parse_stoc_clnt_type_ext(SSL *s, PACKET *pkt, unsigned int context, X509 *x,
                size_t chainidx)
{
    return tls_parse_stoc_cert_type_ext(s, pkt, context, x, chainidx,
            TLSEXT_TYPE_client_certificate_type);
}

/* Construct extension sent from server to client */
EXT_RETURN tls_construct_stoc_clnt_type_ext(SSL *s, WPACKET *pkt, unsigned int context,
                           X509 *x, size_t chainidx)
{
    return tls_construct_stoc_cert_type_ext(s, pkt, context, x, chainidx,
            TLSEXT_TYPE_client_certificate_type);
}

/* Construct extension sent from client to server */
EXT_RETURN tls_construct_ctos_clnt_type_ext(SSL *s, WPACKET *pkt, unsigned int context,
                           X509 *x, size_t chainidx)
{
    return tls_construct_ctos_cert_type_ext(s, pkt, context, x, chainidx,
            TLSEXT_TYPE_client_certificate_type);
}