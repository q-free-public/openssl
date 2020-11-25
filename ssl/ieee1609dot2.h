#pragma once

#include "internal/packet.h"
#include <openssl/x509.h>
#include <openssl/ssl.h>

#define TLSEXT_TYPE_client_certificate_type 19
#define TLSEXT_TYPE_server_certificate_type 20

// check if cert is a 1609.2 certificate
int X509_is_IEEE1609_CERT(X509 * x);
// create new certificate which in fact is an IEEE1609.2 certificate
X509 * X509_new_IEEE1609_CERT(const unsigned char **ppin, long length);
// include 1609 test cert in X509 cert structure
int X509_append_IEEE1609_CERT_test(X509 * x);

void IEEE1609_TLS_init();

// Verify 1609.2 certificate from X509 struct
int IEEE1609_CERT_verify(X509 * x);

// Are we using 1609 for client / server authentication
int SSL_is_using_1609_client(SSL *s);
int SSL_is_using_1609_server(SSL *s);
int SSL_is_using_1609_this_side(SSL *s);
int SSL_is_using_1609_other_side(SSL *s);
int SSL_is_RFC8902_supported(SSL * s);

// add 1609.2 Certificate to TLS Certificate message (instead of X509)
int ssl_add_IEEE1609_CERT_to_wpacket(SSL *s, WPACKET *pkt, X509 *x, int chain);

// Generate 1609.2 Certificate Verify message, using provided cert & input
int tls_construct_IEEE1609_CERT_cert_verify(SSL *s, WPACKET *pkt, X509* x,
    const unsigned char * input, size_t input_len);
// Verify 1609.2 Certificate Verify message, using provided cert & data structures
int tls_process_IEEE1609_CERT_cert_verify(SSL *s, X509 * x,
    const unsigned char * verify_input, size_t verify_input_len,
    const unsigned char * verify_data, size_t verify_data_len);


/* Parse extension sent from client to server */
int tls_parse_ctos_srv_type_ext(SSL *s, PACKET *pkt, unsigned int context, X509 *x,
                  size_t chainidx);
/* Parse extension send from server to client */
int tls_parse_stoc_srv_type_ext(SSL *s, PACKET *pkt, unsigned int context, X509 *x,
                size_t chainidx);
/* Construct extension sent from server to client */
int tls_construct_stoc_srv_type_ext(SSL *s, WPACKET *pkt, unsigned int context,
                           X509 *x, size_t chainidx);
/* Construct extension sent from client to server */
int tls_construct_ctos_srv_type_ext(SSL *s, WPACKET *pkt, unsigned int context,
                           X509 *x, size_t chainidx);
/* Parse extension sent from client to server */
int tls_parse_ctos_clnt_type_ext(SSL *s, PACKET *pkt, unsigned int context, X509 *x,
                 size_t chainidx);
/* Parse extension send from server to client */
int tls_parse_stoc_clnt_type_ext(SSL *s, PACKET *pkt, unsigned int context, X509 *x,
               size_t chainidx);
/* Construct extension sent from server to client */
int tls_construct_stoc_clnt_type_ext(SSL *s, WPACKET *pkt, unsigned int context,
                          X509 *x, size_t chainidx);
/* Construct extension sent from client to server */
int tls_construct_ctos_clnt_type_ext(SSL *s, WPACKET *pkt, unsigned int context,
                          X509 *x, size_t chainidx);


// int SSL_use_1609_cert(SSL *s, const unsigned char * data, size_t len);
