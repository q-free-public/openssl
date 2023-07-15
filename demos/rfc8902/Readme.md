## Wireshark decryption

See https://wiki.wireshark.org/TLS#Using_the_.28Pre.29-Master-Secret

Server secret file is `keylog_server.txt`

Running connection between host machine and sec-ent client:
```
Run on ITS-S:

$ socat tcp-listen:3999,reuseaddr,fork tcp:localhost:3912

Listens on itsXXX:3999 <-connects to-> 127.0.0.1:3912

To listen on another device:
socat tcp-listen:3999,reuseaddr,fork tcp:ITS_IP_ADDR:3999
```

## Open questions
 - Should extensions be in CertificateRequest from the server?

	I think so, but Wireshark complains...
 - signerIdentifier - Full cert or digest?

# Openssl changes:
 - X509 cert structure with version set to 0x1609 is used
 - IEE1609_CERT struct is stored in X509 EX_DATA


# Working parts:
 - adding extensions, based on client/server & type of message (Client Hello/ CertificateRequest, etc..)
 - injecting a fixed certificate in a Server Hello

 - include certificate from the client
 - registered generate CertificateVerify callback
 - registered verify CertificateVerify callback
 - setting `PduFunctionalType` header extension
 - Sending proper CertificateVerify message
 - Verifying CertificateVerify message


# TO DO:
 - using proper certs, not fixed buffers
 - I think cert verification is done twice - this is not necessary
 - send only TLS 1.3 version
 - process the client_cert_type and server_cert_type extensions properly
    extensions.c
 - including CertificateRequest from the server??
 - make sure communication fails if we request a certificate and don't get it!
 s->session->peer [here we decide on extensions?]


# Adding certificate in a server
 - Based on RFC7250 (4.2) cert should be put in Certificate payload, and extension (to Server Hello) set to `server_certificate_type`
 > With the server_certificate_type extension in the server hello,
 > the TLS server indicates the certificate type carried in the
 > Certificate payload.


## References:
 - https://tools.ietf.org/html/rfc8446
 - https://tools.ietf.org/html/rfc7250
 - https://tools.ietf.org/html/rfc8902
