#!/bin/bash

set -eu

# ca key and cert should be common for all communication members
if [ ! -f ca.key.pem ]; then
  openssl genrsa -out ca.key.pem 2048
  openssl req -x509 -new -nodes -key ca.key.pem -sha256 -days 365 -out ca.cert.pem -subj /C=US/ST=CA/L=Somewhere/O=Someone/CN=FoobarCA
fi

openssl genrsa -out server.key.pem 2048
openssl genrsa -out client.key.pem 2048


openssl req -new -sha256 -key server.key.pem -subj /C=US/ST=CA/L=Somewhere/O=Someone/CN=Foobar -out server.csr
openssl x509 -req -in server.csr -CA ca.cert.pem -CAkey ca.key.pem -CAcreateserial -out server.cert.pem -days 365 -sha256

openssl req -new -sha256 -key client.key.pem -subj /C=US/ST=CA/L=Somewhere/O=Someone/CN=Foobar -out client.csr
openssl x509 -req -in client.csr -CA ca.cert.pem -CAkey ca.key.pem -CAcreateserial -out client.cert.pem -days 365 -sha256