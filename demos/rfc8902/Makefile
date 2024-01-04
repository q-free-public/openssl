OPENSSL_DIR=../..

all: tls_client

tls_client: tls_client.c
	$(CC) -g -I$(OPENSSL_DIR)/include -L$(OPENSSL_DIR) -Wl,-rpath=$(OPENSSL_DIR) \
	-o $@ $< -lssl -lcrypto

client_cert:
	LD_LIBRARY_PATH=$(OPENSSL_DIR) $(OPENSSL_DIR)/apps/openssl \
	 req -config openssl.conf -x509 -newkey rsa:4096 \
	 -keyout key.pem -out cert.pem -days 365 -nodes

clean:
	rm -rf tls_client

run: tls_client
	-LD_LIBRARY_PATH=$(OPENSSL_DIR) ./tls_client
	$(shell cat keylog_client.txt keylog_server.txt > keylog_merged.txt)
