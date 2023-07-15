// https://github.com/openssl/openssl/issues/6904
//#define _POSIX_C_SOURCE 1
#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>
#include <errno.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <signal.h>
#include <string.h>
#include <getopt.h>
#include <pcap.h>

/* Managed by IANA */
 enum CertificateType{
	 CertificateTypeX509 = 0,
	 CertificateTypeRawPublicKey = 2,
	 CertificateType1609Dot2 = 3
 } ;


unsigned char __1609dot2_ec_cert_hash[8] = {
	0xC4, 0x3B, 0x88, 0xB2, 0x35, 0x81, 0xDD, 0x3B
};

void handler(int signal) {
    fprintf(stderr, "Server received %d signal\n", signal);
}

pid_t server_pid = -1;
int force_x509 = 0;
char server_ip[INET_ADDRSTRLEN] = "127.0.0.1";

void terminate() {
	if (server_pid >= 0) {
		kill(server_pid, SIGTERM);
	}
	exit(EXIT_FAILURE);
}

FILE *keylog_server_file = NULL;
FILE *keylog_client_file = NULL;

void keylog_client_cb_func(const SSL *ssl, const char *line) {
	if (keylog_client_file != NULL) {
		fprintf(keylog_client_file, "%s\n", line);
		fflush(keylog_client_file);
	} else {
		printf("keylog_client_cb_func: %s\n", line);
	}
}

void keylog_srv_cb_func(const SSL *ssl, const char *line) {
	if (keylog_server_file != NULL) {
		fprintf(keylog_server_file, "%s\n", line);
		fflush(keylog_server_file);
	} else {
		printf("keylog_srv_cb_func: %s\n", line);
	}
}

int ssl_send_message(SSL *s, char * message, size_t message_len) {
	int processed = 0;

	printf("Sending [%ld] %.*s\n", message_len, (int)message_len, message);
	for (const char *start = message; start - message < message_len;
	     start += processed) {

		processed = SSL_write(s, start, message_len - (start - message));
		printf("Client SSL_write returned %d\n", processed);
		if (processed <= 0) {
			int ssl_err = SSL_get_error(s, processed);
			if (ssl_err != SSL_ERROR_WANT_READ && ssl_err != SSL_ERROR_WANT_WRITE) {
				fprintf(stderr, "ssl_send_message failed: ssl_error=%d: ", ssl_err);
				ERR_print_errors_fp(stderr);
				fprintf(stderr, "\n");
			}
		}
	};

	return processed;
}

int ssl_recv_message(SSL *s, char * buff, size_t buff_len) {
	int processed;

	processed = SSL_read(s, buff, buff_len);
	printf("SSL_read returned %d\n", processed);
	if (processed > 0) {
		printf("[recv:] %.*s\n", (int)processed, buff);
	}
	return processed;
}

int ssl_print_1609_status(SSL *s) {
//	uint64_t psid;
//	unsigned char hashed_id[8];
//	if(SSL_get_1609_psid_received(s, &psid, hashed_id) <= 0) {
//		ERR_print_errors_fp(stderr);
//		fprintf(stderr, "SSL_get_1609_psid_received failed\n");
//		return 0;
//	}
//	long verify_result = 0;
//	if((verify_result = SSL_get_verify_result(s)) != X509_V_OK) {
//		ERR_print_errors_fp(stderr);
//		fprintf(stderr, "SSL_get_verify_result failed %ld\n", verify_result);
//		return 0;
//	} else {
//		printf("Peer verification %ld\n", verify_result);
//	}
//
//	printf("Psid used for TLS is %ld\n", psid);
//	printf("Cert used for TLS is ");
//	for (int i = 0; i < 8; i++) {
//		printf("%02X", hashed_id[i]);
//	}
//	printf("\n");
	return 1;
}

void server(int server_port, int test_mode) {
	char buffer[1024];
	int processed;
	SSL_CTX *ssl_ctx;
	SSL *ssl;
	int retval;

	keylog_server_file = fopen("keylog_server.txt", "a");
	if (keylog_server_file == NULL) {
		perror("Error opening file!");
		exit(EXIT_FAILURE);
	}

	struct sockaddr_in server_addr;
	memset((char *) &server_addr, 0, sizeof(server_addr));  /* 0 out the structure */
	server_addr.sin_family = AF_INET;   /* address family */
	server_addr.sin_port = htons(server_port);
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

	/* Server */
	int server_socket = socket(AF_INET, SOCK_STREAM, 0);
	int true = 1;
	if (server_socket < 0) {
		perror("socket failed");
		exit(EXIT_FAILURE);
	}
	if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &true, sizeof(true))) {
		perror("setsockopt failed\n");
		exit(EXIT_FAILURE);
	}
	if (bind(server_socket, (const struct sockaddr *) &server_addr, sizeof(server_addr))) {
		perror("bind failed");
		exit(EXIT_FAILURE);
	}
	if (listen(server_socket, 1)) {
		perror("listen failed");
		exit(EXIT_FAILURE);
	}

	int fd;
	struct sigaction action;
	sigset_t sigset;

	printf("Server\n");

	sigemptyset(&sigset);
	action.sa_handler = handler;
	action.sa_flags = 0;
	action.sa_mask = sigset;
	sigaction(SIGPIPE, &action, NULL);

	int handle_clients = 1;
	while (handle_clients) {
		printf("Waiting for client.. \n");

		fd = accept(server_socket, NULL, 0);
		if (fd < 0) {
			perror("accept failed");
			exit(EXIT_FAILURE);
		}
		printf("TCP accepted.\n");

		/*if (!OPENSSL_init_ssl(0, NULL)) {
			fprintf(stderr, "OPENSSL_init_ssl failed\n");
			exit(EXIT_FAILURE);
		}*/
		/*OpenSSL_add_ssl_algorithms();*/
		ssl_ctx = SSL_CTX_new(TLS_server_method());
		if (!ssl_ctx) {
			fprintf(stderr, "SSL_CTX_new failed\n");
			exit(EXIT_FAILURE);
		}
		SSL_CTX_set_keylog_callback(ssl_ctx, keylog_srv_cb_func);
		if (!SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION)) {
			fprintf(stderr, "SSL_CTX_set_min_proto_version failed: ");
			ERR_print_errors_fp(stderr);
			exit(EXIT_FAILURE);
		}
		if (1 != SSL_CTX_load_verify_locations(ssl_ctx, "ca.cert.pem", NULL)) {
			fprintf(stderr, "SSL_CTX_load_verify_locations failed: ");
			ERR_print_errors_fp(stderr);
			exit(EXIT_FAILURE);
		}
		ssl = SSL_new(ssl_ctx);
		if (!ssl) {
			fprintf(stderr, "SSL_new failed\n");
			exit(EXIT_FAILURE);
		}
		int server_support = SSL_RFC8902_1609 | SSL_RFC8902_X509;
		if (force_x509) {
			server_support = SSL_RFC8902_X509;
		}
		if (!SSL_enable_RFC8902_support(ssl, server_support,
		                                SSL_RFC8902_1609 | SSL_RFC8902_X509)) {
			fprintf(stderr, "SSL_enable_RFC8902_support failed\n");
			ERR_print_errors_fp(stderr);
			exit(EXIT_FAILURE);
		}
		if (force_x509) {
			if (1 != SSL_use_PrivateKey_file(ssl, "server.key.pem", SSL_FILETYPE_PEM)) {
				fprintf(stderr, "SSL_use_PrivatKey_file failed: ");
				ERR_print_errors_fp(stderr);
				exit(EXIT_FAILURE);
			}
			if (1 != SSL_use_certificate_file(ssl, "server.cert.pem", SSL_FILETYPE_PEM)) {
				fprintf(stderr, "SSL_use_certificate_file failed: ");
				ERR_print_errors_fp(stderr);
				exit(EXIT_FAILURE);
			}
		} else {
			if (!SSL_use_1609_cert_by_hash(ssl, __1609dot2_ec_cert_hash, 623)) {
				fprintf(stderr, "SSL_use_1609_cert_by_hash failed\n");
				ERR_print_errors_fp(stderr);
				exit(EXIT_FAILURE);
			}
		}
		if (!SSL_set_fd(ssl, fd)) {
			fprintf(stderr, "SSL_set_fd failed\n");
			exit(EXIT_FAILURE);
		}
	#if OPENSSL_VERSION_NUMBER >= 0x1010100fL
		/* TLS 1.3 server sends session tickets after a handhake as part of
		 * the SSL_accept(). If a client finishes all its job before server
		 * sends the tickets, SSL_accept() fails with EPIPE errno. Since we
		 * are not interested in a session resumption, we can not to send the
		 * tickets. */
		/*if (1 != SSL_set_num_tickets(ssl, 0)) {
			fprintf(stderr, "SSL_set_num_tickets failed\n");
			exit(EXIT_FAILURE);
		}
		Or we can perform two-way shutdown. Client must call SSL_read() before
		the final SSL_shutdown(). */
	#endif

		retval = SSL_accept(ssl);
		if (retval <= 0) {
			fprintf(stderr, "SSL_accept failed ssl_err=%d errno=%s: ",
			        SSL_get_error(ssl, retval), strerror(errno));
			ERR_print_errors_fp(stderr);
			fprintf(stderr, "\n");
			exit(EXIT_FAILURE);
		}
		printf("SSL accepted.\n");
		if (ssl_print_1609_status(ssl) == 0) {
			terminate();
		}

		while (1) {
			processed = SSL_read(ssl, buffer, sizeof(buffer));
			printf("Server SSL_read returned %d\n", processed);
			if (processed > 0) {
				printf("[server:] %.*s\n", (int) processed, buffer);
				ssl_send_message(ssl, buffer, processed);
				if (strcmp(buffer, "exit") == 0) {
					handle_clients = 0;
				}
			} else {
				int ssl_error = SSL_get_error(ssl, processed);
				if (ssl_error == SSL_ERROR_ZERO_RETURN) {
					printf("Server thinks a client closed a TLS session\n");
					ERR_print_errors_fp(stderr);
					break;
				}
				if (ssl_error != SSL_ERROR_WANT_READ &&
				    ssl_error != SSL_ERROR_WANT_WRITE) {
					fprintf(stderr, "server read failed: ssl_error=%d:\n", ssl_error);
					ERR_print_errors_fp(stderr);
					fprintf(stderr, "\n");
					exit(EXIT_FAILURE);
				}
			}

		}
		printf("Server read finished.\n");

		retval = SSL_shutdown(ssl);
		if (retval < 0) {
			int ssl_err = SSL_get_error(ssl, retval);
			fprintf(stderr, "Server SSL_shutdown failed: ssl_err=%d\n", ssl_err);
			terminate();
		}
		printf("Server shut down a TLS session.\n");

		if (retval != 1) {
			retval = SSL_shutdown(ssl);
			if (retval != 1) {
				int ssl_err = SSL_get_error(ssl, retval);
				fprintf(stderr,
				        "Waiting for client shutdown using SSL_shutdown failed: "
				        "ssl_err=%d\n", ssl_err);
				terminate();
			}
		}
		printf("Server thinks a client shut down the TLS session.\n");

		SSL_free(ssl);
		SSL_CTX_free(ssl_ctx);
		close(fd);
		if (test_mode) {
			printf("Server exiting test mode...\n");
			handle_clients = 0;
		}
	}
	if (keylog_server_file != NULL) {
		fflush(keylog_server_file);
		fclose(keylog_server_file);
	}
	exit(EXIT_SUCCESS);
}

void client(int server_port, int test_mode) {
	int client_socket;
	SSL_CTX *ssl_ctx;
	SSL *ssl;
	const char message[] = "text\n";
	char buffer[1024];
	int processed;
	int wstatus;
	int retval;

	keylog_client_file = fopen("keylog_client.txt", "a");
	if (keylog_client_file == NULL) {
		perror("Error opening file!");
		exit(EXIT_FAILURE);
	}

	/* Client */
    printf("Client\n");
    client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket < 0) {
        perror("socket failed");
		terminate();
    }
	struct sockaddr_in server_addr;
	memset((char*)&server_addr, 0, sizeof(server_addr));  /* 0 out the structure */
	server_addr.sin_family = AF_INET;   /* address family */
	server_addr.sin_port = htons(server_port);
	server_addr.sin_addr.s_addr = inet_addr(server_ip);
    if (connect(client_socket, (const struct sockaddr *)&server_addr, sizeof(server_addr))) {
        perror("connect failed");
		terminate();
    }
    printf("TCP connected.\n");

    /*if (!OPENSSL_init_ssl(0, NULL)) {
        fprintf(stderr, "OPENSSL_init_ssl failed\n");
        kill(server_pid, SIGTERM);
        exit(EXIT_FAILURE);
    }*/
    /*OpenSSL_add_ssl_algorithms();*/
    ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!ssl_ctx) {
        fprintf(stderr, "SSL_CTX_new failed\n");
		terminate();
    }
	SSL_CTX_set_keylog_callback(ssl_ctx, keylog_client_cb_func);
	if (!SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION)) {
		fprintf(stderr, "SSL_CTX_set_min_proto_version failed: ");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	if (1 != SSL_CTX_load_verify_locations(ssl_ctx, "ca.cert.pem", NULL)) {
		fprintf(stderr, "SSL_CTX_load_verify_locations failed: ");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    ssl = SSL_new(ssl_ctx);
    if (!ssl) {
		ERR_print_errors_fp(stderr);
        fprintf(stderr, "SSL_new failed\n");
		terminate();
    }
    int server_support = SSL_RFC8902_1609 | SSL_RFC8902_X509;
    int client_support = SSL_RFC8902_1609 | SSL_RFC8902_X509;
    if (force_x509) {
    	client_support = SSL_RFC8902_X509;
    }
	if (!SSL_enable_RFC8902_support(ssl, server_support, client_support)) {
		fprintf(stderr, "SSL_enable_RFC8902_support failed\n");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	if (force_x509) {
		if (1 != SSL_use_PrivateKey_file(ssl, "client.key.pem", SSL_FILETYPE_PEM)) {
			fprintf(stderr, "SSL_CTX_use_PrivatKey_file failed: ");
			ERR_print_errors_fp(stderr);
			terminate();
		}
		if (1 != SSL_use_certificate_file(ssl, "client.cert.pem", SSL_FILETYPE_PEM)) {
			fprintf(stderr, "SSL_CTX_use_certificate_file failed: ");
			ERR_print_errors_fp(stderr);
			terminate();
		}
	} else {
		if (!SSL_use_1609_cert_by_hash(ssl, __1609dot2_ec_cert_hash, 623)) {
			fprintf(stderr, "SSL_use_1609_cert_by_hash failed\n");
			ERR_print_errors_fp(stderr);
			exit(EXIT_FAILURE);
		}
	}
    if (!SSL_set_fd(ssl, client_socket)) {
		ERR_print_errors_fp(stderr);
        fprintf(stderr, "SSL_set_fd failed\n");
        terminate();
    }
    if (SSL_connect(ssl) <= 0) {
		ERR_print_errors_fp(stderr);
        fprintf(stderr, "SSL_connect failed\n");
        terminate();
    }
    printf("SSL connected.\n");
    if (ssl_print_1609_status(ssl) <= 0) {
    	terminate();
    }

    int send_messages = 1;
    while (send_messages) {
	    printf("input message to server\n");
	    char *line = NULL;
	    size_t line_len = 0;
	    if (test_mode) {
			line = malloc(10);
			line_len = sprintf(line, "test");
	    } else {
		    if ((line_len = getline(&line, &line_len, stdin)) == -1) {
			    if (line != NULL) {
				    free(line);
			    }
			    fprintf(stderr, "getline failed\n");
			    terminate();
		    }
	    }

	    if (ssl_send_message(ssl, line, line_len) < 0) {
	    	terminate();
	    }
	    if ((processed = ssl_recv_message(ssl, line, line_len)) < 0) {
		    int ssl_error = SSL_get_error(ssl, processed);
		    ERR_print_errors_fp(stderr);
		    if (ssl_error == SSL_ERROR_ZERO_RETURN) {
			    printf("Client thinks a server finished sending data\n");
			    ERR_print_errors_fp(stderr);
			    break;
		    }
		    if (ssl_error != SSL_ERROR_WANT_READ &&
		        ssl_error != SSL_ERROR_WANT_WRITE) {
			    fprintf(stderr, "Client read failed: ssl_error=%d errno=%s: \n",
			            ssl_error, strerror(errno));
			    ERR_print_errors_fp(stderr);
			    terminate();
		    }
	    }

	    printf("Client write finished.\n");
	    if (strcmp(line, "exit\n") == 0) {
		    printf("Exiting client...\n");
		    send_messages = 0;
	    }
	    free(line);
	    if (test_mode) {
	    	printf("Client exiting test mode...\n");
	    	send_messages = 0;
	    }
    }

    retval = SSL_shutdown(ssl);
    if (retval < 0) {
        int ssl_err = SSL_get_error(ssl, retval);
        fprintf(stderr, "Client SSL_shutdown failed: ssl_err=%d\n", ssl_err);
		ERR_print_errors_fp(stderr);
        terminate();
    }
    printf("Client shut down TLS session.\n");

    if (retval != 1) {
        /* Consume all server's data to access the server's shutdown */
	    char buff[10];
	    while (ssl_recv_message(ssl, buff, 10) > 0) {
        }

        retval = SSL_shutdown(ssl);
        if (retval != 1) {
            int ssl_err = SSL_get_error(ssl, retval);
            fprintf(stderr,
                    "Waiting for server shutdown using SSL_shutdown failed: "
                    "ssl_err=%d\n", ssl_err);
			terminate();
        }
    }
    printf("Client thinks a server shut down the TLS session.\n");

    if (shutdown(client_socket, SHUT_RDWR)) {
        perror("client shutdown failed");
		terminate();
    }
    printf("Client shut down TCP.\n");

    SSL_free(ssl);
    SSL_CTX_free(ssl_ctx);
	fclose(keylog_client_file);
	if (server_pid >= 0) {
		if (server_pid == waitpid(server_pid, &wstatus, 0)) {
			if (WIFEXITED(wstatus)){
				printf("Server process terminated normally with %d exit code\n",
				WEXITSTATUS(wstatus));
			} else if (WIFSIGNALED(wstatus)) {
				printf("Server process terminated with %d signal\n",
				WTERMSIG(wstatus));
			}
		}
	}
    exit(EXIT_SUCCESS);
}

int main(int argc, char **argv) {
	short unsigned int server_port = 3322;
	int start_client = 0;
	int start_server = 0;
	int test = 0;
	int opt, rc;

	while ((opt = getopt(argc, argv, "p:a:cstx")) != -1) {
		switch (opt) {
		case 'c': start_client = 1; break;
		case 's': start_server = 1; break;
		case 'p':
			rc = sscanf(optarg, "%hu", &server_port);
			if (rc < 1) {
				fprintf(stderr, "String-integer conversion error for %s\n", optarg);
				exit(EXIT_FAILURE);
			}
			break;
		case 't': test = 1; break;
		case 'x': force_x509 = 1; break;
		case 'a':
			strcpy(server_ip, optarg);
			break;
		default:
			fprintf(stderr, "Usage: %s [-p port] [-c -> client] [-s -> server]\n"
					"  -t - test mode\n"
					"  -x - force X509 cert\n"
					"  -a - server address\n", argv[0]);
			exit(EXIT_FAILURE);
		}
	}

	printf("Using port %hu\n", server_port);

	if (!(start_client || start_server)) {
		test = 1;
		start_client = 1;
		start_server = 1;
	}

	if (start_client && start_server) {
		test = 1;
	    server_pid = fork();
	    if (server_pid < 0) {
	        perror("fork failed");
	        exit(EXIT_FAILURE);
	    } else if (server_pid == 0) {
			server(server_port, test);
	    }
		sleep(1);
		client(server_port, test);
	} else {
		if (start_client) {
			client(server_port, test);
		}
		if (start_server) {
			server(server_port, test);
		}
	}


}
