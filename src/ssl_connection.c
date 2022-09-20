#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include "ssl_connection.h"
#include "common.h"

SSL_CTX* create_ssl_context() {
    SSL_CTX *ctx = NULL;

    OpenSSL_add_all_algorithms();
    //ERR_load_BIO_strings();
    //ERR_load_crypto_strings();
    SSL_load_error_strings();

    if (SSL_library_init() < 0) {
        fprintf(stderr, "SSL_library_init() failed\n");
        return NULL;
    }

    const SSL_METHOD *method = TLS_client_method();

    if ((ctx = SSL_CTX_new(method)) == NULL) {
        fprintf(stderr, "SSL_CTX_new() failed\n");
        return NULL;
    }

    SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    SSL_CTX_set_options(ctx, SSL_OP_ALL);
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
        fprintf(stderr, "Failed to load CA paths\n");
        SSL_CTX_free(ctx);

        return NULL;
    }

    return ctx;
}

// TODO: not really needed, as hosts are verified while using version 1.1.0
bool check_cert(SSL *ssl, const char host[]) {
    static int MAX_CN_LENGTH = 256;

    long verify_result = 0;
    if ((verify_result = SSL_get_verify_result(ssl)) != X509_V_OK) {
        fprintf(stderr, "Couldn't verify host certificate: %ld\n", verify_result);
        return false;
    }
    
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (cert) X509_free(cert);

    if (cert == NULL) {
        fprintf(stderr, "Couldn't get host certificate\n");
        return false;
    }

    char host_CN[MAX_CN_LENGTH];

    // TODO: X509_NAME_oneline is deprecated in favor of X509_NAME_print_ex
    X509_NAME *subject_name = X509_get_subject_name(cert);
    char* subject_name_txt = X509_NAME_oneline(subject_name, NULL, 4096);
    printf("Certificate information: %s\n", subject_name_txt);
    free(subject_name_txt);

    X509_NAME_get_text_by_NID(subject_name, NID_commonName, host_CN, MAX_CN_LENGTH);

    if (strcasecmp(host_CN, host) != 0) {
        fprintf(stderr, "Common name '%s' does not match host name '%s'\n", host_CN, host);
        return false;
    }

    return true;
}

void ssl_send_msg(SSL *ssl, const char msg[]) {
    char *send_buffer = format_msg(msg);
    if (send_buffer == NULL) return;

    int len = strlen(send_buffer);
    
    int total_write_bytes = 0, write_bytes = 0;
    while (total_write_bytes != len) {
        write_bytes = SSL_write(ssl, send_buffer + total_write_bytes, len - total_write_bytes);
        if (write_bytes <= 0) {
            int error_code = SSL_get_error(ssl, write_bytes);
            fprintf(stderr, "SSL_write() failed: %d\n", SSL_get_error(ssl, write_bytes));

            write_bytes = 0;
            if (error_code == SSL_ERROR_WANT_WRITE) continue; else break;
        }

        printf("SSL_write(): %d bytes sent\n", write_bytes);

        total_write_bytes += write_bytes;
    }

    printf("SEND: %s", send_buffer);
    free(send_buffer);
}

char* ssl_get_lines(SSL *ssl) {
    char *recv_buffer = calloc(0, 1); // empty calloc to be able to call realloc later on
    if (recv_buffer == NULL) {
        fprintf(stderr, "calloc() failed\n");
        return NULL;
    }

    int recv_bytes = 0, total_recv_bytes = 0;
    bool recv_ok = false;

    while (!recv_ok) {
        char *tmp_ptr = realloc(recv_buffer, total_recv_bytes + BUFFER_SIZE + 1);

        if (tmp_ptr == NULL) {
            fprintf(stderr, "realloc() failed\n");

            free(recv_buffer);
            break;
        }

        recv_buffer = tmp_ptr;
        memset(recv_buffer + total_recv_bytes, 0, BUFFER_SIZE + 1);

        if ((recv_bytes = SSL_read(ssl, recv_buffer + total_recv_bytes, BUFFER_SIZE)) <= 0) {
            int error_code = SSL_get_error(ssl, recv_bytes);
            fprintf(stderr, "SSL_read() failed: %d\n", error_code);
            recv_bytes = 0;

            if (error_code == SSL_ERROR_WANT_READ) continue; else break;
        }

        printf("SSL_read(): %d bytes received into %p\n", recv_bytes, &recv_buffer);

        total_recv_bytes += recv_bytes;

        // Received messages should always end in CRLF
        recv_ok = total_recv_bytes >= 2 &&
                  recv_buffer[total_recv_bytes - 2] == '\r' &&
                  recv_buffer[total_recv_bytes - 1] == '\n';
    }

    if (!recv_ok) {
        free(recv_buffer);
        return NULL;
    }

    return recv_buffer;
}

