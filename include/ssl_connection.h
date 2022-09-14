#ifndef SSL_CONNECTION_H
#define SSL_CONNECTION_H

#include <stdbool.h>
#include <openssl/ssl.h>

SSL_CTX* create_ssl_context();

bool check_cert(SSL *ssl, const char host[]);

void ssl_send_msg(SSL *ssl, const char msg[]);

char* ssl_get_lines(SSL *ssl);

#endif

