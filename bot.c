#define _DEFAULT_SOURCE
#define _GNU_SOURCE
#define USE_SSL

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>

#ifdef USE_SSL
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#endif

#define BUFFER_SIZE     512
#define SERVER_ADDRESS  ""
#define SERVER_PORT     ""
#define USERNAME        ""
#define NICKNAME        ""
#define CHANNEL_NAME    ""

int create_connection(const char address[], const char port[]) {
    struct addrinfo hints, *result = NULL, *rp = NULL;
    int sockfd = -1;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = 0;
    hints.ai_protocol = 0;

    if (getaddrinfo(address, port, &hints, &result) != 0) {
        printf("getaddinfo() failed\n");
        return -1;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        char ipv4[INET_ADDRSTRLEN];
        struct sockaddr_in *addr4 = (struct sockaddr_in*)rp->ai_addr;
        inet_ntop(AF_INET, &addr4->sin_addr, ipv4, INET_ADDRSTRLEN);

        printf("Connecting to %s:%s\n", ipv4, SERVER_PORT);

        if ((sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol)) == -1) {
            printf("socket() failed\n");
            continue;
        }

        if (connect(sockfd, rp->ai_addr, rp->ai_addrlen) == -1) {
            printf("connect() failed\n");
            close(sockfd);
            sockfd = -1;
            continue;
        }

        break;
    }

    freeaddrinfo(result);

    return sockfd;
}

#ifdef USE_SSL
SSL_CTX* create_ssl_context() {
    SSL_CTX *ctx = NULL;

    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();
    SSL_load_error_strings();

    if (SSL_library_init() < 0) {
        printf("SSL_library_init() failed\n");
        return NULL;
    }

    const SSL_METHOD *method = SSLv23_client_method();

    if ((ctx = SSL_CTX_new(method)) == NULL) {
        printf("SSL_CTX_new() failed\n");
        return NULL;
    }

    SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
        printf("Failed to load CA paths\n");
        SSL_CTX_free(ctx);

        return NULL;
    }

    return ctx;
}
#endif

#ifdef USE_SSL
bool check_cert(SSL *ssl, const char host[]) {
    static int MAX_CN_LENGTH = 256;

    long verify_result = 0;
    if ((verify_result = SSL_get_verify_result(ssl)) != X509_V_OK) {
        printf("Couldn't verify host certificate: %ld\n", verify_result);
        return false;
    }
    
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (cert) X509_free(cert);

    if (cert == NULL) {
        printf("Couldn't get host certificate\n");
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
        printf("Common name '%s' does not match host name '%s'\n", host_CN, host);
        return false;
    }

    return true;
}
#endif

char* format_msg(const char msg[]) {
    char *formatted;
    int len = strlen(msg);

    if (len >= BUFFER_SIZE - 2) {
        // Maximum message length is BUFFER_SIZE - CRLF
        printf("Warning: Truncated %d characters from sent message\n", len - BUFFER_SIZE - 2);
        len = BUFFER_SIZE - 2;
    }

    formatted = strndup(msg, len);

    // Append CRLF
    formatted[len++] = '\r';
    formatted[len++] = '\n';
    formatted[len] = '\0'; // for printing, not included in message

    return formatted;
}

#ifdef USE_SSL
void ssl_send_msg(SSL *ssl, const char msg[]) {
    char *send_buffer = format_msg(msg);
    int len = strlen(send_buffer);
    
    int total_write_bytes = 0, write_bytes = 0;
    while (total_write_bytes != len) {
        write_bytes = SSL_write(ssl, send_buffer + total_write_bytes, len - total_write_bytes);
        if (write_bytes <= 0) {
            int error_code = SSL_get_error(ssl, write_bytes);
            printf("SSL_write() failed: %d\n", SSL_get_error(ssl, write_bytes));

            write_bytes = 0;
            if (error_code == SSL_ERROR_WANT_WRITE) continue; else break;
        }

        printf("SSL_write(): %d bytes sent\n", write_bytes);

        total_write_bytes += write_bytes;
    }

    printf("SEND: %s", send_buffer);
    free(send_buffer);
}
#endif

void send_msg(int sockfd, const char msg[]) {
    char *send_buffer = format_msg(msg);
    int len = strlen(send_buffer);
    
    int total_write_bytes = 0, write_bytes = 0;
    while (total_write_bytes != len) {
        write_bytes = write(sockfd, send_buffer + total_write_bytes, len - total_write_bytes);
        if (write_bytes == -1) {
            printf("write() failed\n");

            break;
        }

        printf("SSL_write(): %d bytes sent\n", write_bytes);

        total_write_bytes += write_bytes;
    }

    printf("SEND: %s", send_buffer);
    free(send_buffer);
}

// <message>  ::= [':' <prefix> <SPACE> ] <command> <params> <crlf>
// <prefix>   ::= <servername> | <nick> [ '!' <user> ] [ '@' <host> ]
// <command>  ::= <letter> { <letter> } | <number> <number> <number>
// <SPACE>    ::= ' ' { ' ' }
// <params>   ::= <SPACE> [ ':' <trailing> | <middle> <params> ]
//
// <middle>   ::= <Any *non-empty* sequence of octets not including SPACE
//                or NUL or CR or LF, the first of which may not be ':'>
// <trailing> ::= <Any, possibly *empty*, sequence of octets not including
//                  NUL or CR or LF>
//
// <crlf>     ::= CR LF
#ifdef USE_SSL
void ssl_handle_line(SSL *ssl, char line[]) {
#else
void handle_line(int sockfd, char line[]) {
#endif
    if (*line == '\0') return;

    char *tok = line;
    char response[BUFFER_SIZE];
    char prefix[256], command[32], params[500]; // TODO: check lengths
    char *paramv[15];
    int paramc = 0;

    static const char googleCmd[] = "!google";

    printf("RECV: %s\n", line);

    if (*tok == ':') {
        // <servername> | <nick> [ '!' <user> ] [ '@' <host> ]
        strcpy(prefix, strsep(&tok, " ") + 1);
    }

    strcpy(command, strsep(&tok, " "));
    strcpy(params, tok);

    while (tok != NULL) {
        if (*tok == ':') {
            paramv[paramc++] = tok + 1;
            break;
        }

        paramv[paramc++] = strsep(&tok, " ");
    }

    //for(int i = 0; i < paramc; ++i) { printf("%d: %s ", i, paramv[i]); }
    //  printf("\n");

    bool send = false;
    if (strcmp(command, "PING") == 0) { // 0: ping
        snprintf(response, BUFFER_SIZE, "PONG %s", params);
        send = true;
    } else if (strcmp(command, "PRIVMSG") == 0) { // 0: target, 1: message
        if (*paramv[0] != '#') return; // only responsd to channel messages

        if (strncasecmp(paramv[1], googleCmd, strlen(googleCmd)) == 0) {
            snprintf(response, BUFFER_SIZE, "PRIVMSG %s :%s", paramv[0], "https://google.com");
            send = true;
        }
    } else if (strcmp(command, "MODE") == 0) { // 0: target, 1: mode
    } else if (strcmp(command, "INVITE") == 0) { // 0: target, 1: channel
        if (*paramv[1] != '#') return;

        snprintf(response, BUFFER_SIZE, "JOIN %s", paramv[1]);
        send = true;
    } else if (strcmp(command, "KICK") == 0) { // 0: channel, 1: nick, 2: reason
        if (*paramv[0] != '#') return;

        if (strcasecmp(paramv[1], NICKNAME) == 0) { // bot kicked
            snprintf(response, BUFFER_SIZE, "JOIN %s", paramv[0]); // re-join
            send = true;
        }
    } else if (strcmp(command, "376") == 0 || strcmp(command, "422") == 0) { // end of motd
        snprintf(response, BUFFER_SIZE, "JOIN %s", CHANNEL_NAME);
        send = true;
    }

    if (send) {
        #ifdef USE_SSL
        ssl_send_msg(ssl, response);
        #else
        send_msg(sockfd, response);
        #endif
    }
}

#ifdef USE_SSL
char* ssl_get_lines(SSL *ssl) {
#else
char* get_lines(int sockfd) {
#endif
    char *recv_buffer = calloc(0, 1); // empty calloc to be able to call realloc later on
    if (recv_buffer == NULL) {
        printf("calloc() failed\n");
        return NULL;
    }

    int recv_bytes = 0, total_recv_bytes = 0;
    bool recv_ok = false;

    while (!recv_ok) {
        char *tmp_ptr = realloc(recv_buffer, total_recv_bytes + BUFFER_SIZE + 1);

        if (tmp_ptr == NULL) {
            printf("realloc() failed\n");

            free(recv_buffer);
            break;
        }

        recv_buffer = tmp_ptr;
        memset(recv_buffer + total_recv_bytes, 0, BUFFER_SIZE + 1);

        #ifdef USE_SSL
        if ((recv_bytes = SSL_read(ssl, recv_buffer + total_recv_bytes, BUFFER_SIZE)) <= 0) {
            int error_code = SSL_get_error(ssl, recv_bytes);
            printf("SSL_read() failed: %d\n", error_code);
            recv_bytes = 0;

            if (error_code == SSL_ERROR_WANT_READ) continue; else break;
        }

        printf("SSL_read(): %d bytes received into %p\n", recv_bytes, (void*)&recv_buffer);
        #else
        if ((recv_bytes = read(sockfd, recv_buffer + total_recv_bytes, BUFFER_SIZE)) == -1) {
            printf("read() failed");
            break;
        }

        printf("read(): %d bytes received into %p\n", recv_bytes, (void*)&recv_buffer);
        #endif

        total_recv_bytes += recv_bytes;

        // Received messages should always end in CRLF
        recv_ok = recv_bytes >= 2 &&
                  recv_buffer[total_recv_bytes - 2] == '\r' &&
                  recv_buffer[total_recv_bytes - 1] == '\n';
    }

    if (!recv_ok) {
        free(recv_buffer);
        return NULL;
    }

    return recv_buffer;
}

#ifdef USE_SSL
void ssl_auth_user(SSL *ssl) {
#else
void auth_user(int sockfd) {
#endif
    char authMsg[BUFFER_SIZE];

    snprintf(authMsg, BUFFER_SIZE, "USER %s 0 * :%s\r\nNICK %s", USERNAME, USERNAME, NICKNAME);
    #ifdef USE_SSL
    ssl_send_msg(ssl, authMsg);
    #else
    send_msg(sockfd, authMsg);
    #endif
}

int main() {
    int sockfd = -1;

    if ((sockfd = create_connection(SERVER_ADDRESS, SERVER_PORT)) == -1) {
        printf("Failed to connect\n");
        return 1;
    } else {
        printf("Connection ok\n");
    }

    #ifdef USE_SSL
    SSL_CTX *ssl_ctx = NULL;
    SSL *ssl = NULL;
    if ((ssl_ctx = create_ssl_context()) == NULL) {
        printf("Failed to create SSL context\n");
        return 1;
    }

    if ((ssl = SSL_new(ssl_ctx)) == NULL) {
        printf("SSL_new() failed\n");
        return 1;
    }
    
    if (SSL_set_fd(ssl, sockfd) == 0) {
        printf("SSL_set_fd() failed\n");
        return 1;
    }
    
    if (SSL_connect(ssl) != 1) {
        printf("SSL_connect() failed\n");
        return 1;
    } else {
        printf("SSL initialized\n");
    }

    if (!check_cert(ssl, SERVER_ADDRESS)) {
        return 1;
    }
    #endif

    #ifdef USE_SSL
    ssl_auth_user(ssl);
    #else
    auth_user(sockfd);
    #endif

    while (true) {
        #ifdef USE_SSL
        char *lines = ssl_get_lines(ssl);
        #else
        char *lines = get_lines(sockfd);
        #endif
        if (lines == NULL) break;

        char *line = NULL;
        char *tok = lines;
        while ((line = strsep(&tok, "\r\n")) != NULL)
        #ifdef USE_SSL
        ssl_handle_line(ssl, line);
        #else
        handle_line(sockfd, line);
        #endif

        free(lines);
    }

    printf("Cleaning up resources and exiting\n");
    #ifdef USE_SSL
    SSL_free(ssl);
    SSL_CTX_free(ssl_ctx);
    #endif

    close(sockfd);

    return 0;
}
