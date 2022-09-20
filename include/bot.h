#ifndef BOT_H
#define BOT_H

#include <time.h>
#include <stdbool.h>
#include <openssl/ssl.h>

#include "config.h"

typedef struct {
    struct timespec start_time;
    SSL_CTX *ssl_ctx;
    SSL *ssl;
    int sockfd;
    bool use_ssl;
} bot_data;

typedef struct { // TODO: check lengths
    char prefix[256];
    char command[32];
    char params[507];
    char nick[32]; // parsed from prefix
    char user[64]; // parsed from prefix
    char host[64]; // parsed from prefix
    size_t paramc;
    char *paramv[16];
} irc_message;

bool init_ssl(bot_data *data, const char server_address[]);

void cleanup(bot_data *data);

void send_auth(bot_config *config, bot_data *data);

void handle_connection(bot_config **config, bot_data *data);

#endif

