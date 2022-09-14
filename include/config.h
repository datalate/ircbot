#ifndef CONFIG_H
#define CONFIG_H

#include <stdbool.h>
#include <libconfig.h>

typedef struct {
    char match[64];
    char reply[128];
} bot_config_reply;

typedef struct {
    char server_address[64];
    char server_port[10];
    bool use_ssl;
    char username[16];
    char nickname[16]; // NICKLEN = 9
    char channel_name[64]; // CHANNELLEN=50
    char admin_hostname[64];
    size_t num_replies;
    bot_config_reply replies[];
} bot_config;

bool load_config(const char filename[], bot_config **config);

#endif
