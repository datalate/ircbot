#ifndef CONFIG_H
#define CONFIG_H

#include <stdbool.h>
#include <libconfig.h>

typedef struct {
    char match[256];
    char reply[256];
} bot_config_reply;

typedef struct {
    char server_address[256];
    char server_port[6];
    bool use_ssl;
    char username[64];
    char nickname[32];
    char channel_name[64];
    char admin_hostname[64];
    size_t num_replies;
    bot_config_reply replies[];
} bot_config;

bool load_config(const char filename[], bot_config **config);

#endif
