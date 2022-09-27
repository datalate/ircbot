#ifndef CONFIG_H
#define CONFIG_H

#include <stdbool.h>
#include <libconfig.h>

typedef struct {
    char match[256];
    char reply[256];
} bot_config_reply;

typedef struct {
    size_t num_replies;
    bot_config_reply replies[];
} bot_config_reply_data;

typedef struct {
    char channel[64];
    char message[256];
    int at_hour;
    int at_minute;
} bot_config_timed_message;

typedef struct {
    size_t num_timed_messages;
    bot_config_timed_message timed_messages[];
} bot_config_timed_message_data;

typedef struct {
    char server_address[256];
    char server_port[6];
    bool use_ssl;
    char username[64];
    char nickname[32];
    char channel_name[64];
    char admin_hostname[64];
    bot_config_reply_data *reply_data;
    bot_config_timed_message_data *timed_message_data;
} bot_config;

bool load_config(const char filename[], bot_config **config);
void cleanup_config(bot_config *config);

#endif
