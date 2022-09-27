#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <libconfig.h>

#include "config.h"

bool load_config_string(config_setting_t *cfg, const char name[], char* result) {
    const char *tmp_str;

    if (!config_setting_lookup_string(cfg, name, &tmp_str)) {
        fprintf(stderr, "Configuration missing for field '%s'\n", name);
        return false;
    }

    strcpy(result, tmp_str);
    return true;
}

bool load_config_bool(config_setting_t *cfg, const char name[], bool* result) {
    int tmp_int;

    if (!config_setting_lookup_bool(cfg, name, &tmp_int)) {
        fprintf(stderr, "Configuration missing for field '%s'\n", name);
        return false;
    }

    *result = tmp_int;
    return true;
}

bot_config_reply_data* load_config_replies(config_t cfg_file) {
    bot_config_reply_data *reply_data;

    unsigned int replies_count = 0;
    config_setting_t *cfg_setting = config_lookup(&cfg_file, "replies");

    if (cfg_setting == NULL) {
        reply_data = malloc(sizeof(*reply_data));
    } else {
        unsigned int reply_cfg_count = config_setting_length(cfg_setting);
        reply_data = malloc(sizeof(*reply_data) + reply_cfg_count * sizeof(reply_data->replies[0]));

        for (unsigned int i = 0; i < reply_cfg_count; ++i) {
            config_setting_t *reply_cfg_row = config_setting_get_elem(cfg_setting, i);
            const char *match_str, *reply_str;

            if (!(config_setting_lookup_string(reply_cfg_row, "match", &match_str) &&
                  config_setting_lookup_string(reply_cfg_row, "reply", &reply_str))) {

                printf("Ignored invalid row '%d' from reply config\n", i);
                continue;
            }

            strcpy(reply_data->replies[replies_count].match, match_str);
            strcpy(reply_data->replies[replies_count].reply, reply_str);
            replies_count++;
        }
    }

    reply_data->num_replies = replies_count;
    printf("Loaded %u replies from the config\n", replies_count);

    return reply_data;
}

bot_config_timed_message_data* load_config_timed_messages(config_t cfg_file) {
    bot_config_timed_message_data *timed_message_data;

    unsigned int timed_messages_count = 0;
    config_setting_t *cfg_setting = config_lookup(&cfg_file, "timed_messages");

    if (cfg_setting == NULL) {
        timed_message_data = malloc(sizeof(*timed_message_data));
    } else {
        unsigned int timed_message_cfg_count = config_setting_length(cfg_setting);
        timed_message_data = malloc(sizeof(*timed_message_data)
            + timed_message_cfg_count * sizeof(timed_message_data->timed_messages[0]));

        for (unsigned int i = 0; i < timed_message_cfg_count; ++i) {
            config_setting_t *timed_message_cfg_row = config_setting_get_elem(cfg_setting, i);
            const char *channel_str, *message_str;
            int at_minute_int, at_hour_int;

            if (!(config_setting_lookup_string(timed_message_cfg_row, "channel", &channel_str) &&
                  config_setting_lookup_string(timed_message_cfg_row, "message", &message_str) &&
                  config_setting_lookup_int(timed_message_cfg_row, "at_minute", &at_minute_int) &&
                  config_setting_lookup_int(timed_message_cfg_row, "at_hour", &at_hour_int))) {

                printf("Ignored invalid row '%d' from timed message config\n", i);
                continue;
            }

            strcpy(timed_message_data->timed_messages[timed_messages_count].channel, channel_str);
            strcpy(timed_message_data->timed_messages[timed_messages_count].message, message_str);
            timed_message_data->timed_messages[timed_messages_count].at_hour = at_hour_int;
            timed_message_data->timed_messages[timed_messages_count].at_minute = at_minute_int;
            timed_messages_count++;
        }
    }

    timed_message_data->num_timed_messages = timed_messages_count;
    printf("Loaded %u timed messages from the config\n", timed_messages_count);

    return timed_message_data;
}

bool load_config(const char filename[], bot_config **config) {
    config_t cfg_file;
    config_init(&cfg_file);
    bot_config *new_config;

    printf("Loading config file '%s'\n", filename);

    if (!config_read_file(&cfg_file, filename)) {
        fprintf(stderr, "Loading config '%s' failed with code %d (%s)\n", filename,
                config_error_line(&cfg_file), config_error_text(&cfg_file));

        config_destroy(&cfg_file);

        return false;
    }

    new_config = malloc(sizeof(*new_config));
    new_config->reply_data = load_config_replies(cfg_file);
    new_config->timed_message_data = load_config_timed_messages(cfg_file);

    bool load_ok = false;
    config_setting_t *cfg_setting = config_lookup(&cfg_file, "general");

    if (cfg_setting != NULL) {
        load_ok =
            load_config_string(cfg_setting, "server_address", new_config->server_address) &&
            load_config_string(cfg_setting, "server_port", new_config->server_port) &&
            load_config_bool(cfg_setting,   "use_ssl", &new_config->use_ssl) &&
            load_config_string(cfg_setting, "username", new_config->username) &&
            load_config_string(cfg_setting, "nickname", new_config->nickname) &&
            load_config_string(cfg_setting, "channel_name", new_config->channel_name) &&
            load_config_string(cfg_setting, "admin_hostname", new_config->admin_hostname);
    }

    config_destroy(&cfg_file);

    if (load_ok) {
        if ((*config) != NULL)
            cleanup_config(*config);

        *config = new_config;

        printf("Config file loaded successfully\n");
    } else {
        cleanup_config(new_config);

        fprintf(stderr, "Failed to load config file\n");
    }

    return load_ok;
}

void cleanup_config(bot_config *config) {
    free(config->reply_data);
    free(config->timed_message_data);
    free(config);
}

