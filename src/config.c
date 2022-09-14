#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <libconfig.h>

#include "config.h"

bool load_config_string(config_setting_t *cfg, const char name[], char* result) {
    const char *tmp_str;

    if (!config_setting_lookup_string(cfg, name, &tmp_str)) {
        printf("Configuration missing for field '%s'\n", name);
        return false;
    }

    strcpy(result, tmp_str);
    return true;
}

bool load_config_bool(config_setting_t *cfg, const char name[], bool* result) {
    int tmp_int;

    if (!config_setting_lookup_bool(cfg, name, &tmp_int)) {
        printf("Configuration missing for field '%s'\n", name);
        return false;
    }

    *result = tmp_int;
    return true;
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

    unsigned int replies_count = 0;
    config_setting_t *cfg_setting = config_lookup(&cfg_file, "replies");

    if (cfg_setting == NULL) {
        new_config = malloc(sizeof(*new_config));
    } else {
        unsigned int reply_cfg_count = config_setting_length(cfg_setting);
        new_config = malloc(sizeof(*new_config) + reply_cfg_count * sizeof(new_config->replies[0]));

        for (unsigned int i = 0; i < reply_cfg_count; ++i) {
            config_setting_t *reply_cfg_row = config_setting_get_elem(cfg_setting, i);
            const char *match_str, *reply_str;

            if (!(config_setting_lookup_string(reply_cfg_row, "match", &match_str) &&
                  config_setting_lookup_string(reply_cfg_row, "reply", &reply_str))) {

                printf("Ignored invalid row '%d' from reply config\n", i);
                continue;
            }

            strcpy(new_config->replies[replies_count].match, match_str);
            strcpy(new_config->replies[replies_count].reply, reply_str);
            replies_count++;
        }
    }

    new_config->num_replies = replies_count;
    printf("Loaded %u replies from the config\n", replies_count);

    bool load_ok = false;
    cfg_setting = config_lookup(&cfg_file, "general");

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
            free(*config);
        *config = new_config;

        printf("Config file loaded successfully\n");
    } else {
        free(new_config);

        printf("Failed to load config file\n");
    }

    return load_ok;
}

