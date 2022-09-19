#define _DEFAULT_SOURCE
#define _GNU_SOURCE

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <time.h>
#include <openssl/ssl.h>

#include "common.h"
#include "config.h"
#include "connection.h"
#include "ssl_connection.h"

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
    char params[500];
    char nick[16]; // parsed from prefix
    char user[16]; // parsed from prefix
    char host[64]; // parsed from prefix
    int paramc;
    char *paramv[15]; // parsed from params
} irc_message;

irc_message parse_message(const char msg[]) {
    irc_message ircmsg;
    ircmsg.paramc = 0;
    for (int c = 0; c < 16; ++c)
        ircmsg.paramv[c] = NULL;

    printf("RECV: %s\n", msg);

    char *msg_tmp = strdup(msg);
    char *tok = msg_tmp;

    if (*tok == ':') {
        // <servername> | <nick> [ '!' <user> ] [ '@' <host> ]
        strcpy(ircmsg.prefix, strsep(&tok, " ") + 1);

        char *prefix_tmp = strdup(ircmsg.prefix);
        char *prefix_tok = prefix_tmp;

        strcpy(ircmsg.nick, strsep(&prefix_tok, "!"));
        if (prefix_tok != NULL) {
            strcpy(ircmsg.user, strsep(&prefix_tok, "@"));
            if (prefix_tok != NULL) {
                strcpy(ircmsg.host, prefix_tok);
            }
        }
        free(prefix_tmp);
    }

    strcpy(ircmsg.command, strsep(&tok, " "));
    strcpy(ircmsg.params, tok);

    while (tok != NULL) {
        if (*tok == ':') {
            ircmsg.paramv[ircmsg.paramc++] = tok + 1;
            break;
        }

        ircmsg.paramv[ircmsg.paramc++] = strsep(&tok, " ");
    }

    free(msg_tmp);
    return ircmsg;

    //for(int i = 0; i < paramc; ++i) { printf("%d: %s ", i, paramv[i]); }
    //  printf("\n");
}

void send_message(bot_data *data, const char msg[]) {
    if (data->use_ssl)
        ssl_send_msg(data->ssl, msg);
    else
        send_msg(data->sockfd, msg);
}

bool init_ssl(bot_data *data, const char server_address[]) {
    if (data->ssl_ctx == NULL && (data->ssl_ctx = create_ssl_context()) == NULL) {
        printf("Failed to create SSL context\n");
        return false;
    }

    if (data->ssl == NULL && (data->ssl = SSL_new(data->ssl_ctx)) == NULL) {
        printf("SSL_new() failed\n");
        return false;
    } else if (SSL_clear(data->ssl) == 0) {
        printf("SSL_clear() failed\n");
        return false;
    }

    if (SSL_set_fd(data->ssl, data->sockfd) == 0) {
        printf("SSL_set_fd() failed\n");
        return false;
    }

    if (SSL_connect(data->ssl) != 1) {
        printf("SSL_connect() failed\n");
        return false;
    }

    printf("SSL initialized\n");

    if (!check_cert(data->ssl, server_address)) {
        return false;
    }

    return true;
}

void cleanup(bot_data *data) {
    if (data->ssl != NULL)
        SSL_free(data->ssl);

    if (data->ssl_ctx != NULL)
        SSL_CTX_free(data->ssl_ctx);
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
void handle_line(const char line[], bot_config **config, bot_data *data) {
    if (*line == '\0') return;

    irc_message msg = parse_message(line);

    char response[BUFFER_SIZE];
    bool send = false;

    if (strcmp(msg.command, "PING") == 0) { // 0: ping
        snprintf(response, BUFFER_SIZE, "PONG %s", msg.params);
        send = true;
    } else if (strcmp(msg.command, "PRIVMSG") == 0) { // 0: target, 1: message
        if (*msg.paramv[0] != '#') return; // only respond to channel messages

        bool is_admin = strcmp(msg.host, (*config)->admin_hostname) == 0;

        if (is_admin && strcasecmp(msg.paramv[1], "!reload") == 0) {
            load_config(CONFIG_FILE, config);
        } else if (strcasecmp(msg.paramv[1], "!uptime") == 0) {
            struct timespec current_time;

            clock_gettime(CLOCK_MONOTONIC_RAW, &current_time);
            int seconds_passed = current_time.tv_sec - data->start_time.tv_sec;
            int minutes = seconds_passed / 60;
            int seconds = seconds_passed % 60;
            int hours = minutes / 60;
            minutes = minutes % 60;

            snprintf(response, BUFFER_SIZE, "PRIVMSG %s :Current uptime: %02d:%02d:%02d", msg.paramv[0], hours, minutes, seconds);
            send = true;
        } else {
            for (unsigned int i = 0; i < (*config)->num_replies; ++i) {
                if (strcasecmp(msg.paramv[1], (*config)->replies[i].match) == 0) {
                    snprintf(response, BUFFER_SIZE, "PRIVMSG %s :%s", msg.paramv[0], (*config)->replies[i].reply);
                    send = true;
                    break;
                }
            }
        }
    } else if (strcmp(msg.command, "MODE") == 0) { // 0: target, 1: mode
    } else if (strcmp(msg.command, "INVITE") == 0) { // 0: target, 1: channel
        if (*msg.paramv[1] != '#') return;

        snprintf(response, BUFFER_SIZE, "JOIN %s", msg.paramv[1]);
        send = true;
    } else if (strcmp(msg.command, "KICK") == 0) { // 0: channel, 1: nick, 2: reason
        if (*msg.paramv[0] != '#') return;

        // TODO: compare to current nick instead of nick in config
        if (strcasecmp(msg.paramv[1], (*config)->nickname) == 0) { // bot kicked
            snprintf(response, BUFFER_SIZE, "JOIN %s", msg.paramv[0]); // re-join
            send = true;
        }
    } else if (strcmp(msg.command, "433") == 0) { // nick in use
        snprintf(response, BUFFER_SIZE, "NICK %s_", (*config)->nickname);
        send = true;
    } else if (strcmp(msg.command, "376") == 0 || strcmp(msg.command, "422") == 0) { // end of motd
        snprintf(response, BUFFER_SIZE, "JOIN %s", (*config)->channel_name);
        send = true;
    }

    if (send)
        send_message(data, response);
}

char* get_auth_msg(bot_config *config) {
    char auth_msg[BUFFER_SIZE];

    snprintf(auth_msg, BUFFER_SIZE, "USER %s 0 * :%s\r\nNICK %s",
             config->username, config->username, config->nickname);

    return strdup(auth_msg);
}

int main() {
    bot_config *botcfg = NULL;

    bot_data botdata;
    botdata.ssl = NULL;
    botdata.ssl_ctx = NULL;

    clock_gettime(CLOCK_MONOTONIC_RAW, &botdata.start_time);

    if (!load_config(CONFIG_FILE, &botcfg)) {
        return 1;
    }

    while (true) { // connection initiation
        botdata.use_ssl = botcfg->use_ssl; // cannot be reloaded from config
        botdata.sockfd = -1;

        if ((botdata.sockfd = create_connection(botcfg->server_address, botcfg->server_port)) == -1) {
            printf("Failed to connect, waiting for %d seconds and trying again\n", RECONNECT_INTERVAL);
            sleep(RECONNECT_INTERVAL);
            continue;
        } else {
            printf("Connection ok\n");
        }

        if (botdata.use_ssl && !init_ssl(&botdata, botcfg->server_address))
            break;

        char *auth_msg = get_auth_msg(botcfg);
        send_message(&botdata, auth_msg);
        free(auth_msg);

        while (true) { // connected to the server
            char *lines = NULL;
            if (botdata.use_ssl) lines = ssl_get_lines(botdata.ssl); else lines = get_lines(botdata.sockfd);
            
            if (lines == NULL) break; // disconnected

            char *line = NULL;
            char *tok = lines;

            while ((line = strsep(&tok, "\r\n")) != NULL)
                handle_line(line, &botcfg, &botdata);

            free(lines);
        }

        close(botdata.sockfd);

        printf("Connection was lost, trying to reconnect after %d seconds\n", RECONNECT_INTERVAL);
        sleep(RECONNECT_INTERVAL);
    }

    printf("Cleaning up resources and exiting\n");

    cleanup(&botdata);
    free(botcfg);

    return 0;
}

