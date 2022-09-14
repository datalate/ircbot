#define _DEFAULT_SOURCE
#define _GNU_SOURCE

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <openssl/ssl.h>

#include "common.h"
#include "config.h"
#include "connection.h"
#include "ssl_connection.h"

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
char* handle_line(char line[], bot_config **config) {
    if (*line == '\0') return NULL;

    char *tok = line;
    char response[BUFFER_SIZE];
    char prefix[256], command[32], params[500]; // TODO: check lengths
    char nick[16], user[16], host[64]; // NICKLEN=9
    char *paramv[15];
    int paramc = 0;

    printf("RECV: %s\n", line);

    if (*tok == ':') {
        // <servername> | <nick> [ '!' <user> ] [ '@' <host> ]
        strcpy(prefix, strsep(&tok, " ") + 1);

        char *prefix_tmp = strdup(prefix);
        char *prefix_tok = prefix_tmp;

        strcpy(nick, strsep(&prefix_tok, "!"));
        if (prefix_tok != NULL) {
            strcpy(user, strsep(&prefix_tok, "@"));
            if (prefix_tok != NULL) {
                strcpy(host, prefix_tok);
            }
        }
        free(prefix_tmp);
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
        if (*paramv[0] != '#') return NULL; // only respond to channel messages

        bool is_admin = strcmp(host, (*config)->admin_hostname) == 0;

        if (is_admin && strcasecmp(paramv[1], "!reload") == 0) {
            load_config(CONFIG_FILE, config);
        } else {
            for (unsigned int i = 0; i < (*config)->num_replies; ++i) {
                if (strcasecmp(paramv[1], (*config)->replies[i].match) == 0) {
                    snprintf(response, BUFFER_SIZE, "PRIVMSG %s :%s", paramv[0], (*config)->replies[i].reply);
                    send = true;
                    break;
                }
            }
        }
    } else if (strcmp(command, "MODE") == 0) { // 0: target, 1: mode
    } else if (strcmp(command, "INVITE") == 0) { // 0: target, 1: channel
        if (*paramv[1] != '#') return NULL;

        snprintf(response, BUFFER_SIZE, "JOIN %s", paramv[1]);
        send = true;
    } else if (strcmp(command, "KICK") == 0) { // 0: channel, 1: nick, 2: reason
        if (*paramv[0] != '#') return NULL;

        // TODO: compare to current nick instead of nick in config
        if (strcasecmp(paramv[1], (*config)->nickname) == 0) { // bot kicked
            snprintf(response, BUFFER_SIZE, "JOIN %s", paramv[0]); // re-join
            send = true;
        }
    } else if (strcmp(command, "433") == 0) { // nick in use
        snprintf(response, BUFFER_SIZE, "NICK %s_", (*config)->nickname);
        send = true;
    } else if (strcmp(command, "376") == 0 || strcmp(command, "422") == 0) { // end of motd
        snprintf(response, BUFFER_SIZE, "JOIN %s", (*config)->channel_name);
        send = true;
    }

    if (send) {
        return strdup(response);
    } else {
        return NULL;
    }
}

char* get_auth_msg(bot_config *config) {
    char auth_msg[BUFFER_SIZE];

    snprintf(auth_msg, BUFFER_SIZE, "USER %s 0 * :%s\r\nNICK %s",
             config->username, config->username, config->nickname);

	return strdup(auth_msg);
}

int main() {
    bot_config *botcfg = NULL;
    SSL_CTX *ssl_ctx = NULL;
    SSL *ssl = NULL;

    if (!load_config(CONFIG_FILE, &botcfg)) {
        return 1;
    }

    bool use_ssl = botcfg->use_ssl; // cannot be reloaded from config

    while (true) { // connection initiation
        int sockfd = -1;
        if ((sockfd = create_connection(botcfg->server_address, botcfg->server_port)) == -1) {
            printf("Failed to connect, waiting for %d seconds and trying again\n", RECONNECT_INTERVAL);
            sleep(RECONNECT_INTERVAL);
            continue;
        } else {
            printf("Connection ok\n");
        }

        if (use_ssl) {
            if (ssl_ctx == NULL && (ssl_ctx = create_ssl_context()) == NULL) {
                printf("Failed to create SSL context\n");
                break;
            }

            if (ssl == NULL && (ssl = SSL_new(ssl_ctx)) == NULL) {
                printf("SSL_new() failed\n");
                break;
            } else if (SSL_clear(ssl) == 0) {
                printf("SSL_clear() failed\n");
                break;
            }

            if (SSL_set_fd(ssl, sockfd) == 0) {
                printf("SSL_set_fd() failed\n");
                break;
            }

            if (SSL_connect(ssl) != 1) {
                printf("SSL_connect() failed\n");
                break;
            }

            printf("SSL initialized\n");

            if (!check_cert(ssl, botcfg->server_address)) {
                break;
            }
        }

        char *auth_msg = get_auth_msg(botcfg);
        if (use_ssl) ssl_send_msg(ssl, auth_msg); else send_msg(sockfd, auth_msg);
        free(auth_msg);

        while (true) { // connected to the server
            char *lines = NULL;
            if (use_ssl) lines = ssl_get_lines(ssl); else lines = get_lines(sockfd);
            
            if (lines == NULL) break; // disconnected

            char *line = NULL;
            char *tok = lines;

            while ((line = strsep(&tok, "\r\n")) != NULL) {
                char *reply = handle_line(line, &botcfg);
                if (reply != NULL) {
                    if (use_ssl) ssl_send_msg(ssl, reply); else send_msg(sockfd, reply);
                    free(reply);
                }
            }

            free(lines);
        }

        close(sockfd);

        printf("Connection was lost, trying to reconnect after %d seconds\n", RECONNECT_INTERVAL);
        sleep(RECONNECT_INTERVAL);
    }

    printf("Cleaning up resources and exiting\n");

    if (ssl != NULL)
        SSL_free(ssl);
    if (ssl_ctx != NULL)
        SSL_CTX_free(ssl_ctx);

    free(botcfg);

    return 0;
}

