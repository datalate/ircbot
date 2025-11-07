#define PCRE2_CODE_UNIT_WIDTH 8

#define RANDRANGE(n) (int)((double)rand() / ((double)RAND_MAX + 1) * n)
#define MAX(a,b) ((a) > (b) ? (a) : (b))
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#define CARDS_COUNT 53

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <time.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <pcre2.h>
#include <assert.h>

#include "common.h"
#include "config.h"
#include "connection.h"
#include "ssl_connection.h"
#include "timed_message.h"
#include "int_array.h"
#include "bot.h"
#include "database.h"

typedef struct {
  int suit;
  int rank;
} card_t;

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
irc_message* parse_message(const char msg[]) {
    irc_message *ircmsg = malloc(sizeof(*ircmsg));
    if (ircmsg == NULL) {
        fprintf(stderr, "malloc() failed\n");
        return NULL;
    }

    ircmsg->paramc = 0;
    for (int c = 0; c < 15; ++c)
        ircmsg->paramv[c] = NULL;

    printf("RECV: %s\n", msg);

    char *msg_tmp = strdup(msg);
    char *tok = msg_tmp;

    if (*tok == ':') {
        // <servername> | <nick> [ '!' <user> ] [ '@' <host> ]
        strcpy(ircmsg->prefix, strsep(&tok, " ") + 1);

        char *prefix_tmp = strdup(ircmsg->prefix);
        char *prefix_tok = prefix_tmp;

        strcpy(ircmsg->nick, strsep(&prefix_tok, "!"));
        if (prefix_tok != NULL) {
            strcpy(ircmsg->user, strsep(&prefix_tok, "@"));
            if (prefix_tok != NULL) {
                strcpy(ircmsg->host, prefix_tok);
            }
        }

        free(prefix_tmp);
    }

    strcpy(ircmsg->command, strsep(&tok, " "));
    strcpy(ircmsg->params, tok);

    tok = ircmsg->params;
    while (tok != NULL) {
        if (*tok == ':') {
            ircmsg->paramv[ircmsg->paramc++] = tok + 1;
            break;
        }

        ircmsg->paramv[ircmsg->paramc++] = strsep(&tok, " ");
    }

    free(msg_tmp);
    return ircmsg;
}

void send_message(bot_data *data, const char msg[]) {
    if (data->use_ssl)
        ssl_send_msg(data->ssl, msg);
    else
        send_msg(data->sockfd, msg);
}

void send_auth(bot_config *config, bot_data *data) {
    char auth_msg[BUFFER_SIZE];

    snprintf(auth_msg, BUFFER_SIZE, "USER %s 0 * :%s\r\nNICK %s",
             config->username, config->username, config->nickname);

    send_message(data, auth_msg);
}

bool init_ssl(bot_data *data, const char server_address[]) {
    if (data == NULL)
        return false;

    if (data->ssl_ctx == NULL && (data->ssl_ctx = create_ssl_context()) == NULL) {
        fprintf(stderr, "Failed to create SSL context\n");
        return false;
    }

    if (data->ssl == NULL && (data->ssl = SSL_new(data->ssl_ctx)) == NULL) {
        fprintf(stderr, "SSL_new() failed\n");
        return false;
    } else if (SSL_clear(data->ssl) == 0) {
        fprintf(stderr, "SSL_clear() failed\n");
        return false;
    }

    if (SSL_set_fd(data->ssl, data->sockfd) == 0) {
        fprintf(stderr, "SSL_set_fd() failed\n");
        return false;
    }

    if (SSL_connect(data->ssl) != 1) {
        fprintf(stderr, "SSL_connect() failed\n");
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

void handle_privmsg(irc_message *msg, bot_config **config, bot_data *data) {
    // 0: target, 1: message
    if (*msg->paramv[0] != '#') return; // only respond to channel messages

    bool is_admin = strcmp(msg->host, (*config)->admin_hostname) == 0;
    char response[BUFFER_SIZE];

    if (is_admin && strcasecmp(msg->paramv[1], "!reload") == 0) {
        load_config(CONFIG_FILE, config);
        snprintf(response, BUFFER_SIZE, "PRIVMSG %s :Config file reloaded", msg->paramv[0]);
        send_message(data, response);
    } else if (is_admin && strcasecmp(msg->paramv[1], "!reconnect") == 0) {
        snprintf(response, BUFFER_SIZE, "PRIVMSG %s :See you soon! :)\r\nQUIT", msg->paramv[0]);
        send_message(data, response);
    } else if (strcasecmp(msg->paramv[1], "!roulette") == 0) {
        srand(time(NULL));

        if (data->roulette_chamber == -1) data->roulette_chamber = RANDRANGE(6);

        if (data->roulette_current == data->roulette_chamber) {
            snprintf(response, BUFFER_SIZE, "PRIVMSG %s :BANG! %s is dead\r\nPRIVMSG %s :\x01""ACTION loads a round and spins the barrel\x01", msg->paramv[0], msg->nick, msg->paramv[0]);
            data->roulette_chamber = RANDRANGE(6);
            data->roulette_current = 0;
        } else {
            snprintf(response, BUFFER_SIZE, "PRIVMSG %s :*click*", msg->paramv[0]);
            data->roulette_current++;
        }
        send_message(data, response);
    } else if (strcasecmp(msg->paramv[1], "!roll") == 0) {
        srand(time(NULL));

        snprintf(response, BUFFER_SIZE, "PRIVMSG %s :1d6: %d", msg->paramv[0], RANDRANGE(6) + 1);
        send_message(data, response);
    } else if (strncasecmp(msg->paramv[1], "!poker", 6) == 0) {
        srand(time(NULL));

        static const char* suitnames[] = {"🃏", "♠", "♣", "♥", "♦"};
        static const char* ranknames[] = {"?", "A", "2", "3", "4", "5", "6", "7", "8", "9", "10", "J", "Q", "K"};
        static const char* winnames[] = {"HIGH CARD", "ONE PAIR", "TWO PAIRS", "THREE-OF-A-KIND", "STRAIGHT", "FLUSH", "FULL HOUSE", "FOUR-OF-A-KIND", "STRAIGHT FLUSH", "ROYAL FLUSH", "FIVE-OF-A-KIND"};

        card_t cards[CARDS_COUNT];
        char deck[255] = {'\0'};

        size_t cmdlen = strlen(msg->paramv[1]);

        int keep = 0; // 00000
        for (size_t i = 7; i < cmdlen; ++i) { // parse additional input after !poker<space>
            int slot = msg->paramv[1][i] - '0';
            if (slot >= 1 && slot <= 5) keep |= 1 << (slot - 1);
        }

        get_deck(msg->host, deck); // get and delete deck

        if (strlen(deck) == 0 || cmdlen < 8) {
            // init card array
            for (size_t i = 0; i < CARDS_COUNT - 1; ++i) {
                cards[i].rank = (i % 13) + 1;
                cards[i].suit = (i / 13) + 1;
            }

            // insert joker
            cards[CARDS_COUNT - 1].rank = 0;
            cards[CARDS_COUNT - 1].suit = 0;

            // shuffle
            for (size_t i = 0; i < CARDS_COUNT; ++i) {
                size_t j = i + RANDRANGE(CARDS_COUNT - i);
                card_t t = cards[j];
                cards[j] = cards[i];
                cards[i] = t;
            }

            // save deck
            deck[0] = '\0';
            for (size_t i = 0; i < CARDS_COUNT; ++i) {
                snprintf(deck + strlen(deck), 255 - strlen(deck), "%x%x ", cards[i].suit, cards[i].rank);
            }

            save_deck(msg->host, deck);
        } else { // get deck from db
            char *dbiterator = deck;

            for (size_t i = 0; i < CARDS_COUNT; ++i) {
                assert(*dbiterator != '\0'); // only partial deck
                char *next;

                long card = strtol(dbiterator, &next, 16); // 0x00 - 0xFF
                int suit = (card & 0xF0) >> 4; // high bit part
                int rank = (card & 0x0F) >> 0; // low bit part
                assert(suit <= 4);
                assert(rank <= 13);

                cards[i].suit = suit;
                cards[i].rank = rank;
                dbiterator = next;
            }

            // replace discarded cards
            int discarded = 0;
            for (size_t i = 0; i < 5; ++i) {
                int discard = !((keep >> i) & 1);
                if (discard) cards[i] = cards[5 + discarded++];
            }
        }

        int win = 0;
        int joker = 0;
        int pairs = 0;
        int suitpairs = 0;
        int minrank1 = 13;
        int maxrank1 = 1;
        int minrank2 = 14;
        int maxrank2 = 2;

        for (int i = 0; i < 5; ++i) {
            if (cards[i].rank == 0) {
                joker = 1;
            } else {
                int rank = cards[i].rank;
                minrank1 = MIN(rank, minrank1);
                maxrank1 = MAX(rank, maxrank1);

                if (rank == 1) rank = 14;
                minrank2 = MIN(rank, minrank2);
                maxrank2 = MAX(rank, maxrank2);
            }

            for (int j = i + 1; j < 5; ++j) { // compare every card to another
                if (cards[i].rank == cards[j].rank) pairs++;
                if (cards[i].suit == cards[j].suit) suitpairs++;
            }
        }

        int minmaxdiff1 = maxrank1 - minrank1;
        int minmaxdiff2 = maxrank2 - minrank2;
        int flush = ((joker && suitpairs == 6) || suitpairs == 10);
        int straight = (pairs == 0 && (minmaxdiff1 < 5 || minmaxdiff2 < 5));

        if (joker && pairs == 6) win = 10;
        else if (flush && straight && minrank2 > 9) win = 9;
        else if (flush && straight) win = 8;
        else if ((joker && pairs == 3) || pairs == 6) win = 7;
        else if ((joker && pairs == 2) || pairs == 4) win = 6;
        else if (flush) win = 5;
        else if (straight) win = 4;
        else if ((joker && pairs == 1) || pairs == 3) win = 3;
        else if (pairs == 2) win = 2;
        else if (joker || pairs == 1) win = 1;

        snprintf(response, BUFFER_SIZE, "PRIVMSG %s :", msg->paramv[0]);
        snprintf(response + strlen(response), BUFFER_SIZE - strlen(response), "%s: ", winnames[win]);
        for (size_t i = 0; i < 5; ++i) {
            snprintf(response + strlen(response), BUFFER_SIZE - strlen(response), "%s%-2s ", suitnames[cards[i].suit], ranknames[cards[i].rank]);
        }
        send_message(data, response);
    } else if (strcasecmp(msg->paramv[1], "!uptime") == 0) {
        struct timespec current_time;

        clock_gettime(CLOCK_MONOTONIC_RAW, &current_time);
        int seconds_passed = current_time.tv_sec - data->start_time.tv_sec;
        int minutes = seconds_passed / 60;
        int seconds = seconds_passed % 60;
        int hours = minutes / 60;
        minutes = minutes % 60;

        snprintf(response, BUFFER_SIZE, "PRIVMSG %s :Current uptime: %02d:%02d:%02d",
                 msg->paramv[0], hours, minutes, seconds);
        send_message(data, response);
    } else {
        int_array matching_indexes;
        init_array(&matching_indexes);
        if (matching_indexes.array == NULL) return;
        bot_config_reply_data *reply_data = (*config)->reply_data;
        srand(time(NULL));

        for (unsigned int i = 0; i < reply_data->num_replies; ++i) {
            bot_config_reply *reply = &reply_data->replies[i];
            bool match = false;

            if (!reply->use_regex && strcasecmp(msg->paramv[1], reply->match) == 0) {
                match = true;
            } else if (reply->use_regex) {
                pcre2_match_data *match_data = pcre2_match_data_create_from_pattern(reply->regex, NULL);
                PCRE2_SPTR subject = (PCRE2_SPTR)msg->paramv[1];
                PCRE2_SIZE subject_length = (PCRE2_SIZE)strlen((char *)subject);

                int rc = pcre2_match(reply->regex, subject, subject_length, 0, 0, match_data, NULL);
                match = rc >= 0;

                pcre2_match_data_free(match_data);
            }

            if (match) insert_array(&matching_indexes, i);
        }

        if (matching_indexes.length > 0) {
            unsigned int reply_i = matching_indexes.array[RANDRANGE(matching_indexes.length)];
            snprintf(response, BUFFER_SIZE, "PRIVMSG %s :%s", msg->paramv[0], reply_data->replies[reply_i].reply);
            send_message(data, response);
        }

        free_array(&matching_indexes);
    }
}

void handle_line(const char line[], bot_config **config, bot_data *data) {
    if (*line == '\0') return;

    irc_message *msg = parse_message(line);

    char response[BUFFER_SIZE];
    bool send = false;

    if (strcmp(msg->command, "PING") == 0) { // 0: ping
        snprintf(response, BUFFER_SIZE, "PONG %s", msg->params);
        send = true;
    } else if (strcmp(msg->command, "PRIVMSG") == 0) { // 0: target, 1: message
        handle_privmsg(msg, config, data);
    } else if (strcmp(msg->command, "MODE") == 0) { // 0: target, 1: mode
    } else if (strcmp(msg->command, "JOIN") == 0) { // 0: channel
        bot_config_kicklist_data *kicklist = (*config)->kicklist_data;
        for (unsigned int i = 0; i < kicklist->num_hosts; ++i) {
            bool match = false;

            pcre2_match_data *match_data = pcre2_match_data_create_from_pattern(kicklist->hosts[i], NULL);
            PCRE2_SPTR subject = (PCRE2_SPTR)msg->prefix;
            PCRE2_SIZE subject_length = (PCRE2_SIZE)strlen((char *)subject);

            int rc = pcre2_match(kicklist->hosts[i], subject, subject_length, 0, 0, match_data, NULL);
            match = rc >= 0;

            pcre2_match_data_free(match_data);

            if (match) {
                snprintf(response, BUFFER_SIZE, "KICK %s %s", msg->paramv[0], msg->nick);
                send = true;
            }
        }
    } else if (strcmp(msg->command, "INVITE") == 0) { // 0: target, 1: channel
        if (*msg->paramv[1] != '#') return;

        snprintf(response, BUFFER_SIZE, "JOIN %s", msg->paramv[1]);
        send = true;
    } else if (strcmp(msg->command, "KICK") == 0) { // 0: channel, 1: nick, 2: reason
        if (*msg->paramv[0] != '#') return;

        // TODO: compare to current nick instead of nick in config
        if (strcasecmp(msg->paramv[1], (*config)->nickname) == 0) { // bot kicked
            snprintf(response, BUFFER_SIZE, "JOIN %s", msg->paramv[0]); // re-join
            send = true;
        }
    } else if (strcmp(msg->command, "433") == 0) { // nick in use
        snprintf(response, BUFFER_SIZE, "NICK %s_", (*config)->nickname);
        send = true;
    } else if (strcmp(msg->command, "376") == 0 || strcmp(msg->command, "422") == 0) { // end of motd
        snprintf(response, BUFFER_SIZE, "JOIN %s", (*config)->channel_name);
        send = true;
    }

    free(msg);

    if (send)
        send_message(data, response);
}

void handle_connection(bot_config **config, bot_data *data) {
    clock_gettime(CLOCK_MONOTONIC_RAW, &data->start_time);

    send_auth(*config, data);

    pthread_t job_thread;
    timed_message_data *job_data = malloc(sizeof(*job_data));
    job_data->bot_data = data;
    job_data->bot_config = config;
    pthread_mutex_init(&job_data->exit_cond_m, NULL);
    pthread_cond_init(&job_data->exit_cond, NULL);
    pthread_create(&job_thread, NULL, handle_job, job_data); // thread takes care of freeing job_data

    while (true) { // connected to the server
        char *lines = NULL;
        if (data->use_ssl)
            lines = ssl_get_lines(data->ssl);
        else
            lines = get_lines(data->sockfd);

        if (lines == NULL) break; // disconnected

        char *line = NULL;
        char *tok = lines;

        while ((line = strsep(&tok, "\r\n")) != NULL)
            handle_line(line, config, data);

        free(lines);
    }

    pthread_cond_signal(&job_data->exit_cond);
    pthread_join(job_thread, NULL);

    close(data->sockfd);
}

