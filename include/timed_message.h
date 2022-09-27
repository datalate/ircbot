#ifndef TIMED_MESSAGE_H
#define TIMED_MESSAGE_H

#include <pthread.h>
#include "bot.h"
//#include "config.h"

typedef struct {
    bot_data *bot_data;
    //bot_config_timed_message *config;
    char channel[64];
    char message[256];
    int at_hour;
    int at_minute;

    pthread_cond_t exit_cond;
    pthread_mutex_t exit_cond_m;
} timed_message_data;

void* handle_job(void *args);

#endif

