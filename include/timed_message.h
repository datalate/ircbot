#ifndef TIMED_MESSAGE_H
#define TIMED_MESSAGE_H

//#include <time.h>
#include <pthread.h>
#include "bot.h"

typedef struct {
    bot_data *bot_data;
    char channel[64];
    char message[256];
    int at_hour;
    int at_minute;
    pthread_cond_t exit_cond;
    pthread_mutex_t exit_cond_m;
} timed_message_data;

void* handle_job(void *args);

#endif

