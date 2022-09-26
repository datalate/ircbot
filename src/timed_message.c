#include <unistd.h> // for sleep()
#include <time.h>
#include <pthread.h>
#include <errno.h> // for ETIMEDOUT
#include "common.h"
#include "bot.h"
#include "timed_message.h"

static void job_cleanup_handler(void *arg) {
    timed_message_data *data = arg;
    pthread_mutex_unlock(&data->exit_cond_m);
    pthread_cond_destroy(&data->exit_cond);
    pthread_mutex_destroy(&data->exit_cond_m);

    free(data);
}

void* handle_job(void *arg) {
    time_t current_t, job_t;
    struct tm *script_t;
    char channel_message[BUFFER_SIZE];
    timed_message_data *data = arg;

    pthread_mutex_lock(&data->exit_cond_m);
    pthread_cleanup_push(job_cleanup_handler, arg);
    snprintf(channel_message, BUFFER_SIZE, "PRIVMSG %s :%s", data->channel, data->message);

    time(&current_t);
    script_t = localtime(&current_t);

    // in case the job already ran today, run it tomorrow instead
    if ((script_t->tm_hour > data->at_hour) || (script_t->tm_hour == data->at_hour && script_t->tm_min >= data->at_minute))
        script_t->tm_mday++;

    script_t->tm_hour = data->at_hour;
    script_t->tm_min = data->at_minute;
    script_t->tm_sec = 0;

    while (true) {
        job_t = mktime(script_t);
        int sleep_seconds = difftime(job_t, current_t);

        struct timespec wait_until;
        clock_gettime(CLOCK_REALTIME, &wait_until);
        wait_until.tv_sec += sleep_seconds;

        printf("Sleeping for %d seconds\n", sleep_seconds);
        int result = pthread_cond_timedwait(&data->exit_cond, &data->exit_cond_m, &wait_until);
        if (result != ETIMEDOUT) break; // got signal to close thread 

        printf("Running job\n");
        send_message(data->bot_data, channel_message);

        script_t->tm_mday++; // run the job tomorrow at the same time
        time(&current_t); // update current time
    }

    pthread_cleanup_pop(1);
    return NULL;
}

