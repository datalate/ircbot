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

void run_triggered_jobs(timed_message_data *data, int hour, int minute) {
    bot_config_timed_message_data *msg_data = (*data->bot_config)->timed_message_data;
    for (unsigned int i = 0; i < msg_data->num_timed_messages; ++i) {
        bot_config_timed_message *msg = &msg_data->timed_messages[i];
        if (hour == msg->at_hour && minute == msg->at_minute) {
            printf("Running a triggered job\n");
            char channel_message[BUFFER_SIZE];
            snprintf(channel_message, BUFFER_SIZE, "PRIVMSG %s :%s", msg->channel, msg->message);
            send_message(data->bot_data, channel_message);
        }
    }
}

void* handle_job(void *arg) {
    time_t current_t;
    timed_message_data *data = arg;

    pthread_mutex_lock(&data->exit_cond_m);
    pthread_cleanup_push(job_cleanup_handler, arg);

    int interval = 60;
    while (true) {
        struct tm *job_tm;
        int sleep_seconds, sleep_offset;

        time(&current_t);
        job_tm = localtime(&current_t);

        run_triggered_jobs(data, job_tm->tm_hour, job_tm->tm_min);

        sleep_offset = -job_tm->tm_sec;
        sleep_seconds = interval + sleep_offset;
        if (sleep_seconds < 0) sleep_seconds = 0;

        struct timespec wait_until;
        clock_gettime(CLOCK_REALTIME, &wait_until);
        wait_until.tv_sec += sleep_seconds;

        int result = pthread_cond_timedwait(&data->exit_cond, &data->exit_cond_m, &wait_until);
        if (result != ETIMEDOUT) break; // got signal to close thread 
    }

    pthread_cleanup_pop(1);
    return NULL;
}

