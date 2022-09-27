#include <stdio.h>
#include <unistd.h> // for sleep()

#include "common.h"
#include "config.h"
#include "connection.h"
#include "bot.h"

#define RECONNECT_INTERVAL 60

int main() {
    bot_config *botcfg = NULL;

    bot_data botdata;
    botdata.ssl = NULL;
    botdata.ssl_ctx = NULL;

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

        handle_connection(&botcfg, &botdata);

        printf("Connection was lost, trying to reconnect...\n");
    }

    printf("Cleaning up resources and exiting\n");

    cleanup(&botdata);
    cleanup_config(botcfg);

    return 0;
}
