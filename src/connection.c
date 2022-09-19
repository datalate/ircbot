#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "connection.h"
#include "common.h"

int create_connection(const char address[], const char port[]) {
    struct addrinfo hints, *result = NULL, *rp = NULL;
    int sockfd = -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = 0;
    hints.ai_protocol = 0;

    if (getaddrinfo(address, port, &hints, &result) != 0) {
        fprintf(stderr, "getaddinfo() failed\n");
        return -1;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        char ipv4[INET_ADDRSTRLEN];
        struct sockaddr_in *addr4 = (struct sockaddr_in*)rp->ai_addr;
        inet_ntop(AF_INET, &addr4->sin_addr, ipv4, INET_ADDRSTRLEN);

        printf("Connecting to %s:%s\n", ipv4, port);

        if ((sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol)) == -1) {
            fprintf(stderr, "socket() failed\n");
            continue;
        }

        if (connect(sockfd, rp->ai_addr, rp->ai_addrlen) == -1) {
            fprintf(stderr, "connect() failed\n");
            close(sockfd);
            sockfd = -1;
            continue;
        }

        break;
    }

    freeaddrinfo(result);

    return sockfd;
}

void send_msg(int sockfd, const char msg[]) {
    char *send_buffer = format_msg(msg);
    if (send_buffer == NULL) return;

    int len = strlen(send_buffer);
    
    int total_write_bytes = 0, write_bytes = 0;
    while (total_write_bytes != len) {
        write_bytes = write(sockfd, send_buffer + total_write_bytes, len - total_write_bytes);
        if (write_bytes == -1) {
            fprintf(stderr, "write() failed\n");

            break;
        }

        printf("write(): %d bytes sent\n", write_bytes);

        total_write_bytes += write_bytes;
    }

    printf("SEND: %s", send_buffer);
    free(send_buffer);
}

char* get_lines(int sockfd) {
    char *recv_buffer = calloc(0, 1); // empty calloc to be able to call realloc later on
    if (recv_buffer == NULL) {
        fprintf(stderr, "calloc() failed\n");
        return NULL;
    }

    int recv_bytes = 0, total_recv_bytes = 0;
    bool recv_ok = false;

    while (!recv_ok) {
        char *tmp_ptr = realloc(recv_buffer, total_recv_bytes + BUFFER_SIZE + 1);

        if (tmp_ptr == NULL) {
            fprintf(stderr, "realloc() failed\n");

            free(recv_buffer);
            break;
        }

        recv_buffer = tmp_ptr;
        memset(recv_buffer + total_recv_bytes, 0, BUFFER_SIZE + 1);

        if ((recv_bytes = read(sockfd, recv_buffer + total_recv_bytes, BUFFER_SIZE)) <= 0) {
            fprintf(stderr, "read() failed\n");
            break;
        }

        printf("read(): %d bytes received into %p\n", recv_bytes, &recv_buffer);

        total_recv_bytes += recv_bytes;

        // Received messages should always end in CRLF
        recv_ok = total_recv_bytes >= 2 &&
                  recv_buffer[total_recv_bytes - 2] == '\r' &&
                  recv_buffer[total_recv_bytes - 1] == '\n';
    }

    if (!recv_ok) {
        free(recv_buffer);
        return NULL;
    }

    return recv_buffer;
}

