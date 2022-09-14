#ifndef CONNECTION_H
#define CONNECTION_H

int create_connection(const char address[], const char port[]);

void send_msg(int sockfd, const char msg[]);

char* get_lines(int sockfd);

#endif
