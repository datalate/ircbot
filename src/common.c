#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "common.h"

char* format_msg(const char msg[]) {
    int len = strlen(msg);
    char *formatted = malloc(len + 2 + 1);
    if (formatted == NULL) return NULL;

    if (len > BUFFER_SIZE - 3) {
        // Maximum message length is BUFFER_SIZE - CRLF - \0
        printf("Warning: Truncated %d characters from sent message\n", len - (BUFFER_SIZE - 3));
        len = BUFFER_SIZE - 3;
    }

    strncpy(formatted, msg, len);

    // Append CRLF
    formatted[len++] = '\r';
    formatted[len++] = '\n';
    formatted[len] = '\0';

    return formatted;
}

