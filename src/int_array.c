#include <stdlib.h>
#include <stdio.h>
#include "int_array.h"

void init_array(int_array *a) {
    static size_t initial_size = 8;

    a->size = 0;
    a->length = 0;

    int *arr = malloc(initial_size * sizeof(int));
    if (arr == NULL) {
        fprintf(stderr, "malloc() failed\n");
        return;
    }

    a->array = arr;
    a->size = initial_size;
}

void insert_array(int_array *a, int element) {
    if (a->length == a->size) {
        size_t new_size = a->size * 2; // TODO: better handling of size
        int *arr = realloc(a->array, new_size * sizeof(int));

        if (arr == NULL) {
            fprintf(stderr, "realloc() failed\n");
            return;
        }

        a->array = arr;
        a->size = new_size;
    }

    a->array[a->length++] = element;
}

void free_array(int_array *a) {
    free(a->array);
    a->length = 0;
    a->size = 0;
}

