#ifndef INT_ARRAY
#define INT_ARRAY

typedef struct {
    int *array;
    size_t length;
    size_t size;
} int_array;

void init_array(int_array *a);

void insert_array(int_array *a, int element);

void free_array(int_array *a);

#endif
