#include <iostream>
#include <unistd.h>

#define MAX_BLOCK_SIZE 100000000

void *smalloc(size_t size) {
    if (size == 0 || size > MAX_BLOCK_SIZE) {
        return NULL;
    }
    void *res = sbrk(size);
    if (res == (void *) (-1)) {
        return NULL;
    }
    return res;
}