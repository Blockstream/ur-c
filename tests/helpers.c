#include <string.h>

#include "helpers.h"

size_t h2b(const char *hex, size_t size, uint8_t buffer[size]) {
    size_t len = strlen(hex);
    if (len % 2 != 0) {
        return -1;
}
    if (size < len / 2) {
        return -1;
}

    for (size_t i = 0, j = 0; i < len; i += 2, j++)
        buffer[j] = (hex[i] % 32 + 9) % 25 * 16 + (hex[i + 1] % 32 + 9) % 25;
    return len / 2;
}
