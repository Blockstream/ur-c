
#include "wally_core.h"

#include "urc/core.h"

void urc_free(void *ptr) { wally_free(ptr); }

void urc_string_free(char *str) { wally_free_string(str); }


void urc_string_array_free(char *str_array[]) {
    size_t idx = 0;
    while (str_array[idx]) {
        urc_string_free(str_array[idx]);
        str_array[idx] = NULL;
        idx++;
    }
    wally_free(str_array);
}
