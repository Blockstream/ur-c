
#include "wally_core.h"

#include "urc/core.h"

void urc_free(void *ptr) { wally_free(ptr); }

void urc_string_free(char *str) { wally_free_string(str); }
