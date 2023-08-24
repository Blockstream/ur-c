#pragma once

#include <stdint.h>

#include "ur-c/error.h"

#define CRYPTO_SEED_SIZE 16
typedef struct {
    uint8_t seed[CRYPTO_SEED_SIZE];
    uint64_t creation_date;

} crypto_seed;
urc_error parse_seed(size_t size, const uint8_t buffer[size], crypto_seed *out);
