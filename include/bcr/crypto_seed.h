#pragma once

#include <stdint.h>

#include "bcr/error.h"

#define CRYPTO_SEED_SIZE 16
typedef struct crypto_seed {
    uint8_t seed[CRYPTO_SEED_SIZE];
    uint64_t creation_date;

} crypto_seed;
bcr_error parse_seed(size_t size, const uint8_t buffer[size], crypto_seed *out);
