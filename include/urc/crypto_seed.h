#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#include "urc/error.h"

#define CRYPTO_SEED_SIZE 16
typedef struct {
    uint8_t seed[CRYPTO_SEED_SIZE];
    uint64_t creation_date;

} crypto_seed;

int urc_crypto_seed_parse(const uint8_t *buffer, size_t len, crypto_seed *out);

#ifdef __cplusplus
}
#endif
