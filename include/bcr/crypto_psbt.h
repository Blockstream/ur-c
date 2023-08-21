#pragma once

#include <stddef.h>
#include <stdint.h>

#include "bcr/error.h"

typedef struct crypto_psbt {
    uint8_t *buffer;
    size_t buffer_size;
    size_t psbt_len;

} crypto_psbt;
bcr_error parse_psbt(size_t size, const uint8_t buffer[size], crypto_psbt *out);
