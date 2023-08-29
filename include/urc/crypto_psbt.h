#pragma once

#include <stddef.h>
#include <stdint.h>

#include "urc/error.h"

typedef struct {
    uint8_t *buffer;
    size_t buffer_size;
    size_t psbt_len;

} crypto_psbt;

urc_error parse_psbt(size_t size, const uint8_t *buffer, crypto_psbt *out);
