#pragma once

#include <stddef.h>
#include <stdint.h>

#include "urc/error.h"

typedef struct {
    uint8_t *buffer;
    size_t buffer_size;
    size_t psbt_len;

} crypto_psbt;

int urc_crypto_psbt_parse(const uint8_t *buffer, size_t len, crypto_psbt *out);
