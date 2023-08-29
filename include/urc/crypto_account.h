#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "urc/crypto_output.h"
#include "urc/error.h"

#ifndef DESCRIPTORS_MAX_SIZE
#define DESCRIPTORS_MAX_SIZE 10
#endif
typedef struct {
    crypto_output descriptors[DESCRIPTORS_MAX_SIZE];
    size_t descriptors_count;
    uint32_t master_fingerprint;
} crypto_account;

urc_error parse_account(size_t size, const uint8_t *buffer, crypto_account *out);
