#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "ur-c/crypto_output.h"
#include "ur-c/error.h"

#ifndef DESCRIPTORS_MAX_SIZE
#define DESCRIPTORS_MAX_SIZE 10
#endif
typedef struct {
    crypto_output descriptors[DESCRIPTORS_MAX_SIZE];
    size_t descriptors_count;
    uint32_t master_fingerprint;
} crypto_account;
urc_error parse_account(size_t size, const uint8_t buffer[size], crypto_account *out);
