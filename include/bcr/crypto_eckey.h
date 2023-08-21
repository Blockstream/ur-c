
#pragma once

#include <stdint.h>

#include "bcr/error.h"

#define CRYPTO_ECKEY_PRIVATE_SIZE 32
#define CRYPTO_ECKEY_PUBLIC_COMPRESSED_SIZE 33
#define CRYPTO_ECKEY_PUBLIC_UNCOMPRESSED_SIZE 64
typedef struct crypto_eckey {
    union {
        uint8_t private[CRYPTO_ECKEY_PRIVATE_SIZE];
        uint8_t public_compressed[CRYPTO_ECKEY_PUBLIC_COMPRESSED_SIZE];
        uint8_t public_uncompressed[CRYPTO_ECKEY_PUBLIC_UNCOMPRESSED_SIZE];
    } key;
    enum eckey_type {
        eckey_type_na,
        eckey_type_private,
        eckey_type_public_compressed,
        eckey_type_public_uncompressed,
    } type;
} crypto_eckey;
bcr_error parse_eckey(size_t size, const uint8_t buffer[size], crypto_eckey *out);
