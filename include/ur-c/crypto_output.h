#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "ur-c/crypto_eckey.h"
#include "ur-c/crypto_hdkey.h"
#include "ur-c/error.h"

typedef struct {
    enum {
        keyexp_type_na,
        keyexp_type_pk,
        keyexp_type_pkh,
        keyexp_type_wpkh,
        keyexp_type_cosigner,
    } type;

    union {
        crypto_eckey eckey;
        crypto_hdkey hdkey;
    } key;
    enum {
        keyexp_keytype_na,
        keyexp_keytype_eckey,
        keyexp_keytype_hdkey,
    } keytype;
} output_keyexp;


typedef struct {
    union {
        output_keyexp key;           // p2pkh
        uint8_t raw[32];
    } output;
    enum {
        output_type_na,
        output_type__, // p2pk, p2pkh, p2wpkh
        output_type_sh,
        output_type_wsh,
        output_type_sh_wsh,
        output_type_rawscript, // raw field
    } type;
} crypto_output;
urc_error parse_output(size_t size, const uint8_t buffer[size], crypto_output *out);
