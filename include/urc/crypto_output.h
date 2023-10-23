#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "urc/crypto_eckey.h"
#include "urc/crypto_hdkey.h"
#include "urc/error.h"

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

int urc_crypto_output_parse(const uint8_t *buffer, size_t len, crypto_output *out);
