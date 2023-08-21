#pragma once

#include "tinycbor/cbor.h"

#include "bcr/bcr.h"

extern const int cbor_flags;

bcr_error check_map_key(CborValue *cursor, int expected);
bool is_map_key(CborValue *cursor, int expected);
bcr_error check_tag(CborValue *cursor, unsigned long expected_tag);
bcr_error copy_fixed_size_byte_string(CborValue *cursor, size_t expected, uint8_t buffer[expected]);
