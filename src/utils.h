#pragma once

#include "bcr/bcr.h"
#include "tinycbor/cbor.h"

bcr_error check_map_key(CborValue *cursor, int expected);
bool is_map_key(CborValue *cursor, int expected);
bcr_error check_tag(CborValue *cursor, int expected_tag);
bcr_error copy_fixed_size_byte_string(CborValue *cursor, uint8_t *buffer, size_t expected);
