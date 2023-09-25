#pragma once

#include "cbor.h"

#include "urc/error.h"


extern const int cbor_flags;

urc_error check_map_key(CborValue *cursor, int expected);
bool is_map_key(CborValue *cursor, int expected);
urc_error check_tag(CborValue *cursor, unsigned long expected_tag);
bool is_tag(CborValue *cursor, unsigned long expected_tag);
urc_error copy_fixed_size_byte_string(CborValue *cursor, uint8_t *buffer, size_t len);
int copy_fixed_size_byte_string2(CborValue *cursor, uint8_t *buffer, size_t len);
