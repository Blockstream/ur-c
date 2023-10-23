#pragma once

#include "cbor.h"

#include "urc/error.h"


extern const int cbor_flags;

int check_map_key(CborValue *cursor, int expected);
bool is_map_key(CborValue *cursor, int expected);
int check_tag(CborValue *cursor, unsigned long expected_tag);
bool is_tag(CborValue *cursor, unsigned long expected_tag);
int copy_fixed_size_byte_string(CborValue *cursor, uint8_t *buffer, size_t len);
