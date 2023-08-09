#pragma once

#include "tinycbor/cbor.h"

#include "bcr/bcr.h"

bcr_error internal_parse_seed(CborValue *iter, crypto_seed* out);


CborError cbor_value_map_find_value_by_int_key(const CborValue *map, int key, CborValue *element);
