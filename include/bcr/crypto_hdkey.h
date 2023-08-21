#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "bcr/error.h"

#define COININFO_COIN_TYPE_BTC 0

#define COININFO_NETWORK_MAINNET 0
#define COININFO_NETWORK_TESTNET 1


typedef struct child_index_component {
    uint32_t index;
    bool is_hardened;
} child_index_component;

typedef struct child_range_component {
    uint32_t low;
    uint32_t high;
    bool is_hardened;
} child_range_component;

typedef struct child_wildcard_component {
    bool is_hardened;
}child_wildcard_component;


typedef struct child_pair_component {
    child_index_component internal;
    child_index_component external;
} child_pair_component;

typedef struct path_component {
    union {
        child_index_component index;
        child_range_component range;
        child_wildcard_component wildcard;
        child_pair_component pair;
    } component;
    enum path_component_type {
        path_component_type_na,
        path_component_type_index,
        path_component_type_range,
        path_component_type_wildcard,
        path_component_type_pair,
    } type;
} path_component;

#define CRYPTO_KEYPATH_MAX_COMPONENTS 8
typedef struct crypto_keypath {
    path_component components[CRYPTO_KEYPATH_MAX_COMPONENTS];
    size_t components_count;
    uint32_t source_fingerprint;
    uint8_t depth;
} crypto_keypath;

#define CRYPTO_HDKEY_KEYDATA_SIZE 33
#define CRYPTO_HDKEY_CHAINCODE_SIZE 32
typedef struct hd_master_key {
    bool is_master;
    uint8_t keydata[CRYPTO_HDKEY_KEYDATA_SIZE];
    uint8_t chaincode[CRYPTO_HDKEY_CHAINCODE_SIZE];
} hd_master_key;

typedef struct crypto_coininfo {
    uint32_t type;
    int network;
} crypto_coininfo;

typedef struct hd_derived_key {
    bool is_private;
    uint8_t keydata[CRYPTO_HDKEY_KEYDATA_SIZE];

    uint8_t chaincode[CRYPTO_HDKEY_CHAINCODE_SIZE];
    bool valid_chaincode;

    crypto_coininfo useinfo;
    bool valid_useinfo;

} hd_derived_key;

typedef struct crypto_hdkey {
    union {
        hd_master_key master;
        hd_derived_key derived;
    } key;
    enum hdkey_type {
        hdkey_type_na,
        hdkey_type_master,
        hdkey_type_derived,
    } type;
} crypto_hdkey;

bcr_error parse_hdkey(size_t size, const uint8_t buffer[size], crypto_hdkey *out);
