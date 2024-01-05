#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>

#include "urc/error.h"

#define COININFO_COIN_TYPE_BTC 0

#define COININFO_NETWORK_MAINNET 0
#define COININFO_NETWORK_TESTNET 1

typedef struct {
    uint32_t index;
    bool is_hardened;
} child_index_component;

typedef struct {
    uint32_t low;
    uint32_t high;
    bool is_hardened;
} child_range_component;

typedef struct {
    bool is_hardened;
} child_wildcard_component;

typedef struct {
    child_index_component internal;
    child_index_component external;
} child_pair_component;

typedef struct {
    union {
        child_index_component index;
        child_range_component range;
        child_wildcard_component wildcard;
        child_pair_component pair;
    } component;
    enum {
        path_component_type_na,
        path_component_type_index,
        path_component_type_range,
        path_component_type_wildcard,
        path_component_type_pair,
    } type;
} path_component;

#define CRYPTO_KEYPATH_MAX_COMPONENTS 5
typedef struct {
    path_component components[CRYPTO_KEYPATH_MAX_COMPONENTS];
    size_t components_count;
    uint32_t source_fingerprint;
    uint8_t depth;
} crypto_keypath;

#define CRYPTO_HDKEY_KEYDATA_SIZE 33
#define CRYPTO_HDKEY_CHAINCODE_SIZE 32
typedef struct {
    bool is_master;
    uint8_t keydata[CRYPTO_HDKEY_KEYDATA_SIZE];
    uint8_t chaincode[CRYPTO_HDKEY_CHAINCODE_SIZE];
} hd_master_key;

#define CRYPTO_COININFO_TYPE_BTC 0
#define CRYPTO_COININFO_MAINNET 0
#define CRYPTO_COININFO_TESTNET 1
typedef struct {
    uint32_t type;
    int32_t network;
} crypto_coininfo;

#ifndef NAME_BUFFER_SIZE
#define NAME_BUFFER_SIZE 32
#endif
#ifndef NOTE_BUFFER_SIZE
#define NOTE_BUFFER_SIZE 128
#endif
typedef struct {
    bool is_private;
    uint8_t keydata[CRYPTO_HDKEY_KEYDATA_SIZE];

    uint8_t chaincode[CRYPTO_HDKEY_CHAINCODE_SIZE];
    bool valid_chaincode;

    crypto_coininfo useinfo;
    crypto_keypath origin;
    crypto_keypath children;
    uint32_t parent_fingerprint;

    char name[NAME_BUFFER_SIZE];
    char note[NOTE_BUFFER_SIZE];
} hd_derived_key;

typedef struct {
    union {
        hd_master_key master;
        hd_derived_key derived;
    } key;
    enum {
        hdkey_type_na,
        hdkey_type_master,
        hdkey_type_derived,
    } type;
} crypto_hdkey;

int urc_crypto_hdkey_deserialize(const uint8_t *cbor_buffer, size_t cbor_len, crypto_hdkey *out);
#define BIP32_SERIALIZED_LEN 78
bool bip32_serialize(const crypto_hdkey *hdkey, uint8_t out[BIP32_SERIALIZED_LEN]);

// ``out`` must be freed by caller using urc_string_free function
int format_keyorigin(const crypto_hdkey *hdkey, char **out);
int format_keyderivationpath(const crypto_hdkey *hdkey, char **out);
int urc_bip32_tobase58(const crypto_hdkey *hdkey, char **out);

#ifdef __cplusplus
}
#endif
