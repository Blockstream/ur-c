#pragma once

typedef enum {
    urc_urtypes_tags_crypto_seed = 300,
    urc_urtypes_tags_crypto_hdkey = 303,
    urc_urtypes_tags_crypto_keypath = 304,
    urc_urtypes_tags_crypto_coin_info = 305,
    urc_urtypes_tags_crypto_eckey = 306,
    urc_urtypes_tags_crypto_output = 308,
    urc_urtypes_tags_crypto_psbt = 310,

    // reserved to crypto-output
    urc_urtypes_tags_output_sh = 400,
    urc_urtypes_tags_output_wsh = 401,
    urc_urtypes_tags_output_pk = 402,
    urc_urtypes_tags_output_pkh = 403,
    urc_urtypes_tags_output_wpkh = 404,
    urc_urtypes_tags_output_combo = 405,
    urc_urtypes_tags_output_multisig = 406,
    urc_urtypes_tags_output_rawscript = 408,
    urc_urtypes_tags_output_taproot = 409,
    urc_urtypes_tags_output_cosigner = 410,
} urc_tagged_types;

// WARNING: this is going to be deprecated once
// https://github.com/intel/tinycbor/pull/241 is merged
typedef enum {
    CborNumberOfDaysSinceTheEpochDate19700101Tag = 100,
} URCCborKnowTags;

