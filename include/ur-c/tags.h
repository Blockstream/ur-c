#pragma once

typedef enum urc_urtypes_tags {
    urc_urtypes_tags_crypto_seed = 300,
    urc_urtypes_tags_crypto_keypath = 304,
    urc_urtypes_tags_crypto_coin_info = 305,
    urc_urtypes_tags_crypto_eckey = 306,
    urc_urtypes_tags_crypto_psbt = 310,

    urc_urtypes_tags_crypto_psh = 400,
    urc_urtypes_tags_crypto_p2pkh = 403,
    urc_urtypes_tags_crypto_p2wpkh = 404,
} urc_tagged_types;
