
#include "urc/urc.h"

#define BUFSIZE 1000

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t len) {
    int result;

    crypto_seed seed;
    result = urc_crypto_seed_deserialize(data, len, &seed);
    if(result == URC_OK) {
        return -1;
    }

    crypto_psbt psbt;
    result = urc_crypto_psbt_deserialize(data, len, &psbt);
    // it is so easy to generate a valid cbor representation of a psbt that checking the result is pointless
    urc_crypto_psbt_free(&psbt);

    crypto_eckey eckey;
    result = urc_crypto_eckey_deserialize(data, len, &eckey);
    if(result == URC_OK) {
        return -1;
    }

    crypto_hdkey hdkey;
    result = urc_crypto_hdkey_deserialize(data, len, &hdkey);
    if(result == URC_OK) {
        return -1;
    }

    crypto_output output;
    result = urc_crypto_output_deserialize(data, len, &output);
    if(result == URC_OK) {
        return -1;
    }

    crypto_account account;
    result = urc_crypto_account_deserialize(data, len, &account);
    if(result == URC_OK) {
        return -1;
    }
    result = urc_jade_account_deserialize(data, len, &account);
    if(result == URC_OK) {
        return -1;
    }

    jade_bip8539_response response;
    result = urc_jade_bip8539_response_deserialize(data, len, &response);
    urc_jade_bip8539_response_free(&response);
    if (result != URC_OK) {
        return -1;
    }

    char *out = NULL;
    result = urc_jade_rpc_deserialize(data, len, &out);
    if (result != URC_OK) {
        return -1;
    }
    urc_string_free(out);

    return 0;
}
