
#include "urc/urc.h"

#define BUFSIZE 1000

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t len) {
    int result;

    crypto_seed seed;
    result = urc_crypto_seed_parse(data, len, &seed);
    if(result == URC_OK) {
        return -1;
    }

    crypto_psbt psbt;
    uint8_t buffer[BUFSIZE];
    psbt.buffer = buffer;
    psbt.buffer_size = BUFSIZE;
    result = urc_crypto_psbt_parse(data, len, &psbt);
    if(result == URC_OK) {
        return -1;
    }

    crypto_eckey eckey;
    result = urc_crypto_eckey_parse(data, len, &eckey);
    if(result == URC_OK) {
        return -1;
    }

    crypto_hdkey hdkey;
    result = urc_crypto_hdkey_parse(data, len, &hdkey);
    if(result == URC_OK) {
        return -1;
    }

    crypto_output output;
    result = urc_crypto_output_parse(data, len, &output);
    if(result == URC_OK) {
        return -1;
    }

    crypto_account account;
    result = urc_crypto_account_parse(data, len, &account);
    if(result == URC_OK) {
        return -1;
    }
    result = urc_jade_account_parse(data, len, &account);
    if(result == URC_OK) {
        return -1;
    }

    jade_bip8539_response response;
    result = urc_jade_bip8539_response_parse(data, len, &response);
    urc_jade_bip8539_response_clean(&response);
    if (result != URC_OK) {
        return -1;
    }

    char *out = NULL;
    result = urc_jade_rpc_parse(data, len, &out);
    if (result != URC_OK) {
        return -1;
    }
    urc_string_free(out);

    return 0;
}
