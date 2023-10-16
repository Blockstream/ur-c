
#include "urc/urc.h"

#define BUFSIZE 1000

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    urc_error result;

    crypto_seed seed;
    result = parse_seed(size, data, &seed);
    if(result.tag == urc_error_tag_noerror) {
        return -1;
    }

    crypto_psbt psbt;
    uint8_t buffer[BUFSIZE];
    psbt.buffer = buffer;
    psbt.buffer_size = BUFSIZE;
    result = parse_psbt(size, data, &psbt);
    if(result.tag == urc_error_tag_noerror) {
        return -1;
    }

    crypto_eckey eckey;
    result = parse_eckey(size, data, &eckey);
    if(result.tag == urc_error_tag_noerror) {
        return -1;
    }

    crypto_hdkey hdkey;
    result = parse_hdkey(size, data, &hdkey);
    if(result.tag == urc_error_tag_noerror) {
        return -1;
    }

    crypto_output output;
    result = parse_output(size, data, &output);
    if(result.tag == urc_error_tag_noerror) {
        return -1;
    }

    crypto_account account;
    result = parse_account(size, data, &account);
    if(result.tag == urc_error_tag_noerror) {
        return -1;
    }
    result = parse_jadeaccount(size, data, &account);
    if(result.tag == urc_error_tag_noerror) {
        return -1;
    }

    jade_bip8539_response response;
    int err = urc_jade_bip8539_response_parse(data, size, &response, buffer, BUFSIZE);
    if (err != 0) {
        return -1;
    }
    return 0;
}
