#include "../include/CryptoOps.h"
#include <blake2.h>
#include <esp_random.h>
#include <base64.h>

void CryptoOps::begin(DataStorage& dataStorage){
    _dataStorage = &dataStorage;
}

void CryptoOps::doubleSHA256(const unsigned char* input, size_t length, unsigned char* output) {
    mbedtls_sha256_context ctx;
    unsigned char hash[32];

    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts_ret(&ctx, 0);
    mbedtls_sha256_update_ret(&ctx, input, length);
    mbedtls_sha256_finish_ret(&ctx, hash);

    mbedtls_sha256_starts_ret(&ctx, 0);
    mbedtls_sha256_update_ret(&ctx, hash, 32);
    mbedtls_sha256_finish_ret(&ctx, output);

    mbedtls_sha256_free(&ctx);
}

void CryptoOps::doubleBlake2b(const unsigned char* input, size_t length, unsigned char* output) {
    unsigned char hash[32];

    blake2b_state S[1];
    blake2b_init(S, 32);
    blake2b_update(S, input, length);
    blake2b_final(S, hash, 32);

    blake2b_init(S, 32);
    blake2b_update(S, hash, 32);
    blake2b_final(S, output, 32);
}

void CryptoOps::generateRandomIV(byte* iv, size_t ivLength) {
    for (size_t i = 0; i < ivLength; i++) {
        iv[i]
