// Description: This file contains implementations of double SHA-256 and double BLAKE2b hashing functions. 
// It also includes a function to derive a key from a passphrase using SHA-256, and functions to encrypt and decrypt a wallet address using AES-256-GCM.
// The functions are used in a mining application for NameCoin, where the block header is hashed to find a valid nonce for mining.
// The code uses the mbedTLS library for cryptographic operations and the BLAKE2 library for hashing.
#include <cstddef>
#include <mbedtls/sha256.h>
#include <blake2.h>

void doubleSHA256(const unsigned char* input, size_t length, unsigned char* output) {
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

void doubleBlake2b(const unsigned char* input, size_t length, unsigned char* output) {
    unsigned char hash[32];

    blake2b_state S[1];
    blake2b_init(S, 32);
    blake2b_update(S, input, length);
    blake2b_final(S, hash, 32);

    blake2b_init(S, 32);
    blake2b_update(S, hash, 32);
    blake2b_final(S, output, 32);
}
