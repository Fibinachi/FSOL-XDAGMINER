#ifndef NAMEMINER_CRYPTOOPS_H
#define NAMEMINER_CRYPTOOPS_H

#include <mbedtls/sha256.h>
#include <AESLib.h>
#include "DataStorage.h" // Include the DataStorage header file
#include <esp_random.h>
class CryptoOps {
public:
    void begin(DataStorage& dataStorage);
    void doubleSHA256(const unsigned char* input, size_t length, unsigned char* output);
    void doubleBlake2b(const unsigned char* input, size_t length, unsigned char* output);
    void generateRandomIV(byte* iv, size_t ivLength);
    void deriveKey(const char* passphrase, byte* key);
    void encryptWalletAddress(const char* walletAddress, const char* passphrase);
    String decryptWalletAddress(const char* passphrase);
private:
    DataStorage* _dataStorage;
    AESLib _aesLib;
};

#endif // NAMEMINER_CRYPTOOPS_H
