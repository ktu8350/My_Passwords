#include "CryptoManager.h"

std::string CryptoManager::xorEncrypt(const std::string& str, const std::string& key) {
    std::string result = str;
    for (size_t i = 0; i < str.size(); ++i) {
        result[i] ^= key[i % key.size()];
    }
    return result;
}

std::string CryptoManager::xorDecrypt(const std::string& str, const std::string& key) {
    return xorEncrypt(str, key); // XOR is symmetrical
}
