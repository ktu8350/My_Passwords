#ifndef CRYPTO_MANAGER_H
#define CRYPTO_MANAGER_H

#include <string>

class CryptoManager {
public:
    static std::string xorEncrypt(const std::string& str, const std::string& key);
    static std::string xorDecrypt(const std::string& str, const std::string& key);

    static std::string base64Encode(const std::string& data);
    static std::string base64Decode(const std::string& encoded);
};

#endif
