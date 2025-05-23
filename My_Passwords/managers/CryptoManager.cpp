#include "CryptoManager.h"
#include <vector>

// XOR 암호화 (대칭)
std::string CryptoManager::xorEncrypt(const std::string& str, const std::string& key) {
    std::string result = str;
    for (size_t i = 0; i < str.size(); ++i) {
        result[i] ^= key[i % key.size()];
    }
    return result;
}

// XOR 복호화 (동일)
std::string CryptoManager::xorDecrypt(const std::string& str, const std::string& key) {
    return xorEncrypt(str, key); // XOR is symmetrical
}

// Base64 인코딩용 문자 테이블
static const std::string base64_chars =
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz"
"0123456789+/";

std::string CryptoManager::base64Encode(const std::string& data) {
    std::string encoded;
    int val = 0, valb = -6;
    for (unsigned char c : data) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            encoded.push_back(base64_chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) encoded.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
    while (encoded.size() % 4) encoded.push_back('=');
    return encoded;
}

std::string CryptoManager::base64Decode(const std::string& encoded) {
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) T[base64_chars[i]] = i;

    std::string decoded;
    int val = 0, valb = -8;
    for (unsigned char c : encoded) {
        if (T[c] == -1) break;
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) {
            decoded.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return decoded;
}
