#include <iostream>
#include "sha256.h"
#include <string>
#include <sstream>
#include <iomanip>
#include "sha256_string.h"

using namespace std;

string sha256(const string& input) {
    BYTE hash[SHA256_BLOCK_SIZE];
    SHA256_CTX ctx;

    sha256_init(&ctx);
    sha256_update(&ctx, reinterpret_cast<const BYTE*>(input.c_str()), input.length());
    sha256_final(&ctx, hash);

    stringstream ss;
    for (int i = 0; i < SHA256_BLOCK_SIZE; ++i)
        ss << hex << setw(2) << setfill('0') << (int)hash[i];

    return ss.str();
}