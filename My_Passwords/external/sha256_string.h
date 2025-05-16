#pragma once
#ifndef SHA256_STRING_H
#define SHA256_STRING_H
#include "sha256.h"
#include <string>
#include <sstream>
#include <iomanip>

using namespace std;

string sha256(const string& input);

#endif