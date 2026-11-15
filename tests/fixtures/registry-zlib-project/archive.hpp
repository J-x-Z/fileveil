// SPDX-License-Identifier: MPL-2.0
#pragma once
#include <string>
#include <vector>
std::vector<unsigned char> read_file(const std::string &path);
void write_file(const std::string &path, const std::vector<unsigned char> &bytes);
std::vector<unsigned char> encode(const std::vector<unsigned char> &input);
std::vector<unsigned char> decode(const std::vector<unsigned char> &input);
