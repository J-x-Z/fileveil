// SPDX-License-Identifier: MPL-2.0
#include "archive.hpp"
#include <fstream>
#include <stdexcept>
std::vector<unsigned char> read_file(const std::string &path) {
  std::ifstream source(path, std::ios::binary | std::ios::ate);
  if (!source || source.tellg() < 0 || source.tellg() > 16 * 1024 * 1024)
    throw std::runtime_error("invalid or oversized input");
  std::vector<unsigned char> bytes(static_cast<std::size_t>(source.tellg()));
  source.seekg(0);
  if (!bytes.empty() && !source.read(reinterpret_cast<char *>(bytes.data()), bytes.size()))
    throw std::runtime_error("input read failed");
  return bytes;
}
void write_file(const std::string &path, const std::vector<unsigned char> &bytes) {
  std::ofstream target(path, std::ios::binary | std::ios::trunc);
  if (!target || (!bytes.empty() && !target.write(reinterpret_cast<const char *>(bytes.data()), bytes.size())))
    throw std::runtime_error("output write failed");
}
