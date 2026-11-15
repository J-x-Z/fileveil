// SPDX-License-Identifier: MPL-2.0
#include "archive.hpp"
#include <stdexcept>
#include <zlib.h>
std::vector<unsigned char> encode(const std::vector<unsigned char> &input) {
  uLongf size = compressBound(input.size());
  std::vector<unsigned char> output(size + 4);
  for (unsigned i = 0; i < 4; ++i) output[i] = static_cast<unsigned char>(input.size() >> (8 * i));
  if (compress2(output.data() + 4, &size, input.data(), input.size(), Z_BEST_COMPRESSION) != Z_OK)
    throw std::runtime_error("compression failed");
  output.resize(size + 4);
  return output;
}
std::vector<unsigned char> decode(const std::vector<unsigned char> &input) {
  if (input.size() < 4) throw std::runtime_error("invalid archive");
  uLongf size = 0;
  for (unsigned i = 0; i < 4; ++i) size |= static_cast<uLongf>(input[i]) << (8 * i);
  if (size > 16 * 1024 * 1024) throw std::runtime_error("oversized archive");
  const auto expected = size;
  std::vector<unsigned char> output(size ? size : 1);
  if (uncompress(output.data(), &size, input.data() + 4, input.size() - 4) != Z_OK || size != expected)
    throw std::runtime_error("decompression failed");
  output.resize(size);
  return output;
}
