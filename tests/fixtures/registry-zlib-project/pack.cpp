// SPDX-License-Identifier: MPL-2.0
#include "archive.hpp"
#include <iostream>
#include <stdexcept>
int main(int argc, char **argv) {
  try {
    if (argc != 4) throw std::runtime_error("usage: fvpack encode|decode input output");
    const auto bytes = read_file(argv[2]);
    const std::string mode(argv[1]);
    if (mode != "encode" && mode != "decode") throw std::runtime_error("invalid mode");
    const auto result = mode == "encode" ? encode(bytes) : decode(bytes);
    write_file(argv[3], result);
    std::cout << "bytes=" << result.size() << '\n';
    return 0;
  } catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 2;
  }
}
