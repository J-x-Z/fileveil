// SPDX-License-Identifier: MPL-2.0
#include <cstdint>
#include <iostream>
#include <string>
extern "C" uint64_t project_sum(unsigned);
int main(int argc, char **argv) {
  unsigned count = argc > 1 ? std::stoul(argv[1]) : 1000;
  if (count > 1000000) return 2;
  std::cout << project_sum(count) << '\n';
}
