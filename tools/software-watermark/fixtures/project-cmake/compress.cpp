// SPDX-License-Identifier: MPL-2.0
#include <iostream>
#include <string>
extern "C" int project_roundtrip(unsigned);
int main(int argc, char **argv) {
  unsigned count = argc > 1 ? std::stoul(argv[1]) : 1000;
  if (count > 1000000 || project_roundtrip(count)) return 2;
  std::cout << "roundtrip:" << count << '\n';
}
