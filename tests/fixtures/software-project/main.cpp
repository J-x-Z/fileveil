// SPDX-License-Identifier: MPL-2.0
#include <cstdio>
#include <cstdlib>
int main(int argc, char **argv) {
    const int value = argc > 1 ? std::atoi(argv[1]) : 0;
    std::printf("result=%d\n", value * value + 1);
    return 0;
}
