// SPDX-License-Identifier: MPL-2.0
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) {
    const int value = argc > 1 ? atoi(argv[1]) : 0;
    printf("result=%d\n", value * value + 1);
    return 0;
}
