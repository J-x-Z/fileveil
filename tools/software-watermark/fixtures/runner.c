// SPDX-License-Identifier: MPL-2.0
#include <stdio.h>
#include <stdlib.h>
typedef unsigned long long u64;
u64 fileveil_fixture_workload(u64 seed, unsigned rounds);
unsigned fileveil_fixture_constructor_count(void);
int main(int argc, char **argv) {
  unsigned rounds = argc > 1 ? (unsigned)strtoul(argv[1], 0, 10) : 2000000;
  printf("%016llx %u\n", fileveil_fixture_workload(0x123456789abcdef0ULL, rounds),
         fileveil_fixture_constructor_count());
  return fileveil_fixture_constructor_count() == 1 ? 0 : 2;
}
