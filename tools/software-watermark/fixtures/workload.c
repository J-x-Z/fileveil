// SPDX-License-Identifier: MPL-2.0
// Header-free fixture compiles for ELF, PE/COFF and Mach-O without target SDKs.
typedef unsigned long long u64;
static volatile unsigned original_constructor_count;
__attribute__((constructor)) static void original_constructor(void) {
  original_constructor_count += 1;
}
__attribute__((visibility("default"))) unsigned fileveil_fixture_constructor_count(void) {
  return original_constructor_count;
}
__attribute__((visibility("default"))) u64 fileveil_fixture_workload(u64 seed, unsigned rounds) {
  u64 value = seed;
  for (unsigned index = 0; index < rounds; ++index) {
    value ^= value << 13;
    value ^= value >> 7;
    value ^= value << 17;
    value += index * 0x9e3779b9u;
  }
  return value;
}
