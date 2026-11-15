// SPDX-License-Identifier: MPL-2.0
#include <stdio.h>
#include <zlib.h>
int main(int argc, char **argv) {
  if (argc != 2) return 2;
  FILE *file = fopen(argv[1], "rb");
  if (!file) return 2;
  unsigned char buffer[4096];
  unsigned long value = crc32(0L, Z_NULL, 0);
  size_t count;
  while ((count = fread(buffer, 1, sizeof buffer, file))) value = crc32(value, buffer, (uInt)count);
  int failed = ferror(file);
  fclose(file);
  if (failed) return 2;
  printf("%08lx\n", value);
  return 0;
}
