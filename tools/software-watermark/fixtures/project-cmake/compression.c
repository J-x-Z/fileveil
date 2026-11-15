// SPDX-License-Identifier: MPL-2.0
#include <stdlib.h>
#include <string.h>
#include <zlib.h>
int project_roundtrip(unsigned count) {
  unsigned char *source = malloc(count ? count : 1);
  uLongf capacity = compressBound(count), length = count;
  unsigned char *compressed = malloc(capacity), *decoded = malloc(count ? count : 1);
  if (!source || !compressed || !decoded) { free(source); free(compressed); free(decoded); return -1; }
  for (unsigned i = 0; i < count; i++) source[i] = (unsigned char)(i % 251);
  int okay = compress(compressed, &capacity, source, count) == Z_OK &&
             uncompress(decoded, &length, compressed, capacity) == Z_OK &&
             length == count && memcmp(source, decoded, count) == 0;
  free(source); free(compressed); free(decoded);
  return okay ? 0 : -1;
}
