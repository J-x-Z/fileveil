// SPDX-License-Identifier: MPL-2.0
#include <cstdint>
#include <numeric>
#include <vector>
extern "C" uint64_t project_sum(unsigned count) {
  std::vector<uint64_t> values(count);
  std::iota(values.begin(), values.end(), uint64_t{1});
  return std::accumulate(values.begin(), values.end(), uint64_t{0});
}
