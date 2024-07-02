
#include <stdint.h>

// fuzz_target.cc
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  DoSomethingInterestingWithMyAPI(data, size);
  return 0;  // Values other than 0 and -1 are reserved for future use.
}