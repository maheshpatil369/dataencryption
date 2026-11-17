// Host (PC) runner for the same test-suite that runs on the STM32.
// Build: make   Run: ./auv_host_test
#include <chrono>
#include <cstdio>
#define AUV_ALLOW_DEMO_KEYS 1
#include "../../examples/AUV_SelfTest/AUV_TestSuite.h"

static void hostPrint(const char *s) { std::puts(s); }
static uint32_t hostMicros() {
    using namespace std::chrono;
    return (uint32_t)duration_cast<microseconds>(steady_clock::now().time_since_epoch()).count();
}
int main() { return AUV_runAllTests(hostPrint, hostMicros) == 0 ? 0 : 1; }
