#include "ec2b_runtime.h"
#include "ec2b.h"
#include "ec2b_data.h"

#include <atomic>
#include <mutex>

namespace {
    std::once_flag g_once;
    std::vector<uint8_t> g_xorpad;

    void init_xorpad_once() {
        auto arr = derive_xorpad_from_b64(kEc2bB64);
        g_xorpad.assign(arr.begin(), arr.end());
    }
}

const std::vector<uint8_t>& ec2b_xorpad() {
    std::call_once(g_once, init_xorpad_once);
    return g_xorpad;
}

void xor_with_ec2b(uint8_t* data, size_t len) {
    if (!data || len == 0) return;
    const auto& xp = ec2b_xorpad();
    const size_t n = xp.size();

    size_t i = 0;
    for (; i + n <= len; i += n) {
        for (size_t j = 0; j < n; ++j) data[i + j] ^= xp[j];
    }
    for (size_t j = 0; i < len; ++i, ++j) data[i] ^= xp[j];
}
