#include "ec2b_global.h"
#include "ec2b.h"
#include "ec2b_data.h"

const std::vector<uint8_t> g_ec2b_xorpad = [] {
    auto arr = derive_xorpad_from_b64(kEc2bB64, kEc2bB64Len);
    return std::vector<uint8_t>(arr.begin(), arr.end());
    }();
