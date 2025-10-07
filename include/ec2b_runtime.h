#pragma once
#include <cstdint>
#include <cstddef>
#include <vector>

const std::vector<uint8_t>& ec2b_xorpad();

void xor_with_ec2b(uint8_t* data, size_t len);

inline void xor_with_ec2b(std::vector<uint8_t>& buf) {
    if (!buf.empty()) xor_with_ec2b(buf.data(), buf.size());
}
