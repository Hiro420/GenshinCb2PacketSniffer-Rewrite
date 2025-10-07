#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

std::array<uint8_t,4096> derive_xorpad_from_b64(const char* b64, std::size_t len);

inline std::array<uint8_t,4096> derive_xorpad_from_b64(const std::string& s) {
    return derive_xorpad_from_b64(s.c_str(), s.size());
}
