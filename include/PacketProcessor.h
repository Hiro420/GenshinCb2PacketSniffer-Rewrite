#pragma once
#include <vector>
#include <cstdint>

enum class PacketSource {
    Client,
    Server
};

namespace PacketProcessor {
    void Process(const std::vector<uint8_t>& bytes, PacketSource src);
}
