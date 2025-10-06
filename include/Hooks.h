#pragma once
#include <cstdint>
#include <vector>

enum class PacketSource : uint8_t { Client = 0, Server = 1 };

struct ENetPacket {
    void* referenceCount;
    uint32_t  flags;
    uint8_t* data;
    size_t    dataLength;
    void* freeCallback;
    void* userData;
};

namespace PacketProcessor {
    void Process(const std::vector<uint8_t>& bytes, PacketSource src);
    void _InternalShutdown();
}

namespace Hooks {
    bool Initialize();
    void Uninitialize();
}
