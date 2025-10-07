#include "Hooks.h"
#include "MinHook.h"
#include <windows.h>
#include <vector>

using fn_enet_peer_send = int(__cdecl*)(void* peer, uint8_t channelID, ENetPacket* pkt);
using fn_enet_peer_receive = ENetPacket * (__cdecl*)(void* peer, uint8_t* outChannelID);

static fn_enet_peer_send    o_enet_peer_send = nullptr;
static fn_enet_peer_receive o_enet_peer_receive = nullptr;

static FARPROC FindExport(const char* name) {
    HMODULE enet = GetModuleHandleA("enet.dll");
    if (enet) {
        if (auto p = GetProcAddress(enet, name)) return p;
    }
    return GetProcAddress(GetModuleHandleA(nullptr), name);
}

static inline void ProcessPacketIfAny(ENetPacket* p, PacketSource src) {
    if (!p || !p->data || p->dataLength == 0) return;
    std::vector<uint8_t> buf;
    buf.resize(p->dataLength);
    memcpy(buf.data(), p->data, p->dataLength);
    PacketProcessor::Process(buf, src);
}

static int __cdecl hk_enet_peer_send(void* peer, uint8_t channelID, ENetPacket* pkt) {
    ProcessPacketIfAny(pkt, PacketSource::Client);
    return o_enet_peer_send ? o_enet_peer_send(peer, channelID, pkt) : 0;
}

static ENetPacket* __cdecl hk_enet_peer_receive(void* peer, uint8_t* outChannelID) {
    ENetPacket* pkt = o_enet_peer_receive ? o_enet_peer_receive(peer, outChannelID) : nullptr;
    if (pkt) {
        ProcessPacketIfAny(pkt, PacketSource::Server);
    }
    return pkt;
}

namespace Hooks {

    bool Initialize() {
        if (MH_Initialize() != MH_OK && MH_Initialize() != MH_ERROR_ALREADY_INITIALIZED)
            return false;

        struct Item { const char* name; LPVOID detour; LPVOID* original; };
        Item items[] = {
            { "enet_peer_send",      (LPVOID)&hk_enet_peer_send,      (LPVOID*)&o_enet_peer_send },
            { "enet_peer_receive",   (LPVOID)&hk_enet_peer_receive,   (LPVOID*)&o_enet_peer_receive },
        };

        bool any = false;
        for (auto& it : items) {
            if (auto p = FindExport(it.name)) {
                if (MH_CreateHook(p, it.detour, it.original) == MH_OK) {
                    if (MH_EnableHook(p) == MH_OK) any = true;
                }
            }
        }
        return any;
    }

    void Uninitialize() {
        MH_DisableHook(MH_ALL_HOOKS);
        MH_Uninitialize();
        //PacketProcessor::_InternalShutdown();
    }

}
