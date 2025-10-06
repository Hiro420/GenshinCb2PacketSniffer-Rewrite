#pragma once
#include <cstdint>
#include <cstddef>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    ENET_EVENT_TYPE_NONE = 0,
    ENET_EVENT_TYPE_CONNECT = 1,
    ENET_EVENT_TYPE_DISCONNECT = 2,
    ENET_EVENT_TYPE_RECEIVE = 3
} ENetEventType;

typedef struct ENetPacket {
    void* referenceCount; 
    uint32_t flags;
    void* data;
    size_t dataLength;
    void* freeCallback;
    void* userData;
} ENetPacket;

typedef struct ENetEvent {
    ENetEventType type;
    void* peer;
    uint8_t channelID;
    uint32_t data;
    ENetPacket* packet;
} ENetEvent;

#ifdef __cplusplus
}
#endif
