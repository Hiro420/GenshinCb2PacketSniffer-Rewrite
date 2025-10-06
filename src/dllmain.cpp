#include <windows.h>
#include <atomic>
#include <cstdio>
#include "Hooks.h"
#include <iostream>

static HINSTANCE g_hinst = NULL;
static HANDLE g_workerThread = NULL;
static DWORD  g_workerThreadId = 0;
static std::atomic_bool g_hooksInitialized(false);

static bool HasEnetExports(HMODULE mod) {
    if (!mod) return false;
    FARPROC pSend = GetProcAddress(mod, "enet_peer_send");
    FARPROC pService = GetProcAddress(mod, "enet_peer_receive");
    return pSend && pService;
}

static void RedirectStdioToConsole() {
    FILE* fp = nullptr;

    if (freopen_s(&fp, "CONOUT$", "w", stdout) == 0 && fp)
        setvbuf(stdout, nullptr, _IONBF, 0);
    if (freopen_s(&fp, "CONOUT$", "w", stderr) == 0 && fp)
        setvbuf(stderr, nullptr, _IONBF, 0);
    if (freopen_s(&fp, "CONIN$", "r", stdin) == 0 && fp)
        setvbuf(stdin, nullptr, _IONBF, 0);

    std::ios_base::sync_with_stdio(true);
}

static DWORD WINAPI WorkerThread(LPVOID) {
    Sleep(2000);
    if (AllocConsole()) {
        SetConsoleTitleA("EnetSniffer Console");
        RedirectStdioToConsole();
        printf("[EnetSniffer] Console allocated after 2 seconds.\n");
    }

    printf("[EnetSniffer] Waiting for enet.dll (1 ms polling)...\n");
    for (;;) {
        HMODULE enet = GetModuleHandleA("enet.dll");
        if (enet && HasEnetExports(enet)) {
            if (Hooks::Initialize()) {
                g_hooksInitialized.store(true, std::memory_order_release);
                printf("[EnetSniffer] Hooks installed immediately after ENet load.\n");
            }
            else {
                printf("[EnetSniffer] Hooks::Initialize() failed.\n");
            }
            break;
        }
        Sleep(1);
    }

    HANDLE h = g_workerThread;
    g_workerThread = NULL;
    if (h) CloseHandle(h);
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID) {
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        g_hinst = hinst;
        DisableThreadLibraryCalls(hinst);

        if (!g_workerThread) {
            g_workerThread = CreateThread(
                nullptr, 0, WorkerThread, nullptr, 0, &g_workerThreadId
            );
        }
        break;

    case DLL_PROCESS_DETACH:
        if (g_hooksInitialized.load(std::memory_order_acquire)) {
            Hooks::Uninitialize();
            g_hooksInitialized.store(false, std::memory_order_release);
        }
        if (g_workerThread) {
            CloseHandle(g_workerThread);
            g_workerThread = NULL;
        }
        break;
    }
    return TRUE;
}
