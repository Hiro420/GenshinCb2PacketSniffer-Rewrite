#define NOMINMAX
#include "PacketProcessor.h"
#include "ENetTypes.h"
#include <windows.h>

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <deque>
#include <filesystem>
#include <mutex>
#include <string>
#include <fstream>
#include <unordered_map>
#include <vector>
#include <iomanip>
#include <sstream>
#include "ec2b_global.h"

namespace fs = std::filesystem;

static std::string to_hex(const uint8_t* data, size_t len, bool with_ascii = false) {
    std::ostringstream oss;
    oss.setf(std::ios::uppercase);
    size_t bytes_per_line = 16;

    for (size_t i = 0; i < len; ++i) {
        if ((i % bytes_per_line) == 0) {
            if (i) oss << "\n";
        }
        oss << std::setw(2) << std::setfill('0') << std::hex << (unsigned)data[i] << ' ';

        if (with_ascii && ((i + 1) % bytes_per_line) == 0) {
            oss << " |";
            for (size_t j = i + 1 - bytes_per_line; j <= i; ++j) {
                unsigned char c = data[j];
                oss << (std::isprint(c) ? char(c) : '.');
            }
            oss << '|';
        }
    }

    if (with_ascii && (len % bytes_per_line) != 0) {
        size_t rem = len % bytes_per_line;
        for (size_t k = rem; k < bytes_per_line; ++k) oss << "   ";
        if (rem <= 8) oss << ' ';
        oss << " |";
        for (size_t j = len - rem; j < len; ++j) {
            unsigned char c = data[j];
            oss << (std::isprint(c) ? char(c) : '.');
        }
        oss << '|';
    }

    return oss.str();
}

static inline bool ReadVarint(const uint8_t*& p, const uint8_t* end, uint64_t& out) {
    uint64_t v = 0; int shift = 0;
    while (p < end && shift <= 63) {
        uint8_t b = *p++;
        v |= uint64_t(b & 0x7F) << shift;
        if ((b & 0x80) == 0) { out = v; return true; }
        shift += 7;
    }
    return false;
}
static inline bool ReadLen(const uint8_t*& p, const uint8_t* end, size_t& len) {
    uint64_t v = 0;
    if (!ReadVarint(p, end, v)) return false;
    if (v > size_t(end - p)) return false;
    len = size_t(v);
    return true;
}

static inline uint16_t ReadBE16(const uint8_t* p) {
    return (uint16_t(p[0]) << 8) | uint16_t(p[1]);
}
static inline uint32_t ReadBE32(const uint8_t* p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | uint32_t(p[3]);
}

static bool ExtractSecretKeySeed(const uint8_t* payload, size_t payloadLen, uint64_t& secretKeySeed) {
    const uint8_t* p = payload;
    const uint8_t* end = payload + payloadLen;
    while (p < end) {
        uint64_t key = 0;
        if (!ReadVarint(p, end, key)) return false;
        uint32_t fieldNumber = uint32_t(key >> 3);
        uint32_t wireType = uint32_t(key & 0x07);

        switch (wireType) {
        case 0: {
            uint64_t val;
            if (!ReadVarint(p, end, val)) return false;
            if (fieldNumber == 11) {
                secretKeySeed = val;
                return true;
            }
            break;
        }
        case 1: {
            if (end - p < 8) return false;
            if (fieldNumber == 11) {
                secretKeySeed = *reinterpret_cast<const uint64_t*>(p);
                return true;
            }
            p += 8;
            break;
        }
        case 2: {
            size_t len = 0;
            if (!ReadLen(p, end, len)) return false;
            if (end - p < ptrdiff_t(len)) return false;
            p += len;
            break;
        }
        case 5: {
            if (end - p < 4) return false;
            p += 4;
            break;
        }
        default:
            return false;
        }
    }
    return false;
}

static inline bool DecimalToU64(const std::string& s, uint64_t& out) {
    if (s.empty()) return false;
    uint64_t v = 0;
    for (char c : s) {
        if ((unsigned)(c - '0') > 9U) return false;
        uint32_t d = static_cast<uint32_t>(c - '0');
        if (v > ((std::numeric_limits<uint64_t>::max)() - d) / 10ULL) return false;
        v = v * 10ULL + d;
    }
    out = v; return true;
}

class MT64 {
public:
    MT64() { for (auto& v : mt_) v = 0ULL; mti_ = 313; }
    void Seed(uint64_t seed) {
        mt_[0] = seed;
        for (int i = 1; i < 312; ++i)
            mt_[i] = 6364136223846793005ULL * (mt_[i - 1] ^ (mt_[i - 1] >> 62)) + (uint64_t)i;
        mti_ = 312;
    }
    uint64_t Int64() {
        if (mti_ >= 312) {
            if (mti_ == 313) Seed(5489ULL);
            for (int k = 0; k < 311; ++k) {
                uint64_t y = (mt_[k] & 0xFFFFFFFF80000000ULL) | (mt_[k + 1] & 0x7FFFFFFFULL);
                mt_[k] = ((k < 312 - 156) ? mt_[k + 156] : mt_[k + 156 - 312]) ^ (y >> 1) ^ ((y & 1ULL) ? 0xB5026F5AA96619E9ULL : 0ULL);
            }
            uint64_t y = (mt_[311] & 0xFFFFFFFF80000000ULL) | (mt_[0] & 0x7FFFFFFFULL);
            mt_[311] = mt_[155] ^ (y >> 1) ^ ((y & 1ULL) ? 0xB5026F5AA96619E9ULL : 0ULL);
            mti_ = 0;
        }
        uint64_t r = mt_[mti_++];
        r ^= (r >> 29) & 0x5555555555555555ULL;
        r ^= (r << 17) & 0x71D67FFFEDA60000ULL;
        r ^= (r << 37) & 0xFFF7EEE000000000ULL;
        r ^= (r >> 43);
        return r;
    }
private:
    uint64_t mt_[312]; int mti_;
};
static inline std::vector<uint8_t> NewKeyFromSeed(uint64_t seed) {
    MT64 mt; mt.Seed(seed);
    std::vector<uint8_t> key; key.reserve(512 * 8);
    for (int i = 0; i < 512; ++i) {
        uint64_t v = mt.Int64();
        for (int s = 7; s >= 0; --s) key.push_back(uint8_t((v >> (s * 8)) & 0xFF));
    }
    return key;
}

static inline void XorInPlace(std::vector<uint8_t>& buf, const std::vector<uint8_t>& key) {
    if (key.empty()) return;
    const size_t klen = key.size();
    for (size_t i = 0; i < buf.size(); ++i) buf[i] ^= key[i % klen];
}

static inline fs::path GetBaseDir() {
    char buf[MAX_PATH];
    if (GetModuleFileNameA(NULL, buf, (DWORD)MAX_PATH)) {
        std::string path(buf);
        auto pos = path.find_last_of("\\/");
        std::string dir = (pos != std::string::npos) ? path.substr(0, pos) : ".";
        return fs::path(dir);
    }
    return fs::path(".");
}
static inline fs::path RawPacketDir() { return GetBaseDir() / "RawPackets"; }

struct PacketJob {
    std::wstring pathW;
    std::vector<uint8_t> data;
};

static SRWLOCK g_qLock = SRWLOCK_INIT;
static CONDITION_VARIABLE g_qCv = CONDITION_VARIABLE_INIT;
static std::deque<PacketJob> g_queue;
static HANDLE g_writerThread = NULL;
static std::atomic<bool> g_stop{ false };

static DWORD WINAPI WriterThread(LPVOID) {
    for (;;) {
        AcquireSRWLockExclusive(&g_qLock);
        while (g_queue.empty() && !g_stop.load()) {
            SleepConditionVariableSRW(&g_qCv, &g_qLock, INFINITE, 0);
        }
        if (g_stop.load() && g_queue.empty()) {
            ReleaseSRWLockExclusive(&g_qLock);
            break;
        }
        PacketJob job = std::move(g_queue.front());
        g_queue.pop_front();
        ReleaseSRWLockExclusive(&g_qLock);

        HANDLE h = CreateFileW(job.pathW.c_str(),
            GENERIC_WRITE, FILE_SHARE_READ,
            nullptr, CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
            nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            if (!job.data.empty()) {
                DWORD wrote = 0;
                WriteFile(h, job.data.data(), (DWORD)job.data.size(), &wrote, nullptr);
            }
            CloseHandle(h);
        }
    }
    return 0;
}

static void EnsureInitOnce() {
    static std::once_flag once;
    std::call_once(once, [] {
        std::error_code ec;
        fs::create_directories(RawPacketDir(), ec);
        g_stop.store(false);
        g_writerThread = CreateThread(nullptr, 0, WriterThread, nullptr, 0, nullptr);
        });
}

static const std::unordered_map<uint16_t, const char*>& PacketNameMap() {
    static const std::unordered_map<uint16_t, const char*> m = {
        { 1, "KeepAliveNotify" },
        { 2, "GmTalkReq" },
        { 3, "GmTalkRsp" },
        { 4, "ShowMessageNotify" },
        { 5, "PingReq" },
        { 6, "PingRsp" },
        { 8, "GetOnlinePlayerListReq" },
        { 9, "GetOnlinePlayerListRsp" },
        { 10, "ServerTimeNotify" },
        { 11, "ServerLogNotify" },
        { 12, "ClientReconnectNotify" },
        { 13, "ClientFpsStatusNotify" },
        { 14, "RobotPushPlayerDataNotify" },
        { 15, "ClientReportNotify" },
        { 101, "GetPlayerTokenReq" },
        { 102, "GetPlayerTokenRsp" },
        { 103, "PlayerLoginReq" },
        { 104, "PlayerLoginRsp" },
        { 105, "PlayerLogoutReq" },
        { 106, "PlayerLogoutRsp" },
        { 107, "PlayerLogoutNotify" },
        { 108, "PlayerDataNotify" },
        { 109, "ChangeGameTimeReq" },
        { 110, "ChangeGameTimeRsp" },
        { 111, "PlayerGameTimeNotify" },
        { 112, "PlayerPropNotify" },
        { 113, "ClientTriggerEventNotify" },
        { 114, "SetPlayerPropReq" },
        { 115, "SetPlayerPropRsp" },
        { 116, "SetPlayerBornDataReq" },
        { 117, "SetPlayerBornDataRsp" },
        { 118, "DoSetPlayerBornDataNotify" },
        { 119, "PlayerPropChangeNotify" },
        { 120, "SetPlayerNameReq" },
        { 121, "SetPlayerNameRsp" },
        { 122, "SetOpenStateReq" },
        { 123, "SetOpenStateRsp" },
        { 124, "OpenStateUpdateNotify" },
        { 125, "OpenStateChangeNotify" },
        { 126, "PlayerCookReq" },
        { 127, "PlayerCookRsp" },
        { 128, "PlayerRandomCookReq" },
        { 129, "PlayerRandomCookRsp" },
        { 130, "CookDataNotify" },
        { 131, "CookRecipeDataNotify" },
        { 132, "CookGradeDataNotify" },
        { 133, "PlayerCompoundMaterialReq" },
        { 134, "PlayerCompoundMaterialRsp" },
        { 135, "TakeCompoundOutputReq" },
        { 136, "TakeCompoundOutputRsp" },
        { 137, "CompoundDataNotify" },
        { 138, "GetCompoundDataReq" },
        { 139, "GetCompoundDataRsp" },
        { 140, "PlayerTimeNotify" },
        { 141, "PlayerSetPauseReq" },
        { 142, "PlayerSetPauseRsp" },
        { 143, "PlayerSetLanguageReq" },
        { 144, "PlayerSetLanguageRsp" },
        { 145, "DataResVersionNotify" },
        { 146, "DailyTaskDataNotify" },
        { 147, "DailyTaskProgressNotify" },
        { 148, "DailyTaskScoreRewardNotify" },
        { 149, "WorldOwnerDailyTaskNotify" },
        { 150, "AddRandTaskInfoNotify" },
        { 151, "RemoveRandTaskInfoNotify" },
        { 152, "TakePlayerLevelRewardReq" },
        { 153, "TakePlayerLevelRewardRsp" },
        { 154, "PlayerLevelRewardUpdateNotify" },
        { 155, "GivingRecordNotify" },
        { 156, "GivingRecordChangeNotify" },
        { 157, "ItemGivingReq" },
        { 158, "ItemGivingRsp" },
        { 159, "PlayerCookArgsReq" },
        { 160, "PlayerCookArgsRsp" },
        { 161, "PlayerLuaShellNotify" },
        { 162, "ServerDisconnectClientNotify" },
        { 201, "PlayerEnterSceneNotify" },
        { 202, "LeaveSceneReq" },
        { 203, "LeaveSceneRsp" },
        { 204, "SceneInitFinishReq" },
        { 205, "SceneInitFinishRsp" },
        { 206, "SceneEntityAppearNotify" },
        { 207, "SceneEntityDisappearNotify" },
        { 208, "SceneEntityMoveReq" },
        { 209, "SceneEntityMoveRsp" },
        { 210, "SceneAvatarStaminaStepReq" },
        { 211, "SceneAvatarStaminaStepRsp" },
        { 212, "SceneEntityMoveNotify" },
        { 213, "ScenePlayerLocationNotify" },
        { 214, "GetScenePointReq" },
        { 215, "GetScenePointRsp" },
        { 216, "EnterTransPointRegionNotify" },
        { 217, "ExitTransPointRegionNotify" },
        { 218, "ScenePointUnlockNotify" },
        { 219, "SceneTransToPointReq" },
        { 220, "SceneTransToPointRsp" },
        { 221, "EntityJumpNotify" },
        { 222, "GetSceneAreaReq" },
        { 223, "GetSceneAreaRsp" },
        { 224, "SceneAreaUnlockNotify" },
        { 225, "SceneEntityDrownReq" },
        { 226, "SceneEntityDrownRsp" },
        { 227, "SceneCreateEntityReq" },
        { 228, "SceneCreateEntityRsp" },
        { 229, "SceneDestroyEntityReq" },
        { 230, "SceneDestroyEntityRsp" },
        { 231, "SceneForceUnlockNotify" },
        { 232, "SceneForceLockNotify" },
        { 233, "EnterWorldAreaReq" },
        { 234, "EnterWorldAreaRsp" },
        { 235, "EntityForceSyncReq" },
        { 236, "EntityForceSyncRsp" },
        { 237, "SceneAreaExploreNotify" },
        { 238, "SceneGetAreaExplorePercentReq" },
        { 239, "SceneGetAreaExplorePercentRsp" },
        { 240, "ClientTransmitReq" },
        { 241, "ClientTransmitRsp" },
        { 242, "EnterSceneWeatherAreaNotify" },
        { 243, "ExitSceneWeatherAreaNotify" },
        { 244, "SceneAreaWeatherNotify" },
        { 245, "ScenePlayerInfoNotify" },
        { 246, "WorldPlayerLocationNotify" },
        { 247, "BeginCameraSceneLookNotify" },
        { 248, "EndCameraSceneLookNotify" },
        { 249, "MarkEntityInMinMapNotify" },
        { 250, "UnmarkEntityInMinMapNotify" },
        { 251, "DropSubfieldReq" },
        { 252, "DropSubfieldRsp" },
        { 253, "ExecuteGroupTriggerReq" },
        { 254, "ExecuteGroupTriggerRsp" },
        { 255, "LevelupCityReq" },
        { 256, "LevelupCityRsp" },
        { 257, "SceneRouteChangeNotify" },
        { 258, "PlatformStartRouteNotify" },
        { 259, "PlatformStopRouteNotify" },
        { 260, "PlatformChangeRouteNotify" },
        { 261, "ScenePlayerSoundNotify" },
        { 262, "PersonalSceneJumpReq" },
        { 263, "PersonalSceneJumpRsp" },
        { 264, "SealBattleBeginNotify" },
        { 265, "SealBattleEndNotify" },
        { 266, "SealBattleProgressNotify" },
        { 267, "ClientPauseNotify" },
        { 268, "PlayerEnterSceneInfoNotify" },
        { 269, "JoinPlayerSceneReq" },
        { 270, "JoinPlayerSceneRsp" },
        { 271, "SceneKickPlayerReq" },
        { 272, "SceneKickPlayerRsp" },
        { 273, "SceneKickPlayerNotify" },
        { 274, "HitClientTrivialNotify" },
        { 275, "BackMyWorldReq" },
        { 276, "BackMyWorldRsp" },
        { 277, "SeeMonsterReq" },
        { 278, "SeeMonsterRsp" },
        { 279, "AddSeenMonsterNotify" },
        { 280, "AllSeenMonsterNotify" },
        { 281, "SceneTimeNotify" },
        { 282, "EnterSceneReadyReq" },
        { 283, "EnterSceneReadyRsp" },
        { 284, "EnterScenePeerNotify" },
        { 285, "EnterSceneDoneReq" },
        { 286, "EnterSceneDoneRsp" },
        { 287, "WorldPlayerDieNotify" },
        { 288, "WorldPlayerReviveReq" },
        { 289, "WorldPlayerReviveRsp" },
        { 290, "JoinPlayerFailNotify" },
        { 291, "SetSceneWeatherAreaReq" },
        { 292, "SetSceneWeatherAreaRsp" },
        { 293, "ExecuteGadgetLuaReq" },
        { 294, "ExecuteGadgetLuaRsp" },
        { 295, "CutSceneBeginNotify" },
        { 296, "CutSceneFinishNotify" },
        { 297, "CutSceneEndNotify" },
        { 298, "ClientScriptEventNotify" },
        { 299, "SceneEntitiesMovesReq" },
        { 300, "SceneEntitiesMovesRsp" },
        { 301, "EvtBeingHitNotify" },
        { 302, "EvtAnimatorParameterNotify" },
        { 303, "HostPlayerNotify" },
        { 304, "EvtDoSkillSuccNotify" },
        { 305, "EvtCreateGadgetNotify" },
        { 306, "EvtDestroyGadgetNotify" },
        { 307, "EvtFaceToEntityNotify" },
        { 308, "EvtFaceToDirNotify" },
        { 309, "EvtCostStaminaNotify" },
        { 310, "EvtSetAttackTargetNotify" },
        { 311, "EvtAnimatorStateChangedNotify" },
        { 312, "EvtRushMoveNotify" },
        { 313, "EvtBulletHitNotify" },
        { 314, "EvtBulletDeactiveNotify" },
        { 315, "EvtEntityStartDieEndNotify" },
        { 322, "EvtBulletMoveNotify" },
        { 323, "EvtAvatarEnterFocusNotify" },
        { 324, "EvtAvatarExitFocusNotify" },
        { 325, "EvtAvatarUpdateFocusNotify" },
        { 326, "EntityAuthorityChangeNotify" },
        { 327, "AvatarBuffAddNotify" },
        { 328, "AvatarBuffDelNotify" },
        { 329, "MonsterAlertChangeNotify" },
        { 330, "MonsterForceAlertNotify" },
        { 331, "MonsterForceAiNotify" },
        { 332, "AvatarEnterElementViewNotify" },
        { 333, "TriggerCreateGadgetToEquipPartNotify" },
        { 334, "EvtEntityRenderersChangedNotify" },
        { 335, "AnimatorForceSetAirMoveNotify" },
        { 336, "EvtAiSyncSkillCdNotify" },
        { 337, "EvtBeingHitsCombineNotify" },
        { 341, "EvtAvatarSitDownNotify" },
        { 342, "EvtAvatarStandUpNotify" },
        { 343, "CreateMassiveEntityReq" },
        { 344, "CreateMassiveEntityRsp" },
        { 345, "CreateMassiveEntityNotify" },
        { 346, "DestroyMassiveEntityNotify" },
        { 347, "MassiveEntityStateChangedNotify" },
        { 348, "SyncTeamEntityNotify" },
        { 349, "DelTeamEntityNotify" },
        { 350, "CombatInvocationsNotify" },
        { 401, "QuestListNotify" },
        { 402, "QuestListUpdateNotify" },
        { 403, "QuestDelNotify" },
        { 404, "FinishedParentQuestNotify" },
        { 405, "FinishedParentQuestUpdateNotify" },
        { 406, "AddQuestContentProgressReq" },
        { 407, "AddQuestContentProgressRsp" },
        { 408, "GetQuestTalkHistoryReq" },
        { 409, "GetQuestTalkHistoryRsp" },
        { 410, "QuestCreateEntityReq" },
        { 411, "QuestCreateEntityRsp" },
        { 412, "QuestDestroyEntityReq" },
        { 413, "QuestDestroyEntityRsp" },
        { 414, "LogTalkNotify" },
        { 415, "LogCutsceneNotify" },
        { 416, "ChapterStateNotify" },
        { 417, "QuestProgressUpdateNotify" },
        { 418, "QuestUpdateQuestVarReq" },
        { 419, "QuestUpdateQuestVarRsp" },
        { 420, "QuestUpdateQuestVarNotify" },
        { 421, "QuestDestroyNpcReq" },
        { 422, "QuestDestroyNpcRsp" },
        { 501, "NpcTalkReq" },
        { 502, "NpcTalkRsp" },
        { 504, "GetSceneNpcPositionReq" },
        { 505, "GetSceneNpcPositionRsp" },
        { 601, "PlayerStoreNotify" },
        { 602, "StoreWeightLimitNotify" },
        { 603, "StoreItemChangeNotify" },
        { 604, "StoreItemDelNotify" },
        { 605, "ItemAddHintNotify" },
        { 608, "UseItemReq" },
        { 609, "UseItemRsp" },
        { 610, "DropItemReq" },
        { 611, "DropItemRsp" },
        { 614, "WearEquipReq" },
        { 615, "WearEquipRsp" },
        { 616, "TakeoffEquipReq" },
        { 617, "TakeoffEquipRsp" },
        { 618, "AvatarEquipChangeNotify" },
        { 619, "WeaponUpgradeReq" },
        { 620, "WeaponUpgradeRsp" },
        { 621, "WeaponPromoteReq" },
        { 622, "WeaponPromoteRsp" },
        { 623, "ReliquaryUpgradeReq" },
        { 624, "ReliquaryUpgradeRsp" },
        { 625, "ReliquaryPromoteReq" },
        { 626, "ReliquaryPromoteRsp" },
        { 627, "AvatarCardChangeReq" },
        { 628, "AvatarCardChangeRsp" },
        { 629, "GrantRewardNotify" },
        { 630, "WeaponAwakenReq" },
        { 631, "WeaponAwakenRsp" },
        { 632, "ItemCdGroupTimeNotify" },
        { 633, "DropHintNotify" },
        { 634, "CombineReq" },
        { 635, "CombineRsp" },
        { 636, "ForgeQueueDataNotify" },
        { 637, "ForgeGetQueueDataReq" },
        { 638, "ForgeGetQueueDataRsp" },
        { 639, "ForgeStartReq" },
        { 640, "ForgeStartRsp" },
        { 641, "ForgeQueueManipulateReq" },
        { 642, "ForgeQueueManipulateRsp" },
        { 643, "ResinChangeNotify" },
        { 644, "WorldResinChangeNotify" },
        { 647, "BuyWorldResinReq" },
        { 648, "BuyWorldResinRsp" },
        { 649, "BuyResinReq" },
        { 650, "BuyResinRsp" },
        { 651, "MaterialDeleteReturnNotify" },
        { 652, "TakeMaterialDeleteReturnReq" },
        { 653, "TakeMaterialDeleteReturnRsp" },
        { 654, "MaterialDeleteUpdateNotify" },
        { 701, "GetShopReq" },
        { 702, "GetShopRsp" },
        { 703, "BuyGoodsReq" },
        { 704, "BuyGoodsRsp" },
        { 801, "GadgetInteractReq" },
        { 802, "GadgetInteractRsp" },
        { 803, "GadgetStateNotify" },
        { 804, "WorktopOptionNotify" },
        { 805, "SelectWorktopOptionReq" },
        { 806, "SelectWorktopOptionRsp" },
        { 807, "BossChestActivateNotify" },
        { 901, "DungeonEntryInfoReq" },
        { 902, "DungeonEntryInfoRsp" },
        { 903, "PlayerEnterDungeonReq" },
        { 904, "PlayerEnterDungeonRsp" },
        { 905, "PlayerQuitDungeonReq" },
        { 906, "PlayerQuitDungeonRsp" },
        { 907, "DungeonWayPointNotify" },
        { 908, "DungeonWayPointActivateReq" },
        { 909, "DungeonWayPointActivateRsp" },
        { 910, "DungeonSettleNotify" },
        { 911, "DungeonPlayerDieNotify" },
        { 912, "DungeonDieOptionReq" },
        { 913, "DungeonDieOptionRsp" },
        { 914, "DungeonShowReminderNotify" },
        { 915, "DungeonPlayerDieReq" },
        { 916, "DungeonPlayerDieRsp" },
        { 917, "DungeonDataNotify" },
        { 918, "DungeonChallengeBeginNotify" },
        { 919, "DungeonChallengeFinishNotify" },
        { 920, "ChallengeDataNotify" },
        { 921, "DungeonFollowNotify" },
        { 922, "DungeonGetStatueDropReq" },
        { 923, "DungeonGetStatueDropRsp" },
        { 924, "ChallengeRecordNotify" },
        { 925, "DungeonCandidateTeamInfoNotify" },
        { 926, "DungeonCandidateTeamInviteNotify" },
        { 927, "DungeonCandidateTeamRefuseNotify" },
        { 928, "DungeonCandidateTeamPlayerLeaveNotify" },
        { 929, "DungeonCandidateTeamDismissNotify" },
        { 930, "DungeonCandidateTeamCreateReq" },
        { 931, "DungeonCandidateTeamCreateRsp" },
        { 932, "DungeonCandidateTeamInviteReq" },
        { 933, "DungeonCandidateTeamInviteRsp" },
        { 934, "DungeonCandidateTeamKickReq" },
        { 935, "DungeonCandidateTeamKickRsp" },
        { 936, "DungeonCandidateTeamLeaveReq" },
        { 937, "DungeonCandidateTeamLeaveRsp" },
        { 938, "DungeonCandidateTeamReplyInviteReq" },
        { 939, "DungeonCandidateTeamReplyInviteRsp" },
        { 940, "DungeonCandidateTeamSetReadyReq" },
        { 941, "DungeonCandidateTeamSetReadyRsp" },
        { 942, "DungeonCandidateTeamChangeAvatarReq" },
        { 943, "DungeonCandidateTeamChangeAvatarRsp" },
        { 944, "GetDailyDungeonEntryInfoReq" },
        { 945, "GetDailyDungeonEntryInfoRsp" },
        { 1001, "UnlockAvatarTalentReq" },
        { 1002, "UnlockAvatarTalentRsp" },
        { 1003, "AvatarUnlockTalentNotify" },
        { 1004, "AvatarSkillDepotChangeNotify" },
        { 1005, "BigTalentPointConvertReq" },
        { 1006, "BigTalentPointConvertRsp" },
        { 1007, "AvatarSkillMaxChargeCountNotify" },
        { 1008, "AvatarSkillInfoNotify" },
        { 1009, "ProudSkillUpgradeReq" },
        { 1010, "ProudSkillUpgradeRsp" },
        { 1011, "ProudSkillChangeNotify" },
        { 1012, "AvatarSkillUpgradeReq" },
        { 1013, "AvatarSkillUpgradeRsp" },
        { 1014, "AvatarSkillChangeNotify" },
        { 1015, "ProudSkillExtraLevelNotify" },
        { 1016, "CanUseSkillNotify" },
        { 1101, "AbilityInvocationFixedNotify" },
        { 1102, "AbilityInvocationsNotify" },
        { 1103, "ClientAbilityInitBeginNotify" },
        { 1104, "ClientAbilityInitFinishNotify" },
        { 1105, "AbilityInvocationFailNotify" },
        { 1106, "AvatarAbilityResetNotify" },
        { 1107, "ClientAbilitiesInitFinishCombineNotify" },
        { 1108, "ElementReactionLogNotify" },
        { 1109, "AvatarAbilityResetFinishNotify" },
        { 1110, "WindSeedClientNotify" },
        { 1201, "EntityPropNotify" },
        { 1202, "LifeStateChangeNotify" },
        { 1203, "EntityFightPropNotify" },
        { 1204, "EntityFightPropUpdateNotify" },
        { 1205, "AvatarFightPropNotify" },
        { 1206, "AvatarFightPropUpdateNotify" },
        { 1207, "EntityFightPropChangeReasonNotify" },
        { 1208, "AvatarLifeStateChangeNotify" },
        { 1209, "AvatarPropChangeReasonNotify" },
        { 1210, "PlayerPropChangeReasonNotify" },
        { 1211, "AvatarPropNotify" },
        { 1212, "MarkNewNotify" },
        { 1301, "MonsterSummonTagNotify" },
        { 1402, "MailChangeNotify" },
        { 1403, "ReadMailNotify" },
        { 1404, "GetMailItemReq" },
        { 1405, "GetMailItemRsp" },
        { 1406, "DelMailReq" },
        { 1407, "DelMailRsp" },
        { 1408, "GetAuthkeyReq" },
        { 1409, "GetAuthkeyRsp" },
        { 1410, "ClientNewMailNotify" },
        { 1411, "GetAllMailReq" },
        { 1412, "GetAllMailRsp" },
        { 1501, "GetGachaInfoReq" },
        { 1502, "GetGachaInfoRsp" },
        { 1503, "DoGachaReq" },
        { 1504, "DoGachaRsp" },
        { 1701, "AvatarAddNotify" },
        { 1702, "AvatarDelNotify" },
        { 1703, "SetUpAvatarTeamReq" },
        { 1704, "SetUpAvatarTeamRsp" },
        { 1705, "ChooseCurAvatarTeamReq" },
        { 1706, "ChooseCurAvatarTeamRsp" },
        { 1707, "ChangeAvatarReq" },
        { 1708, "ChangeAvatarRsp" },
        { 1709, "AvatarPromoteReq" },
        { 1710, "AvatarPromoteRsp" },
        { 1711, "SpringUseReq" },
        { 1712, "SpringUseRsp" },
        { 1713, "RefreshBackgroundAvatarReq" },
        { 1714, "RefreshBackgroundAvatarRsp" },
        { 1715, "AvatarTeamUpdateNotify" },
        { 1716, "AvatarDataNotify" },
        { 1717, "AvatarUpgradeReq" },
        { 1718, "AvatarUpgradeRsp" },
        { 1719, "AvatarDieAnimationEndReq" },
        { 1720, "AvatarDieAnimationEndRsp" },
        { 1721, "AvatarChangeElementTypeReq" },
        { 1722, "AvatarChangeElementTypeRsp" },
        { 1723, "AvatarFetterDataNotify" },
        { 1724, "AvatarExpeditionDataNotify" },
        { 1725, "AvatarExpeditionAllDataReq" },
        { 1726, "AvatarExpeditionAllDataRsp" },
        { 1727, "AvatarExpeditionStartReq" },
        { 1728, "AvatarExpeditionStartRsp" },
        { 1729, "AvatarExpeditionCallBackReq" },
        { 1730, "AvatarExpeditionCallBackRsp" },
        { 1731, "AvatarExpeditionGetRewardReq" },
        { 1732, "AvatarExpeditionGetRewardRsp" },
        { 1734, "ChangeMpTeamAvatarReq" },
        { 1735, "ChangeMpTeamAvatarRsp" },
        { 1736, "ChangeTeamNameReq" },
        { 1737, "ChangeTeamNameRsp" },
        { 1738, "SceneTeamUpdateNotify" },
        { 1739, "SceneTeamMPDisplayCurAvatarNotify" },
        { 1740, "FocusAvatarReq" },
        { 1741, "FocusAvatarRsp" },
        { 1801, "PlayerApplyEnterMpNotify" },
        { 1802, "PlayerApplyEnterMpReq" },
        { 1803, "PlayerApplyEnterMpRsp" },
        { 1804, "PlayerApplyEnterMpResultNotify" },
        { 1805, "PlayerApplyEnterMpResultReq" },
        { 1806, "PlayerApplyEnterMpResultRsp" },
        { 1807, "PlayerQuitFromMpNotify" },
        { 1808, "PlayerPreEnterMpNotify" },
        { 1809, "GetPlayerMpModeAvailabilityReq" },
        { 1810, "GetPlayerMpModeAvailabilityRsp" },
        { 1901, "PlayerInvestigationAllInfoNotify" },
        { 1902, "TakeInvestigationRewardReq" },
        { 1903, "TakeInvestigationRewardRsp" },
        { 1904, "TakeInvestigationTargetRewardReq" },
        { 1905, "TakeInvestigationTargetRewardRsp" },
        { 1906, "GetInvestigationMonsterReq" },
        { 1907, "GetInvestigationMonsterRsp" },
        { 1908, "PlayerInvestigationNotify" },
        { 1909, "PlayerInvestigationTargetNotify" },
        { 2001, "GetActivityScheduleReq" },
        { 2002, "GetActivityScheduleRsp" },
        { 2003, "GetActivityInfoReq" },
        { 2004, "GetActivityInfoRsp" },
        { 2005, "ActivityPlayOpenAnimNotify" },
        { 2006, "ActivityInfoNotify" },
        { 2007, "ActivityScheduleInfoNotify" },
        { 2014, "SeaLampFlyLampReq" },
        { 2015, "SeaLampFlyLampRsp" },
        { 2016, "SeaLampTakeContributionRewardReq" },
        { 2017, "SeaLampTakeContributionRewardRsp" },
        { 2018, "SeaLampTakePhaseRewardReq" },
        { 2019, "SeaLampTakePhaseRewardRsp" },
        { 2020, "SeaLampContributeItemReq" },
        { 2021, "SeaLampContributeItemRsp" },
        { 2022, "ServerAnnounceNotify" },
        { 2023, "ServerAnnounceRevokeNotify" },
        { 2024, "LoadActivityTerrainNotify" },
        { 2201, "WatcherAllDataNotify" },
        { 2202, "WatcherChangeNotify" },
        { 2203, "WatcherEventNotify" },
        { 2204, "WatcherEventTypeNotify" },
        { 2221, "PushTipsAllDataNotify" },
        { 2222, "PushTipsChangeNotify" },
        { 2223, "PushTipsReadFinishReq" },
        { 2224, "PushTipsReadFinishRsp" },
        { 2225, "GetPushTipsRewardReq" },
        { 2226, "GetPushTipsRewardRsp" },
        { 2301, "QueryPathReq" },
        { 2302, "QueryPathRsp" },
        { 2303, "ObstacleModifyNotify" },
        { 2304, "PathfindingPingNotify" },
        { 2305, "PathfindingEnterSceneReq" },
        { 2306, "PathfindingEnterSceneRsp" },
        { 2351, "GMShowObstacleReq" },
        { 2352, "GMShowObstacleRsp" },
        { 2353, "GMShowNavMeshReq" },
        { 2354, "GMShowNavMeshRsp" },
        { 2401, "TowerBriefDataNotify" },
        { 2402, "TowerFloorRecordChangeNotify" },
        { 2403, "TowerCurLevelRecordChangeNotify" },
        { 2404, "TowerDailyRewardProgressChangeNotify" },
        { 2406, "TowerTeamSelectReq" },
        { 2407, "TowerTeamSelectRsp" },
        { 2408, "TowerAllDataReq" },
        { 2409, "TowerAllDataRsp" },
        { 2411, "TowerEnterLevelReq" },
        { 2412, "TowerEnterLevelRsp" },
        { 2413, "TowerBuffSelectReq" },
        { 2414, "TowerBuffSelectRsp" },
        { 2421, "TowerSurrenderReq" },
        { 2422, "TowerSurrenderRsp" },
        { 2423, "TowerGetFloorStarRewardReq" },
        { 2424, "TowerGetFloorStarRewardRsp" },
        { 2430, "TowerLevelEndNotify" },
        { 2431, "TowerLevelStarCondNotify" },
        { 2432, "TowerMiddleLevelChangeTeamNotify" },
        { 3001, "SceneEntitiesMoveCombineNotify" },
        { 3002, "UnlockTransPointReq" },
        { 3003, "UnlockTransPointRsp" },
        { 3004, "PlatformRouteStateNotify" },
        { 3005, "SceneWeatherForcastReq" },
        { 3006, "SceneWeatherForcastRsp" },
        { 3010, "MarkMapReq" },
        { 3011, "MarkMapRsp" },
        { 3012, "AllMarkPointNotify" },
        { 3013, "WorldDataNotify" },
        { 3014, "EntityMoveRoomNotify" },
        { 3015, "WorldPlayerInfoNotify" },
        { 3016, "PostEnterSceneReq" },
        { 3017, "PostEnterSceneRsp" },
        { 3018, "PlayerChatReq" },
        { 3019, "PlayerChatRsp" },
        { 3020, "PlayerChatNotify" },
        { 3021, "PlayerChatCDNotify" },
        { 3022, "ChatHistoryNotify" },
        { 3023, "SceneDataNotify" },
        { 3024, "DungeonEntryToBeExploreNotify" },
        { 3035, "GetDungeonEntryExploreConditionReq" },
        { 3036, "GetDungeonEntryExploreConditionRsp" },
        { 3037, "UnfreezeGroupLimitNotify" },
        { 4001, "GetPlayerFriendListReq" },
        { 4002, "GetPlayerFriendListRsp" },
        { 4005, "AskAddFriendReq" },
        { 4006, "AskAddFriendRsp" },
        { 4007, "AddFriendReq" },
        { 4008, "AddFriendRsp" },
        { 10001, "StopServerConfigNotify" },
        { 10002, "NodeserverConnectedAndRegisteredNotify" },
        { 10003, "MultiPlayerMsg" },
        { 10004, "AddGateserverNotify" },
        { 10005, "RegisterServiceNotify" },
        { 10006, "PlayerTransferNotify" },
        { 10007, "PacketFreqencyExceedNotify" },
        { 10008, "SceneAsyncLoadGroupBatchNotify" },
        { 10009, "ClientVersionSyncNotify" },
        { 10010, "RegisterServiceSuccessNotify" },
        { 10011, "ReloadConfigNotify" },
        { 10102, "SavePlayerDataReq" },
        { 10103, "SavePlayerDataRsp" },
        { 10104, "PlayerOnlineStatusNotify" },
        { 10107, "ServiceDisconnectNotify" },
        { 10108, "PlayerDisconnectNotify" },
        { 10109, "DisconnectClientNotify" },
        { 10201, "OnlinePlayerNumReq" },
        { 10202, "OnlinePlayerNumRsp" },
        { 10203, "KickoutPlayerNotify" },
        { 10204, "CheckOnlinePlayerReq" },
        { 10205, "CheckOnlinePlayerRsp" },
        { 10206, "PlayerCombatForceReq" },
        { 10207, "PlayerCombatForceRsp" },
        { 10208, "DataAndResVersionReq" },
        { 10209, "DataAndResVersionRsp" },
        { 10210, "PlatformPlayerNumReq" },
        { 10211, "PlatformPlayerNumRsp" },
        { 10212, "QueryPlayerMemDataByMuipReq" },
        { 10213, "QueryPlayerMemDataByMuipRsp" },
        { 10214, "BindGmUidNotify" },
        { 10215, "UnbindGmUidNotify" },
        { 10216, "GetBindGmUidReq" },
        { 10217, "GetBindGmUidRsp" },
        { 10301, "SendMailReq" },
        { 10302, "SendMailRsp" },
        { 10303, "NewMailNotify" },
        { 10304, "ReceiveMailReq" },
        { 10305, "ReceiveMailRsp" },
        { 10306, "UpdateMailNotify" },
        { 10307, "ClearMailBoxDataNotify" },
        { 10308, "SendOfflineMsgReq" },
        { 10309, "SendOfflineMsgRsp" },
        { 10310, "NewOfflineMsgNotify" },
        { 10311, "GetOfflineMsgReq" },
        { 10312, "GetOfflineMsgRsp" },
        { 10313, "RemoveOfflineMsgNotify" },
        { 10314, "ClearOfflineMsgNotify" },
        { 10315, "DelRedisMailByMuipReq" },
        { 10316, "DelRedisMailByMuipRsp" },
        { 10401, "UpdateMpStatusNotify" },
        { 10402, "DelMpStatusNotify" },
        { 10403, "GetPlayerMpStatusListReq" },
        { 10404, "GetPlayerMpStatusListRsp" },
        { 10601, "SeaLampPlayerContributionNotify" },
        { 10602, "SeaLampProgressNotify" },
        { 10603, "SeaLampBroadcastNotify" },
        { 10604, "SeaLampSetProgressByMuipReq" },
        { 10605, "SeaLampSetProgressByMuipRsp" },
        { 10606, "SeaLampProgressImplementNotify" },
        { 10607, "SeaLampClearProgressByGmNotify" },
        { 10608, "SeaLampAddProgressByMuipReq" },
        { 10609, "SeaLampAddProgressByMuipRsp" },
        { 10610, "GetActivityDataByMuipReq" },
        { 10611, "GetActivityDataByMuipRsp" },
        { 10801, "AddAskFriendNotify" },
    };
    return m;
}
static inline std::string PacketIdToString(uint16_t cmd) {
    const auto& m = PacketNameMap();
    auto it = m.find(cmd);
    if (it != m.end()) return std::string(it->second);
    char buf[32]; std::snprintf(buf, sizeof(buf), "Cmd_%u", (unsigned)cmd);
    return std::string(buf);
}

static std::atomic<int> g_Index{ 0 };
static std::vector<uint8_t> g_Key;
static std::atomic<bool> g_DoXor{ false };
static std::atomic<bool> g_loggedXorOn{ false };
static std::atomic<bool> g_loggedKey{ false };

static constexpr uint16_t GET_PLAYER_TOKEN_REQ = 101;
static constexpr uint16_t GET_PLAYER_TOKEN_RSP = 102;

static inline void XorWithEc2bInPlace(std::vector<uint8_t>& buf) {
    const auto& xp = g_ec2b_xorpad;
    if (xp.empty() || buf.empty()) return;
    const size_t n = xp.size();
    for (size_t i = 0; i < buf.size(); ++i) {
        buf[i] ^= xp[i % n];
    }
}

namespace PacketProcessor {
    void Process(const std::vector<uint8_t>& rawBytes, PacketSource src) {
        EnsureInitOnce();
        int index = ++g_Index;

        std::vector<uint8_t> ec2bBuf = rawBytes;
        if (index == 1 || index == 2)
            XorWithEc2bInPlace(ec2bBuf);

        const uint8_t* frameData = nullptr;
        size_t frameLen = 0;
        std::vector<uint8_t> postKeyBuf;

        if (g_DoXor.load(std::memory_order_acquire) && !g_Key.empty()) {
            postKeyBuf = ec2bBuf;
            XorInPlace(postKeyBuf, g_Key);
            frameData = postKeyBuf.data();
            frameLen = postKeyBuf.size();
        }
        else {
            frameData = ec2bBuf.data();
            frameLen = ec2bBuf.size();
        }

        if (frameLen < 8) return;

        const uint8_t* p = frameData;
        uint16_t head = ReadBE16(p); p += 2;
        if (head != 0x4567) {
            const std::string dump = to_hex(rawBytes.data(), rawBytes.size());
            std::printf("Bad head (idx=%d, src=%d, len=%zu):\n%s\n",
                index, (int)src, frameLen, dump.c_str());
            return;
        }

        uint16_t cmdId = ReadBE16(p);      p += 2;
        uint16_t headerLen = ReadBE16(p);  p += 2;
        if (frameData + frameLen < p + 4) return;
        uint32_t payloadLen = ReadBE32(p); p += 4;

        size_t remain = (frameData + frameLen) - p;
        if (remain < size_t(headerLen) + size_t(payloadLen) + 2) return;

        const uint8_t* headerPtr = p; p += headerLen; (void)headerPtr;
        const uint8_t* payloadPtr = p; p += payloadLen;
        uint16_t trailer = ReadBE16(p);
        if (trailer != 0x89AB) return;

        switch (cmdId) {
        case GET_PLAYER_TOKEN_RSP:
            uint64_t keySeed;
            if (ExtractSecretKeySeed(payloadPtr, payloadLen, keySeed)) {
                g_Key = NewKeyFromSeed(keySeed);
            }
            g_DoXor.store(true, std::memory_order_release);
            if (!g_loggedXorOn.exchange(true))
                printf("[PacketProcessor] XOR enabled\n");
            break;

        default:
            break;
        }

        const char* dirFlag = (src == PacketSource::Client) ? "CS" : "SC";
        std::string pktName = PacketIdToString(cmdId);

        char fname[128];
        std::snprintf(fname, sizeof(fname), "%d_%s_%s.bin", index, dirFlag, pktName.c_str());

        fs::path full = RawPacketDir() / fname;

        PacketJob job;
        job.pathW = full.wstring();
        job.data.assign(payloadPtr, payloadPtr + payloadLen);

        AcquireSRWLockExclusive(&g_qLock);
        g_queue.emplace_back(std::move(job));
        WakeConditionVariable(&g_qCv);
        ReleaseSRWLockExclusive(&g_qLock);
    }
}
