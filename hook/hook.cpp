// ============================================================================
// hook.dll — TheRawServer.exe için custom bypass DLL
// CE script'lerinin (hooks.ct) C++ ekvivalanı.
// Inject: Shell.exe ile manual-map veya başka injector ile LoadLibrary.
//
// Build (MSVC, x86):
//   cl /LD /EHsc /O2 /MD hook.cpp /link /OUT:hook.dll /MACHINE:X86
// ============================================================================

#include <windows.h>
#include <cstdio>
#include <cstdint>

// ----- CE script offsetleri (GameServer.dll içinde) -----
// hooks.ct'den birebir alındı. Eğer GameServer.dll güncellense byte mismatch
// olur, IDA ile yeniden bulmak gerekir.
constexpr DWORD GS_PATCH1_OFFSET = 0xEEC95;  // call edx (vtable hijack 1)
constexpr DWORD GS_PATCH2_OFFSET = 0xE78DD;  // call edx (vtable hijack 2 — encryption)
constexpr DWORD GS_PATCH3_OFFSET = 0xE7CC9;  // call edx (vtable hijack 3 — encryption)

// CE script'in patch'lediği orijinal byte'lar — assert için
const uint8_t GS_PATCH1_ORIG[] = { 0xFF, 0xD2, 0x5F, 0x5E, 0x5B };
const uint8_t GS_PATCH2_ORIG[] = { 0xFF, 0xD2, 0x89, 0x45, 0x08 };
const uint8_t GS_PATCH3_ORIG[] = { 0xFF, 0xD2, 0x89, 0x45, 0x08 };

// TheRawServer.exe içinde Hermit::Object::Crypt::None::Factory instance
constexpr DWORD TRS_CRYPT_NONE_OFFSET = 0x3F4108;

static HMODULE g_hGameServer = nullptr;
static uintptr_t g_TheRawServerBase = 0;

// Patch noktaları için trampoline'ler bu allocate edilmiş bölgeye yazılır
static uint8_t* g_TrampolineMem = nullptr;

// ----- Helpers -----

static bool WritePatch(void* addr, const void* bytes, size_t len) {
    DWORD oldProtect;
    if (!VirtualProtect(addr, len, PAGE_EXECUTE_READWRITE, &oldProtect)) return false;
    memcpy(addr, bytes, len);
    VirtualProtect(addr, len, oldProtect, &oldProtect);
    FlushInstructionCache(GetCurrentProcess(), addr, len);
    return true;
}

static bool VerifyAndPatch(void* addr, const uint8_t* original, size_t origLen,
                            const void* patch, size_t patchLen) {
    if (memcmp(addr, original, origLen) != 0) return false;
    return WritePatch(addr, patch, patchLen);
}

// ----- "myfunc" — CE script 2gg/3gg'nin C eşdeğeri -----
// new'den 8 byte alıp, içine TheRawServer.exe + 0x3F4108 (Hermit::Crypt::None
// factory instance) pointer'ını yazar. Caller'ın expected return'u: 8 byte
// allocation, içinde [vtable_ptr] = Crypt::None instance.
static uint32_t __cdecl my_crypt_none_factory(int size_arg) {
    void* ptr = malloc(8);
    if (!ptr) return 0;
    uint32_t* dwordPtr = static_cast<uint32_t*>(ptr);
    *dwordPtr = static_cast<uint32_t>(g_TheRawServerBase + TRS_CRYPT_NONE_OFFSET);
    return reinterpret_cast<uint32_t>(ptr);
}

// ----- Patch installer -----

static bool ApplyPatches() {
    if (!g_hGameServer) return false;
    uintptr_t gsBase = reinterpret_cast<uintptr_t>(g_hGameServer);

    // Patch 2gg: call edx → call my_crypt_none_factory
    void* p2 = reinterpret_cast<void*>(gsBase + GS_PATCH2_OFFSET);
    // 5 byte patch: E8 [rel32] = call near
    int32_t rel2 = reinterpret_cast<intptr_t>(my_crypt_none_factory) -
                   reinterpret_cast<intptr_t>(p2) - 5;
    uint8_t patch2[5] = { 0xE8, 0, 0, 0, 0 };
    memcpy(&patch2[1], &rel2, 4);
    if (!VerifyAndPatch(p2, GS_PATCH2_ORIG, sizeof(GS_PATCH2_ORIG), patch2, 5)) {
        OutputDebugStringA("[hook] PATCH2 byte mismatch — GameServer.dll versiyonu farkli olabilir\n");
        return false;
    }
    OutputDebugStringA("[hook] PATCH2 applied (E78DD)\n");

    // Patch 3gg: aynı şekilde E7CC9
    void* p3 = reinterpret_cast<void*>(gsBase + GS_PATCH3_OFFSET);
    int32_t rel3 = reinterpret_cast<intptr_t>(my_crypt_none_factory) -
                   reinterpret_cast<intptr_t>(p3) - 5;
    uint8_t patch3[5] = { 0xE8, 0, 0, 0, 0 };
    memcpy(&patch3[1], &rel3, 4);
    if (!VerifyAndPatch(p3, GS_PATCH3_ORIG, sizeof(GS_PATCH3_ORIG), patch3, 5)) {
        OutputDebugStringA("[hook] PATCH3 byte mismatch\n");
        return false;
    }
    OutputDebugStringA("[hook] PATCH3 applied (E7CC9)\n");

    // Patch 1 (EEC95) daha karmaşık trampoline gerektiriyor (CE script "func"
    // ile çoklu sub call). İlk testte 2+3 yetebilir; gerekirse sonra ekleriz.
    return true;
}

// ----- Init thread: GameServer.dll yüklenmesini bekle, patch'le -----

static DWORD WINAPI InitThread(LPVOID) {
    g_TheRawServerBase = reinterpret_cast<uintptr_t>(GetModuleHandleA(nullptr));
    OutputDebugStringA("[hook] InitThread starting\n");

    // GameServer.dll henüz yüklenmemiş olabilir; ~5 sn bekle
    for (int i = 0; i < 50 && !g_hGameServer; ++i) {
        g_hGameServer = GetModuleHandleA("GameServer.dll");
        if (!g_hGameServer) Sleep(100);
    }

    if (!g_hGameServer) {
        OutputDebugStringA("[hook] GameServer.dll not loaded after 5s\n");
        return 1;
    }

    char info[256];
    sprintf_s(info, "[hook] TheRawServer base=%p, GameServer.dll base=%p\n",
              reinterpret_cast<void*>(g_TheRawServerBase), g_hGameServer);
    OutputDebugStringA(info);

    if (ApplyPatches()) {
        OutputDebugStringA("[hook] All patches applied — TheRawServer plain mode aktif\n");
    } else {
        OutputDebugStringA("[hook] Patch FAILED — see byte mismatch above\n");
    }
    return 0;
}

BOOL APIENTRY DllMain(HMODULE h, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        CreateThread(nullptr, 0, InitThread, nullptr, 0, nullptr);
    }
    return TRUE;
}
