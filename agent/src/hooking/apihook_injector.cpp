#include "hooking/apihook_injector.h"
#ifdef _WIN32

#include <fstream>
#include <sstream>
#include <vector>
#include <iostream>

namespace miniedr {

static std::wstring ReadAll(const std::wstring& path) {
    std::ifstream ifs(path);
    if (!ifs) return L"";
    std::stringstream ss;
    ss << ifs.rdbuf();
    std::string s = ss.str();
    int wlen = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring w(wlen, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), w.data(), wlen);
    return w;
}

static bool ParseBool(const std::wstring& txt, const std::wstring& key, bool defv) {
    auto pos = txt.find(L"\"" + key + L"\"");
    if (pos == std::wstring::npos) return defv;
    auto tpos = txt.find(L"true", pos);
    auto fpos = txt.find(L"false", pos);
    if (tpos != std::wstring::npos && (fpos == std::wstring::npos || tpos < fpos)) return true;
    if (fpos != std::wstring::npos && (tpos == std::wstring::npos || fpos < tpos)) return false;
    return defv;
}

static std::wstring ParseString(const std::wstring& txt, const std::wstring& key, const std::wstring& defv) {
    auto pos = txt.find(L"\"" + key + L"\"");
    if (pos == std::wstring::npos) return defv;
    pos = txt.find(L":", pos);
    if (pos == std::wstring::npos) return defv;
    pos = txt.find(L"\"", pos);
    if (pos == std::wstring::npos) return defv;
    auto end = txt.find(L"\"", pos + 1);
    if (end == std::wstring::npos) return defv;
    return txt.substr(pos + 1, end - (pos + 1));
}

HookingConfig LoadHookingConfig(const std::wstring& path) {
    HookingConfig cfg;
    auto txt = ReadAll(path);
    if (txt.empty()) return cfg;

    cfg.enable_hooking = ParseBool(txt, L"enable_hooking", false);
    cfg.inject_on_high = ParseBool(txt, L"inject_on_high", true);
    cfg.hook_dll_path = ParseString(txt, L"hook_dll_path", cfg.hook_dll_path);
    return cfg;
}

static bool IsTargetWow64(HANDLE hProcess) {
    // x64-only build: we don't inject into WOW64 processes.
    USHORT p = 0, n = 0;
    auto fn = (decltype(&IsWow64Process2))GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "IsWow64Process2");
    if (fn) {
        if (fn(hProcess, &p, &n)) return p != 0;
        return false;
    }
    BOOL wow = FALSE;
    if (IsWow64Process(hProcess, &wow)) return wow ? true : false;
    return false;
}

bool InjectHookDll(uint32_t pid, const std::wstring& dll_path) {
    HANDLE hp = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                            PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
                            FALSE, pid);
    if (!hp) return false;

    if (IsTargetWow64(hp)) {
        CloseHandle(hp);
        return false;
    }

    size_t bytes = (dll_path.size() + 1) * sizeof(wchar_t);
    void* remote = VirtualAllocEx(hp, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) {
        CloseHandle(hp);
        return false;
    }

    SIZE_T wr = 0;
    if (!WriteProcessMemory(hp, remote, dll_path.c_str(), bytes, &wr) || wr != bytes) {
        VirtualFreeEx(hp, remote, 0, MEM_RELEASE);
        CloseHandle(hp);
        return false;
    }

    auto hKernel = GetModuleHandleW(L"kernel32.dll");
    auto pLoadLibraryW = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel, "LoadLibraryW");
    if (!pLoadLibraryW) {
        VirtualFreeEx(hp, remote, 0, MEM_RELEASE);
        CloseHandle(hp);
        return false;
    }

    HANDLE ht = CreateRemoteThread(hp, nullptr, 0, pLoadLibraryW, remote, 0, nullptr);
    if (!ht) {
        VirtualFreeEx(hp, remote, 0, MEM_RELEASE);
        CloseHandle(hp);
        return false;
    }

    WaitForSingleObject(ht, 5000);
    CloseHandle(ht);
    VirtualFreeEx(hp, remote, 0, MEM_RELEASE);
    CloseHandle(hp);
    return true;
}

} // namespace miniedr
#endif
