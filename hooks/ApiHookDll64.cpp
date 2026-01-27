#include <windows.h>
#include <string>
#include <atomic>

#include "detours.h"

#pragma comment(lib, "advapi32.lib")

// Export ordinal #1 for Detours SampleWithdll requirement.
extern "C" __declspec(dllexport) void __cdecl MiniEDR_DetoursExport() {}
#pragma comment(linker, "/export:MiniEDR_DetoursExport=@1")

static std::atomic<bool> g_inited{false};
static HANDLE g_pipe = INVALID_HANDLE_VALUE;
static SRWLOCK g_lock = SRWLOCK_INIT;

static void EnsurePipe() {
    if (g_pipe != INVALID_HANDLE_VALUE) return;
    AcquireSRWLockExclusive(&g_lock);
    if (g_pipe == INVALID_HANDLE_VALUE) {
        g_pipe = CreateFileW(L"\\\\.\\pipe\\MiniEDR.ApiHook", GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    }
    ReleaseSRWLockExclusive(&g_lock);
}

static void SendLine(const std::string& s) {
    EnsurePipe();
    if (g_pipe == INVALID_HANDLE_VALUE) return;
    DWORD wr = 0;
    std::string line = s;
    line.push_back('\n');
    WriteFile(g_pipe, line.data(), (DWORD)line.size(), &wr, nullptr);
}

// ---- Hooks (minimal MVP) ----
using OpenProcess_t = HANDLE (WINAPI*)(DWORD, BOOL, DWORD);
static OpenProcess_t Real_OpenProcess = ::OpenProcess;

static HANDLE WINAPI Hook_OpenProcess(DWORD desired, BOOL inherit, DWORD pid) {
    HANDLE h = Real_OpenProcess(desired, inherit, pid);
    DWORD err = GetLastError();
    char buf[512];
    wsprintfA(buf,
        "{\"pid\":%lu,\"tid\":%lu,\"api\":\"OpenProcess\",\"module\":\"kernel32\",\"target_pid\":%lu,\"desired_access\":%lu,\"result\":\"%s\",\"err\":%lu}",
        GetCurrentProcessId(), GetCurrentThreadId(), pid, desired, (h ? "ok" : "fail"), err);
    SendLine(buf);
    SetLastError(err);
    return h;
}

using VirtualAllocEx_t = LPVOID (WINAPI*)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
static VirtualAllocEx_t Real_VirtualAllocEx = ::VirtualAllocEx;

static LPVOID WINAPI Hook_VirtualAllocEx(HANDLE hp, LPVOID addr, SIZE_T sz, DWORD at, DWORD prot) {
    LPVOID p = Real_VirtualAllocEx(hp, addr, sz, at, prot);
    DWORD err = GetLastError();
    char buf[512];
    wsprintfA(buf,
        "{\"pid\":%lu,\"tid\":%lu,\"api\":\"VirtualAllocEx\",\"module\":\"kernel32\",\"size\":%lu,\"result\":\"%s\",\"err\":%lu}",
        GetCurrentProcessId(), GetCurrentThreadId(), (unsigned long)sz, (p ? "ok" : "fail"), err);
    SendLine(buf);
    SetLastError(err);
    return p;
}

using WriteProcessMemory_t = BOOL (WINAPI*)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
static WriteProcessMemory_t Real_WriteProcessMemory = ::WriteProcessMemory;

static BOOL WINAPI Hook_WriteProcessMemory(HANDLE hp, LPVOID base, LPCVOID bufp, SIZE_T sz, SIZE_T* out) {
    BOOL ok = Real_WriteProcessMemory(hp, base, bufp, sz, out);
    DWORD err = GetLastError();
    char buf[512];
    wsprintfA(buf,
        "{\"pid\":%lu,\"tid\":%lu,\"api\":\"WriteProcessMemory\",\"module\":\"kernel32\",\"size\":%lu,\"result\":\"%s\",\"err\":%lu}",
        GetCurrentProcessId(), GetCurrentThreadId(), (unsigned long)sz, (ok ? "ok" : "fail"), err);
    SendLine(buf);
    SetLastError(err);
    return ok;
}

using VirtualProtectEx_t = BOOL (WINAPI*)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD*);
static VirtualProtectEx_t Real_VirtualProtectEx = ::VirtualProtectEx;

static BOOL WINAPI Hook_VirtualProtectEx(HANDLE hp, LPVOID base, SIZE_T sz, DWORD prot, DWORD* oldp) {
    BOOL ok = Real_VirtualProtectEx(hp, base, sz, prot, oldp);
    DWORD err = GetLastError();
    char buf[512];
    wsprintfA(buf,
        "{\"pid\":%lu,\"tid\":%lu,\"api\":\"VirtualProtectEx\",\"module\":\"kernel32\",\"size\":%lu,\"result\":\"%s\",\"err\":%lu}",
        GetCurrentProcessId(), GetCurrentThreadId(), (unsigned long)sz, (ok ? "ok" : "fail"), err);
    SendLine(buf);
    SetLastError(err);
    return ok;
}

using CreateRemoteThread_t = HANDLE (WINAPI*)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
static CreateRemoteThread_t Real_CreateRemoteThread = ::CreateRemoteThread;

static HANDLE WINAPI Hook_CreateRemoteThread(HANDLE hp, LPSECURITY_ATTRIBUTES sa, SIZE_T st, LPTHREAD_START_ROUTINE start, LPVOID param, DWORD flags, LPDWORD tid) {
    HANDLE h = Real_CreateRemoteThread(hp, sa, st, start, param, flags, tid);
    DWORD err = GetLastError();
    char buf[512];
    wsprintfA(buf,
        "{\"pid\":%lu,\"tid\":%lu,\"api\":\"CreateRemoteThread\",\"module\":\"kernel32\",\"result\":\"%s\",\"err\":%lu}",
        GetCurrentProcessId(), GetCurrentThreadId(), (h ? "ok" : "fail"), err);
    SendLine(buf);
    SetLastError(err);
    return h;
}

static void InstallHooks() {
    if (g_inited.exchange(true)) return;

    DetourRestoreAfterWith();
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)Real_OpenProcess, Hook_OpenProcess);
    DetourAttach(&(PVOID&)Real_VirtualAllocEx, Hook_VirtualAllocEx);
    DetourAttach(&(PVOID&)Real_WriteProcessMemory, Hook_WriteProcessMemory);
    DetourAttach(&(PVOID&)Real_VirtualProtectEx, Hook_VirtualProtectEx);
    DetourAttach(&(PVOID&)Real_CreateRemoteThread, Hook_CreateRemoteThread);
    DetourTransactionCommit();
}

static void RemoveHooks() {
    if (!g_inited.exchange(false)) return;

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach(&(PVOID&)Real_OpenProcess, Hook_OpenProcess);
    DetourDetach(&(PVOID&)Real_VirtualAllocEx, Hook_VirtualAllocEx);
    DetourDetach(&(PVOID&)Real_WriteProcessMemory, Hook_WriteProcessMemory);
    DetourDetach(&(PVOID&)Real_VirtualProtectEx, Hook_VirtualProtectEx);
    DetourDetach(&(PVOID&)Real_CreateRemoteThread, Hook_CreateRemoteThread);
    DetourTransactionCommit();

    if (g_pipe != INVALID_HANDLE_VALUE) {
        CloseHandle(g_pipe);
        g_pipe = INVALID_HANDLE_VALUE;
    }
}

BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(GetModuleHandleW(nullptr));
        InstallHooks();
    } else if (reason == DLL_PROCESS_DETACH) {
        RemoveHooks();
    }
    return TRUE;
}
