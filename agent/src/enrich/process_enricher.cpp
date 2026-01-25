#include "enrich/process_enricher.h"
#ifdef _WIN32

#include <windows.h>
#include <psapi.h>
#include <wincrypt.h>
#include <softpub.h>
#include <wintrust.h>
#include <bcrypt.h>

#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <algorithm>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "bcrypt.lib")

namespace miniedr {

static std::wstring ToLower(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(), [](wchar_t c){ return (wchar_t)towlower(c); });
    return s;
}

static bool StartsWithDriveOrDevice(const std::wstring& p) {
    if (p.size() >= 3 && iswalpha(p[0]) && p[1] == L':' && (p[2] == L'\\' || p[2] == L'/')) return true;
    if (p.rfind(L"\\\\?\\", 0) == 0) return true;
    if (p.rfind(L"\\Device\\", 0) == 0) return true;
    return false;
}

static std::wstring GetFullImagePath(HANDLE hProc) {
    std::wstring out;
    std::vector<wchar_t> buf(32768);
    DWORD sz = (DWORD)buf.size();
    if (QueryFullProcessImageNameW(hProc, 0, buf.data(), &sz)) {
        out.assign(buf.data(), sz);
    }
    return out;
}

static std::wstring GetUserFromToken(HANDLE hProc) {
    HANDLE hTok = nullptr;
    if (!OpenProcessToken(hProc, TOKEN_QUERY, &hTok)) return L"";

    DWORD need = 0;
    GetTokenInformation(hTok, TokenUser, nullptr, 0, &need);
    std::vector<uint8_t> buf(need);
    if (!GetTokenInformation(hTok, TokenUser, buf.data(), (DWORD)buf.size(), &need)) {
        CloseHandle(hTok);
        return L"";
    }
    CloseHandle(hTok);

    auto* tu = reinterpret_cast<TOKEN_USER*>(buf.data());

    wchar_t name[256]; DWORD nameLen = 256;
    wchar_t dom[256];  DWORD domLen  = 256;
    SID_NAME_USE use;
    if (!LookupAccountSidW(nullptr, tu->User.Sid, name, &nameLen, dom, &domLen, &use)) return L"";

    std::wstring out = dom;
    out += L"\\";
    out += name;
    return out;
}

// Minimal PEB read to extract command line. Best-effort only.
typedef NTSTATUS (NTAPI *pfnNtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG);

typedef struct _UNICODE_STRING_T {
    USHORT Length;
    USHORT MaximumLength;
    ULONGLONG Buffer;
} UNICODE_STRING_T;

typedef struct _RTL_USER_PROCESS_PARAMETERS_T {
    BYTE Reserved1[16];
    ULONGLONG Reserved2[10];
    UNICODE_STRING_T ImagePathName;
    UNICODE_STRING_T CommandLine;
} RTL_USER_PROCESS_PARAMETERS_T;

typedef struct _PEB_T {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    ULONGLONG Reserved3[2];
    ULONGLONG Ldr;
    ULONGLONG ProcessParameters;
} PEB_T;

typedef struct _PROCESS_BASIC_INFORMATION_T {
    ULONGLONG Reserved1;
    ULONGLONG PebBaseAddress;
    ULONGLONG Reserved2[2];
    ULONGLONG UniqueProcessId;
    ULONGLONG Reserved3;
} PROCESS_BASIC_INFORMATION_T;

static std::wstring ReadRemoteUnicodeString(HANDLE hProc, const UNICODE_STRING_T& us) {
    if (us.Length == 0 || us.Buffer == 0) return L"";
    std::vector<wchar_t> tmp((us.Length / sizeof(wchar_t)) + 1);
    SIZE_T read = 0;
    if (!ReadProcessMemory(hProc, (LPCVOID)us.Buffer, tmp.data(), us.Length, &read)) return L"";
    tmp[us.Length / sizeof(wchar_t)] = L'\0';
    return std::wstring(tmp.data());
}

static std::wstring GetCommandLineFromPeb(HANDLE hProc) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return L"";

    auto NtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");
    if (!NtQueryInformationProcess) return L"";

    PROCESS_BASIC_INFORMATION_T pbi{};
    ULONG retLen = 0;
    NTSTATUS st = NtQueryInformationProcess(hProc, 0 /*ProcessBasicInformation*/, &pbi, sizeof(pbi), &retLen);
    if (st != 0) return L"";

    PEB_T peb{};
    SIZE_T read = 0;
    if (!ReadProcessMemory(hProc, (LPCVOID)pbi.PebBaseAddress, &peb, sizeof(peb), &read)) return L"";
    if (peb.ProcessParameters == 0) return L"";

    RTL_USER_PROCESS_PARAMETERS_T upp{};
    if (!ReadProcessMemory(hProc, (LPCVOID)peb.ProcessParameters, &upp, sizeof(upp), &read)) return L"";

    return ReadRemoteUnicodeString(hProc, upp.CommandLine);
}

static std::wstring Hex(const std::vector<uint8_t>& b) {
    static const wchar_t* hexd = L"0123456789abcdef";
    std::wstring out;
    out.reserve(b.size() * 2);
    for (auto v : b) {
        out.push_back(hexd[(v >> 4) & 0xF]);
        out.push_back(hexd[v & 0xF]);
    }
    return out;
}

static std::wstring Sha256File(const std::wstring& path) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return L"";

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    DWORD cbData = 0, cbHashObject = 0, cbHash = 0;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) {
        CloseHandle(h);
        return L"";
    }
    if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbHashObject, sizeof(cbHashObject), &cbData, 0) != 0 ||
        BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PUCHAR)&cbHash, sizeof(cbHash), &cbData, 0) != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        CloseHandle(h);
        return L"";
    }

    std::vector<uint8_t> hashObject(cbHashObject);
    std::vector<uint8_t> hash(cbHash);

    if (BCryptCreateHash(hAlg, &hHash, hashObject.data(), cbHashObject, nullptr, 0, 0) != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        CloseHandle(h);
        return L"";
    }

    std::vector<uint8_t> buf(64 * 1024);
    DWORD read = 0;
    while (ReadFile(h, buf.data(), (DWORD)buf.size(), &read, nullptr) && read > 0) {
        if (BCryptHashData(hHash, buf.data(), read, 0) != 0) break;
    }

    BCryptFinishHash(hHash, hash.data(), cbHash, 0);
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    CloseHandle(h);

    return Hex(hash);
}

static void VerifySignatureAndExtractCert(const std::wstring& file,
                                          bool& trusted,
                                          std::wstring& subj,
                                          std::wstring& issuer,
                                          bool& is_msft) {
    trusted = false;
    subj.clear(); issuer.clear(); is_msft = false;

    WINTRUST_FILE_INFO fi{};
    fi.cbStruct = sizeof(fi);
    fi.pcwszFilePath = file.c_str();

    WINTRUST_DATA wd{};
    wd.cbStruct = sizeof(wd);
    wd.dwUIChoice = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wd.dwUnionChoice = WTD_CHOICE_FILE;
    wd.pFile = &fi;
    wd.dwStateAction = WTD_STATEACTION_VERIFY;
    wd.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

    GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG status = WinVerifyTrust(nullptr, &policy, &wd);
    trusted = (status == ERROR_SUCCESS);

    // Close state
    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &policy, &wd);

    // Extract leaf cert subject/issuer via CryptQueryObject (best-effort)
    HCERTSTORE hStore = nullptr;
    HCRYPTMSG hMsg = nullptr;
    PCCERT_CONTEXT pCert = nullptr;

    DWORD enc = 0, cont = 0, form = 0;
    if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE,
                          file.c_str(),
                          CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                          CERT_QUERY_FORMAT_FLAG_BINARY,
                          0, &enc, &cont, &form, &hStore, &hMsg, nullptr)) {
        return;
    }

    DWORD signerInfoSize = 0;
    if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &signerInfoSize)) {
        if (hStore) CertCloseStore(hStore, 0);
        if (hMsg) CryptMsgClose(hMsg);
        return;
    }

    std::vector<uint8_t> siBuf(signerInfoSize);
    if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, siBuf.data(), &signerInfoSize)) {
        if (hStore) CertCloseStore(hStore, 0);
        if (hMsg) CryptMsgClose(hMsg);
        return;
    }

    auto* si = (CMSG_SIGNER_INFO*)siBuf.data();
    CERT_INFO ci{};
    ci.Issuer = si->Issuer;
    ci.SerialNumber = si->SerialNumber;

    pCert = CertFindCertificateInStore(hStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                       0, CERT_FIND_SUBJECT_CERT, (PVOID)&ci, nullptr);
    if (!pCert) {
        if (hStore) CertCloseStore(hStore, 0);
        if (hMsg) CryptMsgClose(hMsg);
        return;
    }

    wchar_t subjBuf[512]; subjBuf[0]=0;
    wchar_t issBuf[512]; issBuf[0]=0;
    CertGetNameStringW(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, subjBuf, 512);
    CertGetNameStringW(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, nullptr, issBuf, 512);
    subj = subjBuf;
    issuer = issBuf;

    auto s = ToLower(subj);
    auto i = ToLower(issuer);
    if (s.find(L"microsoft") != std::wstring::npos || i.find(L"microsoft") != std::wstring::npos) {
        is_msft = true;
    }

    CertFreeCertificateContext(pCert);
    if (hStore) CertCloseStore(hStore, 0);
    if (hMsg) CryptMsgClose(hMsg);
}

void ProcessEnricher::Enrich(CanonicalEvent& ev) const {
    EnrichOne(ev.proc);
    EnrichOne(ev.target);
}

void ProcessEnricher::EnrichOne(ProcessInfo& p) {
    if (p.pid == 0) return;

    DWORD access = PROCESS_QUERY_LIMITED_INFORMATION;
    // Need VM read for PEB command line read; best-effort, fallback to path only if denied.
    DWORD access2 = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ;

    HANDLE h = OpenProcess(access2, FALSE, p.pid);
    if (!h) h = OpenProcess(access, FALSE, p.pid);
    if (!h) return;

    if (p.image.empty() || !StartsWithDriveOrDevice(p.image)) {
        auto img = GetFullImagePath(h);
        if (!img.empty()) p.image = img;
    }

    if (p.command_line.empty()) {
        auto cmd = GetCommandLineFromPeb(h);
        if (!cmd.empty()) p.command_line = cmd;
    }

    if (p.user.empty()) {
        auto u = GetUserFromToken(h);
        if (!u.empty()) p.user = u;
    }

    CloseHandle(h);

    // Hash/signature require path; only do if looks like file path.
    if (!p.image.empty() && (p.image.find(L"\\") != std::wstring::npos)) {
        if (p.image_sha256.empty()) {
            auto hsh = Sha256File(p.image);
            if (!hsh.empty()) p.image_sha256 = hsh;
        }
        if (p.signer_subject.empty() && p.signer_issuer.empty()) {
            bool trusted=false, isms=false;
            std::wstring subj, iss;
            VerifySignatureAndExtractCert(p.image, trusted, subj, iss, isms);
            p.signer_trusted = trusted;
            p.signer_is_microsoft = isms;
            p.signer_subject = subj;
            p.signer_issuer = iss;
        }
    }
}

} // namespace miniedr
#endif
