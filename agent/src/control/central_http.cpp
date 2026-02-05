#include "control/central_http.h"
#ifdef _WIN32

#include <windows.h>
#include <winhttp.h>

#include <vector>

#pragma comment(lib, "winhttp.lib")

namespace miniedr {

namespace {

bool CrackUrl(const std::wstring& url, URL_COMPONENTS& comps) {
    memset(&comps, 0, sizeof(comps));
    comps.dwStructSize = sizeof(comps);
    comps.dwSchemeLength = (DWORD)-1;
    comps.dwHostNameLength = (DWORD)-1;
    comps.dwUrlPathLength = (DWORD)-1;
    return WinHttpCrackUrl(url.c_str(), 0, 0, &comps) == TRUE;
}

std::wstring BuildPath(const URL_COMPONENTS& comps) {
    std::wstring path;
    if (comps.lpszUrlPath && comps.dwUrlPathLength > 0) {
        path.assign(comps.lpszUrlPath, comps.dwUrlPathLength);
    }
    return path.empty() ? L"/" : path;
}

HttpResponse SendRequest(const std::wstring& url, const std::wstring& api_key, const wchar_t* verb, const std::string& body) {
    HttpResponse out{};
    URL_COMPONENTS comps{};
    if (!CrackUrl(url, comps)) return out;

    std::wstring host(comps.lpszHostName, comps.dwHostNameLength);
    std::wstring path = BuildPath(comps);
    INTERNET_PORT port = comps.nPort;
    bool is_https = (comps.nScheme == INTERNET_SCHEME_HTTPS);

    HINTERNET session = WinHttpOpen(L"MiniEDR/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                    WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) return out;
    HINTERNET connect = WinHttpConnect(session, host.c_str(), port, 0);
    if (!connect) {
        WinHttpCloseHandle(session);
        return out;
    }

    DWORD flags = is_https ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET request = WinHttpOpenRequest(connect, verb, path.c_str(),
                                           nullptr, WINHTTP_NO_REFERER,
                                           WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!request) {
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return out;
    }

    std::wstring headers = L"Content-Type: application/json\r\n";
    if (!api_key.empty()) {
        headers += L"Authorization: Bearer " + api_key + L"\r\n";
    }

    BOOL sent = WinHttpSendRequest(request,
                                   headers.c_str(), (DWORD)headers.size(),
                                   body.empty() ? WINHTTP_NO_REQUEST_DATA : (LPVOID)body.data(),
                                   body.empty() ? 0 : (DWORD)body.size(),
                                   body.empty() ? 0 : (DWORD)body.size(),
                                   0);
    if (!sent || !WinHttpReceiveResponse(request, nullptr)) {
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return out;
    }

    DWORD status = 0;
    DWORD status_size = sizeof(status);
    if (WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &status, &status_size, WINHTTP_NO_HEADER_INDEX)) {
        out.status = (int)status;
    }

    std::string response_body;
    DWORD bytes_available = 0;
    while (WinHttpQueryDataAvailable(request, &bytes_available) && bytes_available > 0) {
        std::vector<char> buffer(bytes_available);
        DWORD bytes_read = 0;
        if (!WinHttpReadData(request, buffer.data(), bytes_available, &bytes_read) || bytes_read == 0) break;
        response_body.append(buffer.data(), buffer.data() + bytes_read);
    }

    out.body = std::move(response_body);
    out.ok = (out.status >= 200 && out.status < 300);

    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connect);
    WinHttpCloseHandle(session);
    return out;
}

} // namespace

HttpResponse CentralHttpClient::Get(const std::wstring& url, const std::wstring& api_key) {
    return SendRequest(url, api_key, L"GET", "");
}

HttpResponse CentralHttpClient::Post(const std::wstring& url, const std::wstring& api_key, const std::string& body) {
    return SendRequest(url, api_key, L"POST", body);
}

} // namespace miniedr

#else

namespace miniedr {

HttpResponse CentralHttpClient::Get(const std::wstring&, const std::wstring&) {
    return {};
}

HttpResponse CentralHttpClient::Post(const std::wstring&, const std::wstring&, const std::string&) {
    return {};
}

} // namespace miniedr

#endif
