#pragma once
#include <string>
#include <optional>

namespace miniedr {

struct HttpResponse {
    bool ok = false;
    int status = 0;
    std::string body;
};

class CentralHttpClient {
public:
    HttpResponse Get(const std::wstring& url, const std::wstring& api_key);
    HttpResponse Post(const std::wstring& url, const std::wstring& api_key, const std::string& body);
};

} // namespace miniedr
