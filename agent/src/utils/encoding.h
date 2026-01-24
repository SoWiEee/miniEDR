#pragma once
#include <string>

namespace miniedr {

std::wstring Utf8ToWide(const std::string& s);
std::string WideToUtf8(const std::wstring& ws);

} // namespace miniedr
