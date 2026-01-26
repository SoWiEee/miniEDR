#pragma once
#ifdef _WIN32
#include <string>
#include <vector>

namespace miniedr {

struct SignerTrustConfig {
    std::vector<std::wstring> allow_subject_contains;
    std::vector<std::wstring> allow_issuer_contains;
    bool allow_microsoft_signed = true;
    bool require_trusted_chain = true;
};

SignerTrustConfig LoadSignerTrustConfig(const std::wstring& path);

bool IsSignerAllowed(const SignerTrustConfig& cfg,
                     bool signer_trusted,
                     bool signer_is_microsoft,
                     const std::wstring& signer_subject,
                     const std::wstring& signer_issuer);

} // namespace miniedr
#endif
