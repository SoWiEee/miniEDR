#include "utils/xml_event_parser.h"

#ifdef _WIN32
#include <windows.h>
#include <xmllite.h>
#include <combaseapi.h>
#include <vector>
#pragma comment(lib, "xmllite.lib")

namespace miniedr {

static std::wstring BstrToW(const wchar_t* s, UINT len) {
    if (!s || len == 0) return L"";
    return std::wstring(s, s + len);
}

static bool GetAttributeValue(IXmlReader* reader, const wchar_t* name, const wchar_t** value) {
    // 先移到第一個屬性
    if (reader->MoveToFirstAttribute() != S_OK)
        return false;
    do {
        const wchar_t* attrName = nullptr;
        UINT attrNameLen = 0;
        if (reader->GetLocalName(&attrName, &attrNameLen) != S_OK)
            continue;
        if (_wcsicmp(attrName, name) == 0) {
            // 取得屬性值
            UINT valueLen = 0;
            if (reader->GetValue(value, &valueLen) == S_OK)
                return true;
        }
    } while (reader->MoveToNextAttribute() == S_OK);
    // 回到元素節點
    reader->MoveToElement();
    return false;
}

static bool AttrEquals(IXmlReader* reader, const wchar_t* name, const wchar_t* expect) {
    const wchar_t* v = nullptr;
    if (!GetAttributeValue(reader, name, &v)) return false;
    return (_wcsicmp(v, expect) == 0);
}

XmlEventParseResult ParseWindowsEventXml(const std::wstring& xml) {
    XmlEventParseResult out;

    if (xml.empty()) {
        out.error = L"empty xml";
        return out;
    }

    IXmlReader* reader = nullptr;
    IStream* stream = nullptr;

    HRESULT hr = CreateXmlReader(__uuidof(IXmlReader), (void**)&reader, nullptr);
    if (FAILED(hr) || !reader) {
        out.error = L"CreateXmlReader failed";
        return out;
    }

    // Create stream over UTF-16 buffer.
    // We wrap the XML string in a global memory stream.
    HGLOBAL hmem = GlobalAlloc(GMEM_MOVEABLE, (xml.size() + 1) * sizeof(wchar_t));
    if (!hmem) {
        reader->Release();
        out.error = L"GlobalAlloc failed";
        return out;
    }
    void* mem = GlobalLock(hmem);
    memcpy(mem, xml.c_str(), (xml.size() + 1) * sizeof(wchar_t));
    GlobalUnlock(hmem);

    hr = CreateStreamOnHGlobal(hmem, TRUE, &stream); // stream owns hmem
    if (FAILED(hr) || !stream) {
        reader->Release();
        out.error = L"CreateStreamOnHGlobal failed";
        return out;
    }

    hr = reader->SetInput(stream);
    if (FAILED(hr)) {
        stream->Release();
        reader->Release();
        out.error = L"IXmlReader::SetInput failed";
        return out;
    }

    // Track context
    std::wstring current_element;
    std::wstring current_data_name;
    bool in_eventid = false;
    bool in_data = false;

    XmlNodeType nodeType;
    while ((hr = reader->Read(&nodeType)) == S_OK) {
        if (nodeType == XmlNodeType_Element) {
            const wchar_t* localName = nullptr;
            UINT localLen = 0;
            reader->GetLocalName(&localName, &localLen);
            current_element = BstrToW(localName, localLen);

            if (_wcsicmp(current_element.c_str(), L"EventID") == 0) {
                in_eventid = true;
            } else if (_wcsicmp(current_element.c_str(), L"TimeCreated") == 0) {
                // Attribute SystemTime
                const wchar_t* v = nullptr;
                if (GetAttributeValue(reader, L"SystemTime", &v) && v) {
                    out.system_time_utc = v;
                }
            } else if (_wcsicmp(current_element.c_str(), L"Data") == 0) {
                in_data = true;
                current_data_name.clear();
                const wchar_t* v = nullptr;
                if (GetAttributeValue(reader, L"Name", &v) && v) {
                    current_data_name = v;
                }
            }
        } else if (nodeType == XmlNodeType_Text || nodeType == XmlNodeType_CDATA) {
            const wchar_t* value = nullptr;
            UINT len = 0;
            reader->GetValue(&value, &len);
            auto text = BstrToW(value, len);

            if (in_eventid && out.event_id.empty()) {
                out.event_id = text;
            } else if (in_data && !current_data_name.empty()) {
                out.data[current_data_name] = text;
            }
        } else if (nodeType == XmlNodeType_EndElement) {
            const wchar_t* localName = nullptr;
            UINT localLen = 0;
            reader->GetLocalName(&localName, &localLen);
            auto endName = BstrToW(localName, localLen);

            if (_wcsicmp(endName.c_str(), L"EventID") == 0) in_eventid = false;
            if (_wcsicmp(endName.c_str(), L"Data") == 0) { in_data = false; current_data_name.clear(); }
        }
    }

    stream->Release();
    reader->Release();

    if (out.event_id.empty()) {
        out.error = L"EventID not found";
        return out;
    }

    out.ok = true;
    return out;
}

} // namespace miniedr
#endif
