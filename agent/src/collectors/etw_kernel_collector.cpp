#include "collectors/etw_kernel_collector.h"

#ifdef _WIN32

// Important: define INITGUID in exactly one translation unit.
#define INITGUID

#include <windows.h>
#include <evntrace.h>
#include <tdh.h>
#include <wmistr.h>
#include <objbase.h>

#include <iostream>
#include <vector>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "ole32.lib")

#ifndef SystemTraceControlGuid
DEFINE_GUID(SystemTraceControlGuid,
    0x9e814aad, 0x3204, 0x11d2, 0x9a, 0x82, 0x00, 0x60, 0x08, 0xa8, 0x69, 0x39);
#endif

#ifndef ProcessGuid
DEFINE_GUID(ProcessGuid,
    0x3d6fa8d0, 0xfe05, 0x11d0, 0x9d, 0xf2, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c);
#endif

#ifndef ImageLoadGuid
DEFINE_GUID(ImageLoadGuid,
    0x2cb15d1d, 0x5fc1, 0x11d2, 0xbe, 0x1a, 0x00, 0xc0, 0x4f, 0xd6, 0x0b, 0x9b);
#endif

namespace miniedr {

static EtwKernelCollector* g_self = nullptr;

EtwKernelCollector::EtwKernelCollector() = default;

EtwKernelCollector::~EtwKernelCollector() {
    Stop();
}

bool EtwKernelCollector::Start(Callback cb) {
    cb_ = std::move(cb);
    stop_requested_ = false;

    // Only one live instance in this educational implementation.
    g_self = this;

    worker_ = std::thread([this]() { Run(); });
    return true;
}

void EtwKernelCollector::Stop() {
    stop_requested_ = true;

    if (trace_handle_) {
        // CloseTrace will cause ProcessTrace to return.
        CloseTrace((TRACEHANDLE)trace_handle_);
        trace_handle_ = nullptr;
    }

    if (worker_.joinable()) worker_.join();

    if (started_session_ && session_handle_) {
        // Stop the kernel logger only if we started it.
        // If another tool started it, stopping it would be disruptive.
        EVENT_TRACE_PROPERTIES props = {};
        ULONG status = ControlTrace((TRACEHANDLE)session_handle_, KERNEL_LOGGER_NAME, &props, EVENT_TRACE_CONTROL_STOP);
        (void)status;
    }

    session_handle_ = nullptr;
    started_session_ = false;
    g_self = nullptr;
}

static EVENT_TRACE_PROPERTIES* AllocKernelProps(size_t name_chars = 1024) {
    const size_t bytes = sizeof(EVENT_TRACE_PROPERTIES) + (name_chars * sizeof(wchar_t)) * 2;
    auto* p = (EVENT_TRACE_PROPERTIES*)calloc(1, bytes);
    if (!p) return nullptr;

    p->Wnode.BufferSize = (ULONG)bytes;
    p->Wnode.Guid = SystemTraceControlGuid;
    p->Wnode.ClientContext = 1; // QPC
    p->Wnode.Flags = WNODE_FLAG_TRACED_GUID;

    p->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    p->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    p->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + (ULONG)(name_chars * sizeof(wchar_t));

    // Collect process + image load signals (starter set).
    p->EnableFlags = EVENT_TRACE_FLAG_PROCESS | EVENT_TRACE_FLAG_IMAGE_LOAD;

    return p;
}

void EtwKernelCollector::Run() {
    auto* props = AllocKernelProps();
    if (!props) {
        std::wcerr << L"[EtwKernelCollector] Allocation failed.\n";
        return;
    }

    TRACEHANDLE session = 0;
    ULONG status = StartTrace(&session, KERNEL_LOGGER_NAME, props);
    if (status == ERROR_ALREADY_EXISTS) {
        // Session already running - that's fine; we'll just consume.
        started_session_ = false;
    } else if (status != ERROR_SUCCESS) {
        std::wcerr << L"[EtwKernelCollector] StartTrace failed. status=" << status
                   << L". Try running as Administrator.\n";
        free(props);
        return;
    } else {
        started_session_ = true;
    }

    session_handle_ = (void*)session;

    EVENT_TRACE_LOGFILE logfile = {};
    logfile.LoggerName = (LPWSTR)KERNEL_LOGGER_NAME;
    logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.EventRecordCallback = (PEVENT_RECORD_CALLBACK)EtwKernelCollector::OnEventRecord;

    TRACEHANDLE trace = OpenTrace(&logfile);
    if (trace == INVALID_PROCESSTRACE_HANDLE) {
        std::wcerr << L"[EtwKernelCollector] OpenTrace failed. GetLastError=" << GetLastError() << L"\n";
        if (started_session_) {
            ControlTrace(session, KERNEL_LOGGER_NAME, props, EVENT_TRACE_CONTROL_STOP);
        }
        free(props);
        return;
    }
    trace_handle_ = (void*)trace;

    std::wcout << L"[EtwKernelCollector] Consuming NT Kernel Logger (Process/ImageLoad) in real-time.\n";

    status = ProcessTrace(&trace, 1, nullptr, nullptr);
    (void)status;

    free(props);
}

void WINAPI EtwKernelCollector::OnEventRecord(_EVENT_RECORD* record) {
    if (g_self) g_self->HandleRecord(record);
}

static std::wstring GuidToWString(const GUID& g) {
    wchar_t buf[64] = {};
    StringFromGUID2(g, buf, 64);
    return buf;
}

std::wstring EtwKernelCollector::GetStringProp(_EVENT_RECORD* record, const wchar_t* name) {
    PROPERTY_DATA_DESCRIPTOR desc = {};
    desc.PropertyName = (ULONGLONG)name;
    desc.ArrayIndex = ULONG_MAX;

    ULONG size = 0;
    if (TdhGetPropertySize(record, 0, nullptr, 1, &desc, &size) != ERROR_SUCCESS || size == 0) {
        return L"";
    }
    std::vector<BYTE> buf(size);
    if (TdhGetProperty(record, 0, nullptr, 1, &desc, size, buf.data()) != ERROR_SUCCESS) {
        return L"";
    }

    // Many kernel MOF string fields are null-terminated wide strings.
    const wchar_t* ws = reinterpret_cast<const wchar_t*>(buf.data());
    size_t n = 0;
    while ((n + 1) * sizeof(wchar_t) <= size && ws[n] != L'\0') n++;
    return std::wstring(ws, n);
}

uint32_t EtwKernelCollector::GetUInt32Prop(_EVENT_RECORD* record, const wchar_t* name) {
    PROPERTY_DATA_DESCRIPTOR desc = {};
    desc.PropertyName = (ULONGLONG)name;
    desc.ArrayIndex = ULONG_MAX;

    ULONG size = 0;
    if (TdhGetPropertySize(record, 0, nullptr, 1, &desc, &size) != ERROR_SUCCESS || size < sizeof(uint32_t)) {
        return 0;
    }
    uint32_t v = 0;
    if (TdhGetProperty(record, 0, nullptr, 1, &desc, sizeof(uint32_t), (PBYTE)&v) != ERROR_SUCCESS) {
        return 0;
    }
    return v;
}

void EtwKernelCollector::HandleRecord(_EVENT_RECORD* record) {
    if (stop_requested_ || !cb_) return;

    // Provider IDs for NT kernel logger classes are documented as constants.
    // ProcessGuid / ImageLoadGuid are defined in evntrace.h when INITGUID is set.
    // We use TDH property extraction for a few well-known fields; missing fields are tolerated.

    const GUID& prov = record->EventHeader.ProviderId;

    CanonicalEvent ev;
    ev.source = L"etw";
    ev.source_eid = record->EventHeader.EventDescriptor.Opcode; // opcode maps to EVENT_TRACE_TYPE_*

    // Timestamp: use QPC-relative; for Phase2 we keep it blank (students can add conversion later).
    // If you want a wall-clock timestamp, convert record->EventHeader.TimeStamp.
    ev.timestamp_utc = L"";

    if (IsEqualGUID(prov, ProcessGuid)) {
        // Process event types: START (1), END (2), etc.
        if (record->EventHeader.EventDescriptor.Opcode == EVENT_TRACE_TYPE_START) {
            ev.type = EventType::ProcessCreate;
            ev.proc.pid = GetUInt32Prop(record, L"ProcessId");
            ev.proc.ppid = GetUInt32Prop(record, L"ParentId");
            ev.proc.image = GetStringProp(record, L"ImageFileName");
            ev.proc.command_line = GetStringProp(record, L"CommandLine"); // may be empty depending on OS/version
            cb_(ev);
        }
        return;
    }

    if (IsEqualGUID(prov, ImageLoadGuid)) {
        // Image load events; map to ImageLoad canonical type.
        ev.type = EventType::ImageLoad;
        ev.proc.pid = GetUInt32Prop(record, L"ProcessId");
        ev.fields[L"ImageLoaded"] = GetStringProp(record, L"FileName");
        if (ev.fields[L"ImageLoaded"].empty()) ev.fields[L"ImageLoaded"] = GetStringProp(record, L"ImageFileName");
        cb_(ev);
        return;
    }

    // Other kernel classes are ignored in Phase 2 starter.
    (void)GuidToWString;
}

} // namespace miniedr

#endif // _WIN32
