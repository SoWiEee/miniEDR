#pragma once

// Device name: \\.\MiniEDRDrv  (symbolic link to \Device\MiniEDRDrv)
#define MINIEDR_DEVICE_DOS_NAME        L"\\\\.\\\\MiniEDRDrv"
#define MINIEDR_DEVICE_NT_NAME         L"\\Device\\MiniEDRDrv"
#define MINIEDR_DEVICE_SYMBOLIC_LINK   L"\\DosDevices\\MiniEDRDrv"

#define MINIEDR_IOCTL_VERSION 0x00010000u

// Event types
typedef enum _MINIEDR_EVENT_TYPE {
    MiniEdrEvent_Invalid = 0,
    MiniEdrEvent_ProcessCreate = 1,
    MiniEdrEvent_ProcessExit   = 2,
    MiniEdrEvent_ImageLoad     = 3,
    MiniEdrEvent_HandleAccess  = 4,
} MINIEDR_EVENT_TYPE;

// Fixed-size payloads to keep kernel code simple and safe.
// User-mode can enrich by querying additional process info if needed.
#pragma pack(push, 1)

typedef struct _MINIEDR_EVENT_HEADER {
    UINT32 Type;       // MINIEDR_EVENT_TYPE
    UINT32 Size;       // total size of event including header
    UINT64 TimestampQpc; // KeQueryPerformanceCounter() value
} MINIEDR_EVENT_HEADER;

typedef struct _MINIEDR_EVT_PROCESS {
    MINIEDR_EVENT_HEADER H;
    UINT32 Pid;
    UINT32 ParentPid;
    UINT8 ImageFileName[16]; // EPROCESS ImageFileName (ANSI, truncated)
} MINIEDR_EVT_PROCESS;

typedef struct _MINIEDR_EVT_IMAGELOAD {
    MINIEDR_EVENT_HEADER H;
    UINT32 Pid;
    UINT32 Reserved;
    wchar_t  ImagePath[260]; // FullImageName (truncated)
} MINIEDR_EVT_IMAGELOAD;

typedef struct _MINIEDR_EVT_HANDLEACCESS {
    MINIEDR_EVENT_HEADER H;
    UINT32 SourcePid;
    UINT32 TargetPid;
    UINT32 DesiredAccess;
    UINT32 Operation; // 1=CreateHandle,2=DuplicateHandle (best-effort)
} MINIEDR_EVT_HANDLEACCESS;

#pragma pack(pop)

// IOCTLs (METHOD_BUFFERED)
#define MINIEDR_IOCTL_BASE      0x800

#define IOCTL_MINIEDR_GET_VERSION CTL_CODE(FILE_DEVICE_UNKNOWN, MINIEDR_IOCTL_BASE + 0, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_MINIEDR_GET_EVENTS  CTL_CODE(FILE_DEVICE_UNKNOWN, MINIEDR_IOCTL_BASE + 1, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_MINIEDR_SET_POLICY  CTL_CODE(FILE_DEVICE_UNKNOWN, MINIEDR_IOCTL_BASE + 2, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_MINIEDR_SET_POLICY_V2 CTL_CODE(FILE_DEVICE_UNKNOWN, MINIEDR_IOCTL_BASE + 3, METHOD_BUFFERED, FILE_WRITE_ACCESS)

// GET_VERSION output
typedef struct _MINIEDR_VERSION_INFO {
    UINT32 Version; // MINIEDR_IOCTL_VERSION
    UINT32 Features; // bitmask (future use)
} MINIEDR_VERSION_INFO;

// SET_POLICY input (minimal; expandable)
typedef struct _MINIEDR_POLICY {
    UINT32 EnableHandleAudit; // 0/1
    UINT32 Reserved;
} MINIEDR_POLICY;

// Policy v2 (variable length PID lists)
#define MINIEDR_POLICY_FLAG_ENFORCE_PROTECT 0x00000001u

#pragma pack(push, 1)
typedef struct _MINIEDR_POLICY_V2 {
    UINT32 Version;         // set to MINIEDR_IOCTL_VERSION
    UINT32 Flags;           // MINIEDR_POLICY_FLAG_*
    UINT32 ProtectedPidCount;
    UINT32 AllowedPidCount;
    // Followed by arrays:
    // uint32_t ProtectedPids[ProtectedPidCount];
    // uint32_t AllowedPids[AllowedPidCount];
} MINIEDR_POLICY_V2;
#pragma pack(pop)
