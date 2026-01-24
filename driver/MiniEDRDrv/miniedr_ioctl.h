#pragma once
#include <stdint.h>

// Device name: \\.\MiniEDRDrv  (symbolic link to \Device\MiniEDRDrv)
#define MINIEDR_DEVICE_DOS_NAME        L"\\\\.\\\\MiniEDRDrv"
#define MINIEDR_DEVICE_NT_NAME         L"\\Device\\MiniEDRDrv"
#define MINIEDR_DEVICE_SYMBOLIC_LINK   L"\\DosDevices\\MiniEDRDrv"

#define MINIEDR_IOCTL_VERSION 0x00010000u
#ifndef FILE_DEVICE_UNKNOWN
#define FILE_DEVICE_UNKNOWN 0x00000022
#endif

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
    uint32_t Type;       // MINIEDR_EVENT_TYPE
    uint32_t Size;       // total size of event including header
    uint64_t TimestampQpc; // KeQueryPerformanceCounter() value
} MINIEDR_EVENT_HEADER;

typedef struct _MINIEDR_EVT_PROCESS {
    MINIEDR_EVENT_HEADER H;
    uint32_t Pid;
    uint32_t ParentPid;
    uint8_t  ImageFileName[16]; // EPROCESS ImageFileName (ANSI, truncated)
} MINIEDR_EVT_PROCESS;

typedef struct _MINIEDR_EVT_IMAGELOAD {
    MINIEDR_EVENT_HEADER H;
    uint32_t Pid;
    uint32_t Reserved;
    wchar_t  ImagePath[260]; // FullImageName (truncated)
} MINIEDR_EVT_IMAGELOAD;

typedef struct _MINIEDR_EVT_HANDLEACCESS {
    MINIEDR_EVENT_HEADER H;
    uint32_t SourcePid;
    uint32_t TargetPid;
    uint32_t DesiredAccess;
    uint32_t Operation; // 1=CreateHandle,2=DuplicateHandle (best-effort)
} MINIEDR_EVT_HANDLEACCESS;

#pragma pack(pop)

// IOCTLs (METHOD_BUFFERED)
#define MINIEDR_IOCTL_BASE      0x800

#define IOCTL_MINIEDR_GET_VERSION CTL_CODE(FILE_DEVICE_UNKNOWN, MINIEDR_IOCTL_BASE + 0, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_MINIEDR_GET_EVENTS  CTL_CODE(FILE_DEVICE_UNKNOWN, MINIEDR_IOCTL_BASE + 1, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_MINIEDR_SET_POLICY  CTL_CODE(FILE_DEVICE_UNKNOWN, MINIEDR_IOCTL_BASE + 2, METHOD_BUFFERED, FILE_WRITE_ACCESS)

// GET_VERSION output
typedef struct _MINIEDR_VERSION_INFO {
    uint32_t Version; // MINIEDR_IOCTL_VERSION
    uint32_t Features; // bitmask (future use)
} MINIEDR_VERSION_INFO;

// SET_POLICY input (minimal; expandable)
typedef struct _MINIEDR_POLICY {
    uint32_t EnableHandleAudit; // 0/1
    uint32_t Reserved;
} MINIEDR_POLICY;
