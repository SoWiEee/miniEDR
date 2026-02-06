#pragma once
#include <ntddk.h>
#include <wdf.h>
#include "../include/miniedr_ioctl.h"

typedef struct _DEVICE_CONTEXT {
    WDFQUEUE Queue;

    // event ring buffer
    WDFSPINLOCK EventLock;
    ULONG WriteIndex;
    ULONG ReadIndex;
    ULONG Dropped;

    // Policy knobs
    BOOLEAN HandleAuditEnabled;

    // Penforcement
    BOOLEAN EnforceProtect;
    BOOLEAN StripInsteadOfDeny;
    WDFSPINLOCK PolicyLock;
    UINT32 ProtectedCount;
    UINT32 AllowedCount;
    UINT32* ProtectedPids; // NonPagedPoolNx
    UINT32* AllowedPids;   // NonPagedPoolNx
} DEVICE_CONTEXT, *PDEVICE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(DEVICE_CONTEXT, DeviceGetContext)

NTSTATUS MiniEdrCreateDevice(_Inout_ PWDFDEVICE_INIT DeviceInit, _Out_ WDFDEVICE* Device);
