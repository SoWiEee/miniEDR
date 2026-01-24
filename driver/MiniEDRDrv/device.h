#pragma once
#include <ntddk.h>
#include <wdf.h>
#include "miniedr_ioctl.h"

typedef struct _DEVICE_CONTEXT {
    WDFQUEUE Queue;

    // event ring buffer (fixed-size entries)
    WDFSPINLOCK EventLock;
    ULONG WriteIndex;
    ULONG ReadIndex;
    ULONG Dropped;

    // Policy knobs
    BOOLEAN HandleAuditEnabled;
} DEVICE_CONTEXT, *PDEVICE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(DEVICE_CONTEXT, DeviceGetContext)

NTSTATUS MiniEdrCreateDevice(_Inout_ PWDFDEVICE_INIT DeviceInit, _Out_ WDFDEVICE* Device);
