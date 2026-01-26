#include "device.h"
#include "queue.h"
#include "callbacks.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text (PAGE, MiniEdrCreateDevice)
#endif

static VOID MiniEdrDeviceContextCleanup(_In_ WDFOBJECT DeviceObject)
{
    WDFDEVICE device = (WDFDEVICE)DeviceObject;
    UNREFERENCED_PARAMETER(device);
    DEVICE_CONTEXT* ctx = DeviceGetContext(device);
    if (ctx->PolicyLock) WdfSpinLockAcquire(ctx->PolicyLock);
    if (ctx->ProtectedPids) { ExFreePoolWithTag(ctx->ProtectedPids, 'rPdM'); ctx->ProtectedPids = NULL; }
    if (ctx->AllowedPids) { ExFreePoolWithTag(ctx->AllowedPids, 'aPdM'); ctx->AllowedPids = NULL; }
    ctx->ProtectedCount = ctx->AllowedCount = 0;
    if (ctx->PolicyLock) WdfSpinLockRelease(ctx->PolicyLock);

    MiniEdrUnregisterCallbacks();
}

NTSTATUS MiniEdrCreateDevice(_Inout_ PWDFDEVICE_INIT DeviceInit, _Out_ WDFDEVICE* Device)
{
    PAGED_CODE();

    NTSTATUS status;
    WDFDEVICE device;
    WDF_OBJECT_ATTRIBUTES attributes;
    WDF_FILEOBJECT_CONFIG fileConfig;
    UNICODE_STRING ntName;
    UNICODE_STRING symLink;

    // Device characteristics: secure open
    WdfDeviceInitSetDeviceType(DeviceInit, FILE_DEVICE_UNKNOWN);
    WdfDeviceInitSetCharacteristics(DeviceInit, FILE_DEVICE_SECURE_OPEN, FALSE);

    // I/O type: buffered
    WdfDeviceInitSetIoType(DeviceInit, WdfDeviceIoBuffered);

    // File object config (no special callbacks in this MVP)
    WDF_FILEOBJECT_CONFIG_INIT(&fileConfig, WDF_NO_EVENT_CALLBACK, WDF_NO_EVENT_CALLBACK, WDF_NO_EVENT_CALLBACK);
    WdfDeviceInitSetFileObjectConfig(DeviceInit, &fileConfig, WDF_NO_OBJECT_ATTRIBUTES);

    // Create device
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attributes, DEVICE_CONTEXT);
    attributes.EvtCleanupCallback = MiniEdrDeviceContextCleanup;

    RtlInitUnicodeString(&ntName, MINIEDR_DEVICE_NT_NAME);
    status = WdfDeviceInitAssignName(DeviceInit, &ntName);
    if (!NT_SUCCESS(status)) return status;

    status = WdfDeviceCreate(&DeviceInit, &attributes, &device);
    if (!NT_SUCCESS(status)) return status;

    // Create symbolic link \\.\MiniEDRDrv
    RtlInitUnicodeString(&symLink, MINIEDR_DEVICE_SYMBOLIC_LINK);
    status = WdfDeviceCreateSymbolicLink(device, &symLink);
    if (!NT_SUCCESS(status)) return status;

    // Initialize ring buffer state
    DEVICE_CONTEXT* ctx = DeviceGetContext(device);
    ctx->WriteIndex = 0;
    ctx->ReadIndex = 0;
    ctx->Dropped = 0;
    ctx->HandleAuditEnabled = TRUE;
    ctx->EnforceProtect = FALSE;
    ctx->StripInsteadOfDeny = TRUE;
    ctx->ProtectedCount = 0;
    ctx->AllowedCount = 0;
    ctx->ProtectedPids = NULL;
    ctx->AllowedPids = NULL;

    status = WdfSpinLockCreate(WDF_NO_OBJECT_ATTRIBUTES, &ctx->EventLock);
    if (!NT_SUCCESS(status)) return status;

    status = WdfSpinLockCreate(WDF_NO_OBJECT_ATTRIBUTES, &ctx->PolicyLock);
    if (!NT_SUCCESS(status)) return status;

    status = MiniEdrQueueInitialize(device);
    if (!NT_SUCCESS(status)) return status;

    status = MiniEdrRegisterCallbacks(device);
    if (!NT_SUCCESS(status)) return status;

    *Device = device;
    return STATUS_SUCCESS;
}
