#include "queue.h"
#include "device.h"
#include "miniedr_ioctl.h"

#include <ntstrsafe.h>

#define RING_CAPACITY 1024

// Fixed slot size: store the largest event type
#define SLOT_SIZE sizeof(MINIEDR_EVT_IMAGELOAD)

static __forceinline ULONG NextIndex(ULONG idx) { return (idx + 1) % RING_CAPACITY; }

// Ring is stored in the device context as an opaque buffer via WDFMEMORY in Phase 4+.
// For this MVP we use a static nonpaged array per-driver instance.
static MINIEDR_EVT_IMAGELOAD g_ring[RING_CAPACITY];

// Producer: write a binary blob into next slot (truncates to SLOT_SIZE)
static VOID RingPush(_In_ WDFDEVICE Device, _In_reads_bytes_(Size) const void* Data, _In_ ULONG Size)
{
    auto ctx = DeviceGetContext(Device);

    WdfSpinLockAcquire(ctx->EventLock);

    ULONG next = NextIndex(ctx->WriteIndex);
    if (next == ctx->ReadIndex) {
        ctx->Dropped++;
        WdfSpinLockRelease(ctx->EventLock);
        return;
    }

    ULONG copy = (Size > SLOT_SIZE) ? SLOT_SIZE : Size;
    RtlZeroMemory(&g_ring[ctx->WriteIndex], SLOT_SIZE);
    RtlCopyMemory(&g_ring[ctx->WriteIndex], Data, copy);
    ctx->WriteIndex = next;

    WdfSpinLockRelease(ctx->EventLock);
}

// Consumer: copy as many events as will fit into OutBuffer
static ULONG RingPopMany(_In_ WDFDEVICE Device, _Out_writes_bytes_(OutCap) uint8_t* OutBuffer, _In_ ULONG OutCap)
{
    auto ctx = DeviceGetContext(Device);
    ULONG written = 0;

    WdfSpinLockAcquire(ctx->EventLock);

    while (ctx->ReadIndex != ctx->WriteIndex) {
        auto* slot = &g_ring[ctx->ReadIndex];
        ULONG sz = slot->H.Size;
        if (sz == 0 || sz > SLOT_SIZE) sz = SLOT_SIZE;

        if (written + sz > OutCap) break;

        RtlCopyMemory(OutBuffer + written, slot, sz);
        written += sz;

        ctx->ReadIndex = NextIndex(ctx->ReadIndex);
    }

    WdfSpinLockRelease(ctx->EventLock);
    return written;
}

// Exposed to callbacks.c
VOID MiniEdrRingPush(_In_ WDFDEVICE Device, _In_reads_bytes_(Size) const void* Data, _In_ ULONG Size)
{
    RingPush(Device, Data, Size);
}

NTSTATUS MiniEdrQueueInitialize(_In_ WDFDEVICE Device)
{
    WDF_IO_QUEUE_CONFIG queueConfig;
    NTSTATUS status;

    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchSequential);
    queueConfig.EvtIoDeviceControl = MiniEdrEvtIoDeviceControl;

    status = WdfIoQueueCreate(Device, &queueConfig, WDF_NO_OBJECT_ATTRIBUTES, &DeviceGetContext(Device)->Queue);
    return status;
}

VOID MiniEdrEvtIoDeviceControl(_In_ WDFQUEUE Queue,
                              _In_ WDFREQUEST Request,
                              _In_ size_t OutputBufferLength,
                              _In_ size_t InputBufferLength,
                              _In_ ULONG IoControlCode)
{
    UNREFERENCED_PARAMETER(InputBufferLength);

    WDFDEVICE device = WdfIoQueueGetDevice(Queue);
    NTSTATUS status = STATUS_SUCCESS;
    size_t bytes = 0;

    if (IoControlCode == IOCTL_MINIEDR_GET_VERSION) {
        MINIEDR_VERSION_INFO* out = nullptr;
        status = WdfRequestRetrieveOutputBuffer(Request, sizeof(MINIEDR_VERSION_INFO), (PVOID*)&out, nullptr);
        if (NT_SUCCESS(status)) {
            out->Version = MINIEDR_IOCTL_VERSION;
            out->Features = 0;
            bytes = sizeof(MINIEDR_VERSION_INFO);
        }
    } else if (IoControlCode == IOCTL_MINIEDR_GET_EVENTS) {
        uint8_t* out = nullptr;
        status = WdfRequestRetrieveOutputBuffer(Request, 1, (PVOID*)&out, nullptr);
        if (NT_SUCCESS(status)) {
            ULONG cap = (ULONG)OutputBufferLength;
            bytes = RingPopMany(device, out, cap);
        }
    } else if (IoControlCode == IOCTL_MINIEDR_SET_POLICY) {
        const MINIEDR_POLICY* in = nullptr;
        status = WdfRequestRetrieveInputBuffer(Request, sizeof(MINIEDR_POLICY), (PVOID*)&in, nullptr);
        if (NT_SUCCESS(status)) {
            auto ctx = DeviceGetContext(device);
            ctx->HandleAuditEnabled = (in->EnableHandleAudit != 0) ? TRUE : FALSE;
            bytes = 0;
        }
    } else {
        status = STATUS_INVALID_DEVICE_REQUEST;
    }

    WdfRequestCompleteWithInformation(Request, status, bytes);
}
