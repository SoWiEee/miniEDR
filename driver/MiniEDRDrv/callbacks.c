#include "callbacks.h"
#include "device.h"
#include "miniedr_ioctl.h"

#include <ntstrsafe.h>

extern VOID MiniEdrRingPush(_In_ WDFDEVICE Device, _In_reads_bytes_(Size) const void* Data, _In_ ULONG Size);

static WDFDEVICE g_device = NULL;
static PVOID g_obHandle = NULL;

static OB_PREOP_CALLBACK_STATUS MiniEdrPreOp(_In_ PVOID RegistrationContext, _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    if (!g_device) return OB_PREOP_SUCCESS;

    auto ctx = DeviceGetContext(g_device);
    if (!ctx->HandleAuditEnabled) return OB_PREOP_SUCCESS;

    // We only audit process handle operations
    if (OperationInformation->ObjectType != *PsProcessType) return OB_PREOP_SUCCESS;

    ULONG srcPid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    ULONG tgtPid = 0;

    PEPROCESS target = (PEPROCESS)OperationInformation->Object;
    if (target) {
        tgtPid = (ULONG)(ULONG_PTR)PsGetProcessId(target);
    }

    ACCESS_MASK desired = 0;
    ULONG op = 0;
    if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
        desired = OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
        op = 1;
    } else if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        desired = OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;
        op = 2;
    }

    MINIEDR_EVT_HANDLEACCESS e = {0};
    e.H.Type = MiniEdrEvent_HandleAccess;
    e.H.Size = sizeof(e);
    e.H.TimestampQpc = (uint64_t)KeQueryPerformanceCounter(NULL).QuadPart;
    e.SourcePid = srcPid;
    e.TargetPid = tgtPid;
    e.DesiredAccess = (uint32_t)desired;
    e.Operation = op;

    MiniEdrRingPush(g_device, &e, sizeof(e));
    return OB_PREOP_SUCCESS; // audit only
}

static VOID MiniEdrProcessNotifyEx(_Inout_ PEPROCESS Process,
                                  _In_ HANDLE ProcessId,
                                  _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    if (!g_device) return;

    if (CreateInfo) {
        // Create
        MiniEdrPushProcessEvent(g_device, TRUE, ProcessId, CreateInfo->ParentProcessId, Process);
    } else {
        // Exit
        MiniEdrPushProcessEvent(g_device, FALSE, ProcessId, NULL, Process);
    }
}

static VOID MiniEdrImageLoadNotify(_In_opt_ PUNICODE_STRING FullImageName,
                                  _In_ HANDLE ProcessId,
                                  _In_ PIMAGE_INFO ImageInfo)
{
    UNREFERENCED_PARAMETER(ImageInfo);
    if (!g_device) return;
    MiniEdrPushImageLoadEvent(g_device, ProcessId, FullImageName);
}

VOID MiniEdrPushProcessEvent(_In_ WDFDEVICE Device, _In_ BOOLEAN Create, _In_ HANDLE ProcessId, _In_opt_ HANDLE ParentId, _In_opt_ PEPROCESS Process)
{
    MINIEDR_EVT_PROCESS e = {0};
    e.H.Type = Create ? MiniEdrEvent_ProcessCreate : MiniEdrEvent_ProcessExit;
    e.H.Size = sizeof(e);
    e.H.TimestampQpc = (uint64_t)KeQueryPerformanceCounter(NULL).QuadPart;
    e.Pid = (uint32_t)(ULONG_PTR)ProcessId;
    e.ParentPid = (uint32_t)(ULONG_PTR)ParentId;

    if (Process) {
        const char* img = PsGetProcessImageFileName(Process); // 15 chars + null
        RtlCopyMemory(e.ImageFileName, img, 15);
        e.ImageFileName[15] = 0;
    }

    MiniEdrRingPush(Device, &e, sizeof(e));
}

VOID MiniEdrPushImageLoadEvent(_In_ WDFDEVICE Device, _In_ HANDLE ProcessId, _In_opt_ PUNICODE_STRING FullImageName)
{
    MINIEDR_EVT_IMAGELOAD e = {0};
    e.H.Type = MiniEdrEvent_ImageLoad;
    e.H.Size = sizeof(e);
    e.H.TimestampQpc = (uint64_t)KeQueryPerformanceCounter(NULL).QuadPart;
    e.Pid = (uint32_t)(ULONG_PTR)ProcessId;

    if (FullImageName && FullImageName->Buffer) {
        // Truncate safely
        size_t cch = (FullImageName->Length / sizeof(wchar_t));
        if (cch > 259) cch = 259;
        RtlCopyMemory(e.ImagePath, FullImageName->Buffer, cch * sizeof(wchar_t));
        e.ImagePath[cch] = L'\0';
    } else {
        e.ImagePath[0] = L'\0';
    }

    MiniEdrRingPush(Device, &e, sizeof(e));
}

VOID MiniEdrPushHandleAccessEvent(_In_ WDFDEVICE Device, _In_ ULONG SourcePid, _In_ ULONG TargetPid, _In_ ACCESS_MASK DesiredAccess, _In_ ULONG Operation)
{
    MINIEDR_EVT_HANDLEACCESS e = {0};
    e.H.Type = MiniEdrEvent_HandleAccess;
    e.H.Size = sizeof(e);
    e.H.TimestampQpc = (uint64_t)KeQueryPerformanceCounter(NULL).QuadPart;
    e.SourcePid = SourcePid;
    e.TargetPid = TargetPid;
    e.DesiredAccess = (uint32_t)DesiredAccess;
    e.Operation = Operation;
    MiniEdrRingPush(Device, &e, sizeof(e));
}

NTSTATUS MiniEdrRegisterCallbacks(_In_ WDFDEVICE Device)
{
    g_device = Device;

    NTSTATUS status = PsSetCreateProcessNotifyRoutineEx(MiniEdrProcessNotifyEx, FALSE);
    if (!NT_SUCCESS(status)) return status;

    status = PsSetLoadImageNotifyRoutine(MiniEdrImageLoadNotify);
    if (!NT_SUCCESS(status)) {
        PsSetCreateProcessNotifyRoutineEx(MiniEdrProcessNotifyEx, TRUE);
        return status;
    }

    // ObRegisterCallbacks: audit process handle access
    OB_CALLBACK_REGISTRATION reg = {0};
    OB_OPERATION_REGISTRATION op = {0};

    UNICODE_STRING altitude;
    RtlInitUnicodeString(&altitude, L"370000"); // developer-chosen altitude; adjust if needed

    op.ObjectType = PsProcessType;
    op.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    op.PreOperation = MiniEdrPreOp;
    op.PostOperation = NULL;

    reg.Version = OB_FLT_REGISTRATION_VERSION;
    reg.OperationRegistrationCount = 1;
    reg.Altitude = altitude;
    reg.RegistrationContext = NULL;
    reg.OperationRegistration = &op;

    status = ObRegisterCallbacks(&reg, &g_obHandle);
    if (!NT_SUCCESS(status)) {
        PsRemoveLoadImageNotifyRoutine(MiniEdrImageLoadNotify);
        PsSetCreateProcessNotifyRoutineEx(MiniEdrProcessNotifyEx, TRUE);
        g_obHandle = NULL;
        return status;
    }

    return STATUS_SUCCESS;
}

VOID MiniEdrUnregisterCallbacks()
{
    if (g_obHandle) {
        ObUnRegisterCallbacks(g_obHandle);
        g_obHandle = NULL;
    }

    PsRemoveLoadImageNotifyRoutine(MiniEdrImageLoadNotify);
    PsSetCreateProcessNotifyRoutineEx(MiniEdrProcessNotifyEx, TRUE);

    g_device = NULL;
}
