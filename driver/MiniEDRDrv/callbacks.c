#include "callbacks.h"
#include "device.h"
#include "../include/miniedr_ioctl.h"

#define PROCESS_TERMINATE (0x0001)
#define PROCESS_CREATE_THREAD (0x0002)
#define PROCESS_SET_SESSIONID (0x0004)
#define PROCESS_VM_OPERATION (0x0008)
#define PROCESS_VM_READ (0x0010)
#define PROCESS_VM_WRITE (0x0020)
#define PROCESS_DUP_HANDLE (0x0040)
#define PROCESS_CREATE_PROCESS (0x0080)
#define PROCESS_SET_QUOTA (0x0100)
#define PROCESS_SET_INFORMATION (0x0200)
#define PROCESS_QUERY_INFORMATION (0x0400)
#define PROCESS_SUSPEND_RESUME (0x0800)
#define PROCESS_QUERY_LIMITED_INFORMATION (0x1000)
#define PROCESS_SET_LIMITED_INFORMATION (0x2000)

UCHAR* PsGetProcessImageFileName(__in PEPROCESS eprocess);
extern VOID MiniEdrRingPush(_In_ WDFDEVICE Device, _In_reads_bytes_(Size) const void* Data, _In_ ULONG Size);

static WDFDEVICE g_device = NULL;
static PVOID g_obHandle = NULL;

static BOOLEAN IsPidInList(_In_reads_opt_(count) const UINT32* list, _In_ UINT32 count, _In_ UINT32 pid)
{
    if (!list || count == 0) return FALSE;
    for (UINT32 i = 0; i < count; ++i) {
        if (list[i] == pid) return TRUE;
    }
    return FALSE;
}

static BOOLEAN IsDangerousProcessAccess(_In_ ACCESS_MASK a)
{
    const ACCESS_MASK dangerous =
        PROCESS_CREATE_THREAD |
        PROCESS_VM_OPERATION |
        PROCESS_VM_READ |
        PROCESS_VM_WRITE |
        PROCESS_DUP_HANDLE |
        PROCESS_TERMINATE |
        PROCESS_SUSPEND_RESUME |
        PROCESS_SET_INFORMATION |
        PROCESS_SET_QUOTA;
    return (a & dangerous) != 0;
}

static OB_PREOP_CALLBACK_STATUS
MiniEdrPreOp(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    if (g_device == NULL) {
        return OB_PREOP_SUCCESS;
    }

    // Optional hardening: ignore kernel handles
    // KernelHandle bit is part of OB_PRE_OPERATION_INFORMATION
    if (OperationInformation->KernelHandle) {
        return OB_PREOP_SUCCESS;
    }

    PDEVICE_CONTEXT ctx = DeviceGetContext(g_device);
    if (!ctx->HandleAuditEnabled) {
        return OB_PREOP_SUCCESS;
    }

    // Only process handle operations
    if (OperationInformation->ObjectType != *PsProcessType) {
        return OB_PREOP_SUCCESS;
    }

    // Target PID
    ULONG tgtPid = 0;
    PEPROCESS target = (PEPROCESS)OperationInformation->Object;
    if (target != NULL) {
        tgtPid = (ULONG)(ULONG_PTR)PsGetProcessId(target);
    }

    // Source PID (note: callback may run in arbitrary thread context per docs;
    // this is still the common pattern used for audit/enforcement heuristics)
    ULONG srcPid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();

    // Get a pointer to DesiredAccess + record operation type
    ACCESS_MASK* pDesired = NULL;
    ACCESS_MASK original = 0;
    ULONG op = 0;

    if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
        pDesired = &OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
        original = OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess;
        op = 1;
    }
    else if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        pDesired = &OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;
        original = OperationInformation->Parameters->DuplicateHandleInformation.OriginalDesiredAccess;
        op = 2;
    }
    else {
        return OB_PREOP_SUCCESS;
    }

    // Optional enforcement: protect selected PIDs from dangerous access
    BOOLEAN enforce = FALSE;
    BOOLEAN targetProtected = FALSE;
    BOOLEAN srcAllowed = FALSE;

    WdfSpinLockAcquire(ctx->PolicyLock);
    enforce = ctx->EnforceProtect;
    if (enforce) {
        targetProtected = IsPidInList(ctx->ProtectedPids, ctx->ProtectedCount, tgtPid);
        srcAllowed = IsPidInList(ctx->AllowedPids, ctx->AllowedCount, srcPid);
    }
    WdfSpinLockRelease(ctx->PolicyLock);

    // If enforced, strip dangerous rights
    if (enforce && targetProtected && !srcAllowed && srcPid != tgtPid && srcPid != 4 /* System */)
    {
        if (IsDangerousProcessAccess(*pDesired)) {
            const ACCESS_MASK dangerous =
                PROCESS_CREATE_THREAD |
                PROCESS_VM_OPERATION |
                PROCESS_VM_READ |
                PROCESS_VM_WRITE |
                PROCESS_DUP_HANDLE |
                PROCESS_TERMINATE |
                PROCESS_SUSPEND_RESUME |
                PROCESS_SET_INFORMATION |
                PROCESS_SET_QUOTA;

            // Option A: remove only dangerous bits (recommended for ¡§least surprise¡¨)
            *pDesired &= ~dangerous;

            // Option B (stricter): force to zero access
            // *pDesired = 0;
        }
    }

    // Audit event
    MINIEDR_EVT_HANDLEACCESS e = { 0 };
    e.H.Type = MiniEdrEvent_HandleAccess;
    e.H.Size = sizeof(e);
    e.H.TimestampQpc = (UINT64)KeQueryPerformanceCounter(NULL).QuadPart;
    e.SourcePid = srcPid;
    e.TargetPid = tgtPid;
    e.DesiredAccess = (UINT32)(pDesired ? *pDesired : 0);
    e.Operation = op;

    MiniEdrRingPush(g_device, &e, sizeof(e));
    return OB_PREOP_SUCCESS;
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
    e.H.TimestampQpc = (UINT64)KeQueryPerformanceCounter(NULL).QuadPart;
    e.Pid = (UINT32)(ULONG_PTR)ProcessId;
    e.ParentPid = (UINT32)(ULONG_PTR)ParentId;

    if (Process) {
        const UCHAR* img = PsGetProcessImageFileName(Process);
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
    e.H.TimestampQpc = (UINT64)KeQueryPerformanceCounter(NULL).QuadPart;
    e.Pid = (UINT32)(ULONG_PTR)ProcessId;

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
    e.H.TimestampQpc = (UINT64)KeQueryPerformanceCounter(NULL).QuadPart;
    e.SourcePid = SourcePid;
    e.TargetPid = TargetPid;
    e.DesiredAccess = (UINT32)DesiredAccess;
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
