#pragma once
#include <ntddk.h>
#include <wdf.h>

NTSTATUS MiniEdrRegisterCallbacks(_In_ WDFDEVICE Device);
VOID MiniEdrUnregisterCallbacks();

// Internal helpers
VOID MiniEdrPushProcessEvent(_In_ WDFDEVICE Device, _In_ BOOLEAN Create, _In_ HANDLE ProcessId, _In_opt_ HANDLE ParentId, _In_opt_ PEPROCESS Process);
VOID MiniEdrPushImageLoadEvent(_In_ WDFDEVICE Device, _In_ HANDLE ProcessId, _In_opt_ PUNICODE_STRING FullImageName);
VOID MiniEdrPushHandleAccessEvent(_In_ WDFDEVICE Device, _In_ ULONG SourcePid, _In_ ULONG TargetPid, _In_ ACCESS_MASK DesiredAccess, _In_ ULONG Operation);
