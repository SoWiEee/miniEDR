#pragma once
#include <wdf.h>

EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL MiniEdrEvtIoDeviceControl;
NTSTATUS MiniEdrQueueInitialize(_In_ WDFDEVICE Device);
