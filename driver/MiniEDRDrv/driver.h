#pragma once
#include <ntddk.h>
#include <wdf.h>
#include "../include/miniedr_ioctl.h"

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD MiniEdrEvtDeviceAdd;
EVT_WDF_OBJECT_CONTEXT_CLEANUP MiniEdrEvtDriverContextCleanup;
