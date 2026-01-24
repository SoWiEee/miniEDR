# MiniEDRDrv (KMDF kernel driver)

This folder contains a **KMDF** kernel driver project that emits telemetry events to user-mode via **IOCTL**.

Implemented callbacks (audit-only in this milestone):
- `PsSetCreateProcessNotifyRoutineEx` (process create/exit)
- `PsSetLoadImageNotifyRoutine` (image load)
- `ObRegisterCallbacks` (audit process handle create/duplicate)

User-mode reads events by calling `DeviceIoControl(IOCTL_MINIEDR_GET_EVENTS)` on `\\.\MiniEDRDrv`.

## Build prerequisites

- Visual Studio 2022
- Windows Driver Kit (WDK) for Windows 10/11
- A test environment (VM recommended)

## Build steps

1. Open `driver/MiniEDRDrv/MiniEDRDrv.vcxproj` in Visual Studio.
2. Select `x64` and `Debug` (or `Release`).
3. Build the project. Output will include `MiniEDRDrv.sys`.

## Install (developer/test environment)

There are multiple valid ways to install a test driver (INF, DevCon, SCM).
This project ships a minimal INF (`MiniEDRDrv.inf`) suitable for test setups.

Important: modern Windows systems enforce driver signing. Use appropriate developer/test signing methods
in a VM. Do not attempt to bypass platform security on production systems.

## IOCTL interface

Shared definitions:
- `driver/include/miniedr_ioctl.h`

Key IOCTLs:
- `IOCTL_MINIEDR_GET_VERSION` → `MINIEDR_VERSION_INFO`
- `IOCTL_MINIEDR_GET_EVENTS`  → returns a packed stream of events (`MINIEDR_EVENT_*`)
- `IOCTL_MINIEDR_SET_POLICY`  → `MINIEDR_POLICY` (currently only toggles handle-audit emission)

## Notes

- Event payloads are fixed-size to keep kernel code simple and safe. User-mode is expected to enrich
  (e.g., query full command line, signer, hashes) after receiving a kernel event.
- Current Ob callback is audit-only (no blocking). Policy enforcement can be added later with
  allowlists and careful compatibility testing.
