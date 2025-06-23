#pragma once



#include "common.h"



// Disk Hook function prototypes
NTSTATUS DiskHook_Initialize(PDRIVER_OBJECT DriverObject);
VOID DiskHook_Cleanup(PDRIVER_OBJECT DriverObject);


// Internal function prototypes
NTSTATUS DiskHook_AttachToDeviceStack(PDRIVER_OBJECT DriverObject, PUNICODE_STRING DeviceName);
NTSTATUS DiskHook_DispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS DiskHook_DispatchPassThrough(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS DiskHook_CompletionRoutine(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context);
NTSTATUS DiskHook_EnumerateAndAttachToDisks(PDRIVER_OBJECT DriverObject);