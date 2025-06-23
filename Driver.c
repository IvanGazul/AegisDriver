#include "common.h"
#include "SmbiosHook.h"
#include "DiskHook.h"

// Forward declarations
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
VOID DriverUnload(PDRIVER_OBJECT DriverObject);
NTSTATUS MasterDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp);

// Main driver entry point
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[HWID Spoofer] Driver loading for cybersecurity research...\n");

    // Set unload routine
    DriverObject->DriverUnload = DriverUnload;

    // Set master dispatch routines for all IRP types
    for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
        DriverObject->MajorFunction[i] = MasterDispatch;
    }

    NTSTATUS status = STATUS_SUCCESS;

    // Initialize SMBIOS spoofing
    status = SmbiosHook_Initialize();
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[HWID Spoofer] Failed to initialize SMBIOS hook: 0x%X\n", status);
        return status;
    }

    // Initialize Disk spoofing (filter driver approach)
    status = DiskHook_Initialize(DriverObject);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[HWID Spoofer] Failed to initialize disk hook: 0x%X\n", status);
        SmbiosHook_Cleanup();
        return status;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[HWID Spoofer] All modules initialized successfully!\n");

    return STATUS_SUCCESS;
}

// Master dispatch routine that routes IRPs to appropriate handlers
NTSTATUS MasterDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION pIoStackLocation = IoGetCurrentIrpStackLocation(Irp);
    PCOMMON_DEVICE_EXTENSION pDeviceExtension = (PCOMMON_DEVICE_EXTENSION)DeviceObject->DeviceExtension;

    // Route to specific module handlers based on IRP type
    switch (pIoStackLocation->MajorFunction) {
    case IRP_MJ_DEVICE_CONTROL:
        if (pDeviceExtension && pDeviceExtension->pfnDeviceControl) {
            return pDeviceExtension->pfnDeviceControl(DeviceObject, Irp);
        }
        break;

    case IRP_MJ_PNP:
        if (pDeviceExtension && pDeviceExtension->pfnPnp) {
            return pDeviceExtension->pfnPnp(DeviceObject, Irp);
        }
        break;

    case IRP_MJ_READ:
        if (pDeviceExtension && pDeviceExtension->pfnRead) {
            return pDeviceExtension->pfnRead(DeviceObject, Irp);
        }
        break;
    }

    // Default pass-through for unhandled IRPs
    if (pDeviceExtension && pDeviceExtension->pNextDeviceInStack) {
        IoSkipCurrentIrpStackLocation(Irp);
        return IoCallDriver(pDeviceExtension->pNextDeviceInStack, Irp);
    }

    // Complete IRP if no filter device
    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_NOT_SUPPORTED;
}

// Driver unload routine
VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[HWID Spoofer] Unloading driver...\n");

    // Cleanup all modules
    DiskHook_Cleanup(DriverObject);
    SmbiosHook_Cleanup();

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[HWID Spoofer] Driver unloaded successfully\n");
}