#include "DiskHook.h"

// Static variables for disk enumeration
static const WCHAR* g_DiskDeviceNames[] = {
    L"\\Device\\Harddisk0\\DR0",
    L"\\Device\\Harddisk1\\DR1",
    L"\\Device\\Harddisk2\\DR2",
    L"\\Device\\Harddisk3\\DR3",
    L"\\Device\\Harddisk4\\DR4",
    L"\\Device\\Harddisk5\\DR5",
    L"\\Device\\Harddisk6\\DR6",
    L"\\Device\\Harddisk7\\DR7"
};

#define MAX_DISK_DEVICES (sizeof(g_DiskDeviceNames) / sizeof(g_DiskDeviceNames[0]))

// Initialize disk spoofing module
NTSTATUS DiskHook_Initialize(PDRIVER_OBJECT DriverObject)
{
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[DiskHook] Initializing disk spoofing module...\n");

    // Enumerate and attach to all available disk devices
    NTSTATUS status = DiskHook_EnumerateAndAttachToDisks(DriverObject);

    if (NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[DiskHook] Disk spoofing module initialized successfully\n");
    }
    else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[DiskHook] Failed to initialize disk spoofing module: 0x%X\n", status);
    }

    return status;
}

// Enumerate and attach to all disk devices
NTSTATUS DiskHook_EnumerateAndAttachToDisks(PDRIVER_OBJECT DriverObject)
{
    NTSTATUS overallStatus = STATUS_SUCCESS;
    ULONG successfulAttachments = 0;

    for (ULONG i = 0; i < MAX_DISK_DEVICES; i++) {
        UNICODE_STRING deviceName;
        RtlInitUnicodeString(&deviceName, g_DiskDeviceNames[i]);

        NTSTATUS status = DiskHook_AttachToDeviceStack(DriverObject, &deviceName);
        if (NT_SUCCESS(status)) {
            successfulAttachments++;
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[DiskHook] Successfully attached to %wZ\n", &deviceName);
        }
        else if (status != STATUS_NO_SUCH_DEVICE && status != STATUS_OBJECT_NAME_NOT_FOUND) {
            // Only log actual errors, not missing devices
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[DiskHook] Failed to attach to %wZ: 0x%X\n", &deviceName, status);
            overallStatus = status;
        }
    }

    if (successfulAttachments > 0) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[DiskHook] Successfully attached to %lu disk devices\n", successfulAttachments);
        return STATUS_SUCCESS;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[DiskHook] No disk devices found or all attachments failed\n");
    return overallStatus != STATUS_SUCCESS ? overallStatus : STATUS_NO_SUCH_DEVICE;
}

// Attach to specific disk device stack
NTSTATUS DiskHook_AttachToDeviceStack(PDRIVER_OBJECT DriverObject, PUNICODE_STRING DeviceName)
{
    NTSTATUS status;
    PDEVICE_OBJECT pFilterDeviceObject = NULL;
    PDEVICE_OBJECT pTargetDeviceObject = NULL;
    PFILE_OBJECT pTargetFileObject = NULL;
    PCOMMON_DEVICE_EXTENSION pDeviceExtension = NULL;

    // Get target device object
    status = IoGetDeviceObjectPointer(DeviceName, FILE_READ_ATTRIBUTES, &pTargetFileObject, &pTargetDeviceObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Create filter device object
    status = IoCreateDevice(
        DriverObject,
        sizeof(COMMON_DEVICE_EXTENSION),
        NULL,
        FILE_DEVICE_DISK,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &pFilterDeviceObject
    );

    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(pTargetFileObject);
        return status;
    }

    // Initialize device extension
    pDeviceExtension = (PCOMMON_DEVICE_EXTENSION)pFilterDeviceObject->DeviceExtension;
    RtlZeroMemory(pDeviceExtension, sizeof(COMMON_DEVICE_EXTENSION));

    // Set module type and handlers
    pDeviceExtension->ModuleType = MODULE_TYPE_DISK_HOOK;
    pDeviceExtension->pfnDeviceControl = DiskHook_DispatchDeviceControl;

    // Attach to device stack
    pDeviceExtension->pNextDeviceInStack = IoAttachDeviceToDeviceStack(pFilterDeviceObject, pTargetDeviceObject);
    if (pDeviceExtension->pNextDeviceInStack == NULL) {
        IoDeleteDevice(pFilterDeviceObject);
        ObDereferenceObject(pTargetFileObject);
        return STATUS_NO_SUCH_DEVICE;
    }

    // Copy device characteristics from target device
    pFilterDeviceObject->Flags |= pDeviceExtension->pNextDeviceInStack->Flags &
        (DO_BUFFERED_IO | DO_DIRECT_IO | DO_POWER_PAGABLE);
    pFilterDeviceObject->DeviceType = pDeviceExtension->pNextDeviceInStack->DeviceType;
    pFilterDeviceObject->Characteristics = pDeviceExtension->pNextDeviceInStack->Characteristics;

    // Clear initializing flag
    pFilterDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    ObDereferenceObject(pTargetFileObject);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[DiskHook] Successfully attached filter to %wZ\n", DeviceName);

    return STATUS_SUCCESS;
}

// Cleanup disk spoofing module
VOID DiskHook_Cleanup(PDRIVER_OBJECT DriverObject)
{
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[DiskHook] Cleaning up disk spoofing module...\n");

    PDEVICE_OBJECT pCurrentDevice = DriverObject->DeviceObject;
    ULONG cleanedDevices = 0;

    while (pCurrentDevice != NULL) {
        PDEVICE_OBJECT pNextDevice = pCurrentDevice->NextDevice;
        PCOMMON_DEVICE_EXTENSION pExtension = (PCOMMON_DEVICE_EXTENSION)pCurrentDevice->DeviceExtension;

        // Only cleanup devices that belong to disk hook module
        if (pExtension && pExtension->ModuleType == MODULE_TYPE_DISK_HOOK) {
            if (pExtension->pNextDeviceInStack) {
                IoDetachDevice(pExtension->pNextDeviceInStack);
            }
            IoDeleteDevice(pCurrentDevice);
            cleanedDevices++;
        }

        pCurrentDevice = pNextDevice;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[DiskHook] Cleaned up %lu disk filter devices\n", cleanedDevices);
}

// Enhanced IOCTL dispatcher for disk requests
NTSTATUS DiskHook_DispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION pIoStackLocation = IoGetCurrentIrpStackLocation(Irp);
    ULONG ioControlCode = pIoStackLocation->Parameters.DeviceIoControl.IoControlCode;

    // Intercept storage property queries
    if (ioControlCode == IOCTL_STORAGE_QUERY_PROPERTY) {
        PSTORAGE_PROPERTY_QUERY pQuery = (PSTORAGE_PROPERTY_QUERY)Irp->AssociatedIrp.SystemBuffer;

        if (pQuery && pQuery->PropertyId == StorageDeviceProperty) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[DiskHook] Intercepting IOCTL_STORAGE_QUERY_PROPERTY for device properties\n");

            // Set completion routine to modify the response
            IoCopyCurrentIrpStackLocationToNext(Irp);
            IoSetCompletionRoutine(Irp, DiskHook_CompletionRoutine, NULL, TRUE, TRUE, TRUE);

            PCOMMON_DEVICE_EXTENSION pDeviceExtension = (PCOMMON_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
            return IoCallDriver(pDeviceExtension->pNextDeviceInStack, Irp);
        }
    }

    // Pass through all other requests
    return DiskHook_DispatchPassThrough(DeviceObject, Irp);
}

// Enhanced completion routine for disk serial number spoofing
NTSTATUS DiskHook_CompletionRoutine(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Context);

    // Check if the request was successful and returned valid data
    if (NT_SUCCESS(Irp->IoStatus.Status) &&
        Irp->IoStatus.Information >= sizeof(STORAGE_DEVICE_DESCRIPTOR)) {

        PSTORAGE_DEVICE_DESCRIPTOR pDescriptor = (PSTORAGE_DEVICE_DESCRIPTOR)Irp->AssociatedIrp.SystemBuffer;

        // Strategy 1: If no serial number exists, inject one in slack space
        if (pDescriptor->SerialNumberOffset == 0) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[DiskHook] No serial number detected, attempting slack space injection\n");

            // Find the end of the last existing string field
            ULONG lastStringEndOffset = sizeof(STORAGE_DEVICE_DESCRIPTOR);

            // Check all string field offsets to find the last one
            ULONG stringOffsets[] = {
                pDescriptor->VendorIdOffset,
                pDescriptor->ProductIdOffset,
                pDescriptor->ProductRevisionOffset
            };

            for (ULONG i = 0; i < ARRAYSIZE(stringOffsets); i++) {
                if (stringOffsets[i] > 0) {
                    size_t stringLen = strlen((char*)pDescriptor + stringOffsets[i]) + 1;
                    ULONG currentEnd = stringOffsets[i] + (ULONG)stringLen;
                    if (currentEnd > lastStringEndOffset) {
                        lastStringEndOffset = currentEnd;
                    }
                }
            }

            // Align injection point to ULONG boundary
            ULONG injectionPoint = (lastStringEndOffset + sizeof(ULONG) - 1) & ~(sizeof(ULONG) - 1);
            size_t requiredLength = strlen(FAKE_DISK_SERIAL_NUMBER) + 1;

            // Check if we have enough slack space
            if (injectionPoint + requiredLength <= Irp->IoStatus.Information) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                    "[DiskHook] Injecting fake serial number at offset %lu\n", injectionPoint);

                // Inject the fake serial number
                char* pNewSerialLocation = (char*)pDescriptor + injectionPoint;
                RtlCopyMemory(pNewSerialLocation, FAKE_DISK_SERIAL_NUMBER, requiredLength);
                pDescriptor->SerialNumberOffset = injectionPoint;
            }
            else {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                    "[DiskHook] Insufficient slack space for serial injection\n");
            }
        }
        // Strategy 2: If serial number exists, overwrite it
        else if (pDescriptor->SerialNumberOffset > 0) {
            char* existingSerial = (char*)pDescriptor + pDescriptor->SerialNumberOffset;
            size_t existingLength = strlen(existingSerial);
            size_t newLength = strlen(FAKE_DISK_SERIAL_NUMBER);

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[DiskHook] Existing serial found: '%s', replacing with fake serial\n", existingSerial);

            // If new serial fits in existing space, overwrite directly
            if (newLength <= existingLength) {
                RtlZeroMemory(existingSerial, existingLength);
                RtlCopyMemory(existingSerial, FAKE_DISK_SERIAL_NUMBER, newLength + 1);
            }
            else {
                // Generate random serial of same length as original
                char* randomSerial = (char*)ExAllocatePoolWithTag(NonPagedPool, existingLength + 1, 'RSER');
                if (randomSerial) {
                    RandomText(randomSerial, (int)existingLength);
                    randomSerial[existingLength] = '\0';
                    RtlCopyMemory(existingSerial, randomSerial, existingLength + 1);
                    ExFreePoolWithTag(randomSerial, 'RSER');
                }
            }
        }

        // Additional spoofing: modify vendor and product information
        if (pDescriptor->VendorIdOffset > 0) {
            char* vendorId = (char*)pDescriptor + pDescriptor->VendorIdOffset;
            size_t vendorLength = strlen(vendorId);
            if (vendorLength > 0) {
                // Replace with generic vendor
                const char* fakeVendor = "GENERICDISK";
                size_t fakeLength = strlen(fakeVendor);
                if (fakeLength <= vendorLength) {
                    RtlZeroMemory(vendorId, vendorLength);
                    RtlCopyMemory(vendorId, fakeVendor, fakeLength + 1);
                }
            }
        }
    }

    // Mark IRP as pending if it was pending
    if (Irp->PendingReturned) {
        IoMarkIrpPending(Irp);
    }

    return Irp->IoStatus.Status;
}

// Pass-through function for unhandled requests
NTSTATUS DiskHook_DispatchPassThrough(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PCOMMON_DEVICE_EXTENSION pDeviceExtension = (PCOMMON_DEVICE_EXTENSION)DeviceObject->DeviceExtension;

    if (pDeviceExtension && pDeviceExtension->pNextDeviceInStack) {
        IoSkipCurrentIrpStackLocation(Irp);
        return IoCallDriver(pDeviceExtension->pNextDeviceInStack, Irp);
    }

    // If no next device, complete with error
    Irp->IoStatus.Status = STATUS_NO_SUCH_DEVICE;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_NO_SUCH_DEVICE;
}