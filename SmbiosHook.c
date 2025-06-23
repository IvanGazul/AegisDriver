#include "SmbiosHook.h"

// Static variables for SMBIOS hook state
static PVOID g_SmbiosMappedMemory = NULL;
static ULONG g_SmbiosTableSize = 0;

// Initialize SMBIOS spoofing module
NTSTATUS SmbiosHook_Initialize(VOID)
{
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[SmbiosHook] Initializing SMBIOS spoofing module...\n");

    NTSTATUS status = SmbiosHook_ModifySystemInformation();
    if (NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[SmbiosHook] SMBIOS spoofing initialized successfully\n");
    }
    else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[SmbiosHook] Failed to initialize SMBIOS spoofing: 0x%X\n", status);
    }

    return status;
}

// Cleanup SMBIOS spoofing module
VOID SmbiosHook_Cleanup(VOID)
{
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[SmbiosHook] Cleaning up SMBIOS module...\n");

    if (g_SmbiosMappedMemory) {
        MmUnmapIoSpace(g_SmbiosMappedMemory, g_SmbiosTableSize);
        g_SmbiosMappedMemory = NULL;
        g_SmbiosTableSize = 0;
    }
}

// Find SMBIOS table location and size
NTSTATUS SmbiosHook_FindSmbiosTable(PPHYSICAL_ADDRESS* physicalAddress, PULONG size)
{
    // Get ntoskrnl.exe base address
    PVOID base = GetModuleBase("ntoskrnl.exe");
    if (!base) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[SmbiosHook] Failed to get ntoskrnl.exe base\n");
        return STATUS_UNSUCCESSFUL;
    }

    // Find SMBIOS physical address pointer
    PPHYSICAL_ADDRESS foundPhysicalAddress = (PPHYSICAL_ADDRESS)FindPatternImage(
        base,
        "\x48\x8B\x0D\x00\x00\x00\x00\x48\x85\xC9\x74\x00\x8B\x15",
        "xxx????xxxx?xx"
    );

    if (!foundPhysicalAddress) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[SmbiosHook] Failed to find SMBIOS physical address pattern\n");
        return STATUS_UNSUCCESSFUL;
    }

    // Calculate actual address
    foundPhysicalAddress = (PPHYSICAL_ADDRESS)((char*)foundPhysicalAddress + 7 +
        *(int*)((char*)foundPhysicalAddress + 3));

    if (!foundPhysicalAddress || foundPhysicalAddress->QuadPart == 0) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[SmbiosHook] Invalid SMBIOS physical address\n");
        return STATUS_UNSUCCESSFUL;
    }

    // Find SMBIOS table size
    PVOID sizeScan = FindPatternImage(
        base,
        "\x8B\x1D\x00\x00\x00\x00\x48\x8B\xD0\x44\x8B\xC3\x48\x8B\xCD\xE8\x00\x00\x00\x00\x8B\xD3\x48\x8B",
        "xx????xxxxxxxxxx????xxxx"
    );

    if (!sizeScan) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[SmbiosHook] Failed to find SMBIOS size pattern\n");
        return STATUS_UNSUCCESSFUL;
    }

    ULONG foundSize = *(ULONG*)((char*)sizeScan + 6 + *(int*)((char*)sizeScan + 2));
    if (!foundSize) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[SmbiosHook] Invalid SMBIOS table size\n");
        return STATUS_UNSUCCESSFUL;
    }

    *physicalAddress = foundPhysicalAddress;
    *size = foundSize;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[SmbiosHook] Found SMBIOS table at PA: 0x%llX, Size: 0x%X\n",
        foundPhysicalAddress->QuadPart, foundSize);

    return STATUS_SUCCESS;
}

// Process individual SMBIOS table
NTSTATUS SmbiosHook_ProcessTable(SMBIOS_HEADER* header)
{
    if (!header || header->Length == 0) {
        return STATUS_UNSUCCESSFUL;
    }

    switch (header->Type) {
    case 1: // System Information
    {
        PSMBIOS_TYPE1 type1 = (PSMBIOS_TYPE1)header;

        // Randomize system serial number
        char* serialNumber = GetSmbiosString(header, type1->SerialNumber);
        if (serialNumber) {
            RandomizeString(serialNumber);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[SmbiosHook] Randomized system serial number\n");
        }

        // Randomize UUID
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[SmbiosHook] Original UUID: %08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX\n",
            type1->Uuid.Data1, type1->Uuid.Data2, type1->Uuid.Data3,
            type1->Uuid.Data4[0], type1->Uuid.Data4[1], type1->Uuid.Data4[2], type1->Uuid.Data4[3],
            type1->Uuid.Data4[4], type1->Uuid.Data4[5], type1->Uuid.Data4[6], type1->Uuid.Data4[7]);

        RandomizeGuid(&type1->Uuid);

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[SmbiosHook] New UUID: %08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX\n",
            type1->Uuid.Data1, type1->Uuid.Data2, type1->Uuid.Data3,
            type1->Uuid.Data4[0], type1->Uuid.Data4[1], type1->Uuid.Data4[2], type1->Uuid.Data4[3],
            type1->Uuid.Data4[4], type1->Uuid.Data4[5], type1->Uuid.Data4[6], type1->Uuid.Data4[7]);
        break;
    }

    case 2: // Motherboard/Baseboard Information
    {
        PSMBIOS_TYPE2 type2 = (PSMBIOS_TYPE2)header;

        char* manufacturer = GetSmbiosString(header, type2->Manufacturer);
        if (manufacturer) {
            RandomizeString(manufacturer);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[SmbiosHook] Randomized motherboard manufacturer\n");
        }

        char* productName = GetSmbiosString(header, type2->ProductName);
        if (productName) {
            RandomizeString(productName);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[SmbiosHook] Randomized motherboard product name\n");
        }

        char* serialNumber = GetSmbiosString(header, type2->SerialNumber);
        if (serialNumber) {
            RandomizeString(serialNumber);
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[SmbiosHook] Randomized motherboard serial number\n");
        }
        break;
    }

    case 4: // Processor Information
    {
        PSMBIOS_TYPE4 type4 = (PSMBIOS_TYPE4)header;
        ULONG seed = KeQueryTimeIncrement();

        UINT64 originalId = type4->ProcessorId;
        type4->ProcessorId = ((UINT64)RtlRandomEx(&seed) << 32) | RtlRandomEx(&seed);

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[SmbiosHook] Processor ID changed: %llX -> %llX\n",
            originalId, type4->ProcessorId);
        break;
    }
    }

    return STATUS_SUCCESS;
}

// Loop through all SMBIOS tables
NTSTATUS SmbiosHook_LoopTables(PVOID mapped, ULONG size)
{
    char* endAddress = (char*)mapped + size;
    PVOID current = mapped;

    while (TRUE) {
        PSMBIOS_HEADER header = (PSMBIOS_HEADER)current;

        // Check for end-of-table marker (Type 127)
        if (header->Type == 127 && header->Length == 4) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[SmbiosHook] Reached end of SMBIOS tables\n");
            break;
        }

        // Process current table
        SmbiosHook_ProcessTable(header);

        // Move to next table
        char* end = (char*)current + header->Length;
        while (end < endAddress - 1 && (0 != (*end | *(end + 1)))) {
            end++;
        }
        end += 2;

        if (end >= endAddress) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[SmbiosHook] Reached end of SMBIOS memory region\n");
            break;
        }

        current = end;
    }

    return STATUS_SUCCESS;
}

// Main function to modify SMBIOS information
NTSTATUS SmbiosHook_ModifySystemInformation(VOID)
{
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[SmbiosHook] Starting SMBIOS modification\n");

    PPHYSICAL_ADDRESS physicalAddress = NULL;
    ULONG size = 0;

    // Find SMBIOS table
    NTSTATUS status = SmbiosHook_FindSmbiosTable(&physicalAddress, &size);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Map SMBIOS physical memory
    PVOID mapped = MmMapIoSpace(*physicalAddress, size, MmNonCached);
    if (!mapped) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[SmbiosHook] Failed to map SMBIOS memory\n");
        return STATUS_UNSUCCESSFUL;
    }

    // Store mapped memory info for cleanup
    g_SmbiosMappedMemory = mapped;
    g_SmbiosTableSize = size;

    // Process all SMBIOS tables
    status = SmbiosHook_LoopTables(mapped, size);

    if (NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[SmbiosHook] SMBIOS modification completed successfully\n");
    }
    else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[SmbiosHook] SMBIOS modification failed: 0x%X\n", status);
    }

    return status;
}