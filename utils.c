#include "common.h"

// Get module base address by name
PVOID GetModuleBase(const char* moduleName)
{
    PVOID address = NULL;
    ULONG size = 0;

    // First call to get required buffer size
    NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, &size, 0, &size);
    if (status != STATUS_INFO_LENGTH_MISMATCH) {
        return NULL;
    }

    // Allocate buffer for module information
    PSYSTEM_MODULE_INFORMATION moduleList = (PSYSTEM_MODULE_INFORMATION)ExAllocatePoolWithTag(
        NonPagedPool, size, 'MODU');
    if (!moduleList) {
        return NULL;
    }

    // Get actual module information
    status = ZwQuerySystemInformation(SystemModuleInformation, moduleList, size, NULL);
    if (!NT_SUCCESS(status)) {
        goto cleanup;
    }

    // Search for the specified module
    for (ULONG i = 0; i < moduleList->ulModuleCount; i++) {
        SYSTEM_MODULE module = moduleList->Modules[i];
        if (strstr(module.ImageName, moduleName)) {
            address = module.Base;
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[Utils] Found module %s at 0x%p\n", moduleName, address);
            break;
        }
    }

cleanup:
    ExFreePoolWithTag(moduleList, 'MODU');
    return address;
}

// Check if pattern matches at given location
BOOLEAN CheckMask(const char* base, const char* pattern, const char* mask)
{
    for (; *mask; ++base, ++pattern, ++mask) {
        if ('x' == *mask && *base != *pattern) {
            return FALSE;
        }
    }
    return TRUE;
}

// Find pattern in memory region
PVOID FindPattern(PVOID base, int length, const char* pattern, const char* mask)
{
    int maskLength = (int)strlen(mask);
    length -= maskLength;

    for (int i = 0; i <= length; ++i) {
        char* data = (char*)base;
        char* address = &data[i];
        if (CheckMask(address, pattern, mask)) {
            return (PVOID)address;
        }
    }
    return NULL;
}

// Find pattern in PE image sections
PVOID FindPatternImage(PVOID base, const char* pattern, const char* mask)
{
    PVOID match = NULL;

    __try {
        // Get NT headers
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)base;
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            return NULL;
        }

        PIMAGE_NT_HEADERS headers = (PIMAGE_NT_HEADERS)((char*)base + dosHeader->e_lfanew);
        if (headers->Signature != IMAGE_NT_SIGNATURE) {
            return NULL;
        }

        PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(headers);

        // Search in executable sections
        for (int i = 0; i < headers->FileHeader.NumberOfSections; ++i) {
            PIMAGE_SECTION_HEADER section = &sections[i];

            // Check if section is executable or contains code/data
            if ((section->Characteristics & IMAGE_SCN_MEM_EXECUTE) ||
                (memcmp(section->Name, ".text", 5) == 0) ||
                (memcmp(section->Name, "PAGE", 4) == 0) ||
                (memcmp(section->Name, ".data", 5) == 0)) {

                match = FindPattern(
                    (char*)base + section->VirtualAddress,
                    section->Misc.VirtualSize,
                    pattern,
                    mask
                );

                if (match) {
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                        "[Utils] Pattern found in section %.8s at offset 0x%X\n",
                        section->Name, (ULONG)((char*)match - (char*)base));
                    break;
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[Utils] Exception occurred while searching pattern\n");
        match = NULL;
    }

    return match;
}

// Generate random text of specified length
VOID RandomText(char* text, const int length)
{
    if (!text || length <= 0) {
        return;
    }

    static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";

    ULONG seed = KeQueryTimeIncrement();

    for (int n = 0; n < length; n++) {
        ULONG key = RtlRandomEx(&seed) % (sizeof(alphanum) - 1);
        text[n] = alphanum[key];
    }
    text[length] = '\0';
}

// Randomize existing string preserving its length
VOID RandomizeString(char* string)
{
    if (!string) {
        return;
    }

    int length = (int)strlen(string);
    if (length == 0) {
        return;
    }

    // Create temporary buffer for random string
    char* buffer = (char*)ExAllocatePoolWithTag(NonPagedPool, length + 1, 'RAND');
    if (!buffer) {
        return;
    }

    // Generate random string of same length
    RandomText(buffer, length);

    // Copy back to original string
    RtlCopyMemory(string, buffer, length);
    string[length] = '\0';

    ExFreePoolWithTag(buffer, 'RAND');

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[Utils] Randomized string of length %d\n", length);
}

// Randomize GUID structure
VOID RandomizeGuid(GUID* guid)
{
    if (!guid) {
        return;
    }

    ULONG seed = KeQueryTimeIncrement();

    // Randomize all 16 bytes of the GUID
    for (int i = 0; i < sizeof(GUID); ++i) {
        ((unsigned char*)guid)[i] = (unsigned char)(RtlRandomEx(&seed) % 256);
    }

    // Ensure proper GUID version and variant bits
    // Set version to 4 (random)
    guid->Data3 = (guid->Data3 & 0x0FFF) | 0x4000;

    // Set variant bits
    guid->Data4[0] = (guid->Data4[0] & 0x3F) | 0x80;
}

// Get SMBIOS string by index
char* GetSmbiosString(SMBIOS_HEADER* header, SMBIOS_STRING string)
{
    if (!header || !string) {
        return NULL;
    }

    const char* start = (const char*)header + header->Length;

    // Check if string table exists
    if (*start == 0) {
        return NULL;
    }

    // Navigate to the requested string (1-based index)
    while (--string) {
        start += strlen(start) + 1;

        // Check for end of string table
        if (*start == 0) {
            return NULL;
        }
    }

    return (char*)start;
}