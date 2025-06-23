#pragma once

#include "common.h"

// SMBIOS Hook function prototypes
NTSTATUS SmbiosHook_Initialize(VOID);
VOID SmbiosHook_Cleanup(VOID);
NTSTATUS SmbiosHook_ModifySystemInformation(VOID);

// Internal function prototypes
NTSTATUS SmbiosHook_ProcessTable(SMBIOS_HEADER* header);
NTSTATUS SmbiosHook_LoopTables(PVOID mapped, ULONG size);
NTSTATUS SmbiosHook_FindSmbiosTable(PPHYSICAL_ADDRESS* physicalAddress, PULONG size);