#pragma once

#include "common.h"

PVOID GetModuleBase(const char* moduleName);
PVOID FindPatternImage(PVOID base, const char* pattern, const char* mask);
char* GetSmbiosString(SMBIOS_HEADER* header, SMBIOS_STRING string);

PDEVICE_OBJECT GetRaidDevice(const wchar_t* deviceName);