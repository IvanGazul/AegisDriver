#pragma once



#pragma warning(disable: 4117)



#define _KERNEL_MODE



#include <ntifs.h>

#include <ntddk.h>

#include <ntdddisk.h>

#include <wdm.h>

#include <ntimage.h>

#include <ntstrsafe.h>

#include <intrin.h>

#include <stdlib.h>

// Forward declarations for external functions

NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(

    IN ULONG SystemInformationClass,

    OUT PVOID SystemInformation,

    IN ULONG SystemInformationLength,

    OUT PULONG ReturnLength OPTIONAL

);



NTSYSAPI NTSTATUS NTAPI ObReferenceObjectByName(

    IN PUNICODE_STRING ObjectName,

    IN ULONG Attributes,

    IN PACCESS_STATE PassedAccessState OPTIONAL,

    IN ACCESS_MASK DesiredAccess OPTIONAL,

    IN POBJECT_TYPE ObjectType,

    IN KPROCESSOR_MODE AccessMode,

    IN OUT PVOID ParseContext OPTIONAL,

    OUT PVOID* Object

);



NTSYSAPI ULONG NTAPI RtlRandomEx(PULONG Seed);



// External object type

extern POBJECT_TYPE* IoDriverObjectType;



// Function prototypes for dispatch routines

typedef NTSTATUS(*PDRIVER_DISPATCH_ROUTINE)(PDEVICE_OBJECT, PIRP);



// Common device extension structure for all filter devices

typedef struct _COMMON_DEVICE_EXTENSION {

    // Pointer to the next driver in the stack

    PDEVICE_OBJECT pNextDeviceInStack;



    // Function pointers to module-specific IRP handlers

    PDRIVER_DISPATCH_ROUTINE pfnDeviceControl;

    PDRIVER_DISPATCH_ROUTINE pfnPnp;

    PDRIVER_DISPATCH_ROUTINE pfnRead;

    PDRIVER_DISPATCH_ROUTINE pfnWrite;



    // Module identification

    ULONG ModuleType;



} COMMON_DEVICE_EXTENSION, * PCOMMON_DEVICE_EXTENSION;



// Module types

#define MODULE_TYPE_DISK_HOOK    0x00000001

#define MODULE_TYPE_SMBIOS_HOOK  0x00000002



// Fake hardware identifiers

#define FAKE_DISK_SERIAL_NUMBER "CYBERDEF-SPOOF-SN-98765"

#define FAKE_SYSTEM_SERIAL      "RESEARCH-SYS-12345"

#define FAKE_MOTHERBOARD_SERIAL "CYBER-MB-67890"



// System Information Class for ZwQuerySystemInformation

typedef enum _SYSTEM_INFORMATION_CLASS {

    SystemModuleInformation = 0xb

} SYSTEM_INFORMATION_CLASS;



typedef struct _SYSTEM_MODULE {

    ULONG_PTR Reserved[2];

    PVOID Base;

    ULONG Size;

    ULONG Flags;

    USHORT Index;

    USHORT Unknown;

    USHORT LoadCount;

    USHORT ModuleNameOffset;

    CHAR ImageName[256];

} SYSTEM_MODULE, * PSYSTEM_MODULE;



typedef struct _SYSTEM_MODULE_INFORMATION {

    ULONG_PTR ulModuleCount;

    SYSTEM_MODULE Modules[1];

} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;



// SMBIOS structure definitions

typedef struct _SMBIOS_HEADER {

    UINT8   Type;

    UINT8   Length;

    UINT8   Handle[2];

} SMBIOS_HEADER, * PSMBIOS_HEADER;



typedef UINT8 SMBIOS_STRING;



// SMBIOS Type 1 - System Information

typedef struct _SMBIOS_TYPE1 {

    SMBIOS_HEADER   Hdr;

    SMBIOS_STRING   Manufacturer;

    SMBIOS_STRING   ProductName;

    SMBIOS_STRING   Version;

    SMBIOS_STRING   SerialNumber;

    GUID            Uuid;

    UINT8           WakeUpType;

} SMBIOS_TYPE1, * PSMBIOS_TYPE1;



// SMBIOS Type 2 - Baseboard/Motherboard Information

typedef struct _SMBIOS_TYPE2 {

    SMBIOS_HEADER   Hdr;

    SMBIOS_STRING   Manufacturer;

    SMBIOS_STRING   ProductName;

    SMBIOS_STRING   Version;

    SMBIOS_STRING   SerialNumber;

} SMBIOS_TYPE2, * PSMBIOS_TYPE2;



// SMBIOS Type 4 - Processor Information

typedef struct _SMBIOS_TYPE4 {

    SMBIOS_HEADER   Hdr;

    SMBIOS_STRING   Socket;

    UINT8           ProcessorType;

    UINT8           ProcessorFamily;

    SMBIOS_STRING   ProcessorManufacture;

    UINT64          ProcessorId;

    SMBIOS_STRING   ProcessorVersion;

    UINT8           Voltage;

    UINT16          ExternalClock;

    UINT16          MaxSpeed;

    UINT16          CurrentSpeed;

    UINT8           Status;

    UINT8           ProcessorUpgrade;

    UINT16          L1CacheHandle;

    UINT16          L2CacheHandle;

    UINT16          L3CacheHandle;

    UINT8           SerialNumber;

    UINT8           AssetTag;

    UINT8           PartNumber;

} SMBIOS_TYPE4, * PSMBIOS_TYPE4;



// Utility function prototypes

PVOID GetModuleBase(const char* moduleName);

PVOID FindPatternImage(PVOID base, const char* pattern, const char* mask);

VOID RandomText(char* text, const int length);

VOID RandomizeString(char* string);

VOID RandomizeGuid(GUID* guid);

char* GetSmbiosString(SMBIOS_HEADER* header, SMBIOS_STRING string);