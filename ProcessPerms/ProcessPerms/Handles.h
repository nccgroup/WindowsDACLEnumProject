/*
A Microsoft Windows process and thread batch permissions dumper with suspicious DACL alerting

Released as open source by NCC Group Plc - http://www.nccgroup.com/

Developed by Ollie Whitehouse, ollie dot whitehouse at nccgroup dot com

https://github.com/nccgroup/WindowsDACLEnumProject

Released under AGPL see LICENSE for more information
*/


// http://blog.airesoft.co.uk/code/handlefinder.cpp
// http://forum.sysinternals.com/howto-enumerate-handles_topic18892.html


typedef NTSTATUS (NTAPI *_NtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

typedef NTSTATUS (NTAPI * OpenDirectory)(
	PHANDLE, 
	ACCESS_MASK, 
	PVOID
);

typedef NTSTATUS (WINAPI * QueryDirectory)(
	HANDLE, 
	PVOID, 
	ULONG, 
	BOOL, 
	BOOL, 
	PULONG, 
	PULONG
);


/* The following structure is actually called SYSTEM_HANDLE_TABLE_ENTRY_INFO, but SYSTEM_HANDLE is shorter. */
typedef struct _SYSTEM_HANDLE
{
    ULONG ProcessId;
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
    ULONG HandleCount; /* Or NumberOfHandles if you prefer. */
    SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;


typedef struct _UNICODE_STRING {
  USHORT  Length;
  USHORT  MaximumLength;
  PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES
{
	DWORD Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	DWORD *a;
	DWORD *b;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _OBJECT_DIRECTORY_INFORMATION {
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, *POBJECT_DIRECTORY_INFORMATION;

#define SystemHandleInformation			16
#define STATUS_INFO_LENGTH_MISMATCH		((NTSTATUS)0xC0000004L)
#define OBJ_CASE_INSENSITIVE			((NTSTATUS)0x00000040L)
#define STATUS_SUCCESS					((NTSTATUS)0x00000000L)
#define DIRECTORY_QUERY					0x0001
bool GetJobHandles(HANDLE hProcess, DWORD dwPID);