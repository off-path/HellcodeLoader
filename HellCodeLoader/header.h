#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include <string>
#include <cwchar>
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <ntstatus.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <vector>
#include <type_traits>

int count = 0 ;

typedef NTSTATUS(NTAPI* PUSER_THREAD_START_ROUTINE)(_In_ PVOID ThreadParameter);

typedef struct PS_APC_ROUTINE {
    PVOID ApcArgument1;
    PVOID ApcArgument2;
    PVOID ApcArgument3;
} PPS_APC_ROUTINE, PPS_APC_ROUTINE;

typedef NTSTATUS(WINAPI* pNtContinue_t)(PCONTEXT, BOOLEAN);
//typedef NTSTATUS(WINAPI* pNtQueueApcThread_t)(HANDLE, PVOID, PVOID, PVOID, PVOID);


#define NT_CREATE_THREAD_EX_SUSPENDED 1
#define NT_CREATE_THREAD_EX_ALL_ACCESS 0x001FFFFF

typedef NTSTATUS(WINAPI* pNtQueueApcThread_t)(
    HANDLE ThreadHandle,
    PVOID ApcRoutine,
    PVOID ApcArgument1,
    PVOID ApcArgument2,
    PVOID ApcArgument3
    );
typedef NTSTATUS(WINAPI* pNtCreateThreadEx_t)(
    OUT PHANDLE hThread,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
    );

#ifndef _UNICODE_STRING_DEFINED
#define _UNICODE_STRING_DEFINED
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;
#endif

#ifndef _OBJECT_ATTRIBUTES_DEFINED
#define _OBJECT_ATTRIBUTES_DEFINED
typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;
#endif

#ifndef _CLIENT_ID_DEFINED
#define _CLIENT_ID_DEFINED
typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;
#endif

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN Spare;
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
} PEB, * PPEB;

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES);       \
    (p)->RootDirectory = r;                        \
    (p)->Attributes = a;                           \
    (p)->ObjectName = n;                           \
    (p)->SecurityDescriptor = s;                   \
    (p)->SecurityQualityOfService = NULL;          \
}
#endif

typedef const OBJECT_ATTRIBUTES* PCOBJECT_ATTRIBUTES;

typedef struct _INITIAL_TEB {
    struct {
        PVOID OldStackBase;
        PVOID OldStackLimit;
    } OldInitialTeb;

    PVOID StackBase;
    PVOID StackLimit;
    PVOID StackAllocationBase;

} INITIAL_TEB, * PINITIAL_TEB;

typedef NTSTATUS(NTAPI* my_NtOpenProcess)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, CLIENT_ID* ClientId);

typedef NTSTATUS(NTAPI* my_NtWriteVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG BufferSize, PULONG NumberOfBytesWritten);

extern "C" {
    extern int my_asm_NtOpenProcess(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
    extern int my_asm_NtAllocateVirtualMemory(HANDLE, PVOID, ULONG_PTR, PSIZE_T, ULONG, ULONG);
    extern int my_asm_NtWriteVirtualMemory(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
    extern int my_asm_NTCreateThreadex(PHANDLE, ACCESS_MASK, PCOBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, LPVOID);
    extern int my_asm_NtOpenThread(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
    extern int my_asm_NtQueueApcThread(HANDLE, PVOID, PVOID, PVOID, PVOID);

    DWORD64 syscallAddress_NtOpenProcess = 0;
    DWORD64 syscallAddress_AllocateVirtualMemory = 0;
    DWORD64 syscallAddress_NtWriteVirtualMemory = 0;
    DWORD64 syscallAddress_CreateThreadEx = 0;
    DWORD64 syscallAddress_NtOpenThread = 0;
    DWORD64 syscallAddress_NtQueueApcThread = 0;
}