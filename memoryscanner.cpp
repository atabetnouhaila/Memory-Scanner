#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>  // For process snapshot functions

#define PROCESS_QUERY_INFORMATION 0x0400
#define MEM_COMMIT 0x00001000
#define PAGE_READWRITE 0x04
#define PROCESS_WM_READ 0x0010

//Get the process ID by the process name
DWORD GetProcessIdByName(const wchar_t* processName) {
    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    if (Process32First(hSnapshot, &processEntry)) {
        do {
            if (!_wcsicmp(processEntry.szExeFile, processName)) {
                CloseHandle(hSnapshot);
                return processEntry.th32ProcessID;
            }
        } while (Process32Next(hSnapshot, &processEntry));
    }

    CloseHandle(hSnapshot);
    return 0;
}

int main() {
    SYSTEM_INFO sysInfo;
    MEMORY_BASIC_INFORMATION memInfo;
    SIZE_T bytesRead;  // Correct type: SIZE_T instead of DWORD

   
    GetSystemInfo(&sysInfo);

    // Get minimum and maximum address space
    LPVOID minAddress = sysInfo.lpMinimumApplicationAddress;
    LPVOID maxAddress = sysInfo.lpMaximumApplicationAddress;

    // Get Notepad process by name
    DWORD processId = GetProcessIdByName(L"notepad.exe");
    if (processId == 0) {
        printf("Unable to find Notepad process.\n");
        return 1;
    }

    // Open the process with necessary privileges
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_WM_READ, FALSE, processId);
    if (hProcess == NULL) {
        printf("Unable to open process.\n");
        return 1;
    }

    // Open file to dump memory using fopen_s for security
    FILE* dumpFile;
    errno_t err = fopen_s(&dumpFile, "dump.txt", "w");
    if (err != 0 || dumpFile == NULL) {
        printf("Unable to create dump file.\n");
        CloseHandle(hProcess);
        return 1;
    }

    // Iterate through the memory regions
    while (minAddress < maxAddress) {
        if (VirtualQueryEx(hProcess, minAddress, &memInfo, sizeof(MEMORY_BASIC_INFORMATION)) == sizeof(MEMORY_BASIC_INFORMATION)) {
            // Check if the memory is committed and writable
            if ((memInfo.State == MEM_COMMIT) && (memInfo.Protect == PAGE_READWRITE)) {
                // Allocate buffer to read memory
                BYTE* buffer = (BYTE*)malloc(memInfo.RegionSize);
                if (ReadProcessMemory(hProcess, memInfo.BaseAddress, buffer, memInfo.RegionSize, &bytesRead)) {
                    // Write the contents to the file
                    for (SIZE_T i = 0; i < bytesRead; i++) {
                        fprintf(dumpFile, "0x%p: %02X\n", (BYTE*)memInfo.BaseAddress + i, buffer[i]);
                    }
                }
                free(buffer);
            }
            // Move to the next memory region
            minAddress = (LPVOID)((SIZE_T)minAddress + memInfo.RegionSize);
        }
    }

    // Clean up
    fclose(dumpFile);
    CloseHandle(hProcess);
    printf("Memory dump completed.\n");

    return 0;
}
