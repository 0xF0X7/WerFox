#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

static BOOL InjectDll(DWORD pid, const char* dllPath) {
    HANDLE hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
                               PROCESS_VM_WRITE | PROCESS_QUERY_LIMITED_INFORMATION,
                               FALSE, pid);
    if (!hProc) {
        printf("OpenProcess failed: %d\n", GetLastError());
        return FALSE;
    }

    SIZE_T pathLen = strlen(dllPath) + 1;
    void* remoteBuf = VirtualAllocEx(hProc, NULL, pathLen, MEM_COMMIT, PAGE_READWRITE);
    if (!remoteBuf) {
        CloseHandle(hProc);
        return FALSE;
    }

    WriteProcessMemory(hProc, remoteBuf, dllPath, pathLen, NULL);

    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0,
        (LPTHREAD_START_ROUTINE)LoadLibraryA, remoteBuf, 0, NULL);
    
    if (hThread) {
        WaitForSingleObject(hThread, 5000);
        CloseHandle(hThread);
    }

    VirtualFreeEx(hProc, remoteBuf, 0, MEM_RELEASE);
    CloseHandle(hProc);
    return hThread != NULL;
}

int main(void) {
    DeleteFileA("C:\\Users\\dcoadmin\\Desktop\\WerFox\\capture.log");

    STARTUPINFOW si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    WCHAR cmd[] = L"rundll32.exe sysdm.cpl,NoEntry";
    if (!CreateProcessW(NULL, cmd, NULL, NULL, FALSE,
            CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("CreateProcess failed: %d\n", GetLastError());
        return 1;
    }

    CHAR dllPath[MAX_PATH];
    GetFullPathNameA("wer_hook.dll", MAX_PATH, dllPath, NULL);

    printf("[*] Injecting %s into PID %d (suspended)...\n", dllPath, pi.dwProcessId);
    
    if (!InjectDll(pi.dwProcessId, dllPath)) {
        printf("[-] Injection failed\n");
        ResumeThread(pi.hThread);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 1;
    }

    printf("[+] Injected. Resuming...\n");
    ResumeThread(pi.hThread);

    printf("[*] Waiting for rundll32 to settle...\n");
    Sleep(3000);

    printf("[*] Crashing target...\n");
    TerminateProcess(pi.hProcess, EXCEPTION_ACCESS_VIOLATION);

    printf("[*] Waiting for WER interaction...\n");
    Sleep(8000);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    printf("[*] Done. Check capture.log\n");
    return 0;
}