// wer_connect.c — Minimal WER ALPC connection test
// Compile: cl wer_connect.c /Fe:wer_connect.exe

#include <windows.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")

typedef LONG NTSTATUS;

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
        struct {
            HANDLE UniqueProcess;
            HANDLE UniqueThread;
        } ClientId;
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

// CORRECT signature from ntdoc.m417z.com
typedef NTSTATUS (NTAPI *pfnNtAlpcConnectPort)(
    PHANDLE PortHandle,
    UNICODE_STRING_T* PortName,
    OBJECT_ATTRIBUTES_T* ObjectAttributes,    // can be NULL
    ALPC_PORT_ATTRIBUTES_T* PortAttributes,   // can be NULL
    ULONG Flags,
    PSID RequiredServerSid,                   // can be NULL
    PORT_MESSAGE_T* ConnectionMessage,        // must be valid PORT_MESSAGE
    PSIZE_T BufferLength,
    PVOID OutMessageAttributes,               // PALPC_MESSAGE_ATTRIBUTES
    PVOID InMessageAttributes,                // PALPC_MESSAGE_ATTRIBUTES
    PLARGE_INTEGER Timeout);

typedef void (NTAPI *pfnRtlInitUnicodeString)(
    UNICODE_STRING_T* DestinationString,
    PCWSTR SourceString);

static pfnNtAlpcConnectPort NtAlpcConnectPort;
static pfnRtlInitUnicodeString RtlInitUnicodeString;

// ---- Start WerSvc ----
static BOOL StartWerSvc(void) {
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) return FALSE;

    SC_HANDLE svc = OpenServiceW(scm, L"WerSvc", SERVICE_START | SERVICE_QUERY_STATUS);
    if (!svc) { CloseServiceHandle(scm); return FALSE; }

    SERVICE_STATUS status;
    if (QueryServiceStatus(svc, &status) && status.dwCurrentState == SERVICE_RUNNING) {
        printf("[+] WerSvc already running\n");
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        return TRUE;
    }

    printf("[*] Starting WerSvc...\n");
    if (StartService(svc, 0, NULL)) {
        printf("[+] StartService succeeded\n");
    } else {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_ALREADY_RUNNING) {
            printf("[+] WerSvc already running\n");
        } else {
            printf("[-] StartService failed: %d\n", err);
            CloseServiceHandle(svc);
            CloseServiceHandle(scm);
            return FALSE;
        }
    }

    for (int i = 0; i < 20; i++) {
        if (QueryServiceStatus(svc, &status) && status.dwCurrentState == SERVICE_RUNNING) {
            CloseServiceHandle(svc);
            CloseServiceHandle(scm);
            return TRUE;
        }
        Sleep(250);
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return FALSE;
}

// ---- Trigger real crash ----
static void TriggerRealCrash(void) {
    printf("[*] Triggering crash to force ALPC port creation...\n");

    STARTUPINFOW si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    // rundll32 with invalid entry
    WCHAR cmd[] = L"rundll32.exe sysdm.cpl,NoEntry";
    if (CreateProcessW(NULL, cmd, NULL, NULL, FALSE,
                       CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        printf("[*] Launched sacrificial process PID %d\n", pi.dwProcessId);
        Sleep(3000);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }

    // WerReportCreate + WerReportSubmit
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
int main(void) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    NtAlpcConnectPort = (pfnNtAlpcConnectPort)
        GetProcAddress(ntdll, "NtAlpcConnectPort");
    RtlInitUnicodeString = (pfnRtlInitUnicodeString)
        GetProcAddress(ntdll, "RtlInitUnicodeString");

    if (!NtAlpcConnectPort || !RtlInitUnicodeString) {
        printf("[-] Failed to resolve NT functions\n");
        return 1;
    }

    printf("=== WER ALPC Connection Test ===\n\n");

    if (!StartWerSvc()) {
        printf("[-] Cannot start WerSvc\n");
        return 1;
    }

    TriggerRealCrash();
    Sleep(2000);

    // ---- Connect ----
    UNICODE_STRING_T portName;
    RtlInitUnicodeString(&portName, L"\\WindowsErrorReportingServicePort");

    OBJECT_ATTRIBUTES_T oa;
    oa.Length = sizeof(oa);
    oa.RootDirectory = NULL;
    oa.ObjectName = portName;
    oa.Attributes = OBJ_CASE_INSENSITIVE;
    oa.SecurityDescriptor = NULL;
    oa.SecurityQualityOfService = NULL;

    ALPC_PORT_ATTRIBUTES_T portAttrs;
    ZeroMemory(&portAttrs, sizeof(portAttrs));
    portAttrs.MaxMessageLength = 0x800;

    // Connection message — must be a valid PORT_MESSAGE
    // Total buffer: PORT_MESSAGE header (0x28) + body
    __declspec(align(8)) BYTE connBuf[0x200];
    ZeroMemory(connBuf, sizeof(connBuf));

    PORT_MESSAGE_T* connMsg = (PORT_MESSAGE_T*)connBuf;
    // Try various total lengths
    USHORT msgSizes[] = { 0x28, 0x30, 0x40, 0x50, 0x80, 0x100, 0x200 };
    int numSizes = sizeof(msgSizes) / sizeof(msgSizes[0]);

    HANDLE hPort = NULL;
    NTSTATUS status = (NTSTATUS)0xC0000001;

    for (int mode = 0; mode < 2 && status != 0; mode++) {
        for (int sz = 0; sz < numSizes && status != 0; sz++) {
            connMsg->u1.s1.TotalLength = msgSizes[sz];
            connMsg->u1.s1.DataLength = (msgSizes[sz] > 0x28) ?
                                         (USHORT)(msgSizes[sz] - 0x28) : 0;
            connMsg->u2.ZeroInit = 0;
            SIZE_T tryLen = msgSizes[sz];

            status = NtAlpcConnectPort(
                &hPort,
                &portName,
                (mode == 0) ? NULL : &oa,
                (mode == 0) ? NULL : &portAttrs,
                0,
                NULL,               // RequiredServerSid
                connMsg,            // ConnectionMessage
                &tryLen,            // BufferLength
                NULL,               // OutMessageAttributes
                NULL,               // InMessageAttributes
                NULL);              // Timeout

            printf("[*] mode=%d len=0x%x: 0x%08X (retLen=%llu)\n",
                   mode, msgSizes[sz],
                   (unsigned int)status, (unsigned long long)tryLen);

            if (status == 0) {
                printf("[+] SUCCESS! Connected to WER ALPC port: 0x%p\n", hPort);
                CloseHandle(hPort);
                return 0;
            }
            Sleep(250);
        }
    }

    printf("\n[-] All connection attempts failed: 0x%08X\n", (unsigned int)status);
    return 1;
}