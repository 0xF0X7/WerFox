#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <tlhelp32.h>

typedef LONG NTSTATUS;

typedef struct _UNICODE_STRING_T {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING_T;

typedef struct _CLIENT_ID_T {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID_T;

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
        CLIENT_ID_T ClientId;
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

typedef NTSTATUS (NTAPI *pfnNtAlpcConnectPort)(
    PHANDLE PortHandle,
    UNICODE_STRING_T* PortName,
    OBJECT_ATTRIBUTES_T* ObjectAttributes,
    ALPC_PORT_ATTRIBUTES_T* PortAttributes,
    ULONG Flags,
    PSID RequiredServerSid,
    PORT_MESSAGE_T* ConnectionMessage,
    PSIZE_T BufferLength,
    PVOID OutMessageAttributes,
    PVOID InMessageAttributes,
    PLARGE_INTEGER Timeout);

typedef void (NTAPI *pfnRtlInitUnicodeString)(
    UNICODE_STRING_T* DestinationString,
    PCWSTR SourceString);

static pfnNtAlpcConnectPort NtAlpcConnectPort;
static pfnRtlInitUnicodeString RtlInitUnicodeString;

#pragma comment(lib, "advapi32.lib")

static void StartWerSvc(void) {
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) return;
    SC_HANDLE svc = OpenServiceW(scm, L"WerSvc", SERVICE_START | SERVICE_QUERY_STATUS);
    if (!svc) { CloseServiceHandle(scm); return; }
    SERVICE_STATUS st;
    if (QueryServiceStatus(svc, &st) && st.dwCurrentState != SERVICE_RUNNING) {
        StartServiceW(svc, 0, NULL);
        for (int i = 0; i < 30; i++) {
            QueryServiceStatus(svc, &st);
            if (st.dwCurrentState == SERVICE_RUNNING) break;
            Sleep(100);
        }
    }
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
}

static void PrimePort(void) {
    STARTUPINFOW si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));
    WCHAR cmd[] = L"rundll32.exe sysdm.cpl,NoEntry";
    if (CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        Sleep(2000);
        TerminateProcess(pi.hProcess, EXCEPTION_ACCESS_VIOLATION);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    Sleep(1500);
}

static BOOL DetectWerFault(void) {
    BOOL found = FALSE;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return FALSE;
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"WerFault.exe") == 0) {
                printf("      >>> WerFault.exe SPAWNED PID=%d <<<\n", pe.th32ProcessID);
                found = TRUE;
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return found;
}

int main(void) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    NtAlpcConnectPort = (pfnNtAlpcConnectPort)GetProcAddress(ntdll, "NtAlpcConnectPort");
    RtlInitUnicodeString = (pfnRtlInitUnicodeString)GetProcAddress(ntdll, "RtlInitUnicodeString");
    if (!NtAlpcConnectPort || !RtlInitUnicodeString) {
        printf("Failed to resolve ntdll exports\n");
        return 1;
    }

    printf("=== WER ALPC Method/Flag Sweeper ===\n\n");
    StartWerSvc();
    PrimePort();

    UNICODE_STRING_T portName;
    RtlInitUnicodeString(&portName, L"\\WindowsErrorReportingServicePort");

    DWORD methods[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A};
    DWORD flagSets[] = {
        0x00000000,
        0x00000020,
        0x00000400,
        0x00000420,
        0x02000000,
        0x02000420,
        0x80000000,
        0x80000420,
        0xFFFFFFFF
    };

    int numMethods = sizeof(methods) / sizeof(methods[0]);
    int numFlags = sizeof(flagSets) / sizeof(flagSets[0]);

    for (int mi = 0; mi < numMethods; mi++) {
        for (int fi = 0; fi < numFlags; fi++) {
            __declspec(align(8)) unsigned char buf[0x200];
            ZeroMemory(buf, sizeof(buf));

            PORT_MESSAGE_T* hdr = (PORT_MESSAGE_T*)buf;
            hdr->u1.s1.TotalLength = 0x200;
            hdr->u1.s1.DataLength = 0x200 - 0x28;
            hdr->u2.ZeroInit = 0;

            DWORD* body = (DWORD*)(buf + 0x28);
            body[0] = methods[mi];
            body[1] = flagSets[fi];
            body[2] = GetCurrentProcessId();
            body[4] = GetCurrentThreadId();

            DWORD* sec = (DWORD*)(buf + 0x60);
            *sec = GetCurrentProcessId();

            DWORD* hv = (DWORD*)(buf + 0x64);
            *hv = 0;

            SIZE_T connLen = 0x200;
            HANDLE hPort = NULL;

            NTSTATUS st = NtAlpcConnectPort(
                &hPort, &portName, NULL, NULL, 0, NULL,
                (PORT_MESSAGE_T*)buf, &connLen, NULL, NULL, NULL);

            DWORD rStatus = 0, rResult = 0;
            if (connLen >= 0x98) {
                rStatus = *(DWORD*)(buf + 0x90);
                rResult = *(DWORD*)(buf + 0x94);
            }

            printf("[M=0x%02X F=0x%08X] nt=0x%08X clen=%zu S=0x%08X R=0x%08X",
                   methods[mi], flagSets[fi], (unsigned)st, connLen, rStatus, rResult);

            if (st == 0) {
                printf(" OK");
                if (DetectWerFault())
                    printf(" *** HIT ***");
                if (hPort) CloseHandle(hPort);
            }
            printf("\n");

            Sleep(200);
        }
        printf("---\n");
    }

    printf("\nDone.\n");
    return 0;
}