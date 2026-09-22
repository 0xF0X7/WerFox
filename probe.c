#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#pragma comment(lib, "advapi32.lib")

#pragma pack(push, 8)
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
#pragma pack(pop)

typedef LONG NTSTATUS;

typedef NTSTATUS (NTAPI *pfnNtQuerySystemInformation)(
    ULONG InfoClass, PVOID Buffer, ULONG Length, PULONG ReturnLength);
typedef NTSTATUS (NTAPI *pfnNtQueryObject)(
    HANDLE Handle, ULONG InfoClass, PVOID Buffer, ULONG Length, PULONG ReturnLength);

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

pfnNtQuerySystemInformation pNtQSI = NULL;
pfnNtQueryObject pNtQO = NULL;

void ResolveExports() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    pNtQSI = (pfnNtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
    pNtQO = (pfnNtQueryObject)GetProcAddress(ntdll, "NtQueryObject");
}

DWORD FindWerSvcPid() {
    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) return 0;

    SC_HANDLE svc = OpenServiceA(scm, "WerSvc", SERVICE_QUERY_STATUS);
    if (!svc) { CloseServiceHandle(scm); return 0; }

    SERVICE_STATUS_PROCESS ssp;
    DWORD needed = 0;
    DWORD pid = 0;

    if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO,
                            (LPBYTE)&ssp, sizeof(ssp), &needed)) {
        pid = ssp.dwProcessId;
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return pid;
}

int main() {
    ResolveExports();
    if (!pNtQSI || !pNtQO) {
        printf("Failed to resolve ntdll exports\n");
        return 1;
    }

    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    SC_HANDLE svc = OpenServiceA(scm, "WerSvc", SERVICE_QUERY_STATUS | SERVICE_START);
    if (svc) {
        SERVICE_STATUS status;
        QueryServiceStatus(svc, &status);
        if (status.dwCurrentState == SERVICE_STOPPED) {
            printf("[*] Starting WerSvc...\n");
            StartServiceA(svc, 0, NULL);
            for (int i = 0; i < 50; i++) {
                QueryServiceStatus(svc, &status);
                if (status.dwCurrentState == SERVICE_RUNNING) break;
                Sleep(100);
            }
        }
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
    }

    Sleep(500);

    DWORD rawPid = FindWerSvcPid();
    if (!rawPid) {
        printf("Failed to find WerSvc PID\n");
        return 1;
    }
    ULONG_PTR targetPid = (ULONG_PTR)rawPid;
    printf("[*] WerSvc PID: %llu\n", (unsigned long long)targetPid);

    HANDLE hSourceProc = OpenProcess(PROCESS_DUP_HANDLE, FALSE, (DWORD)targetPid);
    if (!hSourceProc) {
        printf("[!] OpenProcess(%llu) failed: %lu\n",
               (unsigned long long)targetPid, GetLastError());
        return 1;
    }
    printf("[*] Opened source process: 0x%p\n", hSourceProc);

    ULONG bufLen = 0x100000;
    PVOID buf = NULL;
    ULONG retLen = 0;
    NTSTATUS st;

    for (int attempt = 0; attempt < 5; attempt++) {
        buf = malloc(bufLen);
        if (!buf) { printf("malloc failed\n"); return 1; }
        memset(buf, 0, bufLen);

        st = pNtQSI(64, buf, bufLen, &retLen);
        if (st == 0) break;

        free(buf);
        buf = NULL;

        if (st != 0xC0000004) {
            printf("NtQuerySystemInformation failed: 0x%08X\n", (unsigned int)st);
            return 1;
        }
        bufLen = (retLen > bufLen) ? retLen * 2 : bufLen * 2;
    }

    if (!buf || st != 0) {
        printf("Failed to query handle table\n");
        return 1;
    }

    ULONG_PTR count = *(ULONG_PTR*)buf;
    printf("[*] Total handles: %llu\n", (unsigned long long)count);

    PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX entries =
        (PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX)((ULONG_PTR)buf + 16);

    int matched = 0, dupOk = 0, dupFail = 0;

    for (ULONG_PTR i = 0; i < count; i++) {
        SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX *entry = &entries[i];

        if (entry->UniqueProcessId != targetPid) continue;
        matched++;

        HANDLE hDup = NULL;
        BOOL ok = DuplicateHandle(
                hSourceProc,
                (HANDLE)entry->HandleValue,
                GetCurrentProcess(),
                &hDup,
                0, FALSE, DUPLICATE_SAME_ACCESS);

        if (!ok) {
            dupFail++;
            if (dupFail <= 5) {
                printf("[!] DupHandle fail 0x%04llX err=%lu\n",
                       (unsigned long long)entry->HandleValue, GetLastError());
            }
            continue;
        }
        dupOk++;

        BYTE typeBuf[0x200];
        memset(typeBuf, 0, sizeof(typeBuf));
        ULONG tLen = 0;
        st = pNtQO(hDup, 2, typeBuf, sizeof(typeBuf), &tLen);

        if (st != 0) {
            printf("[?] QObjType fail 0x%04llX st=0x%08X\n",
                   (unsigned long long)entry->HandleValue, (unsigned int)st);
            CloseHandle(hDup);
            continue;
        }

        USHORT nameLen = *(USHORT*)(typeBuf + 0x10);
        PWCHAR namePtr = *(PWCHAR*)(typeBuf + 0x18);

        wchar_t typeName[256] = {0};
        if (nameLen > 0 && namePtr) {
            wcsncpy_s(typeName, 256, namePtr, nameLen / 2);
        }

        BYTE nameBuf[0x1000];
        memset(nameBuf, 0, sizeof(nameBuf));
        ULONG nLen = 0;
        st = pNtQO(hDup, 1, nameBuf, sizeof(nameBuf), &nLen);

        wchar_t objName[1024] = {0};
        if (st == 0) {
            USHORT objNameLen = *(USHORT*)nameBuf;
            PWCHAR objNamePtr = *(PWCHAR*)(nameBuf + 8);
            if (objNameLen > 0 && objNamePtr) {
                wcsncpy_s(objName, 1024, objNamePtr, objNameLen / 2);
            }
        }

        printf("[%04llX] %-22S  %S\n",
               (unsigned long long)entry->HandleValue,
               typeName[0] ? typeName : L"(null)",
               objName[0] ? objName : L"(unnamed)");

        CloseHandle(hDup);
    }

    printf("\n[*] Matched: %d  DupOK: %d  DupFail: %d\n", matched, dupOk, dupFail);
    CloseHandle(hSourceProc);
    free(buf);
    return 0;
}