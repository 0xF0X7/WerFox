#include <windows.h>
#include <detours.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "detours.lib")

typedef LONG NTSTATUS;

typedef struct _PORT_MESSAGE_HK {
    union {
        struct { USHORT DataLength; USHORT TotalLength; } s1;
        ULONG Length;
    } u1;
    union {
        struct { USHORT Type; USHORT DataInfoOffset; } s2;
        ULONG ZeroInit;
    } u2;
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
    ULONG MessageId;
    SIZE_T ClientViewSize;
} PORT_MESSAGE_HK;

typedef NTSTATUS (NTAPI *pNtAlpcSendWaitReceivePort)(
    HANDLE, ULONG, PORT_MESSAGE_HK*, PVOID,
    PORT_MESSAGE_HK*, PULONG, PLARGE_INTEGER, PVOID);

typedef NTSTATUS (NTAPI *pNtAlpcConnectPort)(
    PHANDLE, PVOID, PVOID, PVOID, ULONG, PSID,
    PORT_MESSAGE_HK*, PSIZE_T, PVOID, PVOID, PLARGE_INTEGER);

static pNtAlpcSendWaitReceivePort RealSendRecv = NULL;
static pNtAlpcConnectPort RealConnect = NULL;

static CRITICAL_SECTION g_logLock;

static void LogBuffer(const char* tag, const void* buf, SIZE_T len) {
    EnterCriticalSection(&g_logLock);
    FILE* f = fopen("C:\\Users\\dcoadmin\\Desktop\\WerFox\\capture.log", "a");
    if (f) {
        fprintf(f, "[%s] len=%zu\n", tag, len);
        const unsigned char* b = (const unsigned char*)buf;
        for (SIZE_T i = 0; i < len; i += 16) {
            fprintf(f, "  %03zx:", i);
            for (SIZE_T j = 0; j < 16 && (i+j) < len; j++)
                fprintf(f, " %02x", b[i+j]);
            fprintf(f, "\n");
        }
        fflush(f);
        fclose(f);
    }
    LeaveCriticalSection(&g_logLock);
}

NTSTATUS NTAPI HookSendRecv(
    HANDLE PortHandle, ULONG Flags,
    PORT_MESSAGE_HK* SendMsg, PVOID SendOpts,
    PORT_MESSAGE_HK* RecvMsg, PULONG RecvLen,
    PLARGE_INTEGER Timeout, PVOID PortAttrs)
{
    if (SendMsg) {
        LogBuffer("SEND", SendMsg, SendMsg->u1.s1.TotalLength);
    }
    NTSTATUS st = RealSendRecv(PortHandle, Flags, SendMsg, SendOpts,
                               RecvMsg, RecvLen, Timeout, PortAttrs);
    if (RecvMsg && RecvLen && *RecvLen > 0) {
        LogBuffer("RECV", RecvMsg, *RecvLen);
    }
    return st;
}

NTSTATUS NTAPI HookConnect(
    PHANDLE PortHandle, PVOID PortName, PVOID ObjAttrs,
    PVOID PortAttrs, ULONG Flags, PSSID Sid,
    PORT_MESSAGE_HK* ConnMsg, PSIZE_T ConnLen,
    PVOID OutAttrs, PVOID InAttrs, LARGE_INTEGER* Timeout)
{
    if (ConnMsg && ConnLen) {
        LogBuffer("CONNECT_SEND", ConnMsg, *ConnLen);
    }
    NTSTATUS st = RealConnect(PortHandle, PortName, ObjAttrs, PortAttrs,
                              Flags, Sid, ConnMsg, ConnLen,
                              OutAttrs, InAttrs, Timeout);
    if (ConnMsg && ConnLen) {
        LogBuffer("CONNECT_REPLY", ConnMsg, *ConnLen);
    }
    return st;
}

__declspec(dllexport)
BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        InitializeCriticalSection(&g_logLock);
        DisableThreadLibraryCalls(hInst);
        
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        RealSendRecv = (pNtAlpcSendWaitReceivePort)
            GetProcAddress(ntdll, "NtAlpcSendWaitReceivePort");
        RealConnect = (pNtAlpcConnectPort)
            GetProcAddress(ntdll, "NtAlpcConnectPort");
        
        DetourTransactionBegin();
        DetourAttach(&(PVOID&)RealSendRecv, HookSendRecv);
        DetourAttach(&(PVOID&)RealConnect, HookConnect);
        DetourTransactionCommit();
    }
    else if (reason == DLL_PROCESS_DETACH) {
        DetourTransactionBegin();
        DetourDetach(&(PVOID&)RealSendRecv, HookSendRecv);
        DetourDetach(&(PVOID&)RealConnect, HookConnect);
        DetourTransactionCommit();
        DeleteCriticalSection(&g_logLock);
    }
    return TRUE;
}