#include <windows.h>
#include <stdio.h>
#include "MinHook.h"

#pragma comment(lib, "kernel32.lib")

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
        SYSTEMTIME st;
        GetLocalTime(&st);
        fprintf(f, "[%02d:%02d:%02d.%03d %s] len=%zu\n",
                st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, tag, len);
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
    PVOID PortAttrs, ULONG Flags, PSID Sid,
    PORT_MESSAGE_HK* ConnMsg, PSIZE_T ConnLen,
    PVOID OutAttrs, PVOID InAttrs, LARGE_INTEGER* Timeout)
{
    if (ConnMsg && ConnLen) {
        LogBuffer("CONN_SEND", ConnMsg, *ConnLen);
    }
    NTSTATUS st = RealConnect(PortHandle, PortName, ObjAttrs, PortAttrs,
                              Flags, Sid, ConnMsg, ConnLen,
                              OutAttrs, InAttrs, Timeout);
    if (ConnMsg && ConnLen) {
        LogBuffer("CONN_RECV", ConnMsg, *ConnLen);
    }
    return st;
}

BOOL InitHooks(void) {
    if (MH_Initialize() != MH_OK) return FALSE;
    
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    
    void* pSend = GetProcAddress(ntdll, "NtAlpcSendWaitReceivePort");
    void* pConn = GetProcAddress(ntdll, "NtAlpcConnectPort");
    
    if (!pSend || !pConn) return FALSE;
    
    MH_CreateHook(pSend, &HookSendRecv, (LPVOID*)&RealSendRecv);
    MH_CreateHook(pConn, &HookConnect, (LPVOID*)&RealConnect);
    
    MH_EnableHook(MH_ALL_HOOKS);
    return TRUE;
}

__declspec(dllexport)
BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        InitializeCriticalSection(&g_logLock);
        DisableThreadLibraryCalls(hInst);
        InitHooks();
    }
    else if (reason == DLL_PROCESS_DETACH) {
        MH_DisableHook(MH_ALL_HOOKS);
        MH_Uninitialize();
        DeleteCriticalSection(&g_logLock);
    }
    return TRUE;
}