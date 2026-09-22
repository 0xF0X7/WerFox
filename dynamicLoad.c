// dynamicLoad.c — Dynamically discover WerFault's blob parser
// Compile: cl /Fe:dynamicLoad.exe dynamicLoad.c /link advapi32.lib user32.lib psapi.lib dbghelp.lib

#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <dbghelp.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "dbghelp.lib")

#ifndef STATUS_BREAKPOINT
#define STATUS_BREAKPOINT ((DWORD)0x80000003L)
#endif
#ifndef STATUS_SINGLE_STEP
#define STATUS_SINGLE_STEP ((DWORD)0x80000004L)
#endif

#define MAX_MODULES 512
#define LOG_LINE 2048

static FILE *g_log = NULL;
static CRITICAL_SECTION g_cs;
static BOOL g_hwbp_set = FALSE;
static DWORD64 g_saved_r8 = 0;
static DWORD64 g_sw_bp_retaddr = 0;
static BYTE    g_sw_bp_origbyte = 0;
static int     g_last_hook_slot = -1;

static DWORD64 g_nmvs_remote_addr = 0;
static DWORD64 g_mvf_remote_addr = 0;
static DWORD64 g_clf_remote_addr = 0;

typedef LONG (NTAPI *pfnNtQueryInformationProcess)(
    HANDLE, ULONG, PVOID, ULONG, PULONG);

static pfnNtQueryInformationProcess NtQIP = NULL;

static void Log(const char *fmt, ...) {
    char buf[LOG_LINE];
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);
    EnterCriticalSection(&g_cs);
    if (g_log) {
        fputs(buf, g_log);
        fflush(g_log);
    }
    OutputDebugStringA(buf);
    LeaveCriticalSection(&g_cs);
}

static BOOL EnableDebugPriv(void) {
    HANDLE hTok;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hTok))
        return FALSE;
    LUID luid;
    LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &luid);
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    BOOL ok = AdjustTokenPrivileges(hTok, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hTok);
    return ok;
}

static BOOL SymInit(HANDLE hProc) {
    SymSetOptions(SYMOPT_DEFERRED_LOADS | SYMOPT_UNDNAME | SYMOPT_LOAD_LINES |
                  SYMOPT_FAIL_CRITICAL_ERRORS | SYMOPT_NO_PROMPTS);
    char symPath[MAX_PATH * 2];
    snprintf(symPath, sizeof(symPath), "srv*C:\\symbols*https://msdl.microsoft.com/download/symbols");
    SymSetSearchPath(hProc, symPath);
    return SymInitialize(hProc, NULL, TRUE);
}

static void ResolveFunc(HANDLE hProc, LPVOID addr, char *out, size_t outsz) {
    DWORD64 disp = 0;
    char symBuf[sizeof(SYMBOL_INFO) + 256];
    SYMBOL_INFO *sym = (SYMBOL_INFO *)symBuf;
    sym->SizeOfStruct = sizeof(SYMBOL_INFO);
    sym->MaxNameLen = 255;

    IMAGEHLP_MODULE64 mod;
    ZeroMemory(&mod, sizeof(mod));
    mod.SizeOfStruct = sizeof(mod);
    SymGetModuleInfo64(hProc, (DWORD64)addr, &mod);

    if (SymFromAddr(hProc, (DWORD64)addr, &disp, sym)) {
        _snprintf_s(out, outsz, _TRUNCATE, "%s!%s+0x%llx",
                    mod.ModuleName, sym->Name, disp);
    } else {
        _snprintf_s(out, outsz, _TRUNCATE, "%s!0x%p",
                    mod.ModuleName[0] ? mod.ModuleName : "?", addr);
    }
}

static void SetHWBP(HANDLE hThread, int slot, LPVOID addr) {
    CONTEXT ctx;
    ZeroMemory(&ctx, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(hThread, &ctx);

    DWORD64 *dr = &ctx.Dr0;
    dr[slot] = (DWORD64)addr;

    DWORD64 dr7 = ctx.Dr7;
    dr7 |= (1ULL << (slot * 2));
    int shift = slot * 4 + 16;
    dr7 &= ~((DWORD64)3 << shift);
    dr7 &= ~((DWORD64)3 << (shift + 2));

    ctx.Dr7 = dr7;
    SetThreadContext(hThread, &ctx);
}

static void DisableHWBP(HANDLE hThread, int slot) {
    CONTEXT ctx;
    ZeroMemory(&ctx, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(hThread, &ctx);
    DWORD64 *dr = &ctx.Dr0;
    dr[slot] = 0;
    ctx.Dr7 &= ~(1ULL << (slot * 2));
    SetThreadContext(hThread, &ctx);
}

static void EnableHWBP(HANDLE hThread, int slot, DWORD64 addr) {
    CONTEXT ctx;
    ZeroMemory(&ctx, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(hThread, &ctx);
    DWORD64 *dr = &ctx.Dr0;
    dr[slot] = addr;
    DWORD64 dr7 = ctx.Dr7;
    dr7 |= (1ULL << (slot * 2));
    int shift = slot * 4 + 16;
    dr7 &= ~((DWORD64)3 << shift);
    dr7 &= ~((DWORD64)3 << (shift + 2));
    ctx.Dr7 = dr7;
    SetThreadContext(hThread, &ctx);
}

static void SetupHardwareBreakpoints(HANDLE hProc, HANDLE hThread) {
    if (g_hwbp_set) return;

    HMODULE hNtdllLocal = GetModuleHandleA("ntdll.dll");
    HMODULE hK32Local = GetModuleHandleA("kernel32.dll");
    HMODULE hShLocal = LoadLibraryA("shell32.dll");

    FARPROC mvf_local = GetProcAddress(hK32Local, "MapViewOfFile");
    FARPROC nmvs_local = GetProcAddress(hNtdllLocal, "NtMapViewOfSection");
    FARPROC clf_local = hShLocal ? GetProcAddress(hShLocal, "CommandLineToArgvW") : NULL;

    if (!mvf_local || !nmvs_local) return;

    HMODULE mods[MAX_MODULES];
    DWORD needed = 0;
    if (!EnumProcessModules(hProc, mods, sizeof(mods), &needed)) return;
    int cnt = (int)(needed / sizeof(HMODULE));
    if (cnt > MAX_MODULES) cnt = MAX_MODULES;

    DWORD64 ntdll_remote = 0, k32_remote = 0, sh_remote = 0;
    DWORD64 ntdll_local = (DWORD64)hNtdllLocal;
    DWORD64 k32_local = (DWORD64)hK32Local;
    DWORD64 sh_local = hShLocal ? (DWORD64)hShLocal : 0;

    for (int i = 0; i < cnt; i++) {
        CHAR path[MAX_PATH] = {0};
        GetModuleFileNameExA(hProc, mods[i], path, MAX_PATH);
        
        if (strstr(path, "ntdll.dll")) {
            MODULEINFO mi; ZeroMemory(&mi, sizeof(mi));
            GetModuleInformation(hProc, mods[i], &mi, sizeof(mi));
            ntdll_remote = (DWORD64)mi.lpBaseOfDll;
        }
        if (strstr(path, "kernel32.dll")) {
            MODULEINFO mi; ZeroMemory(&mi, sizeof(mi));
            GetModuleInformation(hProc, mods[i], &mi, sizeof(mi));
            k32_remote = (DWORD64)mi.lpBaseOfDll;
        }
        if (strstr(path, "shell32.dll")) {
            MODULEINFO mi; ZeroMemory(&mi, sizeof(mi));
            GetModuleInformation(hProc, mods[i], &mi, sizeof(mi));
            sh_remote = (DWORD64)mi.lpBaseOfDll;
        }
    }

    // Slot 0: MapViewOfFile
    if (k32_remote && mvf_local) {
        DWORD64 delta = k32_remote - k32_local;
        g_mvf_remote_addr = (DWORD64)mvf_local + delta;
        Log("[*] HWBP on MapViewOfFile (remote) at 0x%llx\n",
            (unsigned long long)g_mvf_remote_addr);
        SetHWBP(hThread, 0, (LPVOID)g_mvf_remote_addr);
    }

    // Slot 1: NtMapViewOfSection
    if (ntdll_remote && nmvs_local) {
        DWORD64 delta = ntdll_remote - ntdll_local;
        g_nmvs_remote_addr = (DWORD64)nmvs_local + delta;
        Log("[*] HWBP on NtMapViewOfSection (remote) at 0x%llx\n",
            (unsigned long long)g_nmvs_remote_addr);
        SetHWBP(hThread, 1, (LPVOID)g_nmvs_remote_addr);
    }

    // Slot 2: CommandLineToArgvW
    if (sh_remote && clf_local) {
        DWORD64 delta = sh_remote - sh_local;
        g_clf_remote_addr = (DWORD64)clf_local + delta;
        Log("[*] HWBP on CommandLineToArgvW (remote) at 0x%llx\n",
            (unsigned long long)g_clf_remote_addr);
        SetHWBP(hThread, 2, (LPVOID)g_clf_remote_addr);
    }

    g_hwbp_set = TRUE;
}

static void OnLoadDll(DEBUG_EVENT *ev, HANDLE hProc) {
    CHAR path[MAX_PATH] = {0};
    if (GetMappedFileNameA(hProc, ev->u.LoadDll.lpBaseOfDll,
                           path, MAX_PATH)) {
        if (strstr(path, "wer.") || strstr(path, "Wer.") ||
            strstr(path, "FAULT") || strstr(path, "fault") ||
            strstr(path, "ntdll")) {
            Log("[LOAD_DLL] base=0x%p '%s'\n",
                ev->u.LoadDll.lpBaseOfDll, path);
        }
    }

    DWORD64 symBase = SymLoadModuleEx(
        hProc, NULL, path, NULL,
        (DWORD64)ev->u.LoadDll.lpBaseOfDll, 0, NULL, 0);
}

static void DumpBlob(HANDLE hProc, PVOID mappedBase) {
    if (!mappedBase) return;
    BYTE blob[0x100] = {0};
    SIZE_T rd = 0;
    if (ReadProcessMemory(hProc, mappedBase, blob, 0xF8, &rd) && rd > 0) {
        Log("  Blob dump (%llu bytes):\n", (unsigned long long)rd);
        for (int i = 0; i < (int)rd; i += 16) {
            char hex[64] = {0}, ascii[20] = {0};
            for (int j = 0; j < 16 && (i + j) < (int)rd; j++) {
                sprintf_s(hex + strlen(hex), sizeof(hex) - strlen(hex),
                          "%02x ", blob[i + j]);
                ascii[j] = (blob[i + j] >= 0x20 && blob[i + j] < 0x7f)
                           ? blob[i + j] : '.';
            }
            Log("    %03x: %-48s %s\n", i, hex, ascii);
        }
        if (rd >= 8) {
            Log("  Size=0x%x TargetPid=%lu\n",
                *(DWORD *)(blob + 0),
                *(DWORD *)(blob + 4));
        }
    }
}

static void OnException(DEBUG_EVENT *ev, HANDLE hProc, HANDLE hThread) {
    EXCEPTION_RECORD *er = &ev->u.Exception.ExceptionRecord;
    char func[256];

    if (er->ExceptionCode == STATUS_BREAKPOINT ||
        er->ExceptionCode == STATUS_SINGLE_STEP) {

        CONTEXT ctx;
        ZeroMemory(&ctx, sizeof(ctx));
        ctx.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
        GetThreadContext(hThread, &ctx);

        BOOL isDr0 = (ctx.Dr6 & 0xF) & 1;
        BOOL isDr1 = (ctx.Dr6 & 0xF) & 2;
        BOOL isDr2 = (ctx.Dr6 & 0xF) & 4;

        // Intercept our injected INT3 FIRST
        if ((er->ExceptionCode == STATUS_BREAKPOINT) &&
            (g_sw_bp_retaddr != 0) &&
            ((DWORD64)er->ExceptionAddress == g_sw_bp_retaddr)) {

            Log("[SW_BP_HIT] Returned from hooked API (origin slot %d)\n", g_last_hook_slot);
            NTSTATUS retVal = (NTSTATUS)ctx.Rax;
            Log("  Return value (RAX): 0x%08lx\n", retVal);

            if (retVal == 0 && g_saved_r8) {
                PVOID mappedBase = NULL;
                SIZE_T rd = 0;
                if (ReadProcessMemory(hProc, (LPCVOID)g_saved_r8,
                                      &mappedBase, sizeof(mappedBase), &rd)) {
                    Log("  Mapped base: 0x%p\n", mappedBase);
                    DumpBlob(hProc, mappedBase);
                }
            } else if (retVal == 0 && g_last_hook_slot == 0) {
                // MapViewOfFile returns base directly in RAX
                PVOID mappedBase = (PVOID)ctx.Rax;
                Log("  MapViewOfFile returned base: 0x%p\n", mappedBase);
                DumpBlob(hProc, mappedBase);
            }

            // Restore original byte
            BYTE obyte = g_sw_bp_origbyte;
            WriteProcessMemory(hProc, (LPVOID)g_sw_bp_retaddr, &obyte, 1, NULL);
            FlushInstructionCache(hProc, (LPCVOID)g_sw_bp_retaddr, 1);
            
            // Rewind RIP
            ctx.Rip--;
            SetThreadContext(hThread, &ctx);
            
            // Re-enable whichever HWBP fired (must happen BEFORE resetting g_last_hook_slot)
            if (g_last_hook_slot == 0 && g_mvf_remote_addr)
                EnableHWBP(hThread, 0, g_mvf_remote_addr);
            if (g_last_hook_slot == 1 && g_nmvs_remote_addr)
                EnableHWBP(hThread, 1, g_nmvs_remote_addr);
            if (g_last_hook_slot == 2 && g_clf_remote_addr)
                EnableHWBP(hThread, 2, g_clf_remote_addr);
            
            g_sw_bp_retaddr = 0;
            g_saved_r8 = 0;
            g_last_hook_slot = -1;
            
            return;
        }

        ResolveFunc(hProc, er->ExceptionAddress, func, sizeof(func));

        if (isDr0 && er->ExceptionCode == STATUS_SINGLE_STEP) {
            // MapViewOfFile hit
            HANDLE hMap = (HANDLE)ctx.Rcx;
            DWORD access = (DWORD)ctx.Rdx;
            Log("[MapViewOfFile HIT] hMap=0x%p Access=0x%lx\n", hMap, access);
            Log("  At: %s\n", func);

            // Install SW BP at return address
            DWORD64 retAddr = 0;
            SIZE_T br = 0;
            if (ReadProcessMemory(hProc, (LPCVOID)ctx.Rsp, &retAddr, sizeof(retAddr), &br)) {
                BYTE origByte = 0;
                if (ReadProcessMemory(hProc, (LPCVOID)retAddr, &origByte, 1, &br)) {
                    if (origByte != 0xCC) {
                        BYTE bp = 0xCC;
                        if (WriteProcessMemory(hProc, (LPVOID)retAddr, &bp, 1, &br)) {
                            FlushInstructionCache(hProc, (LPCVOID)retAddr, 1);
                            g_sw_bp_retaddr = retAddr;
                            g_sw_bp_origbyte = origByte;
                            g_last_hook_slot = 0;
                            Log("[+] Placed INT3 at 0x%llx\n", (unsigned long long)retAddr);
                        }
                    }
                }
            }

            ctx.Dr6 = 0;
            ctx.Dr0 = 0;
            DWORD64 dr7 = ctx.Dr7;
            dr7 &= ~(1ULL << 0);
            ctx.Dr7 = dr7;
            SetThreadContext(hThread, &ctx);

        } else if (isDr1 && er->ExceptionCode == STATUS_SINGLE_STEP) {
            // NtMapViewOfSection hit
            HANDLE hSection = (HANDLE)ctx.Rcx;
            HANDLE hProcTarget = (HANDLE)ctx.Rdx;
            g_saved_r8 = ctx.R8;

            // Filter: Skip mappings into current process (DLL loads)
            // We care about cross-process section mappings (the WER blob)
            DWORD selfPid = GetCurrentProcessId();
            DWORD targetId = GetProcessId(hProcTarget);
            
            // Skip if mapping into self
            if (hProcTarget == (HANDLE)-1 || hProcTarget == (HANDLE)-2 ||
                targetId == selfPid || targetId == ev->dwProcessId) {
                Log("[NtMapViewOfSection SKIP] Self-map Section=0x%p\n", hSection);
                ctx.Dr6 = 0;
                SetThreadContext(hThread, &ctx);
                return;
            }

            Log("[NtMapViewOfSection HIT] Section=0x%p Proc=0x%p (PID %ld) BaseAddress*=0x%llx\n",
                hSection, hProcTarget, targetId, (unsigned long long)g_saved_r8);
            Log("  At: %s\n", func);

            DWORD64 retAddr = 0;
            SIZE_T br = 0;
            if (ReadProcessMemory(hProc, (LPCVOID)ctx.Rsp, &retAddr, sizeof(retAddr), &br)) {
                BYTE origByte = 0;
                if (ReadProcessMemory(hProc, (LPCVOID)retAddr, &origByte, 1, &br)) {
                    if (origByte != 0xCC) {
                        BYTE bp = 0xCC;
                        if (WriteProcessMemory(hProc, (LPVOID)retAddr, &bp, 1, &br)) {
                            FlushInstructionCache(hProc, (LPCVOID)retAddr, 1);
                            g_sw_bp_retaddr = retAddr;
                            g_sw_bp_origbyte = origByte;
                            g_last_hook_slot = 1;
                            Log("[+] Placed INT3 at 0x%llx\n", (unsigned long long)retAddr);
                        }
                    }
                }
            }

            ctx.Dr6 = 0;
            ctx.Dr1 = 0;
            DWORD64 dr7 = ctx.Dr7;
            dr7 &= ~(1ULL << 2);
            ctx.Dr7 = dr7;
            SetThreadContext(hThread, &ctx);

        } else if (isDr2 && er->ExceptionCode == STATUS_SINGLE_STEP) {
            // CommandLineToArgvW hit
            LPCWSTR cmdLineRemote = (LPCWSTR)ctx.Rcx;
            WCHAR cmdLine[2048] = {0};
            SIZE_T br = 0;
            ReadProcessMemory(hProc, cmdLineRemote, cmdLine,
                              sizeof(cmdLine) - 2, &br);

            Log("[CommandLineToArgvW HIT]\n  CmdLine: '%ws'\n", cmdLine);
            Log("  At: %s\n", func);

            // Step over
            ctx.Dr6 = 0;
            ctx.Dr2 = 0;
            DWORD64 dr7 = ctx.Dr7;
            dr7 &= ~(1ULL << 4);
            ctx.Dr7 = dr7;
            ctx.EFlags |= 0x100;
            SetThreadContext(hThread, &ctx);

        } else if (er->ExceptionCode == STATUS_SINGLE_STEP &&
                   (ctx.EFlags & 0x100)) {
            // Stepped over CommandLineToArgvW
            if (g_clf_remote_addr) {
                EnableHWBP(hThread, 2, g_clf_remote_addr);
            }
            ctx.EFlags &= ~0x100;
            ctx.Dr6 = 0;
            SetThreadContext(hThread, &ctx);

        } else {
            if (ev->u.Exception.dwFirstChance) {
                Log("[BP] first-chance at %s\n", func);
            }
        }

    } else if (er->ExceptionCode == DBG_PRINTEXCEPTION_C) {
        // Skip
    } else {
        if (ev->u.Exception.dwFirstChance) {
            Log("[EXC] code=0x%lx first=1\n", er->ExceptionCode);
        }
    }
}

static int DebugLoop(DWORD targetPid) {
    DEBUG_EVENT ev;

    Log("[*] Attaching to PID %ld...\n", targetPid);
    if (!DebugActiveProcess(targetPid)) {
        Log("[-] DebugActiveProcess failed: %lu\n", GetLastError());
        return 1;
    }
    DebugSetProcessKillOnExit(FALSE);

    while (WaitForDebugEvent(&ev, INFINITE)) {
        DWORD status = DBG_CONTINUE;
        HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ev.dwProcessId);
        HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, ev.dwThreadId);

        switch (ev.dwDebugEventCode) {
        case CREATE_PROCESS_DEBUG_EVENT:
            Log("[ATTACH] pid=%ld\n", ev.dwProcessId);
            if (hThread) {
                SetupHardwareBreakpoints(hProc, hThread);
            }
            break;

        case LOAD_DLL_DEBUG_EVENT:
            if (hProc) OnLoadDll(&ev, hProc);
            break;

        case EXCEPTION_DEBUG_EVENT:
            if (hProc && hThread) {
                OnException(&ev, hProc, hThread);
            }
            status = DBG_CONTINUE;
            break;

        case EXIT_PROCESS_DEBUG_EVENT:
            Log("[EXIT_PROCESS] pid=%ld code=%lu\n",
                ev.dwProcessId, ev.u.ExitProcess.dwExitCode);
            if (ev.dwProcessId == targetPid)
                goto done;
            break;

        case CREATE_THREAD_DEBUG_EVENT:
            if (hThread && !g_hwbp_set) {
                SetupHardwareBreakpoints(hProc, hThread);
            }
            break;

        case EXIT_THREAD_DEBUG_EVENT:
            break;

        case RIP_EVENT:
            Log("[RIP] err=%lu\n", ev.u.RipInfo.dwError);
            break;

        case OUTPUT_DEBUG_STRING_EVENT:
            break;
        }

        if (hProc) CloseHandle(hProc);
        if (hThread) CloseHandle(hThread);
        ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, status);
    }

done:
    DebugActiveProcessStop(targetPid);
    return 0;
}

static DWORD WaitForWerFault(DWORD timeoutMs) {
    DWORD start = GetTickCount();
    while (GetTickCount() - start < timeoutMs) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) { Sleep(5); continue; }

        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(snap, &pe)) {
            do {
                if (_wcsicmp(pe.szExeFile, L"WerFault.exe") == 0) {
                    DWORD pid = pe.th32ProcessID;
                    CloseHandle(snap);
                    Log("[+] WerFault.exe spotted PID %ld\n", pid);
                    return pid;
                }
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
        Sleep(5);
    }
    return 0;
}

int main(int argc, char *argv[]) {
    InitializeCriticalSection(&g_cs);
    EnableDebugPriv();
    g_log = fopen("wer_intake.log", "w");
    if (!g_log) { printf("Cannot open log\n"); return 1; }

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    NtQIP = (pfnNtQueryInformationProcess)
        GetProcAddress(ntdll, "NtQueryInformationProcess");

    Log("=== WerFault Intake Parser Discovery ===\n");

    DWORD wfPid = 0;

    if (argc > 1) {
        wfPid = (DWORD)atoi(argv[1]);
        Log("[*] Manual target PID %ld\n", wfPid);
        DebugLoop(wfPid);
    } else {
        STARTUPINFOW si;
        PROCESS_INFORMATION pi;
        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        ZeroMemory(&pi, sizeof(pi));

        WCHAR cmd[] = L"C:\\Users\\dcoadmin\\Desktop\\WerFox\\crasher.exe";
        if (!CreateProcessW(NULL, cmd, NULL, NULL, FALSE,
                            DETACHED_PROCESS | CREATE_NO_WINDOW,
                            NULL, NULL, &si, &pi)) {
            Log("[-] CreateProcess sacrifice failed: %lu\n", GetLastError());
            fclose(g_log);
            return 1;
        }
        Log("[+] Sacrifice PID %ld (detached)\n", pi.dwProcessId);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);

        Log("[*] Polling for WerFault.exe (5ms interval)...\n");
        wfPid = WaitForWerFault(30000);
        if (!wfPid) {
            Log("[-] No WerFault within 30s\n");
            fclose(g_log);
            return 1;
        }

        DebugLoop(wfPid);
    }

    fclose(g_log);
    printf("[*] Done. See wer_intake.log\n");
    DeleteCriticalSection(&g_cs);
    return 0;
}