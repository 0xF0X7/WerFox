┌─────────────────────────────────────────────────────────────┐
│ ATTACKER (Medium IL)                                        │
│                                                             │
│  Process A                    Process B                     │
│  ┌──────────────┐             ┌──────────────────────┐      │
│  │ CreateFile   │             │ Handle spray:        │      │
│  │ Mapping      │             │ Fill indices 0x3C-   │      │
│  │ (size 0xF8)  │             │ 0x200 with events    │      │
│  │              │             │                      │      │
│  │ Write:       │             │ Free index matching  │      │
│  │ [0x00]=0xF8  │             │ H_map_A              │      │
│  │ [0x04]=pidB  │             │                      │      │
│  │              │             │ Place privileged     │      │
│  │ H_map_A =    │             │ handle at that index │      │
│  │ 0x1EC (e.g.) │             │ (e.g. dup of token)  │      │
│  └──────────────┘             └──────────────────────┘      │
│                                                             │
│  ALPC Message:                                              │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ Method=0x20000000                                   │    │
│  │ PidPrimary=pidA    PidSecondary=pidB                │    │
│  │ HandleValue=0x1EC  HandleArray=[0x1EC, 0, 0, 0, 0]  │    │
│  │ Flags=0                                             │    │
│  └─────────────────────────────────────────────────────┘    │
│                          │                                  │
│                          ▼                                  │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ WerSvc.exe (SYSTEM)                                  │   │
│  │                                                      │   │
│  │ FUN_1800156d8: dispatch method 0x20000000            │   │
│  │   → FUN_18001b088                                    │   │
│  │     → FUN_1800149d4: validate H_map_A in pidA ✓      │   │
│  │     → FUN_18001c228:                                 │   │
│  │       → FUN_180016604(NULL, 0x1EC, pidB, &flag)      │   │
│  │         OpenProcess(pidB, 0x50)                      │   │
│  │         DuplicateHandle(pidB_h, 0x1EC, WER, &dup,    │   │
│  │                        0, TRUE, DUPLICATE_SAME_ACCESS)│   │
│  │         ↑ DUPLICATES FROM pidB'S TABLE!               │   │
│  │         ↑ Gets attacker's privileged handle!          │   │
│  │     → FUN_180026608(pidB, pidA, 0x1EC, ...)           │   │
│  │       FUN_180031874: non-protected →                  │   │
│  │         WerpInitiateCrashReporting(...)               │   │
│  │         DuplicateHandle(WER, privileged_handle,       │   │
│  │                        pidB, &out, SYNCHRONIZE, ...)  │   │
│  │         ↑ Pushes handle INTO pidB!                   │   │
│  └──────────────────────────────────────────────────────┘   │
│                          │                                  │
│                          ▼                                  │
│  Process B now has a handle to a privileged object          │
│  (duplicated from its own table via WerSvc)                 │
│                                                             │
│  Wait for WerFault to spawn, inherit handles,               │
│  or directly use the duplicated handle in B                 │
└─────────────────────────────────────────────────────────────┘


Vulnerability Summary
We identified two distinct privilege escalation vulnerabilities in the Windows Error Reporting Service (WerSvc.exe), both stemming from improper validation of client-supplied handle values in ALPC messages. The service runs as SYSTEM and provides an ALPC endpoint for crash reporting. By confusing the service about which process owns a given handle, an attacker can trick SYSTEM into duplicating arbitrary handles from a low-privileged process into a SYSTEM-owned process (WerFault.exe), achieving arbitrary code execution or token theft.

Vulnerability 1: Cross-Process Handle Duplication (FUN_180016604)
Root Cause: The function FUN_180016604 takes a handle value and a PID, then calls OpenProcess on that PID and DuplicateHandle to copy the handle into the WER service. However, it does not verify that the handle value actually belongs to the process identified by PidPrimary. The caller (FUN_18001c228) passes PidSecondary as the source process for the duplication.

The Bug:

Attacker creates Process A and Process B (both running the same low-privileged binary).
Process A creates a file mapping and obtains a handle value (e.g., 0x1EC).
Process B sprays its handle table to ensure a privileged handle sits at index 0x1EC (e.g., a duplicated token handle or a process handle with PROCESS_ALL_ACCESS).
Attacker sends an ALPC message to WerSvc with:
PidPrimary = PID of A
PidSecondary = PID of B
HandleValue = 0x1EC
WerSvc validates that handle 0x1EC exists in Process A (via FUN_1800149d4).
WerSvc then calls FUN_180016604(NULL, 0x1EC, PidSecondary, &flag), which opens Process B and duplicates handle 0x1EC from Process B's handle table.
WerSvc now holds a copy of the privileged handle that was in Process B, believing it to be a validated file mapping from Process A.
Vulnerability 2: Raw Handle Values in Inherit List (FUN_180026b84)
Root Cause: When the target process is protected (checked via NtQueryInformationProcess with ProcessProtectionInformation in FUN_180031874), WerSvc takes a different code path through FUN_180026b84. This function populates the STARTUPINFOEX structure for CreateProcessAsUserW to spawn WerFault.exe. It adds the duplicated handle to the LPPROC_THREAD_ATTRIBUTE_LIST for handle inheritance.

The Bug:
The handle values placed into the inherit list are the raw numeric handle values from the ALPC message (HandleArray[0..4]). Because of Vulnerability 1, these values correspond to handles that were duplicated from the attacker's process B, not the validated mapping from Process A. WerFault.exe inherits these handles with whatever access rights they were duplicated with.

Attack Vector
The complete exploit chain operates as follows:

Setup: The attacker runs two instances of a low-privileged payload binary (Process A and Process B).
Handle Grooming (Process A): Process A creates a pagefile-backed section mapping of size 0xF8 bytes. It maps this section and writes a WER_SHARED_HDR structure where TargetPid is set to the PID of Process B. This passes the validation in FUN_1800149d4. Process A retains the numeric handle value (e.g., 0x1EC).
Handle Grooming (Process B): Process B fills its handle table with cheap objects (Events) until the index corresponding to 0x1EC is reached. It closes the event at that index and immediately creates a "privileged" handle that lands at that index. The ideal payload handle is a duplicated handle to Process B itself with PROCESS_ALL_ACCESS, or a handle to a SYSTEM process if accessible.
ALPC Message Construction: The attacker connects to the WER ALPC port (total message size 0x578 bytes) and sends a message with:
Method = 0x20000000 (crash reporting dispatch)
PidPrimary = PID of A
PidSecondary = PID of B
HandleValue = 0x1EC
HandleArray[0] = 0x1EC
Validation Bypass: WerSvc receives the message in FUN_1800156d8. FUN_180015384 validates the message size (0x578) and method ID. FUN_18001b088 calls FUN_1800149d4, which opens Process A, locates handle 0x1EC, verifies it is a section mapping, and checks that TargetPid in the mapped view matches PidSecondary (Process B). Validation passes.
Handle Confusion: WerSvc calls FUN_18001c228, which calls FUN_180016604. This function opens Process B and duplicates handle 0x1EC from Process B's table. WerSvc now holds the attacker's privileged handle.
Inheritance: WerSvc calls FUN_180026608, which calls FUN_180026b84 (if targeting a protected process) or WerpInitiateCrashReporting. The privileged handle is added to the inherit list for WerFault.exe.
Execution: WerFault.exe spawns as SYSTEM and inherits the privileged handle. If the handle was a PROCESS_ALL_ACCESS handle to Process B, WerFault can now write shellcode into Process B's memory and queue an APC to execute it, resulting in SYSTEM code execution.
Key Functions Analyzed
Function	Role
FUN_1800156d8	Main ALPC dispatch handler.
FUN_180015384	Message validator. Enforces size (0x578/0x510) and method ID whitelist.
FUN_18001b088	Pre-dispatch setup. Calls FUN_1800149d4 to validate the client mapping.
FUN_1800149d4	Validates that HandleValue exists in PidPrimary and is a section mapping. Checks TargetPid in the mapped view.
FUN_18001c228	Calls FUN_180016604 to duplicate the handle. Vulnerable: passes PidSecondary as the source process.
FUN_180016604	Duplicates the handle from the specified process. Vulnerable: trusts the caller's PID without verifying handle ownership.
FUN_180026608	Orchestrates crash reporting. Calls FUN_180031874 to check protection level, then dispatches to FUN_180026b84 or WerpInitiateCrashReporting.
FUN_180031874	Queries ProcessProtectionInformation to determine if the target is a protected process.
FUN_180026b84	Builds STARTUPINFOEX for CreateProcessAsUserW. Vulnerable: adds raw handle values from the ALPC message to the inherit list.
FUN_180015600	Copies 0xF8 bytes from the mapped section into a local buffer. No validation of contents beyond the initial TargetPid check.
Remaining Unknowns
The only missing piece for a fully weaponized exploit is the exact ALPC port name used by WerSvc. The port is created during service initialization and is expected to be in the \RPC Control or \BaseNamedObjects namespace. The enumeration script provided earlier is designed to extract this name from a live system. Once the port name is confirmed, the exploit chain is complete.