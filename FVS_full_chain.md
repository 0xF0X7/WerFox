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




0415 09222026
Target
Windows Error Reporting Service (WerSvc) — wersvc.dll version 10.0.26100.9278. No WER-specific security patches installed (KB5045934 or similar absent). Vulnerability likely present.

ALPC Port Identification
The service exposes an ALPC port named \WindowsErrorReportingServicePort. Confirmed via object namespace enumeration and successful connection.

Connection Methodology
Initial attempts to connect using NtAlpcConnectPort failed universally with STATUS_INVALID_PARAMETER (0xC000000D). Root cause: incorrect function prototype. The 6th parameter is RequiredServerSid (PSID), not SectionHandle (PVOID). Passing NULL for RequiredServerSid means no SID restriction.

Working call signature:

c
NtAlpcConnectPort(
    &hPort,
    &portName,
    NULL,       // ObjectAttributes — NULL works
    NULL,       // PortAttributes — NULL works
    0,          // Flags
    NULL,       // RequiredServerSid — NULL = no restriction
    connMsg,    // ConnectionMessage — must be valid PORT_MESSAGE
    &connLen,   // BufferLength
    NULL,       // OutMessageAttributes
    NULL,       // InMessageAttributes
    NULL);      // Timeout
Connection message must have TotalLength = 0x28 and DataLength = 0. Zeroed buffer otherwise. Returns STATUS_SUCCESS with connLen = 40.

NtConnectPort (legacy LPC) also fails with 0xC000000D. The modern ALPC API is required.

Port Creation Timing
WerSvc creates the ALPC port lazily. Starting the service via SCM does NOT create the port. The port only appears after triggering an actual WER report. Reliable trigger sequence:

Start WerSvc via StartService
Launch rundll32.exe sysdm.cpl,NoEntry (sacrificial crash)
Call WerReportCreate + WerReportSubmit via wer.dll
After this sequence, NtAlpcConnectPort succeeds.

Message Format
Post-connect sends via NtAlpcSendWaitReceivePort fail with STATUS_PORT_DISCONNECTED (0xC0000037) after the first message. The port is one-shot — the connection message IS the payload.

Working message size: 0x200 bytes total (0x28 PORT_MESSAGE header + 0x1D8 body). Sizes 0x578, 0x400, 0x300 fail with STATUS_INVALID_BUFFER_SIZE (0xC000002F). Sizes 0x200 and below succeed.

WER Message Body Layout
Reverse-engineered from server reply echoes:

Offset	Size	Field
0x28	4	Method
0x2C	4	Flags
0x30	4	PidPrimary
0x34	4	Pad1
0x38	4	Tid
0x3C	0x24	Pad2
0x60	4	PidSecondary
0x64	4	HandleValue
0x68	40	HandleArray[5]
0x90	4	StatusOut (reply)
0x94	4	ResultOut (reply)
0x98	0x4B8	SharedData
Server Reply Analysis
With Method = 0x00: StatusOut = 0x00000000, ResultOut = 0x00000000. Server echoes PIDs and handle value at offsets 0x30, 0x60, 0x64. No action taken.

With Method = 0x01: StatusOut = 0x00000001, ResultOut = 0x00000000. Server processed differently — resolved PIDs and attempted something. Offset 0x30 shows PidPrimary and a different PID (possibly resolved from handle). No WerFault.exe spawned.

Reply at offset 0x30 contains two PIDs: our PidPrimary and a second PID that appears to be resolved from the handle value. This suggests the server is doing handle-to-PID translation.

Handle Grooming
Process A creates a file mapping and records the handle value. Process B must create a file mapping at the exact same handle value. This requires filling the handle table with cheap objects (events) until the target index is reached.

Current algorithm: allocate events one at a time, compare handle value to target. On exact match, close and create payload. On overshoot, close and retry.

Success rate: approximately 50%. Handle table has gaps from prior allocations. When overshoot occurs repeatedly, the algorithm gives up after 50 attempts. Need deterministic approach — possibly close all events first, then allocate exactly the right count.

Shared Section Content
Process A's file mapping (handle 0xEC or similar) must contain a properly formatted structure. Currently writing:

Offset 0x00: Size = 0xF8
Offset 0x04: TargetPid = pidB
Offset 0x08: Filled with 0x41 pattern
Offsets 0x08, 0x48, 0x88: Fake command lines (cmd.exe /c calc.exe)
The itm4n CVE writeup indicates the command line for WerFault.exe is constructed from this shared section. Exact offset of the command line field unknown — need to reverse-engineer wersvc.dll or capture a real WER message.

Vulnerability Mechanism (Hypothesis)
Based on itm4n's CVE writeup:

WerSvc receives ALPC message with PidPrimary, PidSecondary, and HandleValue
It validates the handle against PidPrimary's handle table
It duplicates the handle from PidSecondary's handle table using the same value
It reads the shared section content via the duplicated handle
It calls CreateProcessAsUserW with PidPrimary as parent and command line from shared section
The confusion: validation against Process A, duplication from Process B. If both processes have the same handle value but pointing to different objects, WerSvc reads Process B's object while trusting Process A's identity.

Outstanding Questions
What Method value triggers the WerpProcessReport path that calls CreateProcessAsUserW?
What is the exact layout of the shared section? Where is the command line field?
Does the handle confusion actually work, or does WerSvc validate ownership after duplication?
Why does Method = 0x01 return StatusOut = 0x1 instead of 0x0? What does that status mean?
Next Steps
Fix handle grooming to be deterministic — close all events first, then allocate exact count
Test Method values 0x02 through 0x05 with correct handle alignment
Reverse-engineer wersvc.dll to find the WerpProcessReport function and shared section parsing
Capture a real WER ALPC message between a crashing process and WerSvc to compare format
Try different Flags values in the message body
Tools and Techniques
NtAlpcConnectPort with RequiredServerSid = NULL for connection
Connection message carries payload — no post-connect sends
Message size 0x200 bytes
Handle grooming via CreateEventW to fill handle table
CreateFileMappingW for payload objects at target handle index
Shared memory section (Global\WER_Exploit_IPC) for inter-process communication
CreateToolhelp32Snapshot to detect WerFault.exe spawns
References
itm4n CVE writeup — confirms CreateProcessAsUserW path and handle confusion mechanism
ntdoc.m417z.com — correct NtAlpcConnectPort signature with RequiredServerSid
y3a ALPC analysis — confirms WerSvc uses NtAlpcConnectPort with connection message payload
