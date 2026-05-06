// ============================================================
// Project Phantom - Phase 4: PhantomGuard Kernel Driver
// FIXED VERSION — correct extended callback signature
// Author: Proma Roy
// Course: CSC I0420 - Secure Operating Systems
// ============================================================

#include <ntddk.h>

// ── Global Variables ─────────────────────────────────────────
volatile LONG g_ProcessEventCount = 0;
volatile LONG g_ProcessCreateCount = 0;
volatile LONG g_ProcessTerminateCount = 0;
BOOLEAN g_CallbackRegistered = FALSE;

// ── Forward Declarations ──────────────────────────────────────
VOID PhantomProcessNotifyCallbackEx(
    PEPROCESS Process,
    HANDLE ProcessId,
    PPS_CREATE_NOTIFY_INFO CreateInfo);

VOID PhantomGuardUnload(PDRIVER_OBJECT DriverObject);

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath);

// ── Process Notify Callback (Extended Version) ────────────────
// Uses PsSetCreateProcessNotifyRoutineEx compatible signature
// This fixes the C4113 warning that caused the BSOD
VOID PhantomProcessNotifyCallbackEx(
    PEPROCESS Process,
    HANDLE ProcessId,
    PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    UNREFERENCED_PARAMETER(Process);

    InterlockedIncrement(&g_ProcessEventCount);

    if (CreateInfo != NULL) {
        InterlockedIncrement(&g_ProcessCreateCount);

        if (CreateInfo->ImageFileName) {
            DbgPrintEx(
                DPFLTR_IHVDRIVER_ID,
                DPFLTR_INFO_LEVEL,
                "[PhantomGuard] CREATED | PID:%llu | %wZ | Total:%d\n",
                (ULONG64)(ULONG_PTR)ProcessId,
                CreateInfo->ImageFileName,
                g_ProcessEventCount);
        }
        else {
            DbgPrintEx(
                DPFLTR_IHVDRIVER_ID,
                DPFLTR_INFO_LEVEL,
                "[PhantomGuard] CREATED | PID:%llu | <unknown> | Total:%d\n",
                (ULONG64)(ULONG_PTR)ProcessId,
                g_ProcessEventCount);
        }
    }
    else {
        InterlockedIncrement(&g_ProcessTerminateCount);

        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_INFO_LEVEL,
            "[PhantomGuard] TERMINATED | PID:%llu | Total:%d\n",
            (ULONG64)(ULONG_PTR)ProcessId,
            g_ProcessEventCount);
    }
}

// ── Driver Unload ─────────────────────────────────────────────
VOID PhantomGuardUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[PhantomGuard] Unloading...\n");

    if (g_CallbackRegistered) {
        PsSetCreateProcessNotifyRoutineEx(
            PhantomProcessNotifyCallbackEx,
            TRUE);
        g_CallbackRegistered = FALSE;

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "[PhantomGuard] Callback unregistered\n");
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[PhantomGuard] Stats: Created=%d Terminated=%d Total=%d\n",
        g_ProcessCreateCount,
        g_ProcessTerminateCount,
        g_ProcessEventCount);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[PhantomGuard] Unload complete\n");
}

// ── Driver Entry ──────────────────────────────────────────────
NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[PhantomGuard] ============================\n");
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[PhantomGuard] Project Phantom - Phase 4\n");
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[PhantomGuard] Loading PhantomGuard...\n");
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[PhantomGuard] ============================\n");

    DriverObject->DriverUnload = PhantomGuardUnload;

    // use Extended version — fixes C4113 signature mismatch
    NTSTATUS status = PsSetCreateProcessNotifyRoutineEx(
        PhantomProcessNotifyCallbackEx,
        FALSE);

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
            "[PhantomGuard] ERROR: Registration failed 0x%08X\n",
            status);
        return status;
    }

    g_CallbackRegistered = TRUE;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[PhantomGuard] Callback registered OK\n");
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[PhantomGuard] Monitoring ALL process events\n");
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[PhantomGuard] Independent of ETW\n");
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "[PhantomGuard] PhantomGuard is ACTIVE\n");

    return STATUS_SUCCESS;
}