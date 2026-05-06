#include <ntddk.h>

DRIVER_UNLOAD DriverUnload;
void DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    DbgPrint("[ProjectPhantom] Driver unloaded\n");
}

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    DriverObject->DriverUnload = DriverUnload;

    DbgPrint("[ProjectPhantom] Driver loaded successfully!\n");
    DbgPrint("[ProjectPhantom] ETW Phantom research initialized\n");

    return STATUS_SUCCESS;
}