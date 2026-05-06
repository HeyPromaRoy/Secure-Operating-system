#include <ntddk.h>>

DRIVER_UNLOAD driverunload;

void DriverUnload(PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);
	DbgPrint(("[ProjectPhantom] Driver unloaded\n");
}

NTSTATUS DriverEntry(
	_IN_ PDRIVER_OBJECT DriverObject,
	_IN_ PUNICODE_STRING RegistryPath)
{
		UNREFERENCED_PARAMETER(RegistryPath);
		DriverObject->DriverUnload = DriverUnload;

		DbgPrint(("[ProjectPhantom] Driver loaded successfully\n");
		DbgPrint(("[ProjectPhantom] ETW Phantom research initialized\n));

			return STATUS_SUCCESS;
}


