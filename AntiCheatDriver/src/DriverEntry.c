#include "AntiCheatDriver.h"

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
) {
    NTSTATUS status = STATUS_SUCCESS;
    PAC_DRIVER_CONTEXT context = NULL;
    WDF_DRIVER_CONFIG config;
    WDF_OBJECT_ATTRIBUTES driverAttributes;

    UNREFERENCED_PARAMETER(RegistryPath);

    KdPrint(("[AntiCheatDriver] DriverEntry: Loading anti-cheat driver\n"));

    WDF_DRIVER_CONFIG_INIT(&config, WDF_NO_EVENT_CALLBACK);
    config.DriverInitFlags |= WdfDriverInitNonPnpDriver;
    config.EvtDriverUnload = DriverUnload;

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&driverAttributes, AC_DRIVER_CONTEXT);
    driverAttributes.EvtCleanupCallback = NULL;

    status = WdfDriverCreate(DriverObject, RegistryPath, &driverAttributes, &config, &g_WdfDriver);
    if (!NT_SUCCESS(status)) {
        KdPrint(("[AntiCheatDriver] WdfDriverCreate failed: 0x%08X\n", status));
        return status;
    }

    context = AC_GET_DRIVER_CONTEXT(g_WdfDriver);
    g_DriverContext = context;

    InitializeListHead(&context->TrackedProcessList);
    KeInitializeSpinLock(&context->ProcessListLock);
    KeInitializeSpinLock(&context->ViolationLock);
    context->ViolationCount = 0;

    RtlInitUnicodeString(&context->DeviceName, AC_DEVICE_NAME);
    RtlInitUnicodeString(&context->DosDeviceName, AC_DOS_DEVICE_NAME);

    context->Config.EnableProcessMonitoring = TRUE;
    context->Config.EnableThreadMonitoring = TRUE;
    context->Config.EnableImageLoadMonitoring = TRUE;
    context->Config.EnableMemoryScanning = TRUE;
    context->Config.EnableIntegrityChecks = TRUE;
    context->Config.BlockSuspiciousModules = TRUE;
    context->Config.LogViolations = TRUE;
    context->Config.ScanIntervalMs = 5000;
    context->Config.MaxViolations = MAX_VIOLATIONS;

    status = AcInitializeAdvancedDetection();
    if (!NT_SUCCESS(status)) {
        KdPrint(("[AntiCheatDriver] Failed to initialize advanced detection: 0x%08X\n", status));
        return status;
    }

    status = AcCreateDevice(context, g_WdfDriver);
    if (!NT_SUCCESS(status)) {
        KdPrint(("[AntiCheatDriver] Failed to create device: 0x%08X\n", status));
        return status;
    }

    /*
     * O device é um control device do KMDF: os IRPs (inclusive
     * IRP_MJ_DEVICE_CONTROL) são entregues à fila criada em AcCreateDevice,
     * cujo callback é AcEvtIoDeviceControl. Não sobrescrever MajorFunction.
     */

    status = AcRegisterCallbacks(context);
    if (!NT_SUCCESS(status)) {
        KdPrint(("[AntiCheatDriver] Failed to register callbacks: 0x%08X\n", status));
        AcCleanupDevice(context);
        return status;
    }

    KeInitializeDpc(&context->ScanDpc, AcScanTimerCallback, context);
    KeInitializeTimer(&context->ScanTimer);
    context->ScanTimerActive = FALSE;

    LARGE_INTEGER dueTime;
    dueTime.QuadPart = -10000LL * context->Config.ScanIntervalMs;
    KeSetTimer(&context->ScanTimer, dueTime, &context->ScanDpc);
    context->ScanTimerActive = TRUE;

    KdPrint(("[AntiCheatDriver] Driver loaded successfully\n"));
    return STATUS_SUCCESS;
}

VOID DriverUnload(_In_ WDFDRIVER Driver) {
    PAC_DRIVER_CONTEXT context = g_DriverContext;
    PLIST_ENTRY entry;
    PAC_TRACKED_PROCESS trackedProcess;

    UNREFERENCED_PARAMETER(Driver);

    KdPrint(("[AntiCheatDriver] DriverUnload: Unloading anti-cheat driver\n"));

    if (context && context->ScanTimerActive) {
        KeCancelTimer(&context->ScanTimer);
        context->ScanTimerActive = FALSE;
    }

    if (context) {
        AcUnregisterCallbacks(context);
        AcCleanupAdvancedDetection();

        while (!IsListEmpty(&context->TrackedProcessList)) {
            entry = RemoveHeadList(&context->TrackedProcessList);
            trackedProcess = CONTAINING_RECORD(entry, AC_TRACKED_PROCESS, ListEntry);
            ExFreePoolWithTag(trackedProcess, AC_TAG);
        }

        AcCleanupDevice(context);
    }

    g_DriverContext = NULL;
    g_WdfDriver = NULL;

    KdPrint(("[AntiCheatDriver] Driver unloaded\n"));
}