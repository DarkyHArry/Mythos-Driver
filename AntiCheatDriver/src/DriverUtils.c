#include "AntiCheatDriver.h"

PAC_DRIVER_CONTEXT g_DriverContext = NULL;
WDFDRIVER g_WdfDriver = NULL;

NTSTATUS AcCreateDevice(PAC_DRIVER_CONTEXT Context, WDFDRIVER Driver) {
    NTSTATUS status;
    PWDFDEVICE_INIT deviceInit = NULL;
    WDF_OBJECT_ATTRIBUTES deviceAttributes;
    WDF_IO_QUEUE_CONFIG queueConfig;
    WDFQUEUE queue;

    if (!Context || !Driver) {
        return STATUS_INVALID_PARAMETER;
    }

    deviceInit = WdfControlDeviceInitAllocate(Driver, &SDDL_DEVOBJ_SYS_ALL_ADM_RWX_WORLD_RWX_RES_RWX);
    if (!deviceInit) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    WdfDeviceInitSetDeviceType(deviceInit, FILE_DEVICE_UNKNOWN);
    WdfDeviceInitSetCharacteristics(deviceInit, FILE_DEVICE_SECURE_OPEN, TRUE);
    WdfDeviceInitSetExclusive(deviceInit, TRUE);

    status = WdfDeviceInitAssignName(deviceInit, &Context->DeviceName);
    if (!NT_SUCCESS(status)) {
        WdfDeviceInitFree(deviceInit);
        return status;
    }

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&deviceAttributes, AC_DRIVER_CONTEXT);
    deviceAttributes.EvtCleanupCallback = NULL;

    status = WdfDeviceCreate(&deviceInit, &deviceAttributes, &Context->WdfDevice);
    if (!NT_SUCCESS(status)) {
        WdfDeviceInitFree(deviceInit);
        return status;
    }

    Context->DeviceObject = WdfDeviceWdmGetDeviceObject(Context->WdfDevice);

    status = WdfDeviceCreateSymbolicLink(Context->WdfDevice, &Context->DosDeviceName);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchParallel);
    queueConfig.EvtIoDeviceControl = AcEvtIoDeviceControl;

    status = WdfIoQueueCreate(Context->WdfDevice, &queueConfig, WDF_NO_OBJECT_ATTRIBUTES, &queue);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    InitializeListHead(&Context->TrackedProcessList);
    KeInitializeSpinLock(&Context->ProcessListLock);

    Context->ViolationCount = 0;
    KeInitializeSpinLock(&Context->ViolationLock);

    Context->Config.EnableProcessMonitoring = TRUE;
    Context->Config.EnableThreadMonitoring = TRUE;
    Context->Config.EnableImageLoadMonitoring = TRUE;
    Context->Config.EnableMemoryScanning = TRUE;
    Context->Config.EnableIntegrityChecks = TRUE;
    Context->Config.BlockSuspiciousModules = TRUE;
    Context->Config.LogViolations = TRUE;
    Context->Config.ScanIntervalMs = 5000;
    Context->Config.MaxViolations = MAX_VIOLATIONS;

    KeInitializeDpc(&Context->ScanDpc, AcScanTimerCallback, Context);
    KeInitializeTimer(&Context->ScanTimer);
    Context->ScanTimerActive = FALSE;

    return STATUS_SUCCESS;
}

VOID AcCleanupDevice(PAC_DRIVER_CONTEXT Context) {
    if (!Context) {
        return;
    }

    if (Context->ScanTimerActive) {
        KeCancelTimer(&Context->ScanTimer);
        Context->ScanTimerActive = FALSE;
    }

    if (Context->WdfDevice) {
        WdfObjectDelete(Context->WdfDevice);
        Context->WdfDevice = NULL;
    }

    Context->DeviceObject = NULL;
}

NTSTATUS AcRegisterCallbacks(PAC_DRIVER_CONTEXT Context) {
    NTSTATUS status;

    if (!Context) {
        return STATUS_INVALID_PARAMETER;
    }

    status = PsSetCreateProcessNotifyRoutineEx(AcProcessNotifyCallbackEx, FALSE);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    Context->ProcessNotifyHandle = (PVOID)1;

    status = PsSetCreateThreadNotifyRoutine(AcThreadNotifyCallback);
    if (!NT_SUCCESS(status)) {
        PsSetCreateProcessNotifyRoutineEx(AcProcessNotifyCallbackEx, TRUE);
        Context->ProcessNotifyHandle = NULL;
        return status;
    }
    Context->ThreadNotifyHandle = (PVOID)1;

    status = PsSetLoadImageNotifyRoutine(AcImageLoadCallback);
    if (!NT_SUCCESS(status)) {
        PsSetCreateThreadNotifyRoutine(AcThreadNotifyCallback);
        PsSetCreateProcessNotifyRoutineEx(AcProcessNotifyCallbackEx, TRUE);
        Context->ThreadNotifyHandle = NULL;
        Context->ProcessNotifyHandle = NULL;
        return status;
    }
    Context->ImageLoadNotifyHandle = (PVOID)1;

    return STATUS_SUCCESS;
}

VOID AcUnregisterCallbacks(PAC_DRIVER_CONTEXT Context) {
    if (!Context) {
        return;
    }

    if (Context->ImageLoadNotifyHandle) {
        PsRemoveLoadImageNotifyRoutine(AcImageLoadCallback);
        Context->ImageLoadNotifyHandle = NULL;
    }

    if (Context->ThreadNotifyHandle) {
        PsRemoveCreateThreadNotifyRoutine(AcThreadNotifyCallback);
        Context->ThreadNotifyHandle = NULL;
    }

    if (Context->ProcessNotifyHandle) {
        PsSetCreateProcessNotifyRoutineEx(AcProcessNotifyCallbackEx, TRUE);
        Context->ProcessNotifyHandle = NULL;
    }
}

VOID AcScanTimerCallback(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
) {
    PAC_DRIVER_CONTEXT context = (PAC_DRIVER_CONTEXT)DeferredContext;
    PLIST_ENTRY entry;
    PAC_TRACKED_PROCESS trackedProcess;
    KIRQL oldIrql;
    LARGE_INTEGER dueTime;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (!context || !context->Config.EnableMemoryScanning) {
        return;
    }

    KeAcquireSpinLock(&context->ProcessListLock, &oldIrql);

    for (entry = context->TrackedProcessList.Flink;
         entry != &context->TrackedProcessList;
         entry = entry->Flink) {

        trackedProcess = CONTAINING_RECORD(entry, AC_TRACKED_PROCESS, ListEntry);

        if (trackedProcess->IsProtected || trackedProcess->IsGameProcess) {
            AcScanProcessMemory(trackedProcess);
            AcCheckModuleIntegrity(trackedProcess);
        }
    }

    KeReleaseSpinLock(&context->ProcessListLock, oldIrql);

    if (context->ScanTimerActive) {
        dueTime.QuadPart = -((LONG64)context->Config.ScanIntervalMs * 10000);
        KeSetTimer(&context->ScanTimer, dueTime, &context->ScanDpc);
    }
}

BOOLEAN AcIsGameProcess(_In_ PCWSTR ImageName) {
    static const WCHAR* gameProcesses[] = {
        L"game.exe",
        L"client.exe",
        L"launcher.exe",
        L"steam.exe",
        L"epicgameslauncher.exe",
        L"battle.net.exe",
        L"origin.exe",
        L"uplay.exe",
        L"gog.exe",
        L"valorant.exe",
        L"cs2.exe",
        L"csgo.exe",
        L"fortnite.exe",
        L"apex.exe",
        L"pubg.exe",
        L"warzone.exe",
        L"overwatch.exe",
        L"league of legends.exe",
        L"dota2.exe",
        L"rainbow six siege.exe",
        L"destiny2.exe"
    };

    UNICODE_STRING name;
    UNICODE_STRING lowerName;
    ULONG i;
    BOOLEAN found = FALSE;

    if (!ImageName || ImageName[0] == L'\0') {
        return FALSE;
    }

    RtlInitUnicodeString(&name, ImageName);

    lowerName.Buffer = NULL;
    lowerName.Length = 0;
    lowerName.MaximumLength = 0;

    if (!NT_SUCCESS(RtlDowncaseUnicodeString(&lowerName, &name, TRUE))) {
        return FALSE;
    }

    for (i = 0; i < ARRAYSIZE(gameProcesses); i++) {
        if (wcsstr(lowerName.Buffer, gameProcesses[i])) {
            found = TRUE;
            break;
        }
    }

    RtlFreeUnicodeString(&lowerName);
    return found;
}

VOID AcRecordViolation(
    _In_ AC_VIOLATION_TYPE Type,
    _In_ HANDLE ProcessId,
    _In_opt_ PVOID Address,
    _In_ ULONG64 Value1,
    _In_ ULONG64 Value2,
    _In_ PCWSTR Description
) {
    PAC_DRIVER_CONTEXT context = g_DriverContext;
    PAC_VIOLATION violation;
    KIRQL oldIrql;
    LARGE_INTEGER systemTime;

    if (!context) {
        return;
    }

    KeAcquireSpinLock(&context->ViolationLock, &oldIrql);

    if (context->ViolationCount >= MAX_VIOLATIONS) {
        KeReleaseSpinLock(&context->ViolationLock, oldIrql);
        return;
    }

    violation = &context->Violations[context->ViolationCount];
    violation->Type = Type;
    violation->ProcessId = ProcessId;
    violation->Address = Address;
    violation->Value1 = Value1;
    violation->Value2 = Value2;

    KeQuerySystemTime(&systemTime);
    violation->Timestamp = systemTime.QuadPart;

    if (Description) {
        RtlStringCbCopyW(violation->Description, sizeof(violation->Description), Description);
    } else {
        violation->Description[0] = L'\0';
    }

    context->ViolationCount++;

    KeReleaseSpinLock(&context->ViolationLock, oldIrql);

    if (context->Config.LogViolations) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[AntiCheat] Violation: Type=%d, PID=%p, Addr=%p, Desc=%ws\n",
            Type, ProcessId, Address, Description ? Description : L"");
    }
}