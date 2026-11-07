#include "AntiCheatDriver.h"

VOID AcProcessNotifyCallback(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
) {
    PAC_DRIVER_CONTEXT context = g_DriverContext;
    PAC_TRACKED_PROCESS trackedProcess = NULL;
    WCHAR imageName[260] = {0};

    if (!context || !context->Config.EnableProcessMonitoring) {
        return;
    }

    if (CreateInfo) {
        if (CreateInfo->ImageFileName) {
            RtlCopyMemory(imageName, CreateInfo->ImageFileName->Buffer,
                         min(CreateInfo->ImageFileName->Length, sizeof(imageName) - sizeof(WCHAR)));
        }

        KdPrint(("[AntiCheatDriver] Process Create: PID=%llu, Name=%ws\n",
                 (ULONG64)ProcessId, imageName));

        if (AcIsGameProcess(imageName)) {
            trackedProcess = AcCreateTrackedProcess(ProcessId, Process, imageName);
            if (trackedProcess) {
                trackedProcess->IsGameProcess = TRUE;
                trackedProcess->IsProtected = TRUE;
                KdPrint(("[AntiCheatDriver] Game process detected and protected: %ws (PID=%llu)\n",
                         imageName, (ULONG64)ProcessId));
            }
        } else if (wcsstr(imageName, L"cheat") || wcsstr(imageName, L"hack") ||
                   wcsstr(imageName, L"inject") || wcsstr(imageName, L"trainer")) {
            trackedProcess = AcCreateTrackedProcess(ProcessId, Process, imageName);
            if (trackedProcess) {
                trackedProcess->IsProtected = FALSE;
                KdPrint(("[AntiCheatDriver] Suspicious process detected: %ws (PID=%llu)\n",
                         imageName, (ULONG64)ProcessId));
            }
        }
    } else {
        KdPrint(("[AntiCheatDriver] Process Exit: PID=%llu\n", (ULONG64)ProcessId));
        AcRemoveTrackedProcess(ProcessId);
    }
}

VOID AcProcessNotifyCallbackEx(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
) {
    AcProcessNotifyCallback(Process, ProcessId, CreateInfo);
}

PAC_TRACKED_PROCESS AcFindTrackedProcess(HANDLE ProcessId) {
    PAC_DRIVER_CONTEXT context = g_DriverContext;
    PLIST_ENTRY entry;
    PAC_TRACKED_PROCESS trackedProcess = NULL;
    KIRQL oldIrql;

    if (!context) return NULL;

    KeAcquireSpinLock(&context->ProcessListLock, &oldIrql);

    for (entry = context->TrackedProcessList.Flink;
         entry != &context->TrackedProcessList;
         entry = entry->Flink) {
        trackedProcess = CONTAINING_RECORD(entry, AC_TRACKED_PROCESS, ListEntry);
        if (trackedProcess->ProcessId == ProcessId) {
            KeReleaseSpinLock(&context->ProcessListLock, oldIrql);
            return trackedProcess;
        }
    }

    KeReleaseSpinLock(&context->ProcessListLock, oldIrql);
    return NULL;
}

PAC_TRACKED_PROCESS AcCreateTrackedProcess(HANDLE ProcessId, PEPROCESS ProcessObject, PCWSTR ImageName) {
    PAC_DRIVER_CONTEXT context = g_DriverContext;
    PAC_TRACKED_PROCESS trackedProcess = NULL;
    KIRQL oldIrql;
    LARGE_INTEGER createTime;

    if (!context) return NULL;

    trackedProcess = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(AC_TRACKED_PROCESS), AC_TAG);
    if (!trackedProcess) {
        return NULL;
    }

    RtlZeroMemory(trackedProcess, sizeof(AC_TRACKED_PROCESS));
    trackedProcess->ProcessId = ProcessId;
    trackedProcess->ProcessObject = ProcessObject;
    ObReferenceObject(ProcessObject);

    KeQuerySystemTime(&createTime);
    trackedProcess->ProcessCreateTime = createTime.QuadPart;

    if (ImageName) {
        RtlStringCchCopyW(trackedProcess->ImageName, 260, ImageName);
    }

    trackedProcess->IsProtected = FALSE;
    trackedProcess->IsGameProcess = FALSE;
    trackedProcess->ModuleCount = 0;
    KeInitializeSpinLock(&trackedProcess->Lock);
    InitializeListHead(&trackedProcess->ListEntry);

    KeAcquireSpinLock(&context->ProcessListLock, &oldIrql);
    InsertTailList(&context->TrackedProcessList, &trackedProcess->ListEntry);
    KeReleaseSpinLock(&context->ProcessListLock, oldIrql);

    AcUpdateProcessModules(trackedProcess);

    return trackedProcess;
}

VOID AcRemoveTrackedProcess(HANDLE ProcessId) {
    PAC_DRIVER_CONTEXT context = g_DriverContext;
    PAC_TRACKED_PROCESS trackedProcess = NULL;
    KIRQL oldIrql;

    if (!context) return;

    KeAcquireSpinLock(&context->ProcessListLock, &oldIrql);

    PLIST_ENTRY entry;
    for (entry = context->TrackedProcessList.Flink;
         entry != &context->TrackedProcessList;
         entry = entry->Flink) {
        trackedProcess = CONTAINING_RECORD(entry, AC_TRACKED_PROCESS, ListEntry);
        if (trackedProcess->ProcessId == ProcessId) {
            RemoveEntryList(entry);
            break;
        }
    }

    KeReleaseSpinLock(&context->ProcessListLock, oldIrql);

    if (trackedProcess && trackedProcess->ProcessId == ProcessId) {
        if (trackedProcess->ProcessObject) {
            ObDereferenceObject(trackedProcess->ProcessObject);
        }
        ExFreePoolWithTag(trackedProcess, AC_TAG);
    }
}

VOID AcUpdateProcessModules(PAC_TRACKED_PROCESS TrackedProcess) {
    NTSTATUS status;
    PRTL_PROCESS_MODULES modules = NULL;
    ULONG bufferSize = 0;
    ULONG i;
    KIRQL oldIrql;

    if (!TrackedProcess) return;

    KeAcquireSpinLock(&TrackedProcess->Lock, &oldIrql);

    status = ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &bufferSize);
    if (status == STATUS_INFO_LENGTH_MISMATCH) {
        modules = ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSize, AC_TAG);
        if (modules) {
            status = ZwQuerySystemInformation(SystemModuleInformation, modules, bufferSize, NULL);
            if (NT_SUCCESS(status)) {
                TrackedProcess->ModuleCount = 0;
                for (i = 0; i < modules->NumberOfModules && i < MAX_MODULES_PER_PROCESS; i++) {
                    TrackedProcess->ModuleList[i] = modules->Modules[i].ImageBase;
                    TrackedProcess->ModuleHashes[i] = AcCalculateModuleHash(
                        modules->Modules[i].ImageBase,
                        modules->Modules[i].ImageSize
                    );
                    TrackedProcess->ModuleCount++;
                }
            }
            ExFreePoolWithTag(modules, AC_TAG);
        }
    }

    KeReleaseSpinLock(&TrackedProcess->Lock, oldIrql);
}