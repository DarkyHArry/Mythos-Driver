#include "AntiCheatDriver.h"

/*
 * Substitui PsGetThreadStartAddress (não exportada). Abre um handle para o
 * objeto de thread que já possuímos e consulta o "Win32 start address".
 */
static NTSTATUS AcQueryThreadStartAddress(
    _In_ PETHREAD ThreadObject,
    _Out_ PVOID *StartAddress
) {
    NTSTATUS status;
    HANDLE threadHandle = NULL;
    PVOID startAddress = NULL;
    ULONG returnedLength = 0;

    if (!ThreadObject || !StartAddress) {
        return STATUS_INVALID_PARAMETER;
    }

    *StartAddress = NULL;

    status = ObOpenObjectByPointer(
        ThreadObject,
        OBJ_KERNEL_HANDLE,
        NULL,
        THREAD_QUERY_LIMITED_INFORMATION,
        *PsThreadType,
        KernelMode,
        &threadHandle
    );

    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = ZwQueryInformationThread(
        threadHandle,
        ThreadQuerySetWin32StartAddress,
        &startAddress,
        sizeof(startAddress),
        &returnedLength
    );

    ZwClose(threadHandle);

    if (NT_SUCCESS(status)) {
        *StartAddress = startAddress;
    }

    return status;
}

VOID AcThreadNotifyCallback(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ BOOLEAN Create
) {
    PAC_DRIVER_CONTEXT context = g_DriverContext;
    PAC_TRACKED_PROCESS trackedProcess = NULL;
    PETHREAD threadObject = NULL;
    NTSTATUS status;

    if (!context || !context->Config.EnableThreadMonitoring) {
        return;
    }

    trackedProcess = AcFindTrackedProcess(ProcessId);
    if (!trackedProcess || !trackedProcess->IsGameProcess) {
        return;
    }

    if (Create) {
        status = PsLookupThreadByThreadId(ThreadId, &threadObject);
        if (NT_SUCCESS(status)) {
            KdPrint(("[AntiCheatDriver] Thread Create: PID=%llu, TID=%llu\n",
                     (ULONG64)ProcessId, (ULONG64)ThreadId));

            AcDetectThreadHijack(trackedProcess, threadObject, ThreadId);

            ObDereferenceObject(threadObject);
        }
    } else {
        KdPrint(("[AntiCheatDriver] Thread Exit: PID=%llu, TID=%llu\n",
                 (ULONG64)ProcessId, (ULONG64)ThreadId));
    }
}

NTSTATUS AcDetectThreadHijack(
    _In_ PAC_TRACKED_PROCESS TrackedProcess,
    _In_ PETHREAD ThreadObject,
    _In_ HANDLE ThreadId
) {
    NTSTATUS status;
    PVOID startAddress = NULL;
    PVOID teb = NULL;
    CONTEXT context = {0};
    KAPC_STATE apcState;

    if (!TrackedProcess || !TrackedProcess->ProcessObject) {
        return STATUS_INVALID_PARAMETER;
    }

    KeStackAttachProcess((PKPROCESS)TrackedProcess->ProcessObject, &apcState);

    status = AcQueryThreadStartAddress(ThreadObject, &startAddress);
    if (!NT_SUCCESS(status)) {
        KeUnstackDetachProcess(&apcState);
        return status;
    }

    teb = PsGetThreadTeb(ThreadObject);
    if (teb) {
        __try {
            ProbeForRead(teb, sizeof(PVOID), sizeof(PVOID));
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            KeUnstackDetachProcess(&apcState);
            return STATUS_ACCESS_VIOLATION;
        }
    }

    context.ContextFlags = CONTEXT_FULL;
    status = PsGetContextThread(ThreadObject, &context, KernelMode);
    if (!NT_SUCCESS(status)) {
        KeUnstackDetachProcess(&apcState);
        return status;
    }

    BOOLEAN isSuspicious = FALSE;
    WCHAR description[256] = {0};

    if (startAddress) {
        BOOLEAN inKnownModule = FALSE;
        KIRQL oldIrql;
        KeAcquireSpinLock(&TrackedProcess->Lock, &oldIrql);

        for (ULONG i = 0; i < TrackedProcess->ModuleCount; i++) {
            PVOID moduleBase = TrackedProcess->ModuleList[i];
            PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBase;
            if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE) {
                PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((PUCHAR)moduleBase + dosHeader->e_lfanew);
                if (ntHeaders->Signature == IMAGE_NT_SIGNATURE) {
                    ULONG64 moduleEnd = (ULONG64)moduleBase + ntHeaders->OptionalHeader.SizeOfImage;
                    if ((ULONG64)startAddress >= (ULONG64)moduleBase && (ULONG64)startAddress < moduleEnd) {
                        inKnownModule = TRUE;
                        break;
                    }
                }
            }
        }

        KeReleaseSpinLock(&TrackedProcess->Lock, oldIrql);

        if (!inKnownModule) {
            isSuspicious = TRUE;
            RtlStringCchPrintfW(description, 256,
                L"Thread start address 0x%p not in known module", startAddress);
        }
    }

    if (isSuspicious) {
        AcRecordViolation(AC_VIOLATION_THREAD_HIJACK, TrackedProcess->ProcessId,
                         startAddress, (ULONG64)ThreadId, 0, description);
    }

    KeUnstackDetachProcess(&apcState);
    return STATUS_SUCCESS;
}