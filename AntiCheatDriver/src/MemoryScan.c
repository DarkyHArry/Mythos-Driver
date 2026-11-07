#include "AntiCheatDriver.h"

typedef enum _MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation = 0,
    MemoryWorkingSetInformation = 1,
    MemoryMappedFilenameInformation = 2,
    MemoryRegionInformation = 3,
    MemoryWorkingSetExInformation = 4,
    MemorySharedCommitInformation = 5,
    MemoryImageInformation = 6,
    MemoryRegionInformationEx = 7,
    MemoryPrivilegedBasicInformation = 8,
    MemoryEnclaveImageInformation = 9,
    MemoryBasicInformationCapped = 10
} MEMORY_INFORMATION_CLASS;

typedef struct _MEMORY_BASIC_INFORMATION {
    PVOID BaseAddress;
    PVOID AllocationBase;
    ULONG AllocationProtect;
    ULONG PartitionId;
    SIZE_T RegionSize;
    ULONG State;
    ULONG Protect;
    ULONG Type;
} MEMORY_BASIC_INFORMATION, *PMEMORY_BASIC_INFORMATION;

NTSTATUS AcScanProcessMemory(PAC_TRACKED_PROCESS TrackedProcess) {
    NTSTATUS status = STATUS_SUCCESS;
    PAC_DRIVER_CONTEXT context = g_DriverContext;
    KAPC_STATE apcState;
    PVOID address = NULL;
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T regionSize;
    ULONG64 totalScanned = 0;
    ULONG violations = 0;

    if (!TrackedProcess || !TrackedProcess->ProcessObject || !context) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!context->Config.EnableMemoryScanning) {
        return STATUS_SUCCESS;
    }

    KeStackAttachProcess((PKPROCESS)TrackedProcess->ProcessObject, &apcState);

    address = (PVOID)MM_LOWEST_USER_ADDRESS;

    while (address < (PVOID)MM_HIGHEST_USER_ADDRESS) {
        status = ZwQueryVirtualMemory(ZwCurrentProcess(), address,
                                     MemoryBasicInformation, &mbi, sizeof(mbi), &regionSize);

        if (!NT_SUCCESS(status)) {
            address = (PUCHAR)address + PAGE_SIZE;
            continue;
        }

        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {

            status = AcScanMemoryRegion(TrackedProcess, mbi.BaseAddress, mbi.RegionSize);
            if (status == STATUS_DATA_ERROR) {
                violations++;
            }
            totalScanned += mbi.RegionSize;
        }

        address = (PUCHAR)mbi.BaseAddress + mbi.RegionSize;
    }

    KeUnstackDetachProcess(&apcState);

    KdPrint(("[AntiCheatDriver] Memory scan complete: PID=%llu, Scanned=%llu bytes, Violations=%u\n",
             (ULONG64)TrackedProcess->ProcessId, totalScanned, violations));

    return violations > 0 ? STATUS_DATA_ERROR : STATUS_SUCCESS;
}

NTSTATUS AcScanMemoryRegion(PAC_TRACKED_PROCESS TrackedProcess, PVOID BaseAddress, SIZE_T RegionSize) {
    NTSTATUS status;
    PAC_DRIVER_CONTEXT context = g_DriverContext;
    PVOID buffer = NULL;
    SIZE_T bytesRead = 0;
    ULONG64 hash = 0;

    if (!TrackedProcess || !context) return STATUS_INVALID_PARAMETER;

    buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, RegionSize, AC_TAG);
    if (!buffer) return STATUS_INSUFFICIENT_RESOURCES;

    status = MmCopyVirtualMemory(TrackedProcess->ProcessObject, BaseAddress,
                                 PsGetCurrentProcess(), buffer,
                                 RegionSize, KernelMode, &bytesRead);

    if (NT_SUCCESS(status) && bytesRead == RegionSize) {
        hash = AcCalculateModuleHash(BaseAddress, (ULONG)RegionSize);

        BOOLEAN isKnown = FALSE;
        KIRQL oldIrql;
        KeAcquireSpinLock(&TrackedProcess->Lock, &oldIrql);

        for (ULONG i = 0; i < TrackedProcess->ModuleCount; i++) {
            PVOID moduleBase = TrackedProcess->ModuleList[i];
            PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBase;
            if (dosHeader->e_magic == IMAGE_DOS_SIGNATURE) {
                PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((PUCHAR)moduleBase + dosHeader->e_lfanew);
                if (ntHeaders->Signature == IMAGE_NT_SIGNATURE) {
                    ULONG64 moduleEnd = (ULONG64)moduleBase + ntHeaders->OptionalHeader.SizeOfImage;
                    if ((ULONG64)BaseAddress >= (ULONG64)moduleBase && (ULONG64)BaseAddress < moduleEnd) {
                        if (TrackedProcess->ModuleHashes[i] != hash) {
                            AcRecordViolation(AC_VIOLATION_MEMORY_TAMPER,
                                             TrackedProcess->ProcessId,
                                             BaseAddress, RegionSize, hash,
                                             L"Memory region hash mismatch - possible tampering");
                            isKnown = TRUE;
                            break;
                        }
                        isKnown = TRUE;
                        break;
                    }
                }
            }
        }

        KeReleaseSpinLock(&TrackedProcess->Lock, oldIrql);

        if (!isKnown && (hash != 0)) {
            AcRecordViolation(AC_VIOLATION_UNKNOWN_MODULE,
                             TrackedProcess->ProcessId,
                             BaseAddress, RegionSize, hash,
                             L"Unknown executable memory region detected");
        }
    }

    ExFreePoolWithTag(buffer, AC_TAG);
    return status;
}

ULONG64 AcCalculateModuleHash(PVOID BaseAddress, ULONG Size) {
    ULONG64 hash = 0;
    PUCHAR data = (PUCHAR)BaseAddress;

    for (ULONG i = 0; i < Size; i++) {
        hash = (hash * 31) + data[i];
    }

    return hash;
}

NTSTATUS AcCheckModuleIntegrity(PAC_TRACKED_PROCESS TrackedProcess) {
    NTSTATUS status = STATUS_SUCCESS;
    KAPC_STATE apcState;
    KIRQL oldIrql;

    if (!TrackedProcess || !TrackedProcess->ProcessObject) {
        return STATUS_INVALID_PARAMETER;
    }

    KeStackAttachProcess((PKPROCESS)TrackedProcess->ProcessObject, &apcState);

    KeAcquireSpinLock(&TrackedProcess->Lock, &oldIrql);

    for (ULONG i = 0; i < TrackedProcess->ModuleCount; i++) {
        PVOID moduleBase = TrackedProcess->ModuleList[i];
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleBase;

        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            continue;
        }

        PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((PUCHAR)moduleBase + dosHeader->e_lfanew);

        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            continue;
        }

        ULONG64 currentHash = AcCalculateModuleHash(moduleBase, ntHeaders->OptionalHeader.SizeOfImage);

        if (TrackedProcess->ModuleHashes[i] != currentHash && currentHash != 0) {
            AcRecordViolation(AC_VIOLATION_INTEGRITY_CHECK,
                             TrackedProcess->ProcessId,
                             moduleBase, ntHeaders->OptionalHeader.SizeOfImage, currentHash,
                             L"Module integrity check failed - code modification detected");
            status = STATUS_DATA_ERROR;
        }
    }

    KeReleaseSpinLock(&TrackedProcess->Lock, oldIrql);
    KeUnstackDetachProcess(&apcState);

    return status;
}
