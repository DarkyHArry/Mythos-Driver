#include "AntiCheatDriver.h"

VOID AcImageLoadCallback(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo
) {
    PAC_DRIVER_CONTEXT context = g_DriverContext;
    PAC_TRACKED_PROCESS trackedProcess = NULL;
    WCHAR imageName[260] = {0};

    if (!context || !context->Config.EnableImageLoadMonitoring) {
        return;
    }

    trackedProcess = AcFindTrackedProcess(ProcessId);
    if (!trackedProcess) {
        return;
    }

    if (FullImageName && FullImageName->Buffer) {
        RtlCopyMemory(imageName, FullImageName->Buffer,
                     min(FullImageName->Length, sizeof(imageName) - sizeof(WCHAR)));
    }

    KdPrint(("[AntiCheatDriver] Image Load: PID=%llu, Base=0x%p, Size=0x%X, Name=%ws\n",
             (ULONG64)ProcessId, ImageInfo->ImageBase, ImageInfo->ImageSize, imageName));

    if (AcIsSuspiciousModule(imageName)) {
        AcRecordViolation(AC_VIOLATION_SUSPICIOUS_MODULE, ProcessId,
                         ImageInfo->ImageBase, ImageInfo->ImageSize, 0,
                         L"Suspicious module loaded");
        KdPrint(("[AntiCheatDriver] Suspicious module detected: %ws\n", imageName));

        if (context->Config.BlockSuspiciousModules) {
            AcUnloadModule(ProcessId, ImageInfo->ImageBase);
        }
    }

    AcUpdateProcessModules(trackedProcess);
}

BOOLEAN AcIsSuspiciousModule(PCWSTR ModuleName) {
    if (!ModuleName) return FALSE;

    /* Extract basename to reduce false positives from full paths */
    PCWSTR base = ModuleName;
    for (PCWSTR p = ModuleName; *p; p++) {
        if (*p == L'\\' || *p == L'/') base = p + 1;
    }

    static const WCHAR* suspiciousModules[] = {
        L"cheat", L"hack", L"aimbot", L"wallhack", L"esp",
        L"inject", L"trainer", L"modmenu", L"overlay",
        L"reclass", L"cheatengine", L"cehook",
        L"ollydbg", L"x64dbg", L"ida", L"ghidra", L"radare",
        L"frida", L"substrate", L"cycript", L"dlsym",
        L"detours", L"minhook", L"polyhook", L"easyhook"
    };

    for (ULONG i = 0; i < ARRAYSIZE(suspiciousModules); i++) {
        if (_wcsicmp(base, suspiciousModules[i]) == 0 ||
            wcsstr(base, suspiciousModules[i]) != NULL) {
            /* Avoid flagging common legitimate debug helpers unless exact match */
            if (_wcsicmp(suspiciousModules[i], L"dbghelp") == 0) continue;
            return TRUE;
        }
    }

    return FALSE;
}

NTSTATUS AcUnloadModule(HANDLE ProcessId, PVOID BaseAddress) {
    NTSTATUS status;
    PAC_DRIVER_CONTEXT context = g_DriverContext;
    PAC_TRACKED_PROCESS trackedProcess = NULL;
    KAPC_STATE apcState;

    if (!context) return STATUS_UNSUCCESSFUL;

    trackedProcess = AcFindTrackedProcess(ProcessId);
    if (!trackedProcess || !trackedProcess->ProcessObject) {
        return STATUS_PROCESS_IS_TERMINATING;
    }

    KeStackAttachProcess((PKPROCESS)trackedProcess->ProcessObject, &apcState);

    /*
     * LdrUnloadDll é user-mode (ntdll) e não existe no kernel. Para desmapear
     * a imagem do módulo usamos ZwUnmapViewOfSection no processo anexado.
     */
    status = ZwUnmapViewOfSection(ZwCurrentProcess(), BaseAddress);

    KeUnstackDetachProcess(&apcState);

    if (NT_SUCCESS(status)) {
        KdPrint(("[AntiCheatDriver] Successfully unloaded suspicious module at 0x%p\n", BaseAddress));
        AcRecordViolation(AC_VIOLATION_UNLOADED_MODULE, ProcessId,
                         BaseAddress, 0, 0, L"Suspicious module unloaded by driver");
    } else {
        KdPrint(("[AntiCheatDriver] Failed to unload module at 0x%p: 0x%08X\n", BaseAddress, status));
    }

    return status;
}