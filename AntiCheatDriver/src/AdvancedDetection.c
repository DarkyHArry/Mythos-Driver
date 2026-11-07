#include "AntiCheatDriver.h"

#define AC_ADVANCED_POOL_TAG 'dvcA'

typedef struct _AC_ADVANCED_STATE {
    BOOLEAN HypervisorPresent;
    BOOLEAN VmxRootMode;
    BOOLEAN SvmNestedVirt;
    BOOLEAN SmmIntrusionDetected;
    BOOLEAN MeCompromiseDetected;
    BOOLEAN PspCompromiseDetected;
    BOOLEAN MicrocodeAnomaly;
    BOOLEAN HeciAnomaly;
    BOOLEAN VtlEscapeAttempt;
    BOOLEAN SecureKernelTampered;
    BOOLEAN HvciPolicyViolation;
    BOOLEAN KernelCetFailure;
    BOOLEAN PageTableAnomaly;
    ULONG64 HypervisorVendorId;
    ULONG64 VmxBasicMsr;
    ULONG64 SmmStateSaveMap;
    ULONG MicrocodeRevision;
    ULONG HeciStatus;
    KSPIN_LOCK Lock;
} AC_ADVANCED_STATE, *PAC_ADVANCED_STATE;

static AC_ADVANCED_STATE g_AdvancedState = { 0 };

NTSTATUS
AcInitializeAdvancedDetection(
    VOID
)
{
    RtlZeroMemory(&g_AdvancedState, sizeof(g_AdvancedState));
    KeInitializeSpinLock(&g_AdvancedState.Lock);
    return STATUS_SUCCESS;
}

VOID
AcCleanupAdvancedDetection(
    VOID
)
{
    RtlZeroMemory(&g_AdvancedState, sizeof(g_AdvancedState));
}

static BOOLEAN
AcCpuidSupported(
    VOID
)
{
    int cpuInfo[4] = { 0 };
    __cpuid(cpuInfo, 0);
    return cpuInfo[0] >= 1;
}

static VOID
AcReadCpuid(
    _In_ ULONG Leaf,
    _In_ ULONG SubLeaf,
    _Out_ int CpuInfo[4]
)
{
    __cpuidex(CpuInfo, Leaf, SubLeaf);
}

static ULONG64
AcReadMsrSafe(
    _In_ ULONG Msr,
    _Out_ PBOOLEAN Success
)
{
    ULONG64 value = 0;
    *Success = FALSE;

    __try {
        value = __readmsr(Msr);
        *Success = TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        *Success = FALSE;
    }

    return value;
}

static VOID
AcDetectHypervisor(
    VOID
)
{
    int cpuInfo[4] = { 0 };
    KIRQL oldIrql;

    if (!AcCpuidSupported()) {
        return;
    }

    KeAcquireSpinLock(&g_AdvancedState.Lock, &oldIrql);

    __cpuid(cpuInfo, 1);
    g_AdvancedState.VmxRootMode = (cpuInfo[2] & (1 << 5)) != 0;

    __cpuid(cpuInfo, 0x40000000);
    g_AdvancedState.HypervisorPresent = (cpuInfo[0] >= 0x40000001);
    g_AdvancedState.HypervisorVendorId = ((ULONG64)cpuInfo[1] << 32) | (ULONG64)cpuInfo[2];

    __cpuid(cpuInfo, 0x8000000A);
    g_AdvancedState.SvmNestedVirt = (cpuInfo[0] & 1) != 0;

    BOOLEAN success = FALSE;
    g_AdvancedState.VmxBasicMsr = AcReadMsrSafe(0x480, &success);

    KeReleaseSpinLock(&g_AdvancedState.Lock, oldIrql);
}

static VOID
AcDetectSmmIntrusion(
    VOID
)
{
    KIRQL oldIrql;
    BOOLEAN success = FALSE;
    ULONG64 smmBase = 0;

    KeAcquireSpinLock(&g_AdvancedState.Lock, &oldIrql);

    smmBase = AcReadMsrSafe(0x1F2, &success);
    if (success && smmBase != 0) {
        g_AdvancedState.SmmStateSaveMap = smmBase;
        g_AdvancedState.SmmIntrusionDetected = TRUE;
    }

    KeReleaseSpinLock(&g_AdvancedState.Lock, oldIrql);
}

static VOID
AcDetectMePspCompromise(
    VOID
)
{
    KIRQL oldIrql;
    int cpuInfo[4] = { 0 };

    KeAcquireSpinLock(&g_AdvancedState.Lock, &oldIrql);

    __cpuid(cpuInfo, 1);
    BOOLEAN isIntel = (cpuInfo[0] & 0xFFFF) == 0x0000;

    if (isIntel) {
        BOOLEAN success = FALSE;
        ULONG64 heciStatus = AcReadMsrSafe(0x13B, &success);
        if (success) {
            g_AdvancedState.HeciStatus = (ULONG)heciStatus;
            g_AdvancedState.HeciAnomaly = (heciStatus & 0xFFFF0000) != 0;
            g_AdvancedState.MeCompromiseDetected = g_AdvancedState.HeciAnomaly;
        }
    } else {
        __cpuid(cpuInfo, 0x80000001);
        BOOLEAN isAmd = (cpuInfo[2] & (1 << 11)) != 0;
        if (isAmd) {
            BOOLEAN success = FALSE;
            ULONG64 pspStatus = AcReadMsrSafe(0xC0010100, &success);
            if (success) {
                g_AdvancedState.PspCompromiseDetected = (pspStatus & 0x1) != 0;
            }
        }
    }

    KeReleaseSpinLock(&g_AdvancedState.Lock, oldIrql);
}

static VOID
AcDetectMicrocodeAnomaly(
    VOID
)
{
    KIRQL oldIrql;
    BOOLEAN success = FALSE;
    ULONG64 microcodeRev = 0;

    KeAcquireSpinLock(&g_AdvancedState.Lock, &oldIrql);

    microcodeRev = AcReadMsrSafe(0x8B, &success);
    if (success) {
        g_AdvancedState.MicrocodeRevision = (ULONG)microcodeRev;
        g_AdvancedState.MicrocodeAnomaly = (microcodeRev == 0) || (microcodeRev > 0xFFFFFFFF);
    }

    KeReleaseSpinLock(&g_AdvancedState.Lock, oldIrql);
}

static VOID
AcDetectVtlAndHvci(
    VOID
)
{
    KIRQL oldIrql;
    BOOLEAN success = FALSE;
    ULONG64 vtlControl = 0;

    KeAcquireSpinLock(&g_AdvancedState.Lock, &oldIrql);

    vtlControl = AcReadMsrSafe(0xC0010110, &success);
    if (success) {
        g_AdvancedState.VtlEscapeAttempt = (vtlControl & 0x2) != 0;
        g_AdvancedState.SecureKernelTampered = (vtlControl & 0x4) != 0;
    }

    ULONG64 hvciStatus = AcReadMsrSafe(0xC0010111, &success);
    if (success) {
        g_AdvancedState.HvciPolicyViolation = (hvciStatus & 0x1) != 0;
        g_AdvancedState.KernelCetFailure = (hvciStatus & 0x2) != 0;
    }

    ULONG64 pageTableStatus = AcReadMsrSafe(0xC0010112, &success);
    if (success) {
        g_AdvancedState.PageTableAnomaly = (pageTableStatus & 0xF) != 0;
    }

    KeReleaseSpinLock(&g_AdvancedState.Lock, oldIrql);
}

NTSTATUS
AcRunAdvancedDetection(
    VOID
)
{
    AcDetectHypervisor();
    AcDetectSmmIntrusion();
    AcDetectMePspCompromise();
    AcDetectMicrocodeAnomaly();
    AcDetectVtlAndHvci();

    return STATUS_SUCCESS;
}

NTSTATUS
AcQueryAdvancedState(
    _Out_writes_bytes_(OutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG_PTR BytesReturned
)
{
    PAC_ADVANCED_STATE output = (PAC_ADVANCED_STATE)OutputBuffer;
    KIRQL oldIrql;

    if (OutputBufferLength < sizeof(AC_ADVANCED_STATE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    AcRunAdvancedDetection();

    KeAcquireSpinLock(&g_AdvancedState.Lock, &oldIrql);
    RtlCopyMemory(output, &g_AdvancedState, sizeof(AC_ADVANCED_STATE));
    KeReleaseSpinLock(&g_AdvancedState.Lock, oldIrql);

    *BytesReturned = sizeof(AC_ADVANCED_STATE);
    return STATUS_SUCCESS;
}

NTSTATUS
AcGetHypervisorInfo(
    _Out_writes_bytes_(OutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG_PTR BytesReturned
)
{
    typedef struct _AC_HYPERVISOR_INFO {
        BOOLEAN Present;
        BOOLEAN VmxRootMode;
        BOOLEAN SvmNestedVirt;
        ULONG64 VendorId;
        ULONG64 VmxBasicMsr;
    } AC_HYPERVISOR_INFO, *PAC_HYPERVISOR_INFO;

    PAC_HYPERVISOR_INFO output = (PAC_HYPERVISOR_INFO)OutputBuffer;
    KIRQL oldIrql;

    if (OutputBufferLength < sizeof(AC_HYPERVISOR_INFO)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    AcDetectHypervisor();

    KeAcquireSpinLock(&g_AdvancedState.Lock, &oldIrql);
    output->Present = g_AdvancedState.HypervisorPresent;
    output->VmxRootMode = g_AdvancedState.VmxRootMode;
    output->SvmNestedVirt = g_AdvancedState.SvmNestedVirt;
    output->VendorId = g_AdvancedState.HypervisorVendorId;
    output->VmxBasicMsr = g_AdvancedState.VmxBasicMsr;
    KeReleaseSpinLock(&g_AdvancedState.Lock, oldIrql);

    *BytesReturned = sizeof(AC_HYPERVISOR_INFO);
    return STATUS_SUCCESS;
}

NTSTATUS
AcGetVtlInfo(
    _Out_writes_bytes_(OutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG_PTR BytesReturned
)
{
    typedef struct _AC_VTL_INFO {
        BOOLEAN VtlEscapeAttempt;
        BOOLEAN SecureKernelTampered;
    } AC_VTL_INFO, *PAC_VTL_INFO;

    PAC_VTL_INFO output = (PAC_VTL_INFO)OutputBuffer;
    KIRQL oldIrql;

    if (OutputBufferLength < sizeof(AC_VTL_INFO)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    AcDetectVtlAndHvci();

    KeAcquireSpinLock(&g_AdvancedState.Lock, &oldIrql);
    output->VtlEscapeAttempt = g_AdvancedState.VtlEscapeAttempt;
    output->SecureKernelTampered = g_AdvancedState.SecureKernelTampered;
    KeReleaseSpinLock(&g_AdvancedState.Lock, oldIrql);

    *BytesReturned = sizeof(AC_VTL_INFO);
    return STATUS_SUCCESS;
}

NTSTATUS
AcGetHvciInfo(
    _Out_writes_bytes_(OutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG_PTR BytesReturned
)
{
    typedef struct _AC_HVCI_INFO {
        BOOLEAN HvciPolicyViolation;
        BOOLEAN KernelCetFailure;
        BOOLEAN PageTableAnomaly;
    } AC_HVCI_INFO, *PAC_HVCI_INFO;

    PAC_HVCI_INFO output = (PAC_HVCI_INFO)OutputBuffer;
    KIRQL oldIrql;

    if (OutputBufferLength < sizeof(AC_HVCI_INFO)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    AcDetectVtlAndHvci();

    KeAcquireSpinLock(&g_AdvancedState.Lock, &oldIrql);
    output->HvciPolicyViolation = g_AdvancedState.HvciPolicyViolation;
    output->KernelCetFailure = g_AdvancedState.KernelCetFailure;
    output->PageTableAnomaly = g_AdvancedState.PageTableAnomaly;
    KeReleaseSpinLock(&g_AdvancedState.Lock, oldIrql);

    *BytesReturned = sizeof(AC_HVCI_INFO);
    return STATUS_SUCCESS;
}

NTSTATUS
AcGetRingInfo(
    _Out_writes_bytes_(OutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG_PTR BytesReturned
)
{
    typedef struct _AC_RING_INFO {
        BOOLEAN SmmIntrusionDetected;
        BOOLEAN MeCompromiseDetected;
        BOOLEAN PspCompromiseDetected;
        BOOLEAN MicrocodeAnomaly;
        BOOLEAN HeciAnomaly;
        ULONG64 SmmStateSaveMap;
        ULONG MicrocodeRevision;
        ULONG HeciStatus;
    } AC_RING_INFO, *PAC_RING_INFO;

    PAC_RING_INFO output = (PAC_RING_INFO)OutputBuffer;
    KIRQL oldIrql;

    if (OutputBufferLength < sizeof(AC_RING_INFO)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    AcDetectSmmIntrusion();
    AcDetectMePspCompromise();
    AcDetectMicrocodeAnomaly();

    KeAcquireSpinLock(&g_AdvancedState.Lock, &oldIrql);
    output->SmmIntrusionDetected = g_AdvancedState.SmmIntrusionDetected;
    output->MeCompromiseDetected = g_AdvancedState.MeCompromiseDetected;
    output->PspCompromiseDetected = g_AdvancedState.PspCompromiseDetected;
    output->MicrocodeAnomaly = g_AdvancedState.MicrocodeAnomaly;
    output->HeciAnomaly = g_AdvancedState.HeciAnomaly;
    output->SmmStateSaveMap = g_AdvancedState.SmmStateSaveMap;
    output->MicrocodeRevision = g_AdvancedState.MicrocodeRevision;
    output->HeciStatus = g_AdvancedState.HeciStatus;
    KeReleaseSpinLock(&g_AdvancedState.Lock, oldIrql);

    *BytesReturned = sizeof(AC_RING_INFO);
    return STATUS_SUCCESS;
}