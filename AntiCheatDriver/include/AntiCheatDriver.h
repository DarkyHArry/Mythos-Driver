#pragma once

#include <ntddk.h>
#include <wdf.h>
#include <wdmsec.h>

/*
 * ntstrsafe.h usa, por padrão, as versões inline que dependem do CRT
 * (_vsnwprintf -> __stdio_common_vswprintf). Definindo NTSTRSAFE_LIB as
 * rotinas passam a ser resolvidas por ntstrsafe.lib, que é a forma correta
 * em kernel mode.
 */
#ifndef NTSTRSAFE_LIB
#define NTSTRSAFE_LIB
#endif
#include <ntstrsafe.h>
#include <ntimage.h>

#define AC_DEVICE_NAME L"\\Device\\AntiCheatDriver"
#define AC_DOS_DEVICE_NAME L"\\DosDevices\\AntiCheatDriver"
#define AC_TAG 'tEcA'

// IOCTL codes
#define IOCTL_AC_BASE FILE_DEVICE_UNKNOWN
#define IOCTL_AC_REGISTER_PROCESS CTL_CODE(IOCTL_AC_BASE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_AC_UNREGISTER_PROCESS CTL_CODE(IOCTL_AC_BASE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_AC_SCAN_MEMORY CTL_CODE(IOCTL_AC_BASE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_AC_QUERY_INTEGRITY CTL_CODE(IOCTL_AC_BASE, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_AC_GET_VIOLATIONS CTL_CODE(IOCTL_AC_BASE, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_AC_SET_CONFIG CTL_CODE(IOCTL_AC_BASE, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_AC_GET_ADVANCED_STATE CTL_CODE(IOCTL_AC_BASE, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_AC_GET_HYPERVISOR_INFO CTL_CODE(IOCTL_AC_BASE, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_AC_GET_VTL_INFO CTL_CODE(IOCTL_AC_BASE, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_AC_GET_HVCI_INFO CTL_CODE(IOCTL_AC_BASE, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_AC_GET_RING_INFO CTL_CODE(IOCTL_AC_BASE, 0x80A, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Maximum tracked processes
#define MAX_TRACKED_PROCESSES 1024
#define MAX_VIOLATIONS 256
#define MAX_MODULES_PER_PROCESS 512

// Violation types
typedef enum _AC_VIOLATION_TYPE {
    AC_VIOLATION_NONE = 0,
    AC_VIOLATION_UNLOADED_MODULE = 1,
    AC_VIOLATION_MEMORY_TAMPER = 2,
    AC_VIOLATION_THREAD_HIJACK = 3,
    AC_VIOLATION_SUSPICIOUS_MODULE = 4,
    AC_VIOLATION_DEBUGGER_DETECTED = 5,
    AC_VIOLATION_INTEGRITY_FAILURE = 6,
    AC_VIOLATION_API_HOOK = 7,
    AC_VIOLATION_CODE_INJECTION = 8,
    AC_VIOLATION_UNKNOWN_MODULE = 9,
    AC_VIOLATION_INTEGRITY_CHECK = 10,
    // Advanced violation types for Ring -1/-2/-3, VTL, HVCI
    AC_VIOLATION_HYPERVISOR_DETECTED = 11,
    AC_VIOLATION_VMX_ROOT_MODE = 12,
    AC_VIOLATION_SVM_NESTED = 13,
    AC_VIOLATION_SMM_INTRUSION = 14,
    AC_VIOLATION_SMRAM_CORRUPTION = 15,
    AC_VIOLATION_ME_COMPROMISED = 16,
    AC_VIOLATION_PSP_COMPROMISED = 17,
    AC_VIOLATION_HECI_ANOMALY = 18,
    AC_VIOLATION_VTL_ESCAPE = 19,
    AC_VIOLATION_SECURE_KERNEL_TAMPER = 20,
    AC_VIOLATION_HVCI_VIOLATION = 21,
    AC_VIOLATION_KERNEL_CET_FAILURE = 22,
    AC_VIOLATION_PAGE_TABLE_ANOMALY = 23,
    AC_VIOLATION_VTL1_INTEGRITY = 24
} AC_VIOLATION_TYPE;

// Process tracking structure
typedef struct _AC_TRACKED_PROCESS {
    HANDLE ProcessId;
    PEPROCESS ProcessObject;
    ULONG64 ProcessCreateTime;
    WCHAR ImageName[260];
    BOOLEAN IsProtected;
    BOOLEAN IsGameProcess;
    ULONG ModuleCount;
    PVOID ModuleList[MAX_MODULES_PER_PROCESS];
    ULONG64 ModuleHashes[MAX_MODULES_PER_PROCESS];
    KSPIN_LOCK Lock;
    LIST_ENTRY ListEntry;
} AC_TRACKED_PROCESS, *PAC_TRACKED_PROCESS;

// Violation record
typedef struct _AC_VIOLATION {
    AC_VIOLATION_TYPE Type;
    HANDLE ProcessId;
    ULONG64 Timestamp;
    PVOID Address;
    ULONG64 Value1;
    ULONG64 Value2;
    WCHAR Description[256];
} AC_VIOLATION, *PAC_VIOLATION;

// Driver configuration
typedef struct _AC_CONFIG {
    BOOLEAN EnableProcessMonitoring;
    BOOLEAN EnableThreadMonitoring;
    BOOLEAN EnableImageLoadMonitoring;
    BOOLEAN EnableMemoryScanning;
    BOOLEAN EnableIntegrityChecks;
    BOOLEAN BlockSuspiciousModules;
    BOOLEAN LogViolations;
    ULONG ScanIntervalMs;
    ULONG MaxViolations;
} AC_CONFIG, *PAC_CONFIG;

// Global driver context
typedef struct _AC_DRIVER_CONTEXT {
    PDEVICE_OBJECT DeviceObject;
    UNICODE_STRING DeviceName;
    UNICODE_STRING DosDeviceName;
    AC_CONFIG Config;
    LIST_ENTRY TrackedProcessList;
    KSPIN_LOCK ProcessListLock;
    AC_VIOLATION Violations[MAX_VIOLATIONS];
    ULONG ViolationCount;
    KSPIN_LOCK ViolationLock;
    PVOID ProcessNotifyHandle;
    PVOID ThreadNotifyHandle;
    PVOID ImageLoadNotifyHandle;
    KDPC ScanDpc;
    KTIMER ScanTimer;
    BOOLEAN ScanTimerActive;
    WDFDEVICE WdfDevice;
} AC_DRIVER_CONTEXT, *PAC_DRIVER_CONTEXT;

extern PAC_DRIVER_CONTEXT g_DriverContext;
extern WDFDRIVER g_WdfDriver;

// WDF context type info declaration
WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(AC_DRIVER_CONTEXT, AcGetDriverContext)

// Get driver context from WDF driver object
#define AC_GET_DRIVER_CONTEXT(Driver) AcGetDriverContext(Driver)

// System information structures
typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

#define SystemModuleInformation 11

// Function prototypes
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
VOID DriverUnload(WDFDRIVER Driver);

NTSTATUS AcCreateDevice(PAC_DRIVER_CONTEXT Context, WDFDRIVER Driver);
VOID AcCleanupDevice(PAC_DRIVER_CONTEXT Context);

NTSTATUS AcRegisterCallbacks(PAC_DRIVER_CONTEXT Context);
VOID AcUnregisterCallbacks(PAC_DRIVER_CONTEXT Context);

VOID AcEvtIoDeviceControl(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _In_ size_t InputBufferLength,
    _In_ ULONG IoControlCode
);

NTSTATUS AcDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
);

NTSTATUS AcDispatchCreateClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
);

VOID AcProcessNotifyCallback(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
);

VOID AcProcessNotifyCallbackEx(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
);

VOID AcThreadNotifyCallback(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ BOOLEAN Create
);

VOID AcImageLoadCallback(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo
);

NTSTATUS AcScanProcessMemory(PAC_TRACKED_PROCESS TrackedProcess);
NTSTATUS AcCheckModuleIntegrity(PAC_TRACKED_PROCESS TrackedProcess);
NTSTATUS AcDetectApiHooks(PAC_TRACKED_PROCESS TrackedProcess);
NTSTATUS AcDetectCodeInjection(PAC_TRACKED_PROCESS TrackedProcess);
NTSTATUS AcScanMemoryRegion(PAC_TRACKED_PROCESS TrackedProcess, PVOID BaseAddress, SIZE_T RegionSize);
NTSTATUS AcDetectThreadHijack(PAC_TRACKED_PROCESS TrackedProcess, PETHREAD ThreadObject, HANDLE ThreadId);
NTSTATUS AcUnloadModule(HANDLE ProcessId, PVOID BaseAddress);

VOID AcRecordViolation(
    _In_ AC_VIOLATION_TYPE Type,
    _In_ HANDLE ProcessId,
    _In_ PVOID Address,
    _In_ ULONG64 Value1,
    _In_ ULONG64 Value2,
    _In_ PCWSTR Description
);

PAC_TRACKED_PROCESS AcFindTrackedProcess(HANDLE ProcessId);
PAC_TRACKED_PROCESS AcCreateTrackedProcess(HANDLE ProcessId, PEPROCESS ProcessObject, PCWSTR ImageName);
VOID AcRemoveTrackedProcess(HANDLE ProcessId);
VOID AcUpdateProcessModules(PAC_TRACKED_PROCESS TrackedProcess);

NTSTATUS AcDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
);

NTSTATUS AcDispatchCreateClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
);

VOID AcScanTimerCallback(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
);

ULONG64 AcCalculateModuleHash(PVOID BaseAddress, ULONG Size);
BOOLEAN AcIsSuspiciousModule(PCWSTR ModuleName);
BOOLEAN AcIsGameProcess(PCWSTR ImageName);

/* =========================================================================
 * Advanced detection (Ring -1 / Ring -2 / VTL / HVCI / CET / page tables)
 *   IOCTL_AC_GET_ADVANCED_STATE - full AC_ADVANCED_STATE snapshot
 *   IOCTL_AC_GET_HYPERVISOR_INFO - hypervisor presence + VMX/SVM state
 *   IOCTL_AC_GET_VTL_INFO       - VTL escape / secure kernel tamper
 *   IOCTL_AC_GET_HVCI_INFO      - HVCI policy / kernel CET / page tables
 *   IOCTL_AC_GET_RING_INFO      - SMM / ME / PSP / microcode / HECI
 * ========================================================================= */
NTSTATUS AcInitializeAdvancedDetection(VOID);
VOID AcCleanupAdvancedDetection(VOID);
NTSTATUS AcRunAdvancedDetection(VOID);
NTSTATUS AcQueryAdvancedState(
    _Out_writes_bytes_(OutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG_PTR BytesReturned
);
NTSTATUS AcGetHypervisorInfo(
    _Out_writes_bytes_(OutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG_PTR BytesReturned
);
NTSTATUS AcGetVtlInfo(
    _Out_writes_bytes_(OutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG_PTR BytesReturned
);
NTSTATUS AcGetHvciInfo(
    _Out_writes_bytes_(OutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG_PTR BytesReturned
);
NTSTATUS AcGetRingInfo(
    _Out_writes_bytes_(OutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG_PTR BytesReturned
);

// External function declarations
NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
    _In_ ULONG SystemInformationClass,
    _Inout_ PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
);

NTSYSAPI NTSTATUS NTAPI ZwQueryVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _In_ ULONG MemoryInformationClass,
    _Out_writes_bytes_(MemoryInformationLength) PVOID MemoryInformation,
    _In_ SIZE_T MemoryInformationLength,
    _Out_opt_ PSIZE_T ReturnLength
);

// KAPC_STATE structure for thread attachment
typedef struct _KAPC_STATE {
    LIST_ENTRY ApcListHead[2];
    PKPROCESS Process;
    UCHAR KernelApcInProgress;
    UCHAR KernelApcPending;
    UCHAR UserApcPending;
} KAPC_STATE, *PKAPC_STATE;

// KAPC_ENVIRONMENT enum (not in standard headers)
typedef enum _KAPC_ENVIRONMENT {
    OriginalApcEnvironment,
    AttachedApcEnvironment,
    CurrentApcEnvironment,
    InsertApcEnvironment
} KAPC_ENVIRONMENT;

// APC callback routine types (not in standard headers)
typedef VOID (NTAPI *PKNORMAL_ROUTINE)(
    _In_opt_ PVOID NormalContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
);

typedef VOID (NTAPI *PKKERNEL_ROUTINE)(
    _In_ PKAPC Apc,
    _Inout_ PKNORMAL_ROUTINE *NormalRoutine,
    _Inout_ PVOID *NormalContext,
    _Inout_ PVOID *SystemArgument1,
    _Inout_ PVOID *SystemArgument2
);

typedef VOID (NTAPI *PKRUNDOWN_ROUTINE)(
    _In_ PKAPC Apc
);

// External kernel functions not in standard headers
NTSYSAPI NTSTATUS NTAPI PsLookupThreadByThreadId(
    _In_ HANDLE ThreadId,
    _Out_ PETHREAD *ThreadObject
);

NTSYSAPI VOID NTAPI KeStackAttachProcess(
    _In_ PKPROCESS Process,
    _Out_ PKAPC_STATE ApcState
);

NTSYSAPI VOID NTAPI KeUnstackDetachProcess(
    _In_ PKAPC_STATE ApcState
);

NTSYSAPI PVOID NTAPI PsGetThreadTeb(
    _In_ PETHREAD ThreadObject
);

/*
 * PsGetThreadStartAddress/KeGetContextThread NÃO são exportadas pelo
 * ntoskrnl. Usamos as APIs realmente exportadas:
 *   - PsGetContextThread para ler o contexto da thread
 *   - ObOpenObjectByPointer + ZwQueryInformationThread para o start address
 */
NTSYSAPI NTSTATUS NTAPI PsGetContextThread(
    _In_ PETHREAD ThreadObject,
    _Inout_ PCONTEXT Context,
    _In_ KPROCESSOR_MODE PreviousMode
);

NTSYSAPI NTSTATUS NTAPI ObOpenObjectByPointer(
    _In_ PVOID Object,
    _In_ ULONG HandleAttributes,
    _In_opt_ PACCESS_STATE PassedAccessState,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_TYPE ObjectType,
    _In_ KPROCESSOR_MODE AccessMode,
    _Out_ PHANDLE Handle
);

#define ThreadQuerySetWin32StartAddress 9

NTSYSAPI NTSTATUS NTAPI ZwQueryInformationThread(
    _In_ HANDLE ThreadHandle,
    _In_ ULONG ThreadInformationClass,
    _Out_writes_bytes_opt_(ThreadInformationLength) PVOID ThreadInformation,
    _In_ ULONG ThreadInformationLength,
    _Out_opt_ PULONG ReturnLength
);

NTSYSAPI NTSTATUS NTAPI ZwUnmapViewOfSection(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress
);

NTSYSAPI NTSTATUS NTAPI RtlDowncaseUnicodeString(
    _Out_ PUNICODE_STRING DestinationString,
    _In_ PCUNICODE_STRING SourceString,
    _In_ BOOLEAN AllocateDestinationString
);

NTSYSAPI NTSTATUS NTAPI SeLocateProcessImageName(
    _In_ PEPROCESS Process,
    _Out_ PUNICODE_STRING *ImageFileName
);

NTSYSAPI NTSTATUS NTAPI MmCopyVirtualMemory(
    _In_ PEPROCESS SourceProcess,
    _In_ PVOID SourceAddress,
    _In_ PEPROCESS TargetProcess,
    _Out_ PVOID TargetAddress,
    _In_ SIZE_T BufferSize,
    _In_ KPROCESSOR_MODE PreviousMode,
    _Out_ PSIZE_T ReturnSize
);

NTSYSAPI NTSTATUS NTAPI PsLookupProcessByProcessId(
    _In_ HANDLE ProcessId,
    _Out_ PEPROCESS *Process
);

NTSYSAPI VOID NTAPI KeInitializeApc(
    _In_ PKAPC Apc,
    _In_ PKTHREAD Thread,
    _In_ KAPC_ENVIRONMENT Environment,
    _In_ PKKERNEL_ROUTINE KernelRoutine,
    _In_opt_ PKRUNDOWN_ROUTINE RundownRoutine,
    _In_opt_ PKNORMAL_ROUTINE NormalRoutine,
    _In_ KPROCESSOR_MODE ApcMode,
    _In_opt_ PVOID NormalContext
);

NTSYSAPI BOOLEAN NTAPI KeInsertQueueApc(
    _In_ PKAPC Apc,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2,
    _In_ KPRIORITY Increment
);

// MemoryBasicInformation, MEM_COMMIT, PAGE_EXECUTE*, MM_LOWEST/HIGHEST_USER_ADDRESS
// are defined in ntddk.h/ntdef.h - do not redefine to avoid C4005 warnings

/* =========================================================================
 * IOCTL interface (user-mode clients)
 *   IOCTL_AC_REGISTER_PROCESS    - register a process for monitoring
 *   IOCTL_AC_UNREGISTER_PROCESS  - unregister a process
 *   IOCTL_AC_SCAN_MEMORY         - scan process memory region
 *   IOCTL_AC_QUERY_INTEGRITY     - query module integrity
 *   IOCTL_AC_GET_VIOLATIONS      - retrieve recorded violations
 *   IOCTL_AC_SET_CONFIG          - update driver configuration (AC_CONFIG)
 * ========================================================================= */
