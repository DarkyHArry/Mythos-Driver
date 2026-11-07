#include "AntiCheatDriver.h"

/*
 * Lógica comum dos IOCTLs, compartilhada entre o callback WDF
 * (AcEvtIoDeviceControl) e o handler WDM legado (AcDeviceControl).
 */
static NTSTATUS AcHandleIoctl(
    _In_ PAC_DRIVER_CONTEXT Context,
    _In_ ULONG ControlCode,
    _In_opt_ PVOID InputBuffer,
    _In_ ULONG InputLength,
    _In_opt_ PVOID OutputBuffer,
    _In_ ULONG OutputLength,
    _Out_ PULONG_PTR Information
) {
    NTSTATUS status = STATUS_SUCCESS;

    *Information = 0;

    switch (ControlCode) {
        case IOCTL_AC_REGISTER_PROCESS: {
            if (!InputBuffer || InputLength < sizeof(HANDLE)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }

            HANDLE processId = *(PHANDLE)InputBuffer;
            PEPROCESS processObject = NULL;

            status = PsLookupProcessByProcessId(processId, &processObject);
            if (NT_SUCCESS(status)) {
                WCHAR imageName[260] = {0};
                PUNICODE_STRING processImageName = NULL;

                status = SeLocateProcessImageName(processObject, &processImageName);
                if (NT_SUCCESS(status) && processImageName) {
                    RtlCopyMemory(imageName, processImageName->Buffer,
                                 min(processImageName->Length,
                                     sizeof(imageName) - sizeof(WCHAR)));
                    ExFreePool(processImageName);
                }

                if (!AcFindTrackedProcess(processId)) {
                    AcCreateTrackedProcess(processId, processObject, imageName);
                }

                ObDereferenceObject(processObject);
            }
            break;
        }

        case IOCTL_AC_UNREGISTER_PROCESS: {
            if (!InputBuffer || InputLength < sizeof(HANDLE)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            AcRemoveTrackedProcess(*(PHANDLE)InputBuffer);
            break;
        }

        case IOCTL_AC_SCAN_MEMORY: {
            if (!InputBuffer || InputLength < sizeof(HANDLE)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }

            PAC_TRACKED_PROCESS trackedProcess =
                AcFindTrackedProcess(*(PHANDLE)InputBuffer);
            if (trackedProcess) {
                status = AcScanProcessMemory(trackedProcess);
            } else {
                status = STATUS_PROCESS_IS_TERMINATING;
            }
            break;
        }

        case IOCTL_AC_QUERY_INTEGRITY: {
            if (!InputBuffer || !OutputBuffer ||
                InputLength < sizeof(HANDLE) || OutputLength < sizeof(BOOLEAN)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }

            PAC_TRACKED_PROCESS trackedProcess =
                AcFindTrackedProcess(*(PHANDLE)InputBuffer);
            if (trackedProcess) {
                *((PBOOLEAN)OutputBuffer) =
                    (AcCheckModuleIntegrity(trackedProcess) == STATUS_SUCCESS);
                *Information = sizeof(BOOLEAN);
            } else {
                status = STATUS_PROCESS_IS_TERMINATING;
            }
            break;
        }

        case IOCTL_AC_GET_VIOLATIONS: {
            if (!OutputBuffer || OutputLength < sizeof(ULONG)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }

            KIRQL oldIrql;
            KeAcquireSpinLock(&Context->ViolationLock, &oldIrql);

            ULONG capacity = (OutputLength - sizeof(ULONG)) / sizeof(AC_VIOLATION);
            ULONG count = min(Context->ViolationCount, capacity);

            /* Layout: [ULONG count][AC_VIOLATION ...] */
            *(PULONG)OutputBuffer = count;
            if (count > 0) {
                RtlCopyMemory((PUCHAR)OutputBuffer + sizeof(ULONG),
                              Context->Violations,
                              count * sizeof(AC_VIOLATION));
            }
            *Information = sizeof(ULONG) + (count * sizeof(AC_VIOLATION));

            KeReleaseSpinLock(&Context->ViolationLock, oldIrql);
            break;
        }

        case IOCTL_AC_SET_CONFIG: {
            if (!InputBuffer || InputLength < sizeof(AC_CONFIG)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }

            PAC_CONFIG newConfig = (PAC_CONFIG)InputBuffer;
            KIRQL oldIrql;
            KeAcquireSpinLock(&Context->ProcessListLock, &oldIrql);
            Context->Config = *newConfig;
            KeReleaseSpinLock(&Context->ProcessListLock, oldIrql);

            if (Context->ScanTimerActive) {
                LARGE_INTEGER dueTime;
                KeCancelTimer(&Context->ScanTimer);
                dueTime.QuadPart = -((LONG64)Context->Config.ScanIntervalMs * 10000);
                KeSetTimer(&Context->ScanTimer, dueTime, &Context->ScanDpc);
            }
            break;
        }

        case IOCTL_AC_GET_ADVANCED_STATE: {
            if (!OutputBuffer) {
                status = STATUS_INVALID_PARAMETER;
                break;
            }
            status = AcQueryAdvancedState(OutputBuffer, OutputLength, Information);
            break;
        }

        case IOCTL_AC_GET_HYPERVISOR_INFO: {
            if (!OutputBuffer) {
                status = STATUS_INVALID_PARAMETER;
                break;
            }
            status = AcGetHypervisorInfo(OutputBuffer, OutputLength, Information);
            break;
        }

        case IOCTL_AC_GET_VTL_INFO: {
            if (!OutputBuffer) {
                status = STATUS_INVALID_PARAMETER;
                break;
            }
            status = AcGetVtlInfo(OutputBuffer, OutputLength, Information);
            break;
        }

        case IOCTL_AC_GET_HVCI_INFO: {
            if (!OutputBuffer) {
                status = STATUS_INVALID_PARAMETER;
                break;
            }
            status = AcGetHvciInfo(OutputBuffer, OutputLength, Information);
            break;
        }

        case IOCTL_AC_GET_RING_INFO: {
            if (!OutputBuffer) {
                status = STATUS_INVALID_PARAMETER;
                break;
            }
            status = AcGetRingInfo(OutputBuffer, OutputLength, Information);
            break;
        }

        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }

    return status;
}

/*
 * Callback da fila WDF (caminho efetivamente usado pelo control device).
 */
VOID AcEvtIoDeviceControl(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _In_ size_t InputBufferLength,
    _In_ ULONG IoControlCode
) {
    NTSTATUS status;
    PAC_DRIVER_CONTEXT context = g_DriverContext;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    ULONG_PTR information = 0;

    UNREFERENCED_PARAMETER(Queue);

    if (!context) {
        WdfRequestComplete(Request, STATUS_DEVICE_NOT_READY);
        return;
    }

    if (InputBufferLength > 0) {
        status = WdfRequestRetrieveInputBuffer(Request, 0, &inputBuffer, NULL);
        if (!NT_SUCCESS(status)) {
            WdfRequestComplete(Request, status);
            return;
        }
    }

    if (OutputBufferLength > 0) {
        status = WdfRequestRetrieveOutputBuffer(Request, 0, &outputBuffer, NULL);
        if (!NT_SUCCESS(status)) {
            WdfRequestComplete(Request, status);
            return;
        }
    }

    status = AcHandleIoctl(context, IoControlCode,
                           inputBuffer, (ULONG)InputBufferLength,
                           outputBuffer, (ULONG)OutputBufferLength,
                           &information);

    WdfRequestCompleteWithInformation(Request, status, information);
}

/*
 * Handler WDM legado (mantido para uso direto via IRP, caso necessário).
 */
NTSTATUS AcDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
) {
    PAC_DRIVER_CONTEXT context = g_DriverContext;
    PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);
    ULONG controlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;
    ULONG inputLength = irpStack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outputLength = irpStack->Parameters.DeviceIoControl.OutputBufferLength;
    PVOID systemBuffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG_PTR information = 0;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (!context) {
        status = STATUS_DEVICE_NOT_READY;
    } else {
        status = AcHandleIoctl(context, controlCode,
                               systemBuffer, inputLength,
                               systemBuffer, outputLength,
                               &information);
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

NTSTATUS AcDispatchCreateClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
) {
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}
