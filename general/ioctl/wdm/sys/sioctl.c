/*++

Copyright (c) 1990-98  Microsoft Corporation All Rights Reserved

Module Name:

    sioctl.c

Abstract:

    Purpose of this driver is to demonstrate how the four different types
    of IOCTLs can be used, and how the I/O manager handles the user I/O
    buffers in each case. This sample also helps to understand the usage of
    some of the memory manager functions.

Environment:

    Kernel mode only.

--*/


//
// Include files.
//

//#include <ntddk.h>
#include "sioctl.h"
#include "winternl-defs.h"
#include "structures.h"
#include <ntstrsafe.h>


#define NT_DEVICE_NAME      L"\\Device\\SIOCTL"
#define DOS_DEVICE_NAME     L"\\DosDevices\\IoctlTest"

#if DBG
#define SIOCTL_KDPRINT(_x_) \
                DbgPrint("SIOCTL.SYS: ");\
                DbgPrint _x_;

#else
#define SIOCTL_KDPRINT(_x_)
#endif


//
// Device driver routine declarations.
//

DRIVER_INITIALIZE DriverEntry;

_Dispatch_type_(IRP_MJ_CLOSE)
DRIVER_DISPATCH SioctlClose;

_Dispatch_type_(IRP_MJ_CREATE)
DRIVER_DISPATCH SioctlCreate;

_Dispatch_type_(IRP_MJ_CLEANUP)
DRIVER_DISPATCH SioctlCleanup;

_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
DRIVER_DISPATCH SioctlDeviceControl;

DRIVER_UNLOAD SioctlUnloadDriver;

VOID
PrintIrpInfo(
    PIRP Irp
);
VOID
PrintChars(
    _In_reads_(CountChars) PCHAR BufferAddress,
    _In_ size_t CountChars
);

//Functions declaration

void generate_reversed_calls(PVOID DriverObject);
NTSTATUS CompleteIrp(PIRP Irp, NTSTATUS status, ULONG_PTR info);
NTSTATUS processIrp(PIRP Irp);

//CSQ Functions
IO_CSQ_INSERT_IRP CsqInsertIrp;
IO_CSQ_REMOVE_IRP CsqRemoveIrp;
IO_CSQ_PEEK_NEXT_IRP CsqPeekNextIrp;
IO_CSQ_ACQUIRE_LOCK CsqAcquireLock;
IO_CSQ_RELEASE_LOCK CsqReleaseLock;
IO_CSQ_COMPLETE_CANCELED_IRP CsqCompleteCanceledIrp;


#ifdef ALLOC_PRAGMA
#pragma alloc_text( INIT, DriverEntry )
#pragma alloc_text( PAGE, SioctlCreate)
#pragma alloc_text( PAGE, SioctlClose)
#pragma alloc_text( PAGE, SioctlCleanup)
#pragma alloc_text( PAGE, SioctlDeviceControl)
#pragma alloc_text( PAGE, SioctlUnloadDriver)
#pragma alloc_text( PAGE, PrintIrpInfo)
#pragma alloc_text( PAGE, PrintChars)
#endif // ALLOC_PRAGMA



NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT   DriverObject,
    _In_ PUNICODE_STRING      RegistryPath
    ) {
    NTSTATUS        ntStatus;
    UNICODE_STRING  ntUnicodeString;    // NT Device Name "\Device\SIOCTL"
    UNICODE_STRING  ntWin32NameString;    // Win32 Name "\DosDevices\IoctlTest"
    PDEVICE_OBJECT  deviceObject = NULL;    // ptr to device object

    UNREFERENCED_PARAMETER(RegistryPath);

    RtlInitUnicodeString( &ntUnicodeString, NT_DEVICE_NAME );

    ntStatus = IoCreateDevice(
        DriverObject,                   // Our Driver Object
        sizeof(DEVICE_EXT_DATA),                              // We do use a device extension
        &ntUnicodeString,               // Device name "\Device\SIOCTL"
        FILE_DEVICE_UNKNOWN,            // Device type
        FILE_DEVICE_SECURE_OPEN,     // Device characteristics
        FALSE,                          // Not an exclusive device
        &deviceObject );                // Returned ptr to Device Object

    if ( !NT_SUCCESS( ntStatus ) )
    {
        SIOCTL_KDPRINT(("Couldn't create the device object\n"));
        return ntStatus;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = SioctlCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = SioctlClose;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP] = SioctlCleanup;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = SioctlDeviceControl;
    DriverObject->DriverUnload = SioctlUnloadDriver;

    RtlInitUnicodeString( &ntWin32NameString, DOS_DEVICE_NAME );
    ntStatus = IoCreateSymbolicLink(
                        &ntWin32NameString, &ntUnicodeString );

    if ( !NT_SUCCESS( ntStatus ) )
    {
        SIOCTL_KDPRINT(("Couldn't create symbolic link\n"));
        IoDeleteDevice( deviceObject );
    }

    //Create Lists, Events and Timers

    PDEVICE_EXT_DATA DeviceExt = DriverObject->DeviceObject->DeviceExtension;
    KeInitializeSpinLock(&DeviceExt->pending_irp_queue_lock);
    InitializeListHead(&DeviceExt->pending_irp_queue);
    KeInitializeEvent(&DeviceExt->irql_inverted_call_ready_event, NotificationEvent, FALSE);
    KeInitializeEvent(&DeviceExt->termination_event, NotificationEvent, FALSE);

    IoCsqInitialize(&DeviceExt->cancel_safe_queue, CsqInsertIrp, CsqRemoveIrp, CsqPeekNextIrp, 
        CsqAcquireLock, CsqReleaseLock, CsqCompleteCanceledIrp);

    ntStatus = PsCreateSystemThread(&DeviceExt->periodic_reversed_call_thread_handle, GENERIC_ALL, 
        NULL, NULL, NULL, generate_reversed_calls, DriverObject);
    if (!NT_SUCCESS(ntStatus))
    {
        SIOCTL_KDPRINT(("Couldn't create thread to handle reversed calls related IRPS\n"));
        IoDeleteDevice(deviceObject);
    }

    return ntStatus;
}

void generate_reversed_calls(PVOID DriverObject) {
    PDRIVER_OBJECT DriverObj = DriverObject;
    PDEVICE_EXT_DATA DeviceExt = DriverObj->DeviceObject->DeviceExtension;
    NTSTATUS status;

    LARGE_INTEGER timer_interval;
    timer_interval.QuadPart = -3 * 10 * 1000 * 1000; //3s

    while (TRUE) {
        status = KeWaitForSingleObject(&DeviceExt->termination_event, Executive, KernelMode, TRUE, &timer_interval);

        if (status == STATUS_TIMEOUT) {
            //Complete one IRP
            PIRP Irp = IoCsqRemoveNextIrp(&DeviceExt->cancel_safe_queue, NULL);
            if (Irp) {
                CompleteIrp(Irp, STATUS_SUCCESS, 0);
            }
        }
        else if (status == STATUS_SUCCESS || status == STATUS_ALERTED) {
            break;
        }
    }
}

NTSTATUS CompleteIrp(PIRP Irp, NTSTATUS status, ULONG_PTR info)
{
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

NTSTATUS
SioctlCreate(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
    ) {
    UNREFERENCED_PARAMETER(DeviceObject);
    PAGED_CODE();

    return CompleteIrp(Irp, STATUS_SUCCESS, 0);
}

NTSTATUS
SioctlClose(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
) {
    UNREFERENCED_PARAMETER(DeviceObject);
    PAGED_CODE();
    return CompleteIrp(Irp, STATUS_SUCCESS, 0);
}

NTSTATUS
SioctlCleanup(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp) {
    PAGED_CODE();

    PDEVICE_EXT_DATA pdata = DeviceObject->DeviceExtension;
    KeSetEvent(&pdata->termination_event, IO_NO_INCREMENT, FALSE);

    return CompleteIrp(Irp, STATUS_SUCCESS, 0);
}

VOID
SioctlUnloadDriver(
    _In_ PDRIVER_OBJECT DriverObject
    ) {
    PDEVICE_OBJECT deviceObject = DriverObject->DeviceObject; 
    UNICODE_STRING uniWin32NameString;

    PAGED_CODE();

    RtlInitUnicodeString( &uniWin32NameString, DOS_DEVICE_NAME );
    IoDeleteSymbolicLink( &uniWin32NameString );

    if ( deviceObject != NULL )
    {
        IoDeleteDevice( deviceObject );
    }
}

NTSTATUS
SioctlDeviceControl(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    PDEVICE_EXT_DATA pdata = DeviceObject->DeviceExtension;

    PIO_STACK_LOCATION  irpSp = IoGetCurrentIrpStackLocation(Irp);
    if (irpSp->Parameters.DeviceIoControl.IoControlCode != IOCTL_SIOCTL_INVERTED_CALL) {
        return processIrp(Irp);
    }
    else {
        IoMarkIrpPending(Irp);
        IoCsqInsertIrp(&pdata->cancel_safe_queue, Irp, NULL);
        return STATUS_PENDING;
    }

}


NTSTATUS processIrp(PIRP Irp) {

    NTSTATUS ntStatus = STATUS_SUCCESS;
    PCHAR               inBuf, outBuf; // pointer to Input and output buffer

    PIO_STACK_LOCATION  irpSp = IoGetCurrentIrpStackLocation(Irp);
    ULONG inBufLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outBufLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

    if (!inBufLength || !outBufLength)
    {
        return CompleteIrp(Irp, STATUS_INVALID_PARAMETER, 0);
    }

    if (irpSp->Parameters.DeviceIoControl.IoControlCode == IOCTL_SIOCTL_QUERY_PROCESS_LIST_METHOD_BUFFERED) {
        //Debug info
        SIOCTL_KDPRINT(("Called IOCTL_SIOCTL_QUERY_PROCESS_LIST_METHOD_BUFFERED\n"));
        PrintIrpInfo(Irp);

        //Set buffers
        inBuf = Irp->AssociatedIrp.SystemBuffer;
        outBuf = Irp->AssociatedIrp.SystemBuffer;

        //Print data incoming
        SIOCTL_KDPRINT(("\tData from User :"));
        PrintChars(inBuf, inBufLength);

        //Allocate buffer to store process names
        USHORT PROCESS_NAMES_SIZE = 1024 * 16;
        PUNICODE_STRING processes_names = (PUNICODE_STRING) outBuf;
        processes_names->Length = 0;
        processes_names->Buffer = (PWCHAR)(outBuf + sizeof(UNICODE_STRING));
        processes_names->MaximumLength = PROCESS_NAMES_SIZE;

        UNICODE_STRING comma;
        RtlInitUnicodeString(&comma, L",");

        //Perform actual query
        int SPI_BUFFER_SIZE = 1 * 1024 * 1024;
        PVOID spi_buffer = ExAllocatePool2(POOL_FLAG_PAGED, SPI_BUFFER_SIZE, '9gaT');
        if (spi_buffer) {
            PSYSTEM_PROCESS_INFORMATION pspi = (PSYSTEM_PROCESS_INFORMATION)spi_buffer;
            if (NT_SUCCESS(ZwQuerySystemInformation(SystemProcessInformation, pspi, SPI_BUFFER_SIZE, NULL))) {
                while (pspi->NextEntryOffset) {
                    if (pspi->ImageName.Length) {
                        RtlAppendUnicodeStringToString(processes_names, &pspi->ImageName);
                        RtlAppendUnicodeStringToString(processes_names, &comma);
                    }
                    pspi = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)pspi + pspi->NextEntryOffset);
                }

                //Free memory
                ExFreePoolWithTag(spi_buffer, '9gaT');

                Irp->IoStatus.Information = processes_names->Length + sizeof(UNICODE_STRING) < outBufLength ?
                    processes_names->Length + sizeof(UNICODE_STRING) : outBufLength;
            }
        }
    }
    else {
        //Not expected IOCode
        Irp->IoStatus.Information = 0;
        ntStatus = STATUS_INVALID_PARAMETER;
    }

    Irp->IoStatus.Status = ntStatus;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return ntStatus;
}


_Use_decl_annotations_
VOID
CsqInsertIrp(
    PIO_CSQ Csq,
    PIRP  Irp
)
{
    PDEVICE_EXT_DATA devExtension;
    devExtension = CONTAINING_RECORD(Csq, DEVICE_EXT_DATA, cancel_safe_queue);
    InsertTailList(&devExtension->pending_irp_queue, &Irp->Tail.Overlay.ListEntry);
}

_Use_decl_annotations_
VOID
CsqRemoveIrp(
    PIO_CSQ  Csq,
    PIRP  Irp
)
{
    UNREFERENCED_PARAMETER(Csq);
    RemoveEntryList(&Irp->Tail.Overlay.ListEntry);
}

_Use_decl_annotations_
PIRP
CsqPeekNextIrp(
    PIO_CSQ  Csq,
    PIRP  Irp,
    PVOID  PeekContext
)
{
    ASSERT(PeekContext == NULL);

    PDEVICE_EXT_DATA        devExtension;
    PIRP                    nextIrp;
    PLIST_ENTRY             nextEntry;
    PLIST_ENTRY             listHead;

    devExtension = CONTAINING_RECORD(Csq,
        DEVICE_EXT_DATA, cancel_safe_queue);

    listHead = &devExtension->pending_irp_queue;


    //If IRP is null start from the head
    //Else start from the IRP
    if (Irp == NULL) {
        nextEntry = listHead->Flink;
    }
    else {
        nextEntry = Irp->Tail.Overlay.ListEntry.Flink;
    }

    if (nextEntry != listHead) {
        nextIrp = CONTAINING_RECORD(nextEntry, IRP, Tail.Overlay.ListEntry);
    }
    else {
        nextIrp = NULL;
    }

    return nextIrp;
}

_Use_decl_annotations_
VOID
CsqAcquireLock(
    PIO_CSQ  Csq,
    PKIRQL  Irql
)
{
    PDEVICE_EXT_DATA devExtension;
    devExtension = CONTAINING_RECORD(Csq, DEVICE_EXT_DATA, cancel_safe_queue);
    KeAcquireSpinLock(&devExtension->pending_irp_queue_lock, Irql);
}

_Use_decl_annotations_
VOID
CsqReleaseLock(
    PIO_CSQ  Csq,
    KIRQL  Irql
)
{
    PDEVICE_EXT_DATA devExtension;
    devExtension = CONTAINING_RECORD(Csq, DEVICE_EXT_DATA, cancel_safe_queue);
    KeReleaseSpinLock(&devExtension->pending_irp_queue_lock, Irql);
}

_Use_decl_annotations_
VOID
CsqCompleteCanceledIrp(
    _In_ PIO_CSQ  Csq,
    _In_ PIRP  Irp
)
{
    UNREFERENCED_PARAMETER(Csq);
    Irp->IoStatus.Status = STATUS_CANCELLED;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
}

VOID
PrintIrpInfo(
    PIRP Irp)
{
    PIO_STACK_LOCATION  irpSp;
    irpSp = IoGetCurrentIrpStackLocation( Irp );

    PAGED_CODE();

    SIOCTL_KDPRINT(("\tIrp->AssociatedIrp.SystemBuffer = 0x%p\n",
        Irp->AssociatedIrp.SystemBuffer));
    SIOCTL_KDPRINT(("\tIrp->UserBuffer = 0x%p\n", Irp->UserBuffer));
    SIOCTL_KDPRINT(("\tirpSp->Parameters.DeviceIoControl.Type3InputBuffer = 0x%p\n",
        irpSp->Parameters.DeviceIoControl.Type3InputBuffer));
    SIOCTL_KDPRINT(("\tirpSp->Parameters.DeviceIoControl.InputBufferLength = %d\n",
        irpSp->Parameters.DeviceIoControl.InputBufferLength));
    SIOCTL_KDPRINT(("\tirpSp->Parameters.DeviceIoControl.OutputBufferLength = %d\n",
        irpSp->Parameters.DeviceIoControl.OutputBufferLength ));
    return;
}

VOID
PrintChars(
    _In_reads_(CountChars) PCHAR BufferAddress,
    _In_ size_t CountChars
    )
{
    PAGED_CODE();

    if (CountChars) {

        while (CountChars--) {

            if (*BufferAddress > 31
                 && *BufferAddress != 127) {

                KdPrint (( "%c", *BufferAddress) );

            } else {

                KdPrint(( ".") );

            }
            BufferAddress++;
        }
        KdPrint (("\n"));
    }
    return;
}


