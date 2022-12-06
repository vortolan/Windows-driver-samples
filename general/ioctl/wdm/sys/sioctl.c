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
NTSTATUS CancelIrp(PIRP Irp);
VOID CancelAllList(PKSPIN_LOCK lock, PLIST_ENTRY list_head);
PIRP PopIrp(PLIST_ENTRY list_head, PKSPIN_LOCK list_lock);
NTSTATUS processIrp(PIRP Irp);


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
    KeInitializeSpinLock(&DeviceExt->irp_reversed_call_list_lock);
    InitializeListHead(&DeviceExt->irp_reversed_call_list_head);
    KeInitializeEvent(&DeviceExt->irql_inverted_call_ready_event, NotificationEvent, FALSE);
    KeInitializeEvent(&DeviceExt->termination_event, NotificationEvent, FALSE);

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
            PIRP Irp = PopIrp(&DeviceExt->irp_reversed_call_list_head, &DeviceExt->irp_reversed_call_list_lock);
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
NTSTATUS CancelIrp(PIRP Irp)
{
    return CompleteIrp(Irp, STATUS_CANCELLED, 0);
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

    CancelAllList(&pdata->irp_reversed_call_list_lock, &pdata->irp_reversed_call_list_head);
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
        ExInterlockedInsertTailList(&pdata->irp_reversed_call_list_head, &Irp->Tail.Overlay.ListEntry,
            &pdata->irp_reversed_call_list_lock);
        return STATUS_PENDING;
    }

}


VOID
CancelAllList(PKSPIN_LOCK lock, PLIST_ENTRY list_head) {
    KIRQL old_irql;
    KeAcquireSpinLock(lock, &old_irql);

    while (!IsListEmpty(list_head)) {
        PLIST_ENTRY entry = RemoveHeadList(list_head);
        PIRP Irp = CONTAINING_RECORD(entry,
            IRP,
            Tail.
            Overlay.
            ListEntry);
        CancelIrp(Irp);
    }

    KeReleaseSpinLock(lock, old_irql);
}

PIRP PopIrp(PLIST_ENTRY list_head, PKSPIN_LOCK list_lock) {
    PLIST_ENTRY pListEntry = ExInterlockedRemoveHeadList(list_head, list_lock);
    if (!pListEntry) {
        return NULL;
    }
    else {
        PIRP Irp = CONTAINING_RECORD(pListEntry,
            IRP,
            Tail.
            Overlay.
            ListEntry);
        return Irp;
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
        UNICODE_STRING processes_names = { 0 };
        processes_names.Length = 0;
        processes_names.Buffer = (PWCHAR)ExAllocatePool2(POOL_FLAG_PAGED, PROCESS_NAMES_SIZE, '9gaT');
        processes_names.MaximumLength = PROCESS_NAMES_SIZE;

        UNICODE_STRING comma;
        RtlInitUnicodeString(&comma, L",");

        UNICODE_STRING nullstr;
        RtlInitUnicodeString(&nullstr, L"\0");

        //Perform actual query
        int SPI_BUFFER_SIZE = 1 * 1024 * 1024;
        PVOID spi_buffer = ExAllocatePool2(POOL_FLAG_PAGED, SPI_BUFFER_SIZE, '9gaT');
        if (spi_buffer) {
            PSYSTEM_PROCESS_INFORMATION pspi = (PSYSTEM_PROCESS_INFORMATION)spi_buffer;
            if (NT_SUCCESS(ZwQuerySystemInformation(SystemProcessInformation, pspi, SPI_BUFFER_SIZE, NULL))) {

                while (pspi->NextEntryOffset) {
                    if (pspi->ImageName.Length) {
                        RtlAppendUnicodeStringToString(&processes_names, &pspi->ImageName);
                        RtlAppendUnicodeStringToString(&processes_names, &comma);
                    }
                    pspi = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)pspi + pspi->NextEntryOffset);
                }

                //Copy data to out buffer and print
                RtlAppendUnicodeStringToString(&processes_names, &nullstr);
                RtlCopyMemory(outBuf, processes_names.Buffer, processes_names.Length * sizeof(WCHAR));

                //Free memory
                ExFreePoolWithTag(spi_buffer, '9gaT');
                ExFreePoolWithTag(processes_names.Buffer, '9gaT');

                Irp->IoStatus.Information = processes_names.Length < outBufLength ?
                    processes_names.Length : outBufLength;
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


