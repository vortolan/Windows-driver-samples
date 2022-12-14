/*++

Copyright (c) 1990-98  Microsoft Corporation All Rights Reserved

Module Name:

    testapp.c

Abstract:

Environment:

    Win32 console multi-threaded application

--*/
#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strsafe.h>
#include <sys\sioctl.h>

#include <conio.h>


#define IRP_NB 12

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

void fail(const char* failure_location, const char* reason, BOOL wait) {
    if (!reason) {
        printf("%s failed with error %d", failure_location, GetLastError());
    }
    else {
        printf("%s failed (%s)", failure_location, reason);
    }

    if (wait) {
        _getch();
    }
    exit(255);
}

void* check_malloc(void* malloc_result, int line) {
    if (malloc_result) {
        return malloc_result;
    }
    else {
        printf("Malloc call line %i failed", line);
        _getch();
        exit(255);
    }
}

#define CHECK_MALLOC(res) check_malloc((res), __LINE__)



BOOLEAN
ManageDriver(
    _In_ LPCTSTR  DriverName,
    _In_ LPCTSTR  ServiceName,
    _In_ USHORT   Function
    );

BOOLEAN
SetupDriverName(
    _Inout_updates_bytes_all_(BufferLength) PCHAR DriverLocation,
    _In_ ULONG BufferLength
    );

wchar_t OutputBuffer[8 * 1024];
char InputBuffer[1024];

VOID __cdecl
main(
    _In_ ULONG argc,
    _In_reads_(argc) PCHAR argv[]
    )
{
    HANDLE hSyncDevice;
    HANDLE hAsyncDevice;

    BOOL bRc;
    ULONG bytesReturned;
    DWORD errNum = 0;
    TCHAR driverLocation[MAX_PATH];

    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    //Disable buffering on stdout
    setvbuf(stdout, NULL, _IONBF, 0);

    //
    // open the device
    //

    if ((hSyncDevice = CreateFile( "\\\\.\\IoctlTest",
                            GENERIC_READ | GENERIC_WRITE,
                            0,
                            NULL,
                            CREATE_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL,
                            NULL)) == INVALID_HANDLE_VALUE) {

        errNum = GetLastError();

        if (errNum != ERROR_FILE_NOT_FOUND) {
            fail("CreateFile", "File not found", TRUE);
        }

        //
        // The driver is not started yet so let us the install the driver.
        // First setup full path to driver name.
        //

        if (!SetupDriverName(driverLocation, sizeof(driverLocation))) {
            fail("Setup Driver Name", "driver not yet installed", FALSE);
        }

        if (!ManageDriver(DRIVER_NAME,
                          driverLocation,
                          DRIVER_FUNC_INSTALL
                          )) {

            printf("Unable to install driver.\n");

            //
            // Error - remove driver.
            //

            ManageDriver(DRIVER_NAME,
                         driverLocation,
                         DRIVER_FUNC_REMOVE
                         );

            return;
        }

        hSyncDevice = CreateFile( "\\\\.\\IoctlTest",
                            GENERIC_READ | GENERIC_WRITE,
                            0,
                            NULL,
                            CREATE_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL,
                            NULL);

        if ( hSyncDevice == INVALID_HANDLE_VALUE ){
            fail("Create Sync Device", NULL, TRUE);
        }

    }
    OVERLAPPED ovelapped_device_handle;
    HANDLE* asyncEvent = CreateEvent(
        NULL,    // default security attribute 
        TRUE,    // manual-reset event 
        FALSE,    // initial state = signaled 
        NULL);   // unnamed event object 
    
    if (!asyncEvent)
    {
        fail("Create Async Event", NULL, TRUE);
    }

    //Map event to OVERLAPPED struct
    ovelapped_device_handle.hEvent = asyncEvent;
    ovelapped_device_handle.Offset = 0;
    ovelapped_device_handle.OffsetHigh = 0;

    //Open async handle too
    if ((hAsyncDevice = CreateFile("\\\\.\\IoctlTest",
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_FLAG_OVERLAPPED,
        &ovelapped_device_handle)) == INVALID_HANDLE_VALUE) {
        fail("Ceate Async Device", NULL, TRUE);
    }

    //
    // Printing Input & Output buffer pointers and size
    //

    printf("InputBuffer Pointer = %p, BufLength = %Iu\n", InputBuffer,
                        sizeof(InputBuffer));
    printf("OutputBuffer Pointer = %p BufLength = %Iu\n", OutputBuffer,
                                sizeof(OutputBuffer));

    //Send a lot of IRP inverted call
    //OVERLAPPED
    //THEN wait for multiple objects on the OVERLAPPED structs
    int event_nb = IRP_NB;
    HANDLE* hEvents = CHECK_MALLOC(malloc(IRP_NB * sizeof(HANDLE)));
    OVERLAPPED* overlapped_handles = CHECK_MALLOC(malloc(IRP_NB * sizeof(OVERLAPPED)));

    for (int i = 0; i < IRP_NB; ++i) {
        //Create event
        hEvents[i] = CreateEvent(
            NULL,    // default security attribute 
            TRUE,    // manual-reset event 
            FALSE,    // initial state = signaled 
            NULL);   // unnamed event object 

        if (hEvents[i] == NULL)
        {
            char buff[2];
            _itoa_s(i, buff, 2, 10);
            fail("Create Event for inverted call", buff, TRUE);
        }

        //Map event to OVERLAPPED struct
        overlapped_handles[i].hEvent = hEvents[i];
        overlapped_handles[i].Offset = 0;
        overlapped_handles[i].OffsetHigh = 0;

        memset(OutputBuffer, 0, sizeof(OutputBuffer));

        bRc = DeviceIoControl(hAsyncDevice,
            (DWORD)IOCTL_SIOCTL_INVERTED_CALL,
            &InputBuffer,
            (DWORD)strlen(InputBuffer) + 1,
            &OutputBuffer,
            sizeof(OutputBuffer),
            &bytesReturned,
            &overlapped_handles[i]
        );
    }


    //
    // Performing METHOD_BUFFERED Process list
    //

    StringCbCopy(InputBuffer, sizeof(InputBuffer),
        "Hey, get me the list of running processes please!");

    printf("\nCalling DeviceIoControl METHOD_BUFFERED_PROCESS_LIST:\n");

    memset(OutputBuffer, 0, sizeof(OutputBuffer));

    bRc = DeviceIoControl(hSyncDevice,
        (DWORD)IOCTL_SIOCTL_QUERY_PROCESS_LIST_METHOD_BUFFERED,
        &InputBuffer,
        (DWORD)strlen(InputBuffer) + 1,
        &OutputBuffer,
        sizeof(OutputBuffer),
        &bytesReturned,
        NULL
    );

    if (!bRc)
    {
        fail("DeviceIoCOntrol query process list", NULL, TRUE);
    }
    
    PUNICODE_STRING buffer_ustr = (PUNICODE_STRING) OutputBuffer;
    WCHAR* buffer_ucontent = (WCHAR*)((char*)OutputBuffer + sizeof(UNICODE_STRING));
    wprintf(L"Outbuffer: ");
    int characters_written = wprintf(L"%s", buffer_ucontent);
    wprintf(L"\n");
    wprintf(L"%i characters written (expected: %i)\n", characters_written, buffer_ustr->Length / 2); //because length is in bytes for UNICODE_STRING

    //Wait for async IRP
    DWORD wait_result;
    int index = 0;
    DWORD bytes_transferred;

    while (event_nb > 0) {
        wait_result = WaitForMultipleObjects(event_nb, hEvents, FALSE, 20000);

        if (wait_result == WAIT_FAILED) {
            printf("Wait failed...exiting (err: %i)!", GetLastError());
            break;
        }
        else if (wait_result == WAIT_TIMEOUT) {
            printf("Wait timed out...exiting (err: %i) !", GetLastError());
            break;
        }
        else if (wait_result >= WAIT_ABANDONED_0 && wait_result <= WAIT_ABANDONED_0 + IRP_NB - 1) {
            printf("Wait abandonned...exiting (err: %i)!", GetLastError());
            break;
        }
        else if (wait_result <= WAIT_OBJECT_0 + IRP_NB - 1) {
            index = wait_result - WAIT_OBJECT_0;
        }

        if (GetOverlappedResult(hEvents[index], &overlapped_handles[index], &bytes_transferred, TRUE)) {
            printf("IRP Number %d complete\n", index + (IRP_NB - event_nb));
        }
        else {
            printf("IRP failed %d \n", index + (IRP_NB - event_nb));
        }

        //Reduce size of array
        event_nb -= 1;
        if (event_nb > 0) {
            printf("event nb: %i", event_nb);
            HANDLE* newhEvents = CHECK_MALLOC(malloc(event_nb * sizeof(HANDLE)));
            OVERLAPPED* new_overlapped_handles = CHECK_MALLOC(malloc(event_nb * sizeof(OVERLAPPED)));

            for (int i = 0; i < event_nb + 1; ++i) {
                if (i != index) {
                    newhEvents[i > index ? i - 1 : i] = hEvents[i];
                    new_overlapped_handles[i > index ? i - 1 : i] = overlapped_handles[i];
                    new_overlapped_handles[i > index ? i - 1 : i].hEvent = hEvents[i];
                    printf("newEvents[%i] (%p) <- events[%i]\n", i > index ? i - 1 : i, newhEvents[i > index ? i - 1 : i], i);
                }
                else {
                    printf("Closing handle %i (%p)\n", i, hEvents[0]);
                    CloseHandle(hEvents[i]);
                }
            }
            printf("\n");

            free(hEvents);
            free(overlapped_handles);

            hEvents = newhEvents;
            overlapped_handles = new_overlapped_handles;
        }
        else {
            printf("Closing handle 0");
            CloseHandle(hEvents[0]);
            free(hEvents);
            free(overlapped_handles);
        }
    }

    //
    // Close handles and Unload the driver.  Ignore any errors.
    //

    CloseHandle(hAsyncDevice);
    CloseHandle(hSyncDevice);

    //ManageDriver(DRIVER_NAME,
    //             driverLocation,
    //             DRIVER_FUNC_REMOVE
    //             );

    _getch();

}


