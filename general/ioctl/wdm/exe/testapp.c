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

#define IRP_NB 10


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

char OutputBuffer[16 * 1024];
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

            printf("CreateFile failed : %d\n", errNum);

            return ;
        }

        //
        // The driver is not started yet so let us the install the driver.
        // First setup full path to driver name.
        //

        if (!SetupDriverName(driverLocation, sizeof(driverLocation))) {

            return ;
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
            printf ( "Error: CreatFile Failed : %d\n", GetLastError());
            return;
        }

    }
    OVERLAPPED ovelapped_device_handle;
    //Open async handle too
    if ((hAsyncDevice = CreateFile("\\\\.\\IoctlTest",
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_FLAG_OVERLAPPED,
        &ovelapped_device_handle)) == INVALID_HANDLE_VALUE) {

        errNum = GetLastError();

        if (errNum != ERROR_FILE_NOT_FOUND) {

            printf("CreateFile failed : %d\n", errNum);

            return;
        }
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
    HANDLE* hEvents = malloc(event_nb * sizeof(HANDLE));
    OVERLAPPED* overlapped_handles = malloc(event_nb * sizeof(OVERLAPPED));

    for (int i = 0; i < IRP_NB; ++i) {
        //Create event
        hEvents[i] = CreateEvent(
            NULL,    // default security attribute 
            TRUE,    // manual-reset event 
            FALSE,    // initial state = signaled 
            NULL);   // unnamed event object 

        if (hEvents[i] == NULL)
        {
            printf("CreateEvent failed with %d.\n", GetLastError());
            return;
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
        printf("Error in DeviceIoControl : %d", GetLastError());
        return;

    }
    
    wprintf(L"OutBuffer (%d): %s\n", bytesReturned, (WCHAR*) OutputBuffer);


    //Wait for async IRP
    DWORD wait_result;
    int index = 0;
    DWORD bytes_transferred;

    while (event_nb > 0) {
        wait_result = WaitForMultipleObjects(event_nb, hEvents, FALSE, 20000);

        if (wait_result == WAIT_FAILED) {
            printf("Wait failed...exiting !");
            break;
        }
        else if (wait_result == WAIT_TIMEOUT) {
            printf("Wait timed out...exiting !");
            break;
        }
        else if (wait_result >= WAIT_ABANDONED_0 && wait_result <= WAIT_ABANDONED_0 + event_nb - 1) {
            printf("Wait abandonned...exiting !");
            break;
        }
        else if (wait_result <= WAIT_OBJECT_0 + event_nb - 1) {
            index = wait_result - WAIT_OBJECT_0;
        }

        if (GetOverlappedResult(hEvents[index], &overlapped_handles[index], &bytes_transferred, TRUE)) {
            printf("IRP Number %d complete\n", index + (IRP_NB - event_nb));
        }
        else {
            printf("IRP failed");
        }

        //Reduce size of array
        event_nb -= 1;
        if (event_nb > 0) {
            HANDLE* newhEvents = malloc(event_nb * sizeof(HANDLE));
            OVERLAPPED* new_overlapped_handles = malloc(event_nb * sizeof(OVERLAPPED));

            for (int i = 0; i < event_nb + 1; ++i) {
                if (i != index) {
                    newhEvents[i > index ? i - 1 : i] = hEvents[i];
                    new_overlapped_handles[i > index ? i - 1 : i] = overlapped_handles[i];
                }
                else {
                    CloseHandle(hEvents[i]);
                }
            }

            free(hEvents);
            free(overlapped_handles);

            hEvents = newhEvents;
            overlapped_handles = new_overlapped_handles;
        }
        else {
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

    ManageDriver(DRIVER_NAME,
                 driverLocation,
                 DRIVER_FUNC_REMOVE
                 );

    _getch();

}


