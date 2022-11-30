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
    HANDLE hDevice;
    BOOL bRc;
    ULONG bytesReturned;
    DWORD errNum = 0;
    TCHAR driverLocation[MAX_PATH];

    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    //
    // open the device
    //

    if ((hDevice = CreateFile( "\\\\.\\IoctlTest",
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

        hDevice = CreateFile( "\\\\.\\IoctlTest",
                            GENERIC_READ | GENERIC_WRITE,
                            0,
                            NULL,
                            CREATE_ALWAYS,
                            FILE_FLAG_OVERLAPPED,
                            NULL);

        if ( hDevice == INVALID_HANDLE_VALUE ){
            printf ( "Error: CreatFile Failed : %d\n", GetLastError());
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
    OVERLAPPED overlapped_handles[10];

    for (int i = 0; i < sizeof(overlapped_handles) / sizeof(overlapped_handles[0]); ++i) {
        memset(OutputBuffer, 0, sizeof(OutputBuffer));

        bRc = DeviceIoControl(hDevice,
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

    OVERLAPPED process_list_overlapped;
    StringCbCopy(InputBuffer, sizeof(InputBuffer),
        "Hey, get me the list of running processes please!");

    printf("\nCalling DeviceIoControl METHOD_BUFFERED_PROCESS_LIST:\n");

    memset(OutputBuffer, 0, sizeof(OutputBuffer));

    bRc = DeviceIoControl(hDevice,
        (DWORD)IOCTL_SIOCTL_QUERY_PROCESS_LIST_METHOD_BUFFERED,
        &InputBuffer,
        (DWORD)strlen(InputBuffer) + 1,
        &OutputBuffer,
        sizeof(OutputBuffer),
        &bytesReturned,
        &process_list_overlapped
    );

    if (!bRc)
    {
        printf("Error in DeviceIoControl : %d", GetLastError());
        return;

    }
    
    wprintf(L"OutBuffer (%d): %s\n", bytesReturned, (WCHAR*) OutputBuffer);

    CloseHandle ( hDevice );

    //
    // Unload the driver.  Ignore any errors.
    //

    ManageDriver(DRIVER_NAME,
                 driverLocation,
                 DRIVER_FUNC_REMOVE
                 );


    _getch();

}


