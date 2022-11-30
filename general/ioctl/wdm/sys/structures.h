#pragma once

#include <wdm.h>

typedef struct _DEVICE_EXT_DATA {
	//LIST_ENTRY irp_list_head;
	//FAST_MUTEX irp_list_lock;

	LIST_ENTRY irp_reversed_call_list_head;
	FAST_MUTEX irp_reversed_call_list_lock;

	HANDLE irp_thread_handle;
	HANDLE periodic_reversed_call_thread_handle;
	
	KTIMER reversed_call_timer;

	//Events
	//KEVENT irql_ready_event;
	KEVENT irql_reversed_call_ready_event;

	KEVENT termination_event;

} DEVICE_EXT_DATA, * PDEVICE_EXT_DATA;