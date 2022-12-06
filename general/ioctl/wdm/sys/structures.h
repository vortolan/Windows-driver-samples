#pragma once

#include <wdm.h>

typedef struct _DEVICE_EXT_DATA {
	LIST_ENTRY irp_reversed_call_list_head;
	KSPIN_LOCK irp_reversed_call_list_lock;

	HANDLE periodic_reversed_call_thread_handle;

	//Events
	KEVENT irql_inverted_call_ready_event;
	KEVENT termination_event;

} DEVICE_EXT_DATA, * PDEVICE_EXT_DATA;