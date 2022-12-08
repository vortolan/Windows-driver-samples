#pragma once

#include <wdm.h>

typedef struct _DEVICE_EXT_DATA {
	LIST_ENTRY pending_irp_queue;
	KSPIN_LOCK pending_irp_queue_lock;

	HANDLE periodic_reversed_call_thread_handle;

	//Events
	KEVENT irql_inverted_call_ready_event;
	KEVENT termination_event;

	//CSQ
	IO_CSQ cancel_safe_queue;

} DEVICE_EXT_DATA, * PDEVICE_EXT_DATA;