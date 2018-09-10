#pragma once

#define MAX_IPC_SIZE     (4 * 1024)
#define NUM_IPC_MESSAGES 64

struct _ipc_stream {
	struct {
		int     filled;
		uint8_t msg[MAX_IPC_SIZE];
	} ipc[NUM_IPC_MESSAGES];
};

rstate_t
fuzz_chrome(void);

