#pragma once

enum _chrome_ipctype {
	IPCTYPE_INT,
	IPCTYPE_STD_STRING,
	IPCTYPE_BOOL,
	IPCTYPE_GURL,
	IPCTYPE_INT64,
	IPCTYPE_STRING16,

	IPCTYPE_HOSTRESOURCE,
	IPCTYPE_SHARED_MEMORY_HANDLE,
	IPCTYPE_POINT,
	IPCTYPE_SIZE,
	IPCTYPE_RECT,
	IPCTYPE_DOUBLE,
};

struct _chrome_ipc {
	const char *msg_class;

	void *func;
	uint32_t ipc_id;

	int in_params;
	int out_params;

	enum _chome_ipctype params[32];
};

#pragma pack(push, 1)
struct _cipc_hostresource {
	int32_t instance;
	int32_t host_resource;
};

struct _cipc_point {
	int32_t x;
	int32_t y;
};

struct _cipc_size {
	int32_t width;
	int32_t height;
};

struct _cipc_rect {
	struct _cipc_point origin;
	struct _cipc_size  size;
};

struct _cipc_shared_memory_handle {
	uint64_t handle;
	uint32_t pid;
};

struct _chrome_ipc_header {
	uint32_t length;
	uint32_t route;
	uint32_t msg_id;

	union {
		struct {
			uint32_t priority_mask:2;
			uint32_t sync:1;
			uint32_t reply:1;
			uint32_t reply_error:1;
			uint32_t unblock:1;
			uint32_t pumping_msgs:1;
			uint32_t has_sent_time:1;

			uint32_t ref_number:24;
		} fields;

		uint32_t backing;
	} flags;

	uint32_t unknown;
};
#pragma pack(pop)

uint64_t
gen_ipc_stream(_Out_writes_bytes_(len) uint8_t *payload, _In_ uint64_t len,
		_In_ uint64_t max_messages);

uint64_t
gen_ipc_rand(_Out_writes_bytes_(len) uint8_t *payload, _In_ uint64_t len,
		_In_ uint64_t max_messages);

