#pragma once

#define NET_BASE_PORT 1400

#define NET_TERM_PRINTSTR 0xc1bc2ea7cd2f4ac6

#define NET_NOTIFY_REBOOT  0x636300e3c6e4f392
#define NET_REBOOT_REQUEST 0x9d7367f260ec073a

#define NET_REPORT_COVERAGE_STATUS 0xc0330f3bd9f585d9

#define NET_FILE_DOWNLOAD       0x18c59e5b342482c1
#define NET_FILE_DOWNLOAD_RESP  0x767bc53bc2d2ced0
#define NET_FILE_DOWNLOAD_CHUNK 0xeb717e7f8d411b03
#define NET_SNAP_UPLOAD         0x1A8FA024
#define NET_SNAP_UPLOAD_DATA    0x1E004AFA
#define NET_SNAP_UPLOAD_CONF    0x4E0E3AFD
#define NET_FILE_CHUNK_SIZE     8192
#define NET_COVERAGE_INFO       0xe645244373577400

#pragma pack(push, 1)
struct _file_download {
	uint64_t magic;
	uint64_t req_id;
	uint64_t offset;
	uint64_t size;
	uint64_t info_only;
	
	char fn[256];
};

struct _file_download_response {
	uint64_t magic;
	uint64_t req_id;

	uint64_t hash;
	uint64_t file_len; /* -1 if file not found */
};

struct _file_download_chunk {
	uint64_t magic;
	uint64_t req_id;
	uint64_t seq_id;

	uint8_t  buf[8192];
};

struct _snap_upload {
	uint64_t magic;
	uint64_t req_id;
	uint64_t file_len;
	uint64_t padding;
	uint8_t  fn[256];
	__m128i  hash;
};

struct _snap_upload_data {
	uint64_t magic;
	uint64_t req_id;
	uint8_t  data[NET_FILE_CHUNK_SIZE];
};

struct _snap_upload_conf {
	uint64_t magic;
	uint64_t req_id;
};

struct _coverage_info {
	uint64_t magic;
	uint64_t fuzzes;
	uint64_t cc_count;
	uint64_t uniq_crashes;
};
#pragma pack(pop)

struct _net_queue {
	/* Identifier of the queue. This number is used directly for NICs with
	 * multiple queues, so it should be 0-based.
	 *
	 * All queues other than queue 0 must have a filter in order for packets
	 * to be routed to it.
	 *
	 * Maximum number of queues:
	 *
	 * +-------------------------+-----------+-----------+
	 * | Device                  | RX Queues | TX Queues |
	 * +-------------------------+-----------+-----------+
	 * | Intel X540              | 128       | 128       |
	 * +-------------------------+-----------+-----------+
	 */
	int queue_id;

	/* UDP port which will be used as the filter to route to this queue. This
	 * field is unused for queue 0, as no filters are allowed on queue 0.
	 * Filters only apply to RX queues, any TX queue can be used to send any
	 * packet.
	 *
	 * Queues are filtered with the following:
	 *
	 * Packet must be UDP
	 * Packet destination IP must match queue->device->ip.
	 * Packet destination port must match queue->filter_port.
	 */
	int filter_port;

	/* Per-device specific context related to the queue */
	void *device_context;

	/* Pointer to routine to send packets on this queue */
	rstate_t
	(*send)(
			struct _net_queue *queue,
			const void        *packet,
			uint32_t           length);

	/* Pointer to routine to recv packets on this queue */
	rstate_t
	(*recv)(
			struct _net_queue  *queue,
			void              **packet,
			uint32_t           *packet_len);

	/* Pointer to routine to advance recv pointer */
	rstate_t
	(*recv_release)(struct _net_queue *queue);

	/* Current task who owns the lock on this structure. If NULL, available
	 * for use.
	 */
	struct _task *task_using;

	/* Network device to which this queue belongs */
	struct _net_device *device;

	/* Next queue in the linked list of queues for the given device */
	struct _net_queue *next;
};

struct _net_device {
	/* MAC address and IP of this device, stored in network endianness. If
	 * DHCP assignment failed, the IP will be 0.
	 */
	uint8_t  mac[6];
	uint32_t ip;

	/* MAC address and IP of the DHCP server, stored in network endianness. If
	 * DHCP failed both fields will be filled with 0xff.
	 */
	uint8_t  dhcp_mac[6];
	uint32_t dhcp_ip;
	uint32_t dhcp_lease_time;

	/* PCI BAR0 address */
	uintptr_t bar0;

	/* Number of queues for this device */
	uint32_t num_queues;

	/* Linked list of queues associated with this device */
	struct _net_queue  queues;
	struct _net_queue *queues_end;

	/* Queue to use in timer interrupts */
	struct _net_queue *interrupt_queue;

	/* Next network device in the linked list */
	struct _net_device *next;
};

struct _remote_map_state {
	uint64_t  chunk_size;
	void     *chunk_tmp;

	char fn[256];
};

#pragma pack(push, 1)
struct _udp_packet {
	/* MAC header */
	uint8_t  dest_mac[6];
	uint8_t  src_mac[6];
	uint16_t type;

	/* IP header */
	uint8_t  ver;
	uint8_t  svc;
	uint16_t len; /* 28 + payload_len */
	uint16_t ident;
	uint8_t  flags;
	uint8_t  frag;
	uint8_t  ttl;
	uint8_t  proto; /* 0x11 - UDP */
	uint16_t ip_chk;
	uint32_t src_ip;
	uint32_t dest_ip;

	/* UDP header */
	uint16_t src_port;
	uint16_t dest_port;
	uint16_t ulen; /* 8 + payload_len */
	uint16_t udp_chk;

	uint8_t payload[8972];
};
#pragma pack(pop)

#pragma pack(push, 1)
struct _arp_packet {
	/* MAC header */
	uint8_t  dest_mac[6];
	uint8_t  src_mac[6];
	uint16_t type;

	uint16_t hw_type;
	uint16_t proto_type;
	uint8_t  hw_size;
	uint8_t  proto_size;
	uint16_t op;
	uint8_t  sender_mac[6];
	uint32_t sender_ip;
	uint8_t  target_mac[6];
	uint32_t target_ip;
};
#pragma pack(pop)

rstate_t
net_init(void);

rstate_t
net_init_local_queue(void);

void
net_display_devices(void);

rstate_t
net_process_interval(void);

rstate_t
net_consume_unwanted(struct _net_device *device,
		uint8_t *packet, uint32_t packet_len);

rstate_t
net_send_udp(
		struct _net_queue *queue,
		const void        *payload,
		uint32_t           len,
		uint32_t           dest_ip,
		uint32_t           dest_port);

rstate_t
net_parse_udp(
		const void  *packet,
		uint32_t     packet_len,
		void       **udp_payload,
		uint32_t    *udp_payload_len);

rstate_t
net_recv_udp(
		struct _net_queue   *queue,
		void               **packet,
		uint32_t            *packet_len,
		struct _udp_packet **raw);

rstate_t
net_recv_release(struct _net_queue *queue);

rstate_t
net_notify_server(void);

rstate_t
net_download_file(
		struct _net_queue  *queue,
		const char         *filename,
		uint64_t            offset,
		void              **outbuf,
		uint64_t           *outlen);

rstate_t
net_map_remote(
		struct _net_queue  *queue,
		const char         *filename,
		uint64_t            chunk_size,
		void               **outbuf,
		uint64_t            *outlen);

rstate_t
net_start(struct _net_queue *queue);

void
net_stop(struct _net_queue *queue);

rstate_t
net_upload(
		struct _net_queue *queue,
		const char        *fn,
		void              *buf,
		size_t             len);

