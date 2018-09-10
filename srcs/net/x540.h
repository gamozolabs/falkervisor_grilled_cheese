#pragma once

#include <net/net.h>

#define X540_NUM_RX 1024
#define X540_NUM_TX 1024

struct _x540_rx_ring {
	uintptr_t addr;
	uint64_t  status;
};

struct _x540_tx_ring {
	uintptr_t addr;

	union {
		struct {
			uint64_t length:16;
			uint64_t cso:8;
			uint64_t cmd:8;
			uint64_t dd:1;
			uint64_t rsvd:7;
			uint64_t css:8;
			uint64_t vlan:16;
		} b;
		uint64_t val;
	} status;
};

struct _x540_queue {
	uintptr_t             rx_ring_phys;
	uintptr_t             tx_ring_phys;
	struct _x540_rx_ring *rx_ring;
	struct _x540_tx_ring *tx_ring;

	void *rx_bufs[X540_NUM_RX];
	void *tx_bufs[X540_NUM_TX];

	uint64_t rx_head;
	uint64_t tx_head;
	uint64_t tx_tail;
};

rstate_t
x540_init(struct _net_device *device);

rstate_t
x540_queue_init(struct _net_queue *queue);

