#include <grilled_cheese.h>
#include <mm/mm.h>
#include <generic/stdlib.h>
#include <net/net.h>
#include <net/x540.h>
#include <time/time.h>
#include <disp/disp.h>

#define X540_MMIO_UINT32(x) *(volatile uint32_t*)(device->bar0 + (x))

static rstate_t
x540_send_packet(
		struct _net_queue *queue,
		const void        *packet,
		uint32_t           length);

static rstate_t
x540_rx_probe(
		struct _net_queue  *queue,
		void              **packet,
		uint32_t           *packet_len);

static rstate_t
x540_rx_advance(struct _net_queue *queue);

/* x540_init()
 *
 * Summary:
 *
 * This resets and initializes the x540 to a known state.
 */
rstate_t
x540_init(struct _net_device *device)
{
	RSTATE_LOCALS;

	/* Disable all interrupts by writing Fs to the Extended Interrupt Mask
	 * Clear Register (EIMC)
	 */
	X540_MMIO_UINT32(0x0888) = 0x7fffffff;

	/* Reset the device by setting RST in the CTRL register */
	X540_MMIO_UINT32(0x0000) |= (1 << 26);

	/* Poll until the reset bit is cleared, then wait 20ms, as recommended by
	 * the documentation.
	 */
	while(X540_MMIO_UINT32(0x0000) & (1 << 26));
	rdtsc_sleep(20000);

	/* Disable all interrupts by writnig Fs to the Extended Interrupt Mask
	 * Clear Register (EIMC)
	 */
	X540_MMIO_UINT32(0x0888) = 0x7fffffff;

	/* Enable jumbo frames up to 9018 bytes (including CRC) */
	X540_MMIO_UINT32(0x4240) |= (   1 <<  2); /* HLREG0 */
	X540_MMIO_UINT32(0x4268)  = (9018 << 16); /* MAXFRS */

	/* Enable transmit path DMA */
	X540_MMIO_UINT32(0x4a80) |= (1 << 0);

	/* Set the RX control register
	 * Enable the following:
	 * UPE - Unicast promiscuous enable
	 * MPE - Multicast promiscuous enable
	 * BAM - Accept broadcast packets
	 */
	X540_MMIO_UINT32(0x5080) = (1 << 9) | (1 << 8) | (1 << 10);

	/* Enable snooping globally to prevent cache incoherency */
	X540_MMIO_UINT32(0x0018) |= (1 << 16);

	/* Get the NIC mac address from the RAL0 and RAH0 registers. These are
	 * filled from the NVM MAC address upon a NIC reset.
	 */
	*(uint32_t*)(device->mac + 0) = X540_MMIO_UINT32(0xa200) & 0xffffffff;
	*(uint16_t*)(device->mac + 4) = X540_MMIO_UINT32(0xa204) & 0x0000ffff;

	/* Enable all 128 TX queues by setting DCB_ena and NUM_TC_OR_Q to the MTQC
	 */
	X540_MMIO_UINT32(0x8120) = (3 << 2) | (1 << 0);

	rstate_ret = rstate = RSTATE_SUCCESS;
	RSTATE_RETURN;
}

/* x540_init_local_rx()
 *
 * Summary:
 *
 * This function initializes the RX path for this CPU.
 */
static rstate_t
x540_init_queue_rx(struct _net_queue *queue)
{
	int ring;
	uint32_t ring_offset, filter_offset;
	uint64_t key;
	struct _net_device *device     = queue->device;
	struct _x540_queue *x540_queue = queue->device_context;

	RSTATE_LOCALS;

	/* Allocate ring descriptor space */
	rstate = alloc_phys(sizeof(struct _x540_rx_ring) * X540_NUM_RX,
			&x540_queue->rx_ring_phys);
	RSCHECK_NESTED("Failed to allocate the RX ring");

	/* Allocate random virtual address range for RX ring */
	rstate = mm_reserve_random(readcr3(),
			sizeof(struct _x540_rx_ring) * X540_NUM_RX,
			(void*)&x540_queue->rx_ring, 0, &key);
	RSCHECK_NESTED("Failed to reserve room for RX ring");

	/* Map in RX ring */
	rstate = mm_map_contig(readcr3(),
			(uintptr_t)x540_queue->rx_ring,
			x540_queue->rx_ring_phys | 3 | (1UL << 63),
			sizeof(struct _x540_rx_ring) * X540_NUM_RX, key);
	RSCHECK_NESTED("Failed to map in RX ring");

	/* Allocate 12KB for each ring entry */
	for(ring = 0; ring < X540_NUM_RX; ring++){
		rstate = alloc_phys(12 * 1024, &x540_queue->rx_ring[ring].addr);
		RSCHECK_NESTED("Failed to allocate RX ring entry");

		/* Allocate random virtual address range for RX ring */
		rstate = mm_reserve_random(readcr3(),
				12 * 1024,
				(void*)&x540_queue->rx_bufs[ring], 0, &key);
		RSCHECK_NESTED("Failed to reserve room for RX ring entry");

		/* Map in RX ring entry */
		rstate = mm_map_contig(readcr3(),
				(uintptr_t)x540_queue->rx_bufs[ring],
				x540_queue->rx_ring[ring].addr | 3 | (1UL << 63),
				12 * 1024,
				key);
		RSCHECK_NESTED("Failed to map in RX ring entry");

		x540_queue->rx_ring[ring].status = 0;
	}

	if(queue->queue_id < 64){
		ring_offset = queue->queue_id * 0x40;
	} else {
		ring_offset = 0xc000 + (queue->queue_id - 64) * 0x40;
	}

	/* Calculate the offset for this CPUs filter. */
	filter_offset = queue->queue_id * 4;

	if(queue->queue_id){
		/* Create the filter */
		X540_MMIO_UINT32(0xE000 + filter_offset) = device->dhcp_ip;
		X540_MMIO_UINT32(0xE200 + filter_offset) = device->ip;
		X540_MMIO_UINT32(0xE400 + filter_offset) = queue->filter_port << 16;

		/* Associate an RX queue with this filter */
		X540_MMIO_UINT32(0xE800 + filter_offset) = queue->queue_id << 21;

		/* Filter control:
		 * Filter using 3 tuples (source IP, dest IP, protocol)
		 * UDP protocol
		 * Highest priority
		 * Enable filter
		 * Do not use pool field.
		 */
		X540_MMIO_UINT32(0xE600 + filter_offset) = (1 << 0) | (7 << 2) | \
												   (1 << 31) | (1 << 30) | \
												   (1 << 27);
	}

	/* Set up the SRRCTL
	 * 10KB buffer size
	 * 256 byte header buffer (default)
	 * Use legacy descriptor
	 * Drop packets when queue is full
	 */
	X540_MMIO_UINT32(0x01014 + ring_offset) = (10 << 0) | (4 << 8) | (1 << 28);

	/* Set up the high and low parts of the ring buffer address */
	X540_MMIO_UINT32(0x01004 + ring_offset) =
		(x540_queue->rx_ring_phys >> 32);
	X540_MMIO_UINT32(0x01000 + ring_offset) =
		(x540_queue->rx_ring_phys & 0xFFFFFFFF); 

	/* Set up the length of the recieve ring buffer */
	X540_MMIO_UINT32(0x01008 + ring_offset) = X540_NUM_RX * 16;

	/* Store the current read position */
	x540_queue->rx_head = 0;

	/* Enable the ring and poll until it becomes enabled */
	X540_MMIO_UINT32(0x01028 + ring_offset) |= (1 << 25);
	while(!(X540_MMIO_UINT32(0x01028 + ring_offset) & (1 << 25)));

	/* Bump the tail descriptor */
	X540_MMIO_UINT32(0x01018 + ring_offset) = X540_NUM_RX - 1;

	/* Enable RX */
	X540_MMIO_UINT32(0x3000) = (1 << 0);

	rstate_ret = RSTATE_SUCCESS;
cleanup:
	RSTATE_RETURN;
}

/* x540_init_local_tx()
 *
 * Summary:
 *
 * This function initializes the tx path for this CPU.
 */
static rstate_t
x540_init_queue_tx(struct _net_queue *queue)
{
	int ring;
	uint32_t ring_offset;
	uint64_t key;
	struct _net_device *device     = queue->device;
	struct _x540_queue *x540_queue = queue->device_context;

	RSTATE_LOCALS;

	/* Allocate room for the TX ring desciptor */
	rstate = alloc_phys(sizeof(struct _x540_tx_ring) * X540_NUM_TX,
			&x540_queue->tx_ring_phys);
	RSCHECK_NESTED("Failed to allocate the TX ring");

	/* Allocate random virtual address range for TX ring */
	rstate = mm_reserve_random(readcr3(),
			sizeof(struct _x540_tx_ring) * X540_NUM_TX,
			(void*)&x540_queue->tx_ring, 0, &key);
	RSCHECK_NESTED("Failed to reserve room for TX ring");

	/* Map in TX ring */
	rstate = mm_map_contig(readcr3(),
			(uintptr_t)x540_queue->tx_ring,
			x540_queue->tx_ring_phys | 3 | (1UL << 63),
			sizeof(struct _x540_tx_ring) * X540_NUM_TX, key);
	RSCHECK_NESTED("Failed to map in TX ring");

	/* Allocate 12KB for each ring entry */
	for(ring = 0; ring < X540_NUM_TX; ring++){
		rstate = alloc_phys(12 * 1024, &x540_queue->tx_ring[ring].addr);
		RSCHECK_NESTED("Failed to allocate TX ring entry");

		/* Allocate random virtual address range for TX ring */
		rstate = mm_reserve_random(readcr3(),
				12 * 1024,
				(void*)&x540_queue->tx_bufs[ring], 0, &key);
		RSCHECK_NESTED("Failed to reserve room for TX ring entry");

		/* Map in TX ring entry */
		rstate = mm_map_contig(readcr3(),
				(uintptr_t)x540_queue->tx_bufs[ring],
				x540_queue->tx_ring[ring].addr | 3 | (1UL << 63),
				12 * 1024,
				key);
		RSCHECK_NESTED("Failed to map in TX ring entry");

		x540_queue->tx_ring[ring].status.val = (1UL << 32); /* DD bit set */
	}

	ring_offset = queue->queue_id * 0x40;

	/* Set up the high and low parts of the address */
	X540_MMIO_UINT32(0x6004 + ring_offset) =
		(x540_queue->tx_ring_phys >> 32);
	X540_MMIO_UINT32(0x6000 + ring_offset) =
		(x540_queue->tx_ring_phys & 0xFFFFFFFF); 

	/* Set up the length of the TX ring buffer */
	X540_MMIO_UINT32(0x6008 + ring_offset) = X540_NUM_TX * 16;

	/* Enable transmit queue */
	X540_MMIO_UINT32(0x6028 + ring_offset) |= (1 << 25);

	/* Set up the tail pointer */
	X540_MMIO_UINT32(0x6018 + ring_offset) = 0;

	/* Set up the internal tail pointer */
	x540_queue->tx_head = 0;
	x540_queue->tx_tail = 0;

	rstate_ret = RSTATE_SUCCESS;
cleanup:
	RSTATE_RETURN;
}

/* x540_queue_init()
 *
 * Summary:
 *
 * This function initializes the x540 device for use on the current CPU.
 */
rstate_t
x540_queue_init(struct _net_queue *queue)
{
	RSTATE_LOCALS;

	rstate = phalloc(sizeof(struct _x540_queue), &queue->device_context);
	RSCHECK_NESTED("Failed to allocate room for device context");

	rstate = x540_init_queue_rx(queue);
	RSCHECK_NESTED("Failed to initialize queue RX state");
	rstate = x540_init_queue_tx(queue);
	RSCHECK_NESTED("Failed to initialize queue TX state");

	queue->send         = x540_send_packet;
	queue->recv         = x540_rx_probe;
	queue->recv_release = x540_rx_advance;

	rstate_ret = RSTATE_SUCCESS;
cleanup:
	RSTATE_RETURN;
}

/* x540_send_packet()
 *
 * Summary:
 *
 * This function transmits a raw packet.
 */
static rstate_t
x540_send_packet(
		struct _net_queue *queue,
		const void        *packet,
		uint32_t           length)
{
	uint32_t next_ring;

	struct _udp_packet *ring_packet;
	struct _net_device *device     = queue->device;
	struct _x540_queue *x540_queue = queue->device_context;

	volatile struct _x540_tx_ring *tx_ring;

	RSTATE_LOCALS;

	RSCHECK(queue->task_using == current_cpu->task,
			"Queue not currently locked by the running task");

	RSCHECK(length <= 9014, "Packet too large");

	tx_ring = x540_queue->tx_ring;

wait_for_packets:
	/* Update the head by going through packets pending for send and checking
	 * for descriptor done.
	 */
	while(x540_queue->tx_head < x540_queue->tx_tail &&
			tx_ring[x540_queue->tx_head % X540_NUM_TX].status.b.dd){
		x540_queue->tx_head++;
	}

	/* We cannot have the whole ring full, because a full ring has the head
	 * and tail to the same value, which also means empty. Thus, if
	 * X540_NUM_TX - 1 entries are currently in use, wait until more send.
	 */
	if((x540_queue->tx_tail - x540_queue->tx_head) >= (X540_NUM_TX - 1)){
		goto wait_for_packets;
	}

	/* Get a ring number to use */
	next_ring = x540_queue->tx_tail % X540_NUM_TX;
	x540_queue->tx_tail++;

	/* Wait for the descriptor done bit to become set */
	while(!tx_ring[next_ring].status.b.dd);

	/* Get the backing ring buffer and copy the packet into it */
	ring_packet = (struct _udp_packet*)x540_queue->tx_bufs[next_ring];
	memcpy(ring_packet, packet, length);

	/* Set this ring entry's status */
	tx_ring[next_ring].status.val      = 0;
	tx_ring[next_ring].status.b.length = length;
	tx_ring[next_ring].status.b.cmd	   = (1 << 3) | 3;

	/* Transmit the packet! */
	{
		uint32_t ring_offset = queue->queue_id * 0x40;
		X540_MMIO_UINT32(0x6018 + ring_offset) = (next_ring + 1) % X540_NUM_TX;
	}

	rstate_ret = rstate = RSTATE_SUCCESS;
cleanup:
	RSTATE_RETURN;
}

/* x540_rx_probe()
 *
 * Summary:
 *
 * This is a nonblocking packet rx function. On success it returns either
 * NULL in packet (indiciating no packet is present), or a pointer to a
 * buffer containing the packet and the length of the packet.
 */
static rstate_t
x540_rx_probe(
		struct _net_queue  *queue,
		void              **packet,
		uint32_t           *packet_len)
{
	uint32_t head;

	struct _x540_queue *x540_queue = queue->device_context;

	volatile struct _x540_rx_ring *rx_ring;

	RSTATE_LOCALS;

	RSCHECK(queue->task_using == current_cpu->task,
			"Queue not currently locked by the running task");

	rx_ring = x540_queue->rx_ring;
	head    = x540_queue->rx_head % X540_NUM_RX;

	/* Check if the packet at head is present */
	if(!(rx_ring[head].status & (1UL << 32))){
		*packet     = NULL;
		*packet_len = 0;

		return RSTATE_SUCCESS;
	}

	*packet     = (uint8_t*)x540_queue->rx_bufs[head];
	*packet_len = rx_ring[head].status & 0xFFFF;

	rstate_ret = rstate = RSTATE_SUCCESS;
cleanup:
	RSTATE_RETURN;
}

/* x540_rx_advance()
 *
 * Summary:
 *
 * This increments the internal x540 rx state for this CPU and places the
 * previous buffer back up for use.
 */
static rstate_t
x540_rx_advance(struct _net_queue *queue)
{
	uint32_t ring_offset;

	struct _net_device *device     = queue->device;
	struct _x540_queue *x540_queue = queue->device_context;

	RSTATE_LOCALS;

	RSCHECK(queue->task_using == current_cpu->task,
			"Queue not currently locked by the running task");

	if(queue->queue_id < 64){
		ring_offset = queue->queue_id * 0x40;
	} else {
		ring_offset = 0xc000 + (queue->queue_id - 64) * 0x40;
	}

	/* Put the packet back up for storage */
	x540_queue->rx_ring[x540_queue->rx_head % X540_NUM_RX].status = 0;

	/* Update the RX tail */
	X540_MMIO_UINT32(0x1018 + ring_offset) = x540_queue->rx_head % X540_NUM_RX;
	x540_queue->rx_head++;

	rstate_ret = rstate = RSTATE_SUCCESS;
cleanup:
	RSTATE_RETURN;
}

