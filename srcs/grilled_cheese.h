#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>
#include <x86intrin.h>

#define _In_
#define _In_z_
#define _In_opt_
#define _In_reads_bytes_(x)
#define _Out_
#define _Outptr_
#define _Out_writes_bytes_(x)
#define _Out_writes_bytes_all_(x)
#define _Printf_format_string_

#define NULL ((void*)0)

typedef uintptr_t size_t;

#define BEXTR(val, high, low) \
	(((val) >> (low)) & ((1UL << ((high) - (low) + 1))-1))
#define MASK(val, high, low) \
	((val) & (((1UL << ((high) - (low) + 1))-1)<<(low)))

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

#define htons(val) \
 ( (((uint16_t)(val) >> 8) & 0x00FF) | (((uint16_t)(val) << 8) & 0xFF00) )

#define htonl(val) \
 ( (((uint32_t)(val) >> 24) & 0x000000FF) | \
   (((uint32_t)(val) >>  8) & 0x0000FF00) | \
   (((uint32_t)(val) <<  8) & 0x00FF0000) | \
   (((uint32_t)(val) << 24) & 0xFF000000) )

#define htonq(val) \
 ( (((uint64_t)(val) >> 56) & 0x00000000000000FF) | \
   (((uint64_t)(val) >> 40) & 0x000000000000FF00) | \
   (((uint64_t)(val) >> 24) & 0x0000000000FF0000) | \
   (((uint64_t)(val) >>  8) & 0x00000000FF000000) | \
   (((uint64_t)(val) <<  8) & 0x000000FF00000000) | \
   (((uint64_t)(val) << 24) & 0x0000FF0000000000) | \
   (((uint64_t)(val) << 40) & 0x00FF000000000000) | \
   (((uint64_t)(val) << 56) & 0xFF00000000000000) )

#define byteswap(val) ((sizeof(val) == 2) ? htons(val) : \
		((sizeof(val) == 4) ? htonl(val) : htonq(val)))

#define ntohs htons
#define ntohl htohl
#define ntohq htonq

#define current_cpu  get_current_cpu()
#define current_task (get_current_cpu()->task)

#define STACK_SIZE (1024 * 1024)

#include <cpu/cpu.h>
#include <rstate/rstate.h>
#include <generic/locks.h>
#include <task/task.h>

/* Structure of a 64-bit iret frame */
struct _iret {
	uint64_t rip;
	uint64_t cs;
	uint64_t rflags;
	uint64_t rsp;
	uint64_t ss;
};

/* Exception information structure */
struct _exception {
	/* iret frame */
	struct _iret iret;

	/* Exception vector */
	uintptr_t vector;

	/* Exception error code (optional based on vector) */
	uintptr_t error;

	/* Faulting address for page faults */
	uintptr_t cr2;
};

/* Boot parameters structure passed in from bootloader. This must match the
 * definition used in the bootloader otherwise there will be problems. This
 * structure is read only.
 */
struct _boot_parameters {
	/* Virtual address mapping in the screen (0xb8000) */
	void *screen;

	/* Pointer to the end of the stack created by the bootloader. This is
	 * the standard stack that will be used during kernel operation. This
	 * may not be relevant to the current stack if we are in an interrupt.
	 */
	void *top_of_stack;

	/* Pointer to e820 map */
	void *e820_map;

	/* Physical window page table and base. */
	void      *phy_window_page_table;
	uintptr_t  phy_window_base;

	/* Address of start of memory available by use for the OS. Anything below
	 * this is reserved by the bootloader and must not be touched.
	 */
	uintptr_t free_memory_base;

	/* Address to jump to perform a soft reboot. When jumping to this the first
	 * 4GB of memory must be identity mapped.
	 */
	void *soft_reboot;

	/* Physical address of the PE download base, physical pointer to the size,
	 * and maximum size available. When a soft reboot is done it loads the
	 * kernel from the location and size specified by the base and size.
	 */
	void     *kern_download_base;
	uint32_t *kern_download_size_ptr;
	uint64_t  kern_download_max_size;

	/* Pointer to the start of this structure itself */
	void *boot_parameters;

	/* Virtual address of the start and size of the text section. This can be
	 * used in unwind routines to determine which addresses may be code.
	 */
	void     *text_base;
	uint64_t  text_size;

	/* APIC ID for this core */
	uint64_t apic_id;
};

struct _cpu {
	/* Do not move this, pointer to self */
	void *gs_base;

	/* Current running task on the CPU */
	struct _task *task;

	/* Information about this CPU */
	unsigned int apic_id; /* APIC ID */
	unsigned int cpu_id;  /* CPU ID. This number is assigned sequentially
							 by the OS. The BSP will always be 0. */
	unsigned int node_id; /* Node ID that this CPU belongs to */
	unsigned int is_bsp;  /* 1 if this CPU is the BSP, zero otherwise */

	/* Seed for the aes_rand() random number generator */
	__m128i rng_seed;

	/* Physical window page table, base, and in use information. This is what
	 * is used to access physical memory on the system.
	 */
	volatile uint64_t  *phy_window_page_table;
	volatile uintptr_t  phy_window_base;
	volatile int        phy_window_inuse[512];

	/* When interrupts are disabled this gets incremented. When they're enabled
	 * this gets decremented. When it hits 0 interrupts actually get enabled.
	 */
	volatile unsigned int interrupt_level;

	/* Virtual address pointing to this CPU's APIC */
	volatile uint8_t *apic;

	/* Default network queue for this CPU */
    struct _net_queue *net_queue;

	/* Boot parameters for this CPU */
	const struct _boot_parameters *boot_params;

	/* For each spinlock on the system we maintain whether or not the current
	 * CPU has the lock held. This is done for deadlock detection.
	 */
	unsigned int spinlocks_held[MAX_SPINLOCK_ID];

	/* Destination to branch to on a usermode exception. When a usermode
	 * exception occurs we will save the exception state into um_exception
	 * and then jump to the um_exception_handler.
	 */
	struct _iret      um_exception_handler;
	struct _exception um_exception;
};

