#pragma once

/* All spinlock definitions on the system. To add a new spinlock, simply
 * add another definition to this enum. Make sure that that last entry in the
 * enum is MAX_SPINLOCK_ID
 */
enum spinlock_id {
	PAGE_TABLE_LOCK,
	DISP_LOCK,
	NUMA_MEMORY_LOCK,
	MAX_SPINLOCK_ID
};

struct _spinlock {
	volatile unsigned int lock;
	volatile unsigned int unlock;
};

void
spinlock_acquire(_In_ enum spinlock_id id);

void
spinlock_release(_In_ enum spinlock_id id);

