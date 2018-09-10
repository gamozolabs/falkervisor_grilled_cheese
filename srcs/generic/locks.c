#include <grilled_cheese.h>
#include <disp/disp.h>
#include <generic/stdlib.h>
#include <generic/locks.h>

/* Storage for all locks */
static volatile struct _spinlock spinlocks[MAX_SPINLOCK_ID] = { { 0 } };

/* spinlock_acquire()
 *
 * Summary:
 *
 * This function acquires the spinlock corresponding to id. If the spinlock
 * is already held on this CPU, a deadlock will occur. We track this and are
 * able to panic when a deadlock is about to happen.
 *
 * In the special case that the spinlock is the display lock, we will output
 * to the screen without a lock. This may result in mangled output on the
 * screen.
 *
 * Parameters:
 *
 * _In_ id - Spinlock ID to acquire
 */
void
spinlock_acquire(_In_ enum spinlock_id id)
{
	unsigned int ticket;

	/* Bounds check */
	if(id >= MAX_SPINLOCK_ID){
		panic("Spinlock ID invalid for acquire");
	}

	/* First, validate that this cpu doesn't already have this spinlock
	 * held
	 */
	if(__sync_val_compare_and_swap(
				&current_cpu->spinlocks_held[id], 0, 1) != 0){
		if(id == DISP_LOCK){
			disp_err_mode();
			puts_nolock("Disp lock deadlock");
			halt();
		} else {
			printf("Already held lock %d", id);
			panic("Spinlock already held on CPU, deadlock");
		}
	}

	/* Grab a ticket to wait in queue until it's our turn */
	ticket = __sync_fetch_and_add(&spinlocks[id].lock, 1);
	while(ticket != spinlocks[id].unlock){
		_mm_pause();
	}
	
	return;
}

/* spinlock_release()
 *
 * Summary:
 *
 * This function releases a spinlock acquired by spinlock_acquire(). If the
 * spinlock is not held on this CPU we will panic as we're trying to release a
 * lock not owned by us.
 *
 * Parameters:
 *
 * _In_ id - Spinlock ID to release
 */
void
spinlock_release(_In_ enum spinlock_id id)
{
	/* Bounds check */
	if(id >= MAX_SPINLOCK_ID){
		panic("Spinlock ID invalid for release");
	}

	/* First, validate that this lock is held on this CPU */
	if(__sync_val_compare_and_swap(
				&current_cpu->spinlocks_held[id], 1, 0) != 1){
		printf("Not held lock %d", id);
		panic("Spinlock not held at time of release");
	}

	/* Bump up the unlock count */
	spinlocks[id].unlock++;

	return;
}

