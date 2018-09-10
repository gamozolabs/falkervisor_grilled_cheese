#pragma once

struct _task {
	/* 0 if this task is available for use, 1 if it is already in use */
	int in_use;

	/* 0 if this is not an init task, 1 if it is */
	int is_init;

	/* Stack and depth used by the rstate subsystem */
	const struct _return_state *rstate_stack[RSTATE_STACK_ENTRIES];
	int rstate_stack_depth;

	/* Interrupts that are allowed when this task is running. If an interrupt
	 * occurs which is not allowed during a task a panic will occur.
	 */
	uint8_t interrupt_allowed[256];

	/* Physical 4k page free list */
	uintptr_t free_list;
	size_t    free_list_entries;
};

void
task_create_init(void);

struct _task*
task_create(void);

void
task_destroy(struct _task *task);

