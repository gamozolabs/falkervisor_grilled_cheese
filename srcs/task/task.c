#include <grilled_cheese.h>
#include <generic/stdlib.h>
#include <task/task.h>

#define NUM_TASKS_PER_CPU 4

struct _cpu_task {
	struct _task init;
	struct _task tasks[NUM_TASKS_PER_CPU];
};

static struct _cpu_task cpu_tasks[256] = { { { 0 } } };

void
task_create_init(void)
{
	struct _task *tmp = &cpu_tasks[current_cpu->apic_id].init;

	/* Set task in use */
	tmp->in_use = 1;

	/* Set that this is the init task */
	tmp->is_init = 1;

	/* Allow all interrupts */
	memset(tmp->interrupt_allowed, 1, 256);

	/* Swap in this task */
	current_cpu->task = tmp;

	return;
}

struct _task*
task_create(void)
{
	int ii;
	struct _task *tmp;

	/* Look for a free task */
	for(ii = 0; ii < NUM_TASKS_PER_CPU; ii++){
		if(!cpu_tasks[current_cpu->apic_id].tasks[ii].in_use){
			break;
		}
	}

	if(ii == NUM_TASKS_PER_CPU){
		return NULL;
	}

	tmp = &cpu_tasks[current_cpu->apic_id].tasks[ii];

	/* Zero out the task */
	memset(tmp, 0, sizeof(*tmp));

	/* Set task in use */
	tmp->in_use = 1;

	/* Allow all exceptions */
	memset(tmp->interrupt_allowed, 1, 32);

	return tmp;
}

void
task_destroy(struct _task *task)
{
	task->in_use = 0;
	return;
}

