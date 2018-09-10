#include <grilled_cheese.h>
#include <disp/disp.h>

const struct _return_state rstate_invalid =
	{ RSTATE_CODE_INVALID, __LINE__, __FILE__, "Invalid rstate", "<nofunc>" };

void
rstate_push(rstate_t rstate)
{
	if(current_task->rstate_stack_depth == RSTATE_STACK_ENTRIES){
		return;
	}

	current_task->rstate_stack[current_task->rstate_stack_depth] = rstate;
	current_task->rstate_stack_depth++;

	return;
}

void
rstate_clear(void)
{
	current_task->rstate_stack_depth = 0;
	return;
}

void
rstate_unwind(void)
{
	int i;

	for(i = 0; i < current_task->rstate_stack_depth; i++){
		printf("%s:%u %s() %s",
				current_task->rstate_stack[i]->source_fn,
				current_task->rstate_stack[i]->source_line,
				current_task->rstate_stack[i]->funcname,
				current_task->rstate_stack[i]->str);
	}

	return;
}

void
rstate_panic(void)
{
	printf("!!! PANIC !!!");
	rstate_unwind();
	panic("rstate_panic() invoked");
}

