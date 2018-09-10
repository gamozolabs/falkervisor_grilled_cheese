#pragma once

/* Success states */
#define RSTATE_SUCCESS NULL

/* Error code used indicating invalid rstate. This occurs if an uninitialized
 * rstate is returned.
 */
#define RSTATE_CODE_INVALID 0xe1f2e965

/* Error code indicating rstate is nested */
#define RSTATE_CODE_NESTED  0x9f1c0505

/* Number of entires in the rstate stack */
#define RSTATE_STACK_ENTRIES 512

/* Invalid state. Used for initializing rstate at a function start. */
extern const struct _return_state rstate_invalid;

/* Quick defines for locals in any function that uses rstates. */
#define RSTATE_LOCALS rstate_t rstate = (&rstate_invalid), \
										rstate_ret = (&rstate_invalid);

#define RSTATE_RETURN \
	if(rstate_ret != RSTATE_SUCCESS){ \
		if(rstate_ret->code != RSTATE_CODE_NESTED) \
			rstate_clear(); \
		rstate_push(rstate_ret); \
	} \
	return rstate_ret;

#define RSCHECK(statement, str) \
	if(!(statement)){ \
		static const struct _return_state rs = \
			{ 0, __LINE__, __FILE__, str, __FUNCTION__ }; \
		rstate_ret = &rs; \
		goto cleanup; \
	}

#define RSCHECK_NESTED(str) \
	if(rstate != RSTATE_SUCCESS){ \
		static const struct _return_state rs = \
			{ RSTATE_CODE_NESTED, __LINE__, __FILE__, str, __FUNCTION__ }; \
		rstate_ret = &rs; \
		goto cleanup; \
	}

#define RSTATE_PANIC \
	if(rstate_ret != RSTATE_SUCCESS){ \
		if(rstate_ret->code != RSTATE_CODE_NESTED) \
			rstate_clear(); \
		rstate_push(rstate_ret); \
	} \
	rstate_panic();

struct _return_state {
	const uint32_t  code;
	const uint32_t  source_line;
	const char     *source_fn;
	const char     *str;
	const char     *funcname;
};

typedef const struct _return_state *rstate_t;

void
rstate_push(rstate_t rstate);

void
rstate_clear(void);

void
rstate_unwind(void);

void
rstate_panic(void);

