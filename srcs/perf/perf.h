#pragma once

struct _pmc_desc {
	unsigned int event;
	unsigned int umask;

	const char *name;
};

rstate_t
perf_get_pmc_by_id(
		unsigned int             perf_id,
		const struct _pmc_desc **pmc);

