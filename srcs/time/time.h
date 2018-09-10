#pragma once

void
rdtsc_calibrate(void);

uint64_t
rdtsc_freq(void);

uint64_t
rdtsc_future(_In_ uint64_t microseconds);

uint64_t
rdtsc_uptime(void);

void
rdtsc_sleep(_In_ uint64_t microseconds);

