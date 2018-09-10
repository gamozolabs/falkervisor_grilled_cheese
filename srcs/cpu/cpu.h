#pragma once

/* Different CPU types */
enum _cpu_type {
	UNKNOWN,
	INTEL,
	AMD
};

struct _cpu*
get_current_cpu(void);

void
halt(void);

void
panic(_In_z_ const char *reason);

int
sync_bool_compare_and_swap_si128(
		_In_ volatile __m128i *src, _In_ __m128i cmp, _In_ __m128i val);

uint64_t
rdpmc(_In_ uint32_t ctr_id);

void
interrupts_enable_force(void);

void
interrupts_disable_force(void);

void
writedr0(_In_ uint64_t val);

void
writedr1(_In_ uint64_t val);

void
writedr2(_In_ uint64_t val);

void
writedr3(_In_ uint64_t val);

void
invlpg(_In_ void *addr);

void
lgdt(_In_ void *gdt);

void
lidt(_In_ void *idt);

void
ltr(_In_ uint16_t tr);

void
outb(_In_ uint16_t port, _In_ uint8_t val);

void
outd(_In_ uint16_t port, _In_ uint32_t val);

uint8_t
inb(_In_ uint16_t port);

uint32_t
ind(_In_ uint16_t port);

uintptr_t
readcr2(void);

uintptr_t
readcr3(void);

void
cpuid(_In_ uint32_t val, _Out_writes_bytes_all_(16) uint32_t *output);

void
wrmsr(_In_ uint32_t msr_id, _In_ uint64_t val);

uint64_t
rdmsr(_In_ uint32_t msr_id);

enum _cpu_type
get_cpu_type(void);

int
is_bsp(void);

void
cpu_start_aps(void);

