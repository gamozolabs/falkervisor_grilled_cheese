#include <grilled_cheese.h>
#include <disp/disp.h>
#include <generic/stdlib.h>
#include <time/time.h>

/* get_current_cpu()
 *
 * Summary:
 *
 * Get a pointer to the current CPU's _cpu structure. This can only be used
 * after mm_init_cpu() was called. The gs segment's base always points to
 * the _cpu structure, and the first entry of this structure is a pointer
 * to itself. Thus we dereference qword [gs:0] to get this pointer.
 *
 * This function is what is internally used by the 'current_cpu' macro.
 *
 * Returns:
 *
 * Pointer to current CPU's _cpu structure.
 */
struct _cpu*
get_current_cpu(void)
{
	struct _cpu *ret;
	__asm__ volatile("movq %%gs:0, %0" : "=r"(ret));
	return ret;
}

/* halt()
 *
 * Summary:
 *
 * Halt the system forever.
 */
void
halt(void)
{
	for( ; ; ){
		__asm__ volatile("hlt");
	}
}

/* panic()
 *
 * Summary:
 *
 * Put the screen into error mode, print a panic reason, and then halt
 * forever. If we are the BSP, enable interrupts such that we can still get
 * timer interrupts to check for a reboot command.
 *
 * Parameters:
 *
 * _In_z_ reason - Null-terminated string with the reason of why we are
 *                 panicing.
 */
void
panic(_In_z_ const char *reason)
{
	/* Put the display into error mode, flashing text */
	disp_err_mode();

	/* Print out the panic reason */
	printf("!!! PANIC !!!");
	printf("%s", reason);

	/* BSP needs interrupts enabled so we can soft reboot */
	if(is_bsp()){
		printf("Panic occured on BSP, enabling interrupts for soft reboot");

		/* Allow timer interrupts on this task */
		current_cpu->task->interrupt_allowed[69] = 1;

		/* Enable interrupts so we can soft reboot */
		interrupts_enable_force();
	}

	halt();
}

/* sync_bool_compare_and_swap_si128()
 *
 * Summary:
 *
 * This function uses the cmpxchg16b instruction to do an atomic compare
 * exchange of a 128-bit value.
 *
 * src is compared against with cmp. If src matches cmp, val will be swapped
 * into val. If the match (and thus the swap) occurs, 1 will be returned.
 * Otherwise 0 will be returned.
 *
 * Parameters:
 *
 * _In_ src - Source memory location to be compared against and potentially
 *            written to.
 * _In_ cmp - Value to compare against
 * _In_ val - Value to place into *src if cmp matches src.
 *
 * Returns:
 *
 * If the compare matched and thus the swap occured returns 1.
 * Otherwise returns 0.
 */
int
sync_bool_compare_and_swap_si128(
		_In_ volatile __m128i *src, _In_ __m128i cmp, _In_ __m128i val)
{
	uint8_t result;

	uint64_t cmp_low, cmp_high;
	uint64_t val_low, val_high;

	cmp_low  = _mm_extract_epi64(cmp, 0);
	cmp_high = _mm_extract_epi64(cmp, 1);
	
	val_low  = _mm_extract_epi64(val, 0);
	val_high = _mm_extract_epi64(val, 1);

	__asm__ volatile("lock cmpxchg16b %1 ; setz %0" :
			"=r"(result) :
			"m"(*src), "d"(cmp_high), "a"(cmp_low),
			"c"(val_high), "b"(val_low));

	return (int)result;
}

/* rdpmc()
 *
 * Summary:
 *
 * This function performs a rdpmc instruction using the counter provided by
 * ctr_id.
 *
 * Paramters:
 *
 * _In_ ctr_id - Performance counter ID to read
 *
 * Returns:
 *
 * 64-bit value containing the contents of performance counter ctr_id
 */
uint64_t
rdpmc(_In_ uint32_t ctr_id)
{
	uint64_t low, high;

	__asm__ volatile("rdpmc" : "=a"(low), "=d"(high) : "c"(ctr_id));

	return (high << 32) | low;
}

/* interrupts_enable_force()
 *
 * Summary:
 *
 * This function enables interrupts without any checks. This function should
 * never be used by non-internal code. Instead, use interrupts_enable().
 */
void
interrupts_enable_force(void)
{
	__asm__ volatile("sti");
}

/* interrupts_disable_force()
 *
 * Summary:
 *
 * This function disables interrupts without any checks. This function should
 * never be used by non-internal code. Instead, use interrupts_disable().
 */
void
interrupts_disable_force(void)
{
	__asm__ volatile("cli");
}

/* writedr0()
 *
 * Summary:
 *
 * This function writes the value val into debug register 0.
 *
 * Parameters:
 *
 * _In_ val - Value to write into debug register
 */
void
writedr0(_In_ uint64_t val)
{
	__asm__ volatile("movq %0, %%dr0" :: "r"(val));
}

/* writedr1()
 *
 * Summary:
 *
 * This function writes the value val into debug register 1.
 *
 * Parameters:
 *
 * _In_ val - Value to write into debug register
 */
void
writedr1(_In_ uint64_t val)
{
	__asm__ volatile("movq %0, %%dr1" :: "r"(val));
}

/* writedr2()
 *
 * Summary:
 *
 * This function writes the value val into debug register 2.
 *
 * Parameters:
 *
 * _In_ val - Value to write into debug register
 */
void
writedr2(_In_ uint64_t val)
{
	__asm__ volatile("movq %0, %%dr2" :: "r"(val));
}

/* writedr3()
 *
 * Summary:
 *
 * This function writes the value val into debug register 3.
 *
 * Parameters:
 *
 * _In_ val - Value to write into debug register
 */
void
writedr3(_In_ uint64_t val)
{
	__asm__ volatile("movq %0, %%dr3" :: "r"(val));
}

/* invlpg()
 *
 * Summary:
 *
 * This function invalidates the page tables responsible for translating the
 * page indicated by virtual address vaddr.
 *
 * Parameters:
 *
 * _In_ addr - Virtual address indicating page to invalidate
 */
void
invlpg(_In_ void *addr)
{
	__asm__ volatile("invlpg (%0)" :: "r"(addr));
}

/* lgdt()
 *
 * Summary:
 *
 * This function uses the lgdt instruction to load up the gdt specified by gdt.
 * gdt must point to the gdt pseudo-descriptor containing both the base and
 * limit.
 *
 * Parameters:
 *
 * _In_ gdt - Virtual address pointing to gdt pseudo descriptor
 */
void
lgdt(_In_ void *gdt)
{
	__asm__ volatile("lgdt (%0)" :: "r"(gdt));
}

/* lidt()
 *
 * Summary:
 *
 * This function uses the lidt instruction to load up the idt specified by idt.
 * idt must point to the idt pseudo-descriptor containing both the base and
 * limit.
 *
 * Parameters:
 *
 * _In_ idt - Virtual address pointing to idt pseudo descriptor
 */
void
lidt(_In_ void *idt)
{
	__asm__ volatile("lidt (%0)" :: "r"(idt));
}

/* ltr()
 *
 * Summary:
 *
 * This function uses the ltr instruction to load up a new TSS segment. The
 * tr value passed in indicates the selector for the TSS segment in the
 * GDT.
 *
 * Parameters:
 *
 * _In_ tr - Segment selector of the TSS in the GDT.
 */
void
ltr(_In_ uint16_t tr)
{
	__asm__ volatile("ltr %0" :: "c"(tr));
}

/* outb()
 *
 * Summary:
 *
 * This function writes 8-bit val to I/O port port.
 *
 * Parameters:
 *
 * _In_ port - I/O port to write to
 * _In_ val  - Value to write to I/O port
 */
void
outb(_In_ uint16_t port, _In_ uint8_t val)
{
	__asm__ volatile("outb %0, %1" :: "a"(val), "d"(port));
}

/* outd()
 *
 * Summary:
 *
 * This function writes 32-bit val to I/O port port.
 *
 * Parameters:
 *
 * _In_ port - I/O port to write to
 * _In_ val  - Value to write to I/O port
 */
void
outd(_In_ uint16_t port, _In_ uint32_t val)
{
	__asm__ volatile("outl %0, %1" :: "a"(val), "d"(port));
}

/* inb()
 *
 * Summary:
 *
 * This function reads an 8-bit value from the I/O port specified by port.
 *
 * Parameters:
 *
 * _In_ port - I/O port to read from
 *
 * Returns:
 *
 * Value read from I/O port
 */
uint8_t
inb(_In_ uint16_t port)
{
	uint8_t ret;
	__asm__ volatile("inb %1, %0" : "=a"(ret) : "d"(port));
	return ret;
}

/* ind()
 *
 * Summary:
 *
 * This function reads a 32-bit value from the I/O port specified by port.
 *
 * Parameters:
 *
 * _In_ port - I/O port to read from
 *
 * Returns:
 *
 * Value read from I/O port
 */
uint32_t
ind(_In_ uint16_t port)
{
	uint32_t ret;
	__asm__ volatile("inl %1, %0" : "=a"(ret) : "d"(port));
	return ret;
}

/* readcr2()
 *
 * Summary:
 *
 * This function reads the value contained in control register 2.
 *
 * Returns:
 *
 * Contents of cr2 register
 */
uintptr_t
readcr2(void)
{
	uintptr_t cr2;
	__asm__ volatile("movq %%cr2, %0" : "=r"(cr2));
	return cr2;
}

/* readcr3()
 *
 * Summary:
 *
 * This function reads the value contained in control register 3.
 *
 * Returns:
 *
 * Contents of cr3 register
 */
uintptr_t
readcr3(void)
{
	uintptr_t cr3;
	__asm__ volatile("movq %%cr3, %0" : "=r"(cr3));
	return cr3;
}

/* cpuid()
 *
 * Summary:
 *
 * This function performs a cpuid instruction using val to select the ID.
 * It outputs a 4 dword tuple in the form (eax, ebx, ecx, edx).
 *
 * Parameters:
 *
 * _In_  val    - cpuid id
 * _Out_ output - Tuple in the form (eax, ebx, ecx, edx) containing the results
 *                of the cpuid instruction. Caller allocated storage, must be
 *                large enough to hold 4 dwords (16 bytes)
 */
void
cpuid(_In_ uint32_t val, _Out_writes_bytes_all_(16) uint32_t *output)
{
	__asm__ volatile("cpuid" :
			"=a"(output[0]), "=b"(output[1]),
			"=c"(output[2]), "=d"(output[3]) :
			"a"(val));
}

/* wrmsr()
 *
 * Summary:
 *
 * This function writes val to the MSR specified by msr_id.
 *
 * Parameters:
 *
 * _In_ msr_id - MSR to write to
 * _In_ val    - 64-bit value to write into MSR msr_id.
 */
void
wrmsr(_In_ uint32_t msr_id, _In_ uint64_t val)
{
	__asm__ volatile("wrmsr" :: "d"(val >> 32), "a"(val & 0xffffffff), "c"(msr_id));
}

/* rdmsr()
 *
 * Summary:
 *
 * This function reads from the MSR specified by msr_id.
 *
 * Returns:
 *
 * Contents of MSR msr_id.
 */
uint64_t
rdmsr(_In_ uint32_t msr_id)
{
	uint64_t high;
	uint64_t low;

	__asm__ volatile("rdmsr" : "=d"(high), "=a"(low) : "c"(msr_id));

	return ((high << 32) | low);
}

/* get_cpu_type()
 *
 * Summary:
 *
 * This function gets the current CPU model. Either INTEL, AMD, or UNKNOWN.
 * It internally uses the CPU vendor string CPUID and a memcmp. Thus this is
 * very slow.
 *
 * Returns:
 *
 * CPU manufacturer enum, either INTEL, AMD, or UNKNOWN.
 */
enum _cpu_type
get_cpu_type(void)
{
	uint32_t res[4];
	uint8_t  cpu_string[12] = { 0 };

	cpuid(0, res);

	*(uint32_t*)(cpu_string + 0) = res[1];
	*(uint32_t*)(cpu_string + 4) = res[3];
	*(uint32_t*)(cpu_string + 8) = res[2];

	if(!memcmp(cpu_string, "GenuineIntel", 12)){
		return INTEL;
	} else if(!memcmp(cpu_string, "AuthenticAMD", 12)){
		return AMD;
	} else {
		return UNKNOWN;
	}
}

/* is_bsp()
 *
 * Summary:
 *
 * This function returns 1 if the current running CPU is the BSP. Returns 0
 * otherwise. This just reads out the contents of is_bsp from current_cpu.
 * This value is populated during current_cpu initialization in mm_init_cpu().
 */
int
is_bsp(void)
{
	return current_cpu->is_bsp;
}

/* cpu_start_aps()
 *
 * Summary:
 *
 * This function broadcasts to all-but-self an INIT-SIPI-SIPI sequence to
 * bring up the APs on the system.
 */
void
cpu_start_aps(void)
{
	/* Bring up all other CPUs by sending INIT and SIPI to all but self */
	*(volatile uint32_t*)(current_cpu->apic + 0x300) = 0xc4500;
	rdtsc_sleep(1000);
	*(volatile uint32_t*)(current_cpu->apic + 0x300) = 0xc4608;
	rdtsc_sleep(1000);
	*(volatile uint32_t*)(current_cpu->apic + 0x300) = 0xc4608;
	rdtsc_sleep(1000);

	return;
}

