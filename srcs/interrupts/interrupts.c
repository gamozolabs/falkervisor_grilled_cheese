#include <grilled_cheese.h>
#include <mm/mm.h>
#include <generic/stdlib.h>
#include <disp/disp.h>
#include <time/time.h>
#include <net/net.h>
#include <interrupts/interrupts.h>
#include <task/task.h>

extern struct _boot_parameters *boot_parameters;
static volatile const struct _net_device *soft_reboot_requested = NULL;

/* profiling_enable()
 *
 * Summary:
 *
 * This function enables the APIC timer to fire at roughly 1000 times per
 * second on vector 69.
 */
static void
profiling_enable(void)
{
	/* APIC runs at 200,000,000 (200MHz) times per second.
	 *
	 * Such that 200,000,000 / 2 / 100000 = 1000 times per second
	 */

	/* Enable the APIC */
	*(volatile uint32_t*)(current_cpu->apic + 0xf0) = 0x1ff;

	/* Disable the timer */
	*(volatile uint32_t*)(current_cpu->apic + 0x380) = 0;
	*(volatile uint32_t*)(current_cpu->apic + 0x320) = 0;

	/* Set up the timer to fire on interrupt 69 */
	*(volatile uint32_t*)(current_cpu->apic + 0x3e0) = 0;
	*(volatile uint32_t*)(current_cpu->apic + 0x320) = (1 << 17) | 69;
	*(volatile uint32_t*)(current_cpu->apic + 0x380) = 100000;

	return;
}

/* profiling_disable()
 *
 * Summary:
 *
 * This function disables the APIC timer.
 */
static void
profiling_disable(void)
{
	/* Disable timer */
	*(volatile uint32_t*)(current_cpu->apic + 0x380) = 0;
	*(volatile uint32_t*)(current_cpu->apic + 0x320) = 0;

	return;
}

/* request_soft_reboot()
 *
 * Summary:
 *
 * Request that we perform a soft reboot next time it is safe to. We store
 * off the network device that notified us to reboot, this is the device we
 * will use to pull down the next kernel.
 */
void
request_soft_reboot(const void *dev)
{
	soft_reboot_requested = dev;
	return;
}

/* interrupts_enable()
 *
 * Summary:
 *
 * This function lowers the interrupt level. When the interrupt level falls
 * to zero interrupts are enabled, otherwise interrupts are left disabled.
 * This allows us to use this in a nested situation.
 */
void
interrupts_enable(void)
{
	if(--current_cpu->interrupt_level == 0){
		interrupts_enable_force();
	}

	return;
}

/* interrupts_disable()
 *
 * Summary:
 *
 * This function disables interrupts unconditionally, and then increases the
 * interrupt level.
 */
void
interrupts_disable(void)
{
	interrupts_disable_force();
	current_cpu->interrupt_level++;
	return;
}

#if 0
void
profiling_dump(void)
{
	uint64_t pf, ii = 0;

	struct {
		uint64_t rip;
		uint64_t count;
	} entries[512] = { 0 };

	for(pf = 0; pf < boot_parameters->text_size; pf++){
		if(profiling_buf[pf]){
			entries[ii].rip   = (uint64_t)boot_parameters->text_base + pf;
			entries[ii].count = profiling_buf[pf];
			ii++;

			if(ii == 512) break;
		}
	}

	if(current_cpu->net_queue){
		if(net_send_udp(current_cpu->net_queue, entries, sizeof(entries), 0, 0) !=
				RSTATE_SUCCESS){
			panic("Failed to send profiling dump");
		}
	}

	return;
}
#endif

/* profiling_handler()
 *
 * Summary:
 *
 * This function is the handler for the timer interrupts on the system. On
 * the BSP routine operations are performed such as checking the interrupt
 * network queue for packets and responding to them (such as DHCP and ARP). It
 * also checks for reboot packets which will trigger a request for a soft
 * reboot. When a soft reboot is requested, it is also initiated from this
 * handler.
 *
 * For all CPUs this function also records profiling information by storing
 * the RIP of the code that was running when the interrupt occured.
 */
rstate_t
profiling_handler(uintptr_t vector, struct _iret *iret, uintptr_t error,
		uintptr_t rip)
{
	RSTATE_LOCALS;

	if(is_bsp()){
#if 0
		if(!profiling_buf){
			void *tmp;

			if(phalloc(boot_parameters->text_size * sizeof(uint64_t),
						&tmp) != RSTATE_SUCCESS){
				panic("Failed to allocate room for profiling buf");
			}

			profiling_buf = tmp;
		}
#endif

		/* Do network interval processing */
		rstate = net_process_interval();
		RSCHECK_NESTED("Network interval processing failed");

		/* Check if a soft reboot was requested */
		if(soft_reboot_requested){
			int ii;

			void     *new_kernel = NULL;
			uint64_t  new_kernel_len = 0;

			/* Enable the 4GB identity map by marking the first 512GB PML4E as
			 * present.
			 */
			{
				void *virt;

				virt = mm_get_phys_mapping(readcr3());
				*(uint64_t*)virt |= 1;
				mm_release_phys_mapping(virt);
			}

			/* Download a new kernel */
try_again:
			new_kernel     = current_cpu->boot_params->kern_download_base;
			new_kernel_len = current_cpu->boot_params->kern_download_max_size;
			rstate = net_download_file(soft_reboot_requested->interrupt_queue,
					"grilled_cheese.kern", 0, &new_kernel, &new_kernel_len);
			if(rstate != RSTATE_SUCCESS){
				rdtsc_sleep(100000);
				goto try_again;
			}

			/* Disable profiling */
			profiling_disable();
	
			/* Update the downloaded PE size */
			*current_cpu->boot_params->kern_download_size_ptr =
				(uint32_t)new_kernel_len;

			/* INIT all APs 16 times with 1ms between each INIT */
			for(ii = 0; ii < 16; ii++){
				*(volatile uint32_t*)(current_cpu->apic + 0x300) = 0x000C4500;
				rdtsc_sleep(1000);
			}
			rdtsc_sleep(10000);

			/* Set up the interrupt return address to the soft reboot
			 * location.
			 */
			iret->rip    = (uint64_t)current_cpu->boot_params->soft_reboot;
			iret->cs     = 0x08;
			iret->rflags = 0;
			iret->rsp    = (uint64_t)current_cpu->boot_params->top_of_stack;
			iret->ss     = 0x10;

			rstate_ret = RSTATE_SUCCESS;
			goto cleanup;
		}
	}

#if 0
	if(profiling_buf){
		uintptr_t offset = rip - (uintptr_t)boot_parameters->text_base;

		if(offset < boot_parameters->text_size){
			profiling_buf[offset]++;
		}
	}
#endif

	rstate_ret = RSTATE_SUCCESS;
cleanup:
	/* Send EOI to the APIC */
	*(volatile uint32_t*)(current_cpu->apic + 0xb0) = 1;
	RSTATE_RETURN;
}

/* interrupt_handler()
 *
 * Summary:
 *
 * This function is the C landing point for all interrupts.
 */
void
interrupt_handler(uintptr_t vector, struct _iret *iret, uintptr_t error)
{
	uintptr_t rip = iret->rip;
	uintptr_t cr2 = readcr2();

	struct _task *old_task = current_cpu->task, *new_task;
	
	RSTATE_LOCALS;

	/* Increment the interrupt level as interrupts were disabled by the
	 * handler itself.
	 */
	current_cpu->interrupt_level++;

	/* Check if this interrupt is allowed */
	if(!current_cpu->task->interrupt_allowed[vector]){
		printf("Unhandled vector %lu", vector);
		panic("Got interrupt in task which did not allow it");
	}

	/* Switch tasks */
	new_task = task_create();
	if(!new_task){
		panic("Out of tasks for core");
	}
	current_cpu->task = new_task;

	/* ---------------------------------------------------------------
	 * After this point you can now use rstate and other task specific
	 * things as we have created a new task.
	 * ---------------------------------------------------------------
	 */

	/* Eat all NMIs */
	if(vector == 2){
		goto end_interrupt;
	}

	/* Invoke the profiling handler if we're on vector 69 */
	if(vector == 69){
		rstate = profiling_handler(vector, iret, error, rip);
		RSCHECK_NESTED("Failed to run profiling handler");
	}

	if(vector < 32){
		if(vector == 14){
			rstate = page_fault(vector, iret, error, cr2);
			if(rstate == RSTATE_SUCCESS){
				/* Handled successfully */
				goto end_interrupt;
			}
		}

		/* We were unable to handle an exception, panic */
		if((iret->cs & 3) != 3){
			if(vector == 14){
				RSCHECK_NESTED("Page fault could not be handled");
			} else {
				RSCHECK(1 == 0, "Unhandled exception");
			}
		}
	}

	/* User-mode exception, jump to exception handler */
	if((iret->cs & 3) == 3){
		current_cpu->um_exception.iret = *iret;

		current_cpu->um_exception.vector = vector;
		current_cpu->um_exception.error  = error;
		current_cpu->um_exception.cr2    = cr2;
		*iret = current_cpu->um_exception_handler;
		goto end_interrupt;
	}

end_interrupt:
	/* Restore old task */
	current_cpu->task = old_task;
	task_destroy(new_task);

	/* Decrement the interrupt level */
	current_cpu->interrupt_level--;
	return;

cleanup:
	printf(
			"=== EXCEPTION =======================================\n"
			"Unhandled exception %lu on CPU %u\n"
			"pc     %.4lx:%.16lx (toff %.16lx)\n"
			"stack  %.4lx:%.16lx\n"
			"rflags %.16lx\n"
			"cr2    %.16lx\n"
			"error  %.16lx",
			vector, current_cpu->apic_id,
			iret->cs, iret->rip,
			iret->rip - (uint64_t)current_cpu->boot_params->text_base,
			iret->ss, iret->rsp,
			iret->rflags,
			cr2,
			error);

	RSTATE_PANIC;
}

/* gdt_init()
 *
 * Summary:
 *
 * This function allocates, initializes, and loads a new GDT for this CPU.
 */
static rstate_t
gdt_init(void)
{
#pragma pack(push, 1)
	struct _gdt {
		uint64_t null;
		uint64_t code;
		uint64_t data;
		uint64_t code16;
		uint64_t data16;

		uint64_t tss_low;
		uint64_t tss_high;

		uint64_t datar3;
		uint64_t coder3;

		uint16_t len;
		uint64_t base;
	} *gdt;

	struct _tss {
		uint32_t reserved1;
		uint64_t rsp[3];
		uint64_t reserved2;
		uint64_t ist[7];
		uint64_t reserved3;
		uint16_t reserved4;
		uint16_t iopb_offset;
	} *tss;
#pragma pack(pop)

	uint8_t *rsp0_stack, *timer_stack, *sint_stack;
	
	RSTATE_LOCALS;

	/* Allocate room for the GDT */
	rstate = phalloc(sizeof(*gdt), (void**)&gdt);
	RSCHECK_NESTED("Failed to allocate room for GDT");

	/* Allocate room for the TSS */
	rstate = phalloc(16 * 1024, (void**)&tss);
	RSCHECK_NESTED("Failed to allocate room for TSS");
	
	/* Allocate room for a default interrupt stack */
	rstate = phalloc(STACK_SIZE, (void**)&rsp0_stack);
	RSCHECK_NESTED("Failed to allocate room for interrupt stack");
	rsp0_stack += STACK_SIZE;

	/* Allocate room for a timer interrupt stack */
	rstate = phalloc(STACK_SIZE, (void**)&timer_stack);
	RSCHECK_NESTED("Failed to allocate room for timer stack");
	timer_stack += STACK_SIZE;

	/* Allocate room for a special (NMI, DF, MC) interrupt stack */
	rstate = phalloc(STACK_SIZE, (void**)&sint_stack);
	RSCHECK_NESTED("Failed to allocate room for special interrupt stack");
	sint_stack += STACK_SIZE;

	tss->rsp[0] = (uint64_t)rsp0_stack;
	tss->ist[0] = (uint64_t)timer_stack;
	tss->ist[1] = (uint64_t)sint_stack;

	/* Create a GDT with the same properties from the bootloader.
	 * A null descriptor, a 64-bit code and data descriptor, and a 16-bit
	 * code and data selector.
	 */
	gdt->null   = 0x0000000000000000; /* 0x00 */
	gdt->code   = 0x00209a0000000000; /* 0x08 */
	gdt->data   = 0x0000920000000000; /* 0x10 */
	gdt->code16 = 0x00009a000000ffff; /* 0x18 */
	gdt->data16 = 0x000092000000ffff; /* 0x20 */

	/* 0x28 */
	gdt->tss_low = 0x890000000000 | (BEXTR((uint64_t)tss, 31, 24) << 56) |
		(BEXTR((uint64_t)tss, 23, 0) << 16) | 0x3FFF;
	gdt->tss_high = (uint64_t)tss >> 32;

	gdt->datar3 = 0x0000f20000000000; /* 0x38 */
	gdt->coder3 = 0x0020fa0000000000; /* 0x40 */

	/* Create the IDTR */
	gdt->len  = offsetof(struct _gdt, len) - 1;
	gdt->base = (uint64_t)gdt;

	/* Load the new GDT */
	lgdt(&gdt->len);

	/* Set up the task register */
	ltr(0x28);

	rstate_ret = RSTATE_SUCCESS;
cleanup:
	RSTATE_RETURN;
}

/* pic_init()
 *
 * Summary:
 *
 * This function remaps the PIC to not have overlapping regions and also
 * masks all interrupts from the PIC.
 */
void
pic_init(void)
{
	/* Remap the PIC to have IRQ0-7 map to int 0x20-0x27 and IRQ8-15
	 * to int 0x30-0x37.
	 */
	outb(0x20, 0x11);
	outb(0xa0, 0x11);
	outb(0x21, 0x20);
	outb(0xa1, 0x30);
	outb(0x21, 4);
	outb(0xa1, 2);
	outb(0x21, 1);
	outb(0xa1, 1);

	/* Mask all interrupts */
	outb(0x21, 0xff);
	outb(0xa1, 0xff);

	return;
}

/* interrupts_init()
 *
 * Summary:
 *
 * This function creates and switches over to a new IDT. It contains generic
 * handlers for every vector, which will then in turn invoke
 * interrupt_handler() for handling of the interrupts in C.
 */
rstate_t
interrupts_init(void)
{
	extern void vec_interrupt_0(void);
	extern void vec_interrupt_1(void);
	extern void vec_interrupt_2(void);
	extern void vec_interrupt_3(void);
	extern void vec_interrupt_4(void);
	extern void vec_interrupt_5(void);
	extern void vec_interrupt_6(void);
	extern void vec_interrupt_7(void);
	extern void vec_interrupt_8(void);
	extern void vec_interrupt_9(void);
	extern void vec_interrupt_10(void);
	extern void vec_interrupt_11(void);
	extern void vec_interrupt_12(void);
	extern void vec_interrupt_13(void);
	extern void vec_interrupt_14(void);
	extern void vec_interrupt_15(void);
	extern void vec_interrupt_16(void);
	extern void vec_interrupt_17(void);
	extern void vec_interrupt_18(void);
	extern void vec_interrupt_19(void);
	extern void vec_interrupt_20(void);
	extern void vec_interrupt_21(void);
	extern void vec_interrupt_22(void);
	extern void vec_interrupt_23(void);
	extern void vec_interrupt_24(void);
	extern void vec_interrupt_25(void);
	extern void vec_interrupt_26(void);
	extern void vec_interrupt_27(void);
	extern void vec_interrupt_28(void);
	extern void vec_interrupt_29(void);
	extern void vec_interrupt_30(void);
	extern void vec_interrupt_31(void);
	extern void vec_interrupt_32(void);
	extern void vec_interrupt_33(void);
	extern void vec_interrupt_34(void);
	extern void vec_interrupt_35(void);
	extern void vec_interrupt_36(void);
	extern void vec_interrupt_37(void);
	extern void vec_interrupt_38(void);
	extern void vec_interrupt_39(void);
	extern void vec_interrupt_40(void);
	extern void vec_interrupt_41(void);
	extern void vec_interrupt_42(void);
	extern void vec_interrupt_43(void);
	extern void vec_interrupt_44(void);
	extern void vec_interrupt_45(void);
	extern void vec_interrupt_46(void);
	extern void vec_interrupt_47(void);
	extern void vec_interrupt_48(void);
	extern void vec_interrupt_49(void);
	extern void vec_interrupt_50(void);
	extern void vec_interrupt_51(void);
	extern void vec_interrupt_52(void);
	extern void vec_interrupt_53(void);
	extern void vec_interrupt_54(void);
	extern void vec_interrupt_55(void);
	extern void vec_interrupt_56(void);
	extern void vec_interrupt_57(void);
	extern void vec_interrupt_58(void);
	extern void vec_interrupt_59(void);
	extern void vec_interrupt_60(void);
	extern void vec_interrupt_61(void);
	extern void vec_interrupt_62(void);
	extern void vec_interrupt_63(void);
	extern void vec_interrupt_64(void);
	extern void vec_interrupt_65(void);
	extern void vec_interrupt_66(void);
	extern void vec_interrupt_67(void);
	extern void vec_interrupt_68(void);
	extern void vec_interrupt_69(void);
	extern void vec_interrupt_70(void);
	extern void vec_interrupt_71(void);
	extern void vec_interrupt_72(void);
	extern void vec_interrupt_73(void);
	extern void vec_interrupt_74(void);
	extern void vec_interrupt_75(void);
	extern void vec_interrupt_76(void);
	extern void vec_interrupt_77(void);
	extern void vec_interrupt_78(void);
	extern void vec_interrupt_79(void);
	extern void vec_interrupt_80(void);
	extern void vec_interrupt_81(void);
	extern void vec_interrupt_82(void);
	extern void vec_interrupt_83(void);
	extern void vec_interrupt_84(void);
	extern void vec_interrupt_85(void);
	extern void vec_interrupt_86(void);
	extern void vec_interrupt_87(void);
	extern void vec_interrupt_88(void);
	extern void vec_interrupt_89(void);
	extern void vec_interrupt_90(void);
	extern void vec_interrupt_91(void);
	extern void vec_interrupt_92(void);
	extern void vec_interrupt_93(void);
	extern void vec_interrupt_94(void);
	extern void vec_interrupt_95(void);
	extern void vec_interrupt_96(void);
	extern void vec_interrupt_97(void);
	extern void vec_interrupt_98(void);
	extern void vec_interrupt_99(void);
	extern void vec_interrupt_100(void);
	extern void vec_interrupt_101(void);
	extern void vec_interrupt_102(void);
	extern void vec_interrupt_103(void);
	extern void vec_interrupt_104(void);
	extern void vec_interrupt_105(void);
	extern void vec_interrupt_106(void);
	extern void vec_interrupt_107(void);
	extern void vec_interrupt_108(void);
	extern void vec_interrupt_109(void);
	extern void vec_interrupt_110(void);
	extern void vec_interrupt_111(void);
	extern void vec_interrupt_112(void);
	extern void vec_interrupt_113(void);
	extern void vec_interrupt_114(void);
	extern void vec_interrupt_115(void);
	extern void vec_interrupt_116(void);
	extern void vec_interrupt_117(void);
	extern void vec_interrupt_118(void);
	extern void vec_interrupt_119(void);
	extern void vec_interrupt_120(void);
	extern void vec_interrupt_121(void);
	extern void vec_interrupt_122(void);
	extern void vec_interrupt_123(void);
	extern void vec_interrupt_124(void);
	extern void vec_interrupt_125(void);
	extern void vec_interrupt_126(void);
	extern void vec_interrupt_127(void);
	extern void vec_interrupt_128(void);
	extern void vec_interrupt_129(void);
	extern void vec_interrupt_130(void);
	extern void vec_interrupt_131(void);
	extern void vec_interrupt_132(void);
	extern void vec_interrupt_133(void);
	extern void vec_interrupt_134(void);
	extern void vec_interrupt_135(void);
	extern void vec_interrupt_136(void);
	extern void vec_interrupt_137(void);
	extern void vec_interrupt_138(void);
	extern void vec_interrupt_139(void);
	extern void vec_interrupt_140(void);
	extern void vec_interrupt_141(void);
	extern void vec_interrupt_142(void);
	extern void vec_interrupt_143(void);
	extern void vec_interrupt_144(void);
	extern void vec_interrupt_145(void);
	extern void vec_interrupt_146(void);
	extern void vec_interrupt_147(void);
	extern void vec_interrupt_148(void);
	extern void vec_interrupt_149(void);
	extern void vec_interrupt_150(void);
	extern void vec_interrupt_151(void);
	extern void vec_interrupt_152(void);
	extern void vec_interrupt_153(void);
	extern void vec_interrupt_154(void);
	extern void vec_interrupt_155(void);
	extern void vec_interrupt_156(void);
	extern void vec_interrupt_157(void);
	extern void vec_interrupt_158(void);
	extern void vec_interrupt_159(void);
	extern void vec_interrupt_160(void);
	extern void vec_interrupt_161(void);
	extern void vec_interrupt_162(void);
	extern void vec_interrupt_163(void);
	extern void vec_interrupt_164(void);
	extern void vec_interrupt_165(void);
	extern void vec_interrupt_166(void);
	extern void vec_interrupt_167(void);
	extern void vec_interrupt_168(void);
	extern void vec_interrupt_169(void);
	extern void vec_interrupt_170(void);
	extern void vec_interrupt_171(void);
	extern void vec_interrupt_172(void);
	extern void vec_interrupt_173(void);
	extern void vec_interrupt_174(void);
	extern void vec_interrupt_175(void);
	extern void vec_interrupt_176(void);
	extern void vec_interrupt_177(void);
	extern void vec_interrupt_178(void);
	extern void vec_interrupt_179(void);
	extern void vec_interrupt_180(void);
	extern void vec_interrupt_181(void);
	extern void vec_interrupt_182(void);
	extern void vec_interrupt_183(void);
	extern void vec_interrupt_184(void);
	extern void vec_interrupt_185(void);
	extern void vec_interrupt_186(void);
	extern void vec_interrupt_187(void);
	extern void vec_interrupt_188(void);
	extern void vec_interrupt_189(void);
	extern void vec_interrupt_190(void);
	extern void vec_interrupt_191(void);
	extern void vec_interrupt_192(void);
	extern void vec_interrupt_193(void);
	extern void vec_interrupt_194(void);
	extern void vec_interrupt_195(void);
	extern void vec_interrupt_196(void);
	extern void vec_interrupt_197(void);
	extern void vec_interrupt_198(void);
	extern void vec_interrupt_199(void);
	extern void vec_interrupt_200(void);
	extern void vec_interrupt_201(void);
	extern void vec_interrupt_202(void);
	extern void vec_interrupt_203(void);
	extern void vec_interrupt_204(void);
	extern void vec_interrupt_205(void);
	extern void vec_interrupt_206(void);
	extern void vec_interrupt_207(void);
	extern void vec_interrupt_208(void);
	extern void vec_interrupt_209(void);
	extern void vec_interrupt_210(void);
	extern void vec_interrupt_211(void);
	extern void vec_interrupt_212(void);
	extern void vec_interrupt_213(void);
	extern void vec_interrupt_214(void);
	extern void vec_interrupt_215(void);
	extern void vec_interrupt_216(void);
	extern void vec_interrupt_217(void);
	extern void vec_interrupt_218(void);
	extern void vec_interrupt_219(void);
	extern void vec_interrupt_220(void);
	extern void vec_interrupt_221(void);
	extern void vec_interrupt_222(void);
	extern void vec_interrupt_223(void);
	extern void vec_interrupt_224(void);
	extern void vec_interrupt_225(void);
	extern void vec_interrupt_226(void);
	extern void vec_interrupt_227(void);
	extern void vec_interrupt_228(void);
	extern void vec_interrupt_229(void);
	extern void vec_interrupt_230(void);
	extern void vec_interrupt_231(void);
	extern void vec_interrupt_232(void);
	extern void vec_interrupt_233(void);
	extern void vec_interrupt_234(void);
	extern void vec_interrupt_235(void);
	extern void vec_interrupt_236(void);
	extern void vec_interrupt_237(void);
	extern void vec_interrupt_238(void);
	extern void vec_interrupt_239(void);
	extern void vec_interrupt_240(void);
	extern void vec_interrupt_241(void);
	extern void vec_interrupt_242(void);
	extern void vec_interrupt_243(void);
	extern void vec_interrupt_244(void);
	extern void vec_interrupt_245(void);
	extern void vec_interrupt_246(void);
	extern void vec_interrupt_247(void);
	extern void vec_interrupt_248(void);
	extern void vec_interrupt_249(void);
	extern void vec_interrupt_250(void);
	extern void vec_interrupt_251(void);
	extern void vec_interrupt_252(void);
	extern void vec_interrupt_253(void);
	extern void vec_interrupt_254(void);
	extern void vec_interrupt_255(void);

	uint64_t interrupt_thunks[256] = {
		(uint64_t)vec_interrupt_0,
		(uint64_t)vec_interrupt_1,
		(uint64_t)vec_interrupt_2,
		(uint64_t)vec_interrupt_3,
		(uint64_t)vec_interrupt_4,
		(uint64_t)vec_interrupt_5,
		(uint64_t)vec_interrupt_6,
		(uint64_t)vec_interrupt_7,
		(uint64_t)vec_interrupt_8,
		(uint64_t)vec_interrupt_9,
		(uint64_t)vec_interrupt_10,
		(uint64_t)vec_interrupt_11,
		(uint64_t)vec_interrupt_12,
		(uint64_t)vec_interrupt_13,
		(uint64_t)vec_interrupt_14,
		(uint64_t)vec_interrupt_15,
		(uint64_t)vec_interrupt_16,
		(uint64_t)vec_interrupt_17,
		(uint64_t)vec_interrupt_18,
		(uint64_t)vec_interrupt_19,
		(uint64_t)vec_interrupt_20,
		(uint64_t)vec_interrupt_21,
		(uint64_t)vec_interrupt_22,
		(uint64_t)vec_interrupt_23,
		(uint64_t)vec_interrupt_24,
		(uint64_t)vec_interrupt_25,
		(uint64_t)vec_interrupt_26,
		(uint64_t)vec_interrupt_27,
		(uint64_t)vec_interrupt_28,
		(uint64_t)vec_interrupt_29,
		(uint64_t)vec_interrupt_30,
		(uint64_t)vec_interrupt_31,
		(uint64_t)vec_interrupt_32,
		(uint64_t)vec_interrupt_33,
		(uint64_t)vec_interrupt_34,
		(uint64_t)vec_interrupt_35,
		(uint64_t)vec_interrupt_36,
		(uint64_t)vec_interrupt_37,
		(uint64_t)vec_interrupt_38,
		(uint64_t)vec_interrupt_39,
		(uint64_t)vec_interrupt_40,
		(uint64_t)vec_interrupt_41,
		(uint64_t)vec_interrupt_42,
		(uint64_t)vec_interrupt_43,
		(uint64_t)vec_interrupt_44,
		(uint64_t)vec_interrupt_45,
		(uint64_t)vec_interrupt_46,
		(uint64_t)vec_interrupt_47,
		(uint64_t)vec_interrupt_48,
		(uint64_t)vec_interrupt_49,
		(uint64_t)vec_interrupt_50,
		(uint64_t)vec_interrupt_51,
		(uint64_t)vec_interrupt_52,
		(uint64_t)vec_interrupt_53,
		(uint64_t)vec_interrupt_54,
		(uint64_t)vec_interrupt_55,
		(uint64_t)vec_interrupt_56,
		(uint64_t)vec_interrupt_57,
		(uint64_t)vec_interrupt_58,
		(uint64_t)vec_interrupt_59,
		(uint64_t)vec_interrupt_60,
		(uint64_t)vec_interrupt_61,
		(uint64_t)vec_interrupt_62,
		(uint64_t)vec_interrupt_63,
		(uint64_t)vec_interrupt_64,
		(uint64_t)vec_interrupt_65,
		(uint64_t)vec_interrupt_66,
		(uint64_t)vec_interrupt_67,
		(uint64_t)vec_interrupt_68,
		(uint64_t)vec_interrupt_69,
		(uint64_t)vec_interrupt_70,
		(uint64_t)vec_interrupt_71,
		(uint64_t)vec_interrupt_72,
		(uint64_t)vec_interrupt_73,
		(uint64_t)vec_interrupt_74,
		(uint64_t)vec_interrupt_75,
		(uint64_t)vec_interrupt_76,
		(uint64_t)vec_interrupt_77,
		(uint64_t)vec_interrupt_78,
		(uint64_t)vec_interrupt_79,
		(uint64_t)vec_interrupt_80,
		(uint64_t)vec_interrupt_81,
		(uint64_t)vec_interrupt_82,
		(uint64_t)vec_interrupt_83,
		(uint64_t)vec_interrupt_84,
		(uint64_t)vec_interrupt_85,
		(uint64_t)vec_interrupt_86,
		(uint64_t)vec_interrupt_87,
		(uint64_t)vec_interrupt_88,
		(uint64_t)vec_interrupt_89,
		(uint64_t)vec_interrupt_90,
		(uint64_t)vec_interrupt_91,
		(uint64_t)vec_interrupt_92,
		(uint64_t)vec_interrupt_93,
		(uint64_t)vec_interrupt_94,
		(uint64_t)vec_interrupt_95,
		(uint64_t)vec_interrupt_96,
		(uint64_t)vec_interrupt_97,
		(uint64_t)vec_interrupt_98,
		(uint64_t)vec_interrupt_99,
		(uint64_t)vec_interrupt_100,
		(uint64_t)vec_interrupt_101,
		(uint64_t)vec_interrupt_102,
		(uint64_t)vec_interrupt_103,
		(uint64_t)vec_interrupt_104,
		(uint64_t)vec_interrupt_105,
		(uint64_t)vec_interrupt_106,
		(uint64_t)vec_interrupt_107,
		(uint64_t)vec_interrupt_108,
		(uint64_t)vec_interrupt_109,
		(uint64_t)vec_interrupt_110,
		(uint64_t)vec_interrupt_111,
		(uint64_t)vec_interrupt_112,
		(uint64_t)vec_interrupt_113,
		(uint64_t)vec_interrupt_114,
		(uint64_t)vec_interrupt_115,
		(uint64_t)vec_interrupt_116,
		(uint64_t)vec_interrupt_117,
		(uint64_t)vec_interrupt_118,
		(uint64_t)vec_interrupt_119,
		(uint64_t)vec_interrupt_120,
		(uint64_t)vec_interrupt_121,
		(uint64_t)vec_interrupt_122,
		(uint64_t)vec_interrupt_123,
		(uint64_t)vec_interrupt_124,
		(uint64_t)vec_interrupt_125,
		(uint64_t)vec_interrupt_126,
		(uint64_t)vec_interrupt_127,
		(uint64_t)vec_interrupt_128,
		(uint64_t)vec_interrupt_129,
		(uint64_t)vec_interrupt_130,
		(uint64_t)vec_interrupt_131,
		(uint64_t)vec_interrupt_132,
		(uint64_t)vec_interrupt_133,
		(uint64_t)vec_interrupt_134,
		(uint64_t)vec_interrupt_135,
		(uint64_t)vec_interrupt_136,
		(uint64_t)vec_interrupt_137,
		(uint64_t)vec_interrupt_138,
		(uint64_t)vec_interrupt_139,
		(uint64_t)vec_interrupt_140,
		(uint64_t)vec_interrupt_141,
		(uint64_t)vec_interrupt_142,
		(uint64_t)vec_interrupt_143,
		(uint64_t)vec_interrupt_144,
		(uint64_t)vec_interrupt_145,
		(uint64_t)vec_interrupt_146,
		(uint64_t)vec_interrupt_147,
		(uint64_t)vec_interrupt_148,
		(uint64_t)vec_interrupt_149,
		(uint64_t)vec_interrupt_150,
		(uint64_t)vec_interrupt_151,
		(uint64_t)vec_interrupt_152,
		(uint64_t)vec_interrupt_153,
		(uint64_t)vec_interrupt_154,
		(uint64_t)vec_interrupt_155,
		(uint64_t)vec_interrupt_156,
		(uint64_t)vec_interrupt_157,
		(uint64_t)vec_interrupt_158,
		(uint64_t)vec_interrupt_159,
		(uint64_t)vec_interrupt_160,
		(uint64_t)vec_interrupt_161,
		(uint64_t)vec_interrupt_162,
		(uint64_t)vec_interrupt_163,
		(uint64_t)vec_interrupt_164,
		(uint64_t)vec_interrupt_165,
		(uint64_t)vec_interrupt_166,
		(uint64_t)vec_interrupt_167,
		(uint64_t)vec_interrupt_168,
		(uint64_t)vec_interrupt_169,
		(uint64_t)vec_interrupt_170,
		(uint64_t)vec_interrupt_171,
		(uint64_t)vec_interrupt_172,
		(uint64_t)vec_interrupt_173,
		(uint64_t)vec_interrupt_174,
		(uint64_t)vec_interrupt_175,
		(uint64_t)vec_interrupt_176,
		(uint64_t)vec_interrupt_177,
		(uint64_t)vec_interrupt_178,
		(uint64_t)vec_interrupt_179,
		(uint64_t)vec_interrupt_180,
		(uint64_t)vec_interrupt_181,
		(uint64_t)vec_interrupt_182,
		(uint64_t)vec_interrupt_183,
		(uint64_t)vec_interrupt_184,
		(uint64_t)vec_interrupt_185,
		(uint64_t)vec_interrupt_186,
		(uint64_t)vec_interrupt_187,
		(uint64_t)vec_interrupt_188,
		(uint64_t)vec_interrupt_189,
		(uint64_t)vec_interrupt_190,
		(uint64_t)vec_interrupt_191,
		(uint64_t)vec_interrupt_192,
		(uint64_t)vec_interrupt_193,
		(uint64_t)vec_interrupt_194,
		(uint64_t)vec_interrupt_195,
		(uint64_t)vec_interrupt_196,
		(uint64_t)vec_interrupt_197,
		(uint64_t)vec_interrupt_198,
		(uint64_t)vec_interrupt_199,
		(uint64_t)vec_interrupt_200,
		(uint64_t)vec_interrupt_201,
		(uint64_t)vec_interrupt_202,
		(uint64_t)vec_interrupt_203,
		(uint64_t)vec_interrupt_204,
		(uint64_t)vec_interrupt_205,
		(uint64_t)vec_interrupt_206,
		(uint64_t)vec_interrupt_207,
		(uint64_t)vec_interrupt_208,
		(uint64_t)vec_interrupt_209,
		(uint64_t)vec_interrupt_210,
		(uint64_t)vec_interrupt_211,
		(uint64_t)vec_interrupt_212,
		(uint64_t)vec_interrupt_213,
		(uint64_t)vec_interrupt_214,
		(uint64_t)vec_interrupt_215,
		(uint64_t)vec_interrupt_216,
		(uint64_t)vec_interrupt_217,
		(uint64_t)vec_interrupt_218,
		(uint64_t)vec_interrupt_219,
		(uint64_t)vec_interrupt_220,
		(uint64_t)vec_interrupt_221,
		(uint64_t)vec_interrupt_222,
		(uint64_t)vec_interrupt_223,
		(uint64_t)vec_interrupt_224,
		(uint64_t)vec_interrupt_225,
		(uint64_t)vec_interrupt_226,
		(uint64_t)vec_interrupt_227,
		(uint64_t)vec_interrupt_228,
		(uint64_t)vec_interrupt_229,
		(uint64_t)vec_interrupt_230,
		(uint64_t)vec_interrupt_231,
		(uint64_t)vec_interrupt_232,
		(uint64_t)vec_interrupt_233,
		(uint64_t)vec_interrupt_234,
		(uint64_t)vec_interrupt_235,
		(uint64_t)vec_interrupt_236,
		(uint64_t)vec_interrupt_237,
		(uint64_t)vec_interrupt_238,
		(uint64_t)vec_interrupt_239,
		(uint64_t)vec_interrupt_240,
		(uint64_t)vec_interrupt_241,
		(uint64_t)vec_interrupt_242,
		(uint64_t)vec_interrupt_243,
		(uint64_t)vec_interrupt_244,
		(uint64_t)vec_interrupt_245,
		(uint64_t)vec_interrupt_246,
		(uint64_t)vec_interrupt_247,
		(uint64_t)vec_interrupt_248,
		(uint64_t)vec_interrupt_249,
		(uint64_t)vec_interrupt_250,
		(uint64_t)vec_interrupt_251,
		(uint64_t)vec_interrupt_252,
		(uint64_t)vec_interrupt_253,
		(uint64_t)vec_interrupt_254,
		(uint64_t)vec_interrupt_255,
	};

#pragma pack(push, 1)
	struct {
		struct {
			uint16_t offset_15_0;
			uint16_t selector;
			uint8_t  ist;
			uint8_t  type;
			uint16_t offset_31_16;
			uint32_t offset_63_32;
			uint32_t reserved;
		} ent[256];

		uint16_t limit;
		uint64_t addr;
	} *idt = NULL;
#pragma pack(pop)

	int i;
	
	RSTATE_LOCALS;

	/* Initialize the GDT */
	rstate = gdt_init();
	RSCHECK_NESTED("Failed to initialize GDT");

	/* Allocate room for the IDT */
	rstate = phalloc(sizeof(*idt), (void**)&idt);
	RSCHECK_NESTED("Failed to allocate room for the IDT");

	/* Set up the IDTR */
	idt->limit = 4095;
	idt->addr  = (uint64_t)idt;

	/* Set up all interrupt handlers */
	for(i = 0; i < 256; i++){
		uint64_t func;

		func = interrupt_thunks[i];

		idt->ent[i].offset_15_0  = func & 0xffff;
		idt->ent[i].selector	 = 8;
		idt->ent[i].ist          = 0;
		idt->ent[i].type         = 0xee;
		idt->ent[i].offset_31_16 = (func >> 16) & 0xffff;
		idt->ent[i].offset_63_32 = (func >> 32) & 0xffffffff;
		idt->ent[i].reserved     = 0;

		/* Timer */
		if(i == 69){
			idt->ent[i].ist = 1;
		}

		/* NMI, double fault, machine check */
		if(i == 2 || i == 8 || i == 18){
			idt->ent[i].ist = 2;
		}
	}

	/* Load the new IDT */
	lidt(&idt->limit);

	/* Enable profiling */
	profiling_enable();
	interrupts_enable();

	rstate_ret = RSTATE_SUCCESS;
cleanup:
	RSTATE_RETURN;
}

