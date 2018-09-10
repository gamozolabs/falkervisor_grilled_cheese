#include <grilled_cheese.h>
#include <mm/mm.h>
#include <generic/stdlib.h>
#include <vm/vm.h>
#include <vm/svm.h>
#include <disp/disp.h>

/* vm_x86_create()
 *
 * Summary:
 *
 * Create an x86 VM that is initialized to a post-BIOS boot state. RIP
 * points to 0x7c00 and the VM is in real mode.
 */
rstate_t
vm_x86_create(_Outptr_ struct _vm **out_vm, _In_ enum _vm_subtype type)
{
	struct _vm *vm;

	RSTATE_LOCALS;

	rstate = phalloc(sizeof(struct _vm), (void**)&vm);
	RSCHECK_NESTED("Failed to allocate room for VM");

	/* Set that we're an X86 VM */
	vm->type    = GUEST_X86;
	vm->subtype = type;

	/* Initialize segment state */
	vm->regs.x86_regs.es_sel    = 0;
	vm->regs.x86_regs.es_attrib = 0x93;
	vm->regs.x86_regs.es_base   = 0;
	vm->regs.x86_regs.es_limit  = 0xffff;

	vm->regs.x86_regs.cs_sel    = 0;
	vm->regs.x86_regs.cs_attrib = 0x93;
	vm->regs.x86_regs.cs_base   = 0;
	vm->regs.x86_regs.cs_limit  = 0xffff;

	vm->regs.x86_regs.ss_sel    = 0;
	vm->regs.x86_regs.ss_attrib = 0x93;
	vm->regs.x86_regs.ss_base   = 0;
	vm->regs.x86_regs.ss_limit  = 0xffff;

	vm->regs.x86_regs.ds_sel    = 0;
	vm->regs.x86_regs.ds_attrib = 0x93;
	vm->regs.x86_regs.ds_base   = 0;
	vm->regs.x86_regs.ds_limit  = 0xffff;

	vm->regs.x86_regs.fs_sel    = 0;
	vm->regs.x86_regs.fs_attrib = 0x93;
	vm->regs.x86_regs.fs_base   = 0;
	vm->regs.x86_regs.fs_limit  = 0xffff;

	vm->regs.x86_regs.gs_sel    = 0;
	vm->regs.x86_regs.gs_attrib = 0x93;
	vm->regs.x86_regs.gs_base   = 0;
	vm->regs.x86_regs.gs_limit  = 0xffff;

	vm->regs.x86_regs.gdtr_sel    = 0;
	vm->regs.x86_regs.gdtr_attrib = 0x82;
	vm->regs.x86_regs.gdtr_base   = 0;
	vm->regs.x86_regs.gdtr_limit  = 0xffff;

	vm->regs.x86_regs.ldtr_sel    = 0;
	vm->regs.x86_regs.ldtr_attrib = 0x82;
	vm->regs.x86_regs.ldtr_base   = 0;
	vm->regs.x86_regs.ldtr_limit  = 0xffff;

	vm->regs.x86_regs.idtr_sel    = 0;
	vm->regs.x86_regs.idtr_attrib = 0x82;
	vm->regs.x86_regs.idtr_base   = 0;
	vm->regs.x86_regs.idtr_limit  = 0xffff;
	
	vm->regs.x86_regs.tr_sel    = 0;
	vm->regs.x86_regs.tr_attrib = 0x82;
	vm->regs.x86_regs.tr_base   = 0;
	vm->regs.x86_regs.tr_limit  = 0xffff;

	/* Initialize register state */
	vm->regs.x86_regs.rfl.rfl = 2;
	vm->regs.x86_regs.rip.rip = 0x7c00;
	vm->regs.x86_regs.rsp.rsp = 0x7000;
	vm->regs.x86_regs.rdx.rdx = 0x80;

	/* Initialize the architecture specific VM state */
	if(vm->subtype == X86_VTX){
		RSCHECK(1 == 0, "Intel CPUs not currently supported");
	} else if(vm->subtype == X86_SVM){
		rstate = svm_create(vm);
		RSCHECK_NESTED("Failed to create SVM state for VM");

		vm->step       = svm_step;
		vm->map_phys   = svm_map_phys;
		vm->dump_state = svm_dump_state;
		vm->guest_phys_to_host_phys = svm_guest_phys_to_host_phys;
		vm->guest_virt_to_host_phys = svm_guest_virt_to_host_phys;
	} else if(vm->subtype == X86_USER){
		rstate = x86_user_create(vm);
		RSCHECK_NESTED("Failed to create x86_user state for VM");
	} else {
		RSCHECK(1 == 0, "Unsupported VM type");
	}

	*out_vm = vm;
	rstate_ret = RSTATE_SUCCESS;
cleanup:
	RSTATE_RETURN;
}

/* vm_x86_dump_state()
 *
 * Summary:
 *
 * Dump the entire generic x86 state to the screen.
 */
void
vm_x86_dump_state(struct _vm *vm)
{
	uint64_t stack = 0;
	struct _x86_regs *r = &vm->regs.x86_regs;

	vm_read_virt(vm, r->rsp.rsp, &stack, 8);

	printf(
			"rax %.16lx rbx %.16lx rcx %.16lx rdx %.16lx\n"
			"rsi %.16lx rdi %.16lx rbp %.16lx rsp %.16lx\n"
			"r8  %.16lx r9  %.16lx r10 %.16lx r11 %.16lx\n"
			"r12 %.16lx r13 %.16lx r14 %.16lx r15 %.16lx\n"
			"rfl %.16lx\n"
			"rsp %.16lx (%.16lx)\n"
			"rip %.4x:%.16lx (%.16lx)\n",
			r->rax.rax, r->rbx.rbx, r->rcx.rcx, r->rdx.rdx,
			r->rsi.rsi, r->rdi.rdi, r->rbp.rbp, r->rsp.rsp,
			r->r8.r8, r->r9.r9, r->r10.r10, r->r11.r11,
			r->r12.r12, r->r13.r13, r->r14.r14, r->r15.r15,
			r->rfl.rfl,
			r->rsp.rsp, stack,
			r->cs_sel, r->rip.rip, r->cs_base + r->rip.rip);

	printf(
			"es  %.4x attrib %.4x base %.16lx limit %.8x\n"
			"ds  %.4x attrib %.4x base %.16lx limit %.8x\n"
			"fs  %.4x attrib %.4x base %.16lx limit %.8x\n"
			"gs  %.4x attrib %.4x base %.16lx limit %.8x\n"
			"ss  %.4x attrib %.4x base %.16lx limit %.8x\n"
			"cs  %.4x attrib %.4x base %.16lx limit %.8x\n"
			"idt %.4x attrib %.4x base %.16lx limit %.8x\n"
			"gdt %.4x attrib %.4x base %.16lx limit %.8x\n"
			"ldt %.4x attrib %.4x base %.16lx limit %.8x\n"
			"tr  %.4x attrib %.4x base %.16lx limit %.8x",
		r->es_sel, r->es_attrib, r->es_base, r->es_limit,
		r->ds_sel, r->ds_attrib, r->ds_base, r->ds_limit,
		r->fs_sel, r->fs_attrib, r->fs_base, r->fs_limit,
		r->gs_sel, r->gs_attrib, r->gs_base, r->gs_limit,
		r->ss_sel, r->ss_attrib, r->ss_base, r->ss_limit,
		r->cs_sel, r->cs_attrib, r->cs_base, r->cs_limit,
		r->idtr_sel, r->idtr_attrib, r->idtr_base, r->idtr_limit,
		r->gdtr_sel, r->gdtr_attrib, r->gdtr_base, r->gdtr_limit,
		r->ldtr_sel, r->ldtr_attrib, r->ldtr_base, r->ldtr_limit,
		r->tr_sel, r->tr_attrib, r->tr_base, r->tr_limit);

	return;
}

