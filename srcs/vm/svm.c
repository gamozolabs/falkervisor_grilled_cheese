#include <grilled_cheese.h>
#include <mm/mm.h>
#include <net/x540.h>
#include <vm/vm.h>
#include <vm/svm.h>
#include <disp/disp.h>
#include <generic/stdlib.h>
#include <time/time.h>
#include <dstruc/hash_table.h>
#include <fuzzers/chrome.h>
#include <fuzzers/helpers.h>

/* svm_init()
 *
 * Summary:
 *
 * Initialize the SVM state for this CPU. Call this once per CPU.
 */
rstate_t
svm_init(void)
{
	uintptr_t hsave;

	RSTATE_LOCALS;

	/* Enable SVM in the EFER */
	wrmsr(0xc0000080, rdmsr(0xc0000080) | (1 << 12));

	rstate = alloc_phys(4096, &hsave);
	RSCHECK_NESTED("Failed to allocate memory for hsave area");

	/* Set up VM_HSAVE_PA MSR */
	wrmsr(0xC0010117, hsave);

	rstate_ret = RSTATE_SUCCESS;
cleanup:
	RSTATE_RETURN;
}

/* svm_create()
 *
 * Summary:
 *
 * This function initialzes the SVM specific context for a VM.
 */
rstate_t
svm_create(struct _vm *vm)
{
	struct _svm_vm *svm_vm;
	struct _vmcb *vmcb;

	RSTATE_LOCALS;

	/* Allocate the SVM specific context structure */
	rstate = phalloc(sizeof(struct _svm_vm), (void**)&svm_vm);
	RSCHECK_NESTED("Failed to allocate room for SVM context");

	/* Allocate room for the host VMCB save space */
	rstate = alloc_physvirt_4k(&svm_vm->host_vmcb_pa,
			(void**)&svm_vm->host_vmcb);
	RSCHECK_NESTED("Failed to allocate host VMCB");
	
	/* Allocate room for the guest VMCB */
	rstate = alloc_physvirt_4k(&svm_vm->vmcb_pa, (void**)&svm_vm->vmcb);
	RSCHECK_NESTED("Failed to allocate guest VMCB");

	/* Allocate room for the host xsave */
	rstate = phalloc(4096, &svm_vm->host_xsave);
	RSCHECK_NESTED("Failed to allocate host XSAVE area");
	
	/* Allocate room for the guest xsave */
	rstate = phalloc(4096, &svm_vm->xsave);
	RSCHECK_NESTED("Failed to allocate guest XSAVE area");

	/* Allocate room for the guest IOPM */
	rstate = alloc_phys(12 * 1024, &svm_vm->vmcb->iopm);
	RSCHECK_NESTED("Failed to allocate room for IOPM");

	/* Allocate room for the guest MSRPM */
	rstate = alloc_phys(16 * 1024, &svm_vm->vmcb->msrpm);
	RSCHECK_NESTED("Failed to allocate room for MSRPM");

	vmcb = svm_vm->vmcb;

	{
		void *tmp_map;

		/* Fill the IOPM with 0xffs, causing all I/O instructions to cause
		 * a #VMEXIT.
		 */
		tmp_map = mm_get_phys_mapping(vmcb->iopm + 0x0000);
		memset(tmp_map, 0xff, 4096);
		mm_release_phys_mapping(tmp_map);
		tmp_map = mm_get_phys_mapping(vmcb->iopm + 0x1000);
		memset(tmp_map, 0xff, 4096);
		mm_release_phys_mapping(tmp_map);
		tmp_map = mm_get_phys_mapping(vmcb->iopm + 0x2000);
		memset(tmp_map, 0xff, 4096);
		mm_release_phys_mapping(tmp_map);
	}

	{
		void *tmp_map;

		/* Fill the MSRPM with 0xffs, causing all MSR accesses to cause a
		 * #VMEXIT.
		 */
		tmp_map = mm_get_phys_mapping(vmcb->msrpm + 0x0000);
		memset(tmp_map, 0xff, 4096);
		mm_release_phys_mapping(tmp_map);
		tmp_map = mm_get_phys_mapping(vmcb->msrpm + 0x1000);
		memset(tmp_map, 0xff, 4096);
		mm_release_phys_mapping(tmp_map);
		tmp_map = mm_get_phys_mapping(vmcb->msrpm + 0x2000);
		memset(tmp_map, 0xff, 4096);
		mm_release_phys_mapping(tmp_map);
		tmp_map = mm_get_phys_mapping(vmcb->msrpm + 0x3000);
		memset(tmp_map, 0xff, 4096);
		mm_release_phys_mapping(tmp_map);
	}

	/* Start an empty nested page table and enable nested paging */
	rstate = alloc_phys_4k(&vmcb->n_cr3);
	RSCHECK_NESTED("Failed to allocate nested cr3");
	vmcb->np_enabled = 1;

	vmcb->tlb_and_asid = (3UL << 32) | 1;
	vmcb->vint         = 0;
	vmcb->CR_icpt      = 0xffffffff;
	vmcb->DR_icpt      = 0xffffffff;
	vmcb->except_icpt  = 0xffffffff;
	vmcb->icpt_set_1   = 0xffffffff;
	vmcb->icpt_set_2   = 0x3fff;

	vmcb->cr0   = 0x10;
	vmcb->cpl   = 0;
	vmcb->efer  = (1 << 12);
	vmcb->dr6   = 0;
	vmcb->dr7   = 0;
	vmcb->g_pat = 0x0007040600070406;

	/* Save off the SVM specific state to the VM */
	vm->state.svm_state = svm_vm;

	rstate_ret = RSTATE_SUCCESS;
cleanup:
	RSTATE_RETURN;
}

/* svm_enter_regsegs()
 *
 * Summary:
 *
 * Before a VM entry, this function converts the generic x86 VM state to the
 * SVM specific vmcb state.
 */
void
svm_enter_regsegs(struct _vm *vm)
{
	struct _vmcb *vmcb = vm->state.svm_state->vmcb;

	vmcb->es_sel    = vm->regs.x86_regs.es_sel;
	vmcb->es_attrib = vm->regs.x86_regs.es_attrib;
	vmcb->es_base   = vm->regs.x86_regs.es_base;
	vmcb->es_limit  = vm->regs.x86_regs.es_limit;

	vmcb->cs_sel    = vm->regs.x86_regs.cs_sel;
	vmcb->cs_attrib = vm->regs.x86_regs.cs_attrib;
	vmcb->cs_base   = vm->regs.x86_regs.cs_base;
	vmcb->cs_limit  = vm->regs.x86_regs.cs_limit;

	vmcb->ss_sel    = vm->regs.x86_regs.ss_sel;
	vmcb->ss_attrib = vm->regs.x86_regs.ss_attrib;
	vmcb->ss_base   = vm->regs.x86_regs.ss_base;
	vmcb->ss_limit  = vm->regs.x86_regs.ss_limit;

	vmcb->ds_sel    = vm->regs.x86_regs.ds_sel;
	vmcb->ds_attrib = vm->regs.x86_regs.ds_attrib;
	vmcb->ds_base   = vm->regs.x86_regs.ds_base;
	vmcb->ds_limit  = vm->regs.x86_regs.ds_limit;

	vmcb->fs_sel    = vm->regs.x86_regs.fs_sel;
	vmcb->fs_attrib = vm->regs.x86_regs.fs_attrib;
	vmcb->fs_base   = vm->regs.x86_regs.fs_base;
	vmcb->fs_limit  = vm->regs.x86_regs.fs_limit;

	vmcb->gs_sel    = vm->regs.x86_regs.gs_sel;
	vmcb->gs_attrib = vm->regs.x86_regs.gs_attrib;
	vmcb->gs_base   = vm->regs.x86_regs.gs_base;
	vmcb->gs_limit  = vm->regs.x86_regs.gs_limit;

	vmcb->gdtr_sel    = vm->regs.x86_regs.gdtr_sel;
	vmcb->gdtr_attrib = vm->regs.x86_regs.gdtr_attrib;
	vmcb->gdtr_base   = vm->regs.x86_regs.gdtr_base;
	vmcb->gdtr_limit  = vm->regs.x86_regs.gdtr_limit;

	vmcb->ldtr_sel    = vm->regs.x86_regs.ldtr_sel;
	vmcb->ldtr_attrib = vm->regs.x86_regs.ldtr_attrib;
	vmcb->ldtr_base   = vm->regs.x86_regs.ldtr_base;
	vmcb->ldtr_limit  = vm->regs.x86_regs.ldtr_limit;

	vmcb->idtr_sel    = vm->regs.x86_regs.idtr_sel;
	vmcb->idtr_attrib = vm->regs.x86_regs.idtr_attrib;
	vmcb->idtr_base   = vm->regs.x86_regs.idtr_base;
	vmcb->idtr_limit  = vm->regs.x86_regs.idtr_limit;
	
	vmcb->tr_sel    = vm->regs.x86_regs.tr_sel;
	vmcb->tr_attrib = vm->regs.x86_regs.tr_attrib;
	vmcb->tr_base   = vm->regs.x86_regs.tr_base;
	vmcb->tr_limit  = vm->regs.x86_regs.tr_limit;

	vmcb->rip = vm->regs.x86_regs.rip.rip;
	vmcb->rsp = vm->regs.x86_regs.rsp.rsp;
	vmcb->rfl = vm->regs.x86_regs.rfl.rfl;
	vmcb->rax = vm->regs.x86_regs.rax.rax;

	return;
}

/* svm_exit_regsegs()
 *
 * Summary:
 *
 * After a VM exit this function converts the SVM VMCB specific state to the
 * generic x86 register state.
 */
void
svm_exit_regsegs(struct _vm *vm)
{
	struct _vmcb *vmcb = vm->state.svm_state->vmcb;

	vm->regs.x86_regs.es_sel    = vmcb->es_sel;
	vm->regs.x86_regs.es_attrib = vmcb->es_attrib;
	vm->regs.x86_regs.es_base   = vmcb->es_base;
	vm->regs.x86_regs.es_limit  = vmcb->es_limit;

	vm->regs.x86_regs.cs_sel    = vmcb->cs_sel;
	vm->regs.x86_regs.cs_attrib = vmcb->cs_attrib;
	vm->regs.x86_regs.cs_base   = vmcb->cs_base;
	vm->regs.x86_regs.cs_limit  = vmcb->cs_limit;

	vm->regs.x86_regs.ss_sel    = vmcb->ss_sel;
	vm->regs.x86_regs.ss_attrib = vmcb->ss_attrib;
	vm->regs.x86_regs.ss_base   = vmcb->ss_base;
	vm->regs.x86_regs.ss_limit  = vmcb->ss_limit;

	vm->regs.x86_regs.ds_sel    = vmcb->ds_sel;
	vm->regs.x86_regs.ds_attrib = vmcb->ds_attrib;
	vm->regs.x86_regs.ds_base   = vmcb->ds_base;
	vm->regs.x86_regs.ds_limit  = vmcb->ds_limit;

	vm->regs.x86_regs.fs_sel    = vmcb->fs_sel;
	vm->regs.x86_regs.fs_attrib = vmcb->fs_attrib;
	vm->regs.x86_regs.fs_base   = vmcb->fs_base;
	vm->regs.x86_regs.fs_limit  = vmcb->fs_limit;

	vm->regs.x86_regs.gs_sel    = vmcb->gs_sel;
	vm->regs.x86_regs.gs_attrib = vmcb->gs_attrib;
	vm->regs.x86_regs.gs_base   = vmcb->gs_base;
	vm->regs.x86_regs.gs_limit  = vmcb->gs_limit;

	vm->regs.x86_regs.gdtr_sel    = vmcb->gdtr_sel;
	vm->regs.x86_regs.gdtr_attrib = vmcb->gdtr_attrib;
	vm->regs.x86_regs.gdtr_base   = vmcb->gdtr_base;
	vm->regs.x86_regs.gdtr_limit  = vmcb->gdtr_limit;

	vm->regs.x86_regs.ldtr_sel    = vmcb->ldtr_sel;
	vm->regs.x86_regs.ldtr_attrib = vmcb->ldtr_attrib;
	vm->regs.x86_regs.ldtr_base   = vmcb->ldtr_base;
	vm->regs.x86_regs.ldtr_limit  = vmcb->ldtr_limit;

	vm->regs.x86_regs.idtr_sel    = vmcb->idtr_sel;
	vm->regs.x86_regs.idtr_attrib = vmcb->idtr_attrib;
	vm->regs.x86_regs.idtr_base   = vmcb->idtr_base;
	vm->regs.x86_regs.idtr_limit  = vmcb->idtr_limit;
	
	vm->regs.x86_regs.tr_sel    = vmcb->tr_sel;
	vm->regs.x86_regs.tr_attrib = vmcb->tr_attrib;
	vm->regs.x86_regs.tr_base   = vmcb->tr_base;
	vm->regs.x86_regs.tr_limit  = vmcb->tr_limit;

	vm->regs.x86_regs.rip.rip = vmcb->rip;
	vm->regs.x86_regs.rsp.rsp = vmcb->rsp;
	vm->regs.x86_regs.rfl.rfl = vmcb->rfl;
	vm->regs.x86_regs.rax.rax = vmcb->rax;

	return;
}

rstate_t
svm_step(struct _vm *vm)
{
	struct _vmcb *vmcb = vm->state.svm_state->vmcb;

	RSTATE_LOCALS;

reenter_vm:
	svm_enter_regsegs(vm);
	svm_asm_step(vm->state.svm_state, &vm->regs.x86_regs);
	svm_exit_regsegs(vm);

	if(vmcb->exitcode == 0x400){
		int handled       = 0;
		int write_attempt = vmcb->exitinfo1 & (1 << 1);
		int exec_attempt  = vmcb->exitinfo1 & (1 << 4);

		rstate = vm->npf_handler(vm, vmcb->exitinfo2, 1, write_attempt,
				exec_attempt, &handled);
		RSCHECK_NESTED("Guest page fault handler returned error");

		if(handled){
			goto reenter_vm;
		}
	}

	rstate_ret = RSTATE_SUCCESS;
cleanup:
	RSTATE_RETURN;
}

void
svm_dump_state(struct _vm *vm)
{
	struct _vmcb *vmcb = vm->state.svm_state->vmcb;

	printf(
			"EC: %lx EI1: %lx EI2: %lx Inst bytes: %.16lx",
			vmcb->exitcode, vmcb->exitinfo1, vmcb->exitinfo2,
			byteswap(vmcb->guest_inst[0]));

	vm_x86_dump_state(vm);

	return;
}

rstate_t
svm_map_phys(struct _vm *vm, uint64_t address,
		int readable, int writable, int executable,
		uint64_t backing_page)
{
	uint64_t permissions = (1UL << 63) | 5;

	RSTATE_LOCALS;

	if(writable){
		permissions |= (1 << 1);
	}
	if(executable){
		permissions &= ~(1UL << 63);
	}

	RSCHECK((backing_page & 0xfff) == 0, "Backing page must be page aligned");
	RSCHECK((address & 0xfff) == 0, "Address must be page aligned");

	rstate = mm_map_4k_nolock(vm->state.svm_state->vmcb->n_cr3, address,
			backing_page | permissions, 0);
	RSCHECK_NESTED("Failed to map in page");

	rstate_ret = RSTATE_SUCCESS;
cleanup:
	RSTATE_RETURN;
}

rstate_t
svm_guest_phys_to_host_phys(
		struct _vm *vm,
		uint64_t    guest_paddr,
		int         is_read,
		int         is_write,
		int         is_exec,
		uint64_t   *host_paddr)
{
	int can_read, can_write, can_exec;
	uint64_t ent;
	uintptr_t paddr;
	struct _vmcb *vmcb = vm->state.svm_state->vmcb;

	RSTATE_LOCALS;

	paddr = mm_get_phys_nolock(vmcb->n_cr3, guest_paddr, &ent);

	can_read  = 1;
	can_write = ent & (1 << 1);
	can_exec  = !(ent & (1UL << 63));

	/* If the page is not present, invoke the NPF handler. This will pull
	 * in lazy loaded pages or NPF pages.
	 */
	if(!paddr || (is_read && !can_read) || (is_write && !can_write) ||
			(is_exec && !can_exec)){
		int handled;

		rstate = vm->npf_handler(vm, guest_paddr, is_read, is_write,
				is_exec, &handled);
		RSCHECK_NESTED("Guest NPF handler returned failure");
		RSCHECK(handled, "Attempted to access invalid guest physical memory");

		paddr = mm_get_phys_nolock(vmcb->n_cr3, guest_paddr, &ent);

		/* Recheck permissions */
		can_read  = 1;
		can_write = ent & (1 << 1);
		can_exec  = !(ent & (1UL << 63));
		if(!paddr || (is_read && !can_read) || (is_write && !can_write) ||
			(is_exec && !can_exec)){
			RSCHECK(1 == 0, "After NPF handler page is still not usable");
		}
	}

	*host_paddr = paddr;
	rstate_ret  = RSTATE_SUCCESS;
cleanup:
	RSTATE_RETURN;
}

rstate_t
svm_guest_virt_to_host_phys(
		struct _vm *vm,
		uint64_t    guest_vaddr,
		int         is_read,
		int         is_write,
		int         is_exec,
		uint64_t   *host_paddr)
{
    uint64_t *cur, entry, pml4o, pdpo, pdo, pto;
	struct _vmcb *vmcb = vm->state.svm_state->vmcb;

	RSTATE_LOCALS;

    /* Extract the PML4 address from cr3 */
    cur = (uint64_t*)MASK((uint64_t)vmcb->cr3, 51, 12);

    /* Get each part of the address used in translation */
    pml4o = BEXTR(guest_vaddr, 47, 39);
    pdpo  = BEXTR(guest_vaddr, 38, 30);
    pdo   = BEXTR(guest_vaddr, 29, 21);
    pto   = BEXTR(guest_vaddr, 20, 12);

    /* PML4 */
	rstate = vm_read_phys(vm, (uint64_t)(cur + pml4o), &entry, sizeof(entry));
	RSCHECK_NESTED("Failed to read PML4 entry");
    RSCHECK(entry & 1, "PML4 entry not present");
    cur = (uint64_t*)MASK(entry, 51, 12);

    /* PDP */
	rstate = vm_read_phys(vm, (uint64_t)(cur + pdpo), &entry, sizeof(entry));
	RSCHECK_NESTED("Failed to read PDP entry");
    RSCHECK(entry & 1, "PDP entry not present");

    if(entry & (1 << 7)){
        *host_paddr = (MASK(entry, 51, 12) + MASK(guest_vaddr, 29, 0));
		goto success;
    }
    cur = (uint64_t*)MASK(entry, 51, 12);

    /* PD */
	rstate = vm_read_phys(vm, (uint64_t)(cur + pdo), &entry, sizeof(entry));
	RSCHECK_NESTED("Failed to read PD entry");
    RSCHECK(entry & 1, "PD entry not present");

    if(entry & (1 << 7)){ 
       *host_paddr = (MASK(entry, 51, 12) + MASK(guest_vaddr, 20, 0));
	   goto success;
    }
    cur = (uint64_t*)MASK(entry, 51, 12);

    /* PT */
	rstate = vm_read_phys(vm, (uint64_t)(cur + pto), &entry, sizeof(entry));
	RSCHECK_NESTED("Failed to read PT entry");
    RSCHECK(entry & 1, "PT entry not present");
    
	*host_paddr = (MASK(entry, 51, 12) + MASK(guest_vaddr, 11, 0));

success:
	rstate = vm->guest_phys_to_host_phys(vm, *host_paddr,
			is_read, is_write, is_exec, host_paddr);
	RSCHECK_NESTED("Failed to translate guest phys to host phys");

	rstate_ret = RSTATE_SUCCESS;
cleanup:
	RSTATE_RETURN;
}

