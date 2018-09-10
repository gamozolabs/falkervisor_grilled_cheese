#include <grilled_cheese.h>
#include <vm/vm.h>
#include <disp/disp.h>
#include <time/time.h>
#include <mm/mm.h>
#include <generic/stdlib.h>
#include <net/net.h>
#include <vm/svm.h>
#include <dstruc/hash_table.h>

static uint64_t VM_MEMORY_SIZE = (4UL * 1024 * 1024 * 1024);

static struct _svm_legacy_snapshot *word_snapshot = NULL;
static uint64_t word_snapshot_len = 0;

rstate_t
x86_fuzz_npf_handler(struct _vm *vm, uint64_t address,
		int read_access, int write_access, int exec_access,
		int *handled)
{
	uint8_t   *tmp;
	uintptr_t  page;

	RSTATE_LOCALS;

	/* Page align the address */
	address &= ~0xfff;

	if(address >= VM_MEMORY_SIZE){
		*handled = 0;
		return RSTATE_SUCCESS;
	}

	if(!mm_is_avail(address, 4096)){
		*handled = 0;
		return RSTATE_SUCCESS;
	}

	rstate = alloc_phys_4k(&page);
	RSCHECK_NESTED("Failed to allocate 4k page");

	tmp = mm_get_phys_mapping((uint64_t)page);
	memcpy(tmp, &word_snapshot->physical_memory[address], 4096);

	if(!memcmp(&tmp[0x691],
				"\x8b\xc8\xba\x02\x00\x00\x00\x81\xf9\x06\x00\x00\xd0\x74\x41\x81", 16)){
		tmp[0x691] = 0xcc;
	}

	mm_release_phys_mapping(tmp);

	rstate = vm->map_phys(vm, address, 1, 1, 1, (uint64_t)page);
	RSCHECK_NESTED("Failed to map in physical memory");

	*handled = 1;
	rstate_ret = RSTATE_SUCCESS;
cleanup:
	RSTATE_RETURN;
}

void
restore_page(void *ctxt, uint64_t vaddr, uint64_t paddr)
{
	void *tmp;
	tmp = mm_get_phys_mapping(paddr);
	memcpy(tmp, &word_snapshot->physical_memory[vaddr], 4096);
	mm_release_phys_mapping(tmp);
}

rstate_t
minimize_rtf(uint8_t *fuzz_input, uint64_t fuzz_input_len)
{
	uint64_t nnl = nonnulllast(fuzz_input, fuzz_input_len);
	uint64_t sel = aes_rand() % nnl;
	uint64_t cpy = (aes_rand() % nnl);

	if(!(aes_rand() % 4)){
		cpy = 1;
	}

	if(cpy > (fuzz_input_len - sel)){
		return RSTATE_SUCCESS;
	}

	memcpy(fuzz_input + sel, fuzz_input + sel + cpy, fuzz_input_len - (sel + cpy));
	memset(fuzz_input + fuzz_input_len - cpy, 0, cpy);

	return RSTATE_SUCCESS;
}

/*#define MINIMIZE*/

rstate_t
create_corrupt_rtf(uint8_t *fuzz_input, uint64_t fuzz_input_len)
{
	uint8_t  *entry;
	uint64_t  entry_len = 0;

	struct _hash_table *input_db;
	struct _hash_table *crash_db;

#ifndef MINIMIZE
	uint64_t ii;
#endif

	static volatile int ready_for_aps = 0;
	static uint8_t *corpus = NULL;
	static uint64_t corpus_len;

	static uint8_t *parsed_rtfs;
	static uint64_t parsed_rtfs_len;

	static struct _rtf_chunk {
		uint64_t offset;
		uint64_t size;
	} *bkt_db, *cw_db;
	static uint64_t bkt_db_ents, cw_db_ents;

	RSTATE_LOCALS;

	if(!corpus && is_bsp()){
		rstate = net_map_remote(current_cpu->net_queue, "waffle.ftar", 1024 * 1024,
				(void**)&corpus, &corpus_len);
		RSCHECK_NESTED("Failed to map corpus");

		rstate = net_map_remote(current_cpu->net_queue, "parsed_rtfs", 1024 * 1024,
				(void**)&parsed_rtfs, &parsed_rtfs_len);
		RSCHECK_NESTED("Failed to map parsed_rtfs");

		rstate = net_map_remote(current_cpu->net_queue, "bkt_db.bin", 1024 * 1024,
				(void**)&bkt_db, &bkt_db_ents);
		RSCHECK_NESTED("Failed to map bkt_db");
		bkt_db_ents /= 0x10;

		rstate = net_map_remote(current_cpu->net_queue, "cw_db.bin", 1024 * 1024,
				(void**)&cw_db, &cw_db_ents);
		RSCHECK_NESTED("Failed to map cw_db");
		cw_db_ents /= 0x10;

		RSCHECK(bkt_db_ents && cw_db_ents && parsed_rtfs_len && corpus_len,
				"bkt_db, cw_db, corpus, or parsed_rtfs was empty");

		ready_for_aps = 1;
	} else {
		while(!ready_for_aps);
	}

	RSCHECK(corpus && corpus_len, "No corpus present");

	rstate = fuzz_get_input_db(&input_db);
	RSCHECK_NESTED("Failed to get input DB");
	
	rstate = fuzz_get_crash_db(&crash_db);
	RSCHECK_NESTED("Failed to get crash DB");

	/* Pick a random entry from out DB */
	while(!entry_len){
		rand_ftar(corpus, corpus_len, &entry, &entry_len);
	}
	memcpy(fuzz_input, entry, MIN(entry_len, fuzz_input_len));

#ifndef MINIMIZE
	/* 75% chance of using an already existing input */
	if(aes_rand() % 4){
		struct _input_ent *ent = ht_rand(input_db);
		if(ent){
			memcpy(fuzz_input, ent->buf, ent->len);
		}
	}

	{
		uint64_t donor_off = aes_rand() % (corpus_len     - 32);
		uint64_t fuzz_off  = aes_rand() % (fuzz_input_len - 32);

		for(ii = 0; ii < aes_rand() % 4; ii++){
			memcpy(fuzz_input + fuzz_off, corpus + donor_off, aes_rand() % 32);
		}
	}

	for(ii = 0; ii < aes_rand() % 256; ii++){
		uint64_t offset = aes_rand() % fuzz_input_len;
		uint64_t remain = fuzz_input_len - offset;
		struct _rtf_chunk *rand_bkt = &bkt_db[aes_rand() % bkt_db_ents];

		memcpy(fuzz_input + offset, parsed_rtfs + rand_bkt->offset,
				MIN(rand_bkt->size, remain));
	}

	for(ii = 0; ii < aes_rand() % 8; ii++){
		uint64_t offset = aes_rand() % fuzz_input_len;
		uint64_t remain = fuzz_input_len - offset;
		struct _rtf_chunk *rand_cw = &cw_db[aes_rand() % cw_db_ents];

		memcpy(fuzz_input + offset, parsed_rtfs + rand_cw->offset,
				MIN(rand_cw->size, remain));
	}
#else
	if(aes_rand() % 128){
		struct _crash_entry *ent = ht_rand(crash_db);
		if(ent){
			struct _input_ent *input = fuzz_get_input(ent->hash);
			if(input){
				memcpy(fuzz_input, input->buf, input->len);
			}
		}
	}
#endif

	minimize_rtf(fuzz_input, fuzz_input_len);
	minimize_rtf(fuzz_input, fuzz_input_len);

	rstate_ret = RSTATE_SUCCESS;
cleanup:
	RSTATE_RETURN;
}

volatile uint64_t fuzzes = 0;

rstate_t
fuzz_word(void)
{
	int hit_pf = 0;
	static volatile int ready_for_aps = 0;
	static volatile uint64_t sum_vmexits = 0, fuzz_start = 0;

	uint8_t  *fuzz_input;
	uint64_t  fuzz_input_len = 229376, single_step = 0, vm_timeout, vmexits;

	struct _x86_regs pf_regs;
	struct _vmcb     pf_vmcb;
	uint8_t          pf_xsave[4096];

	struct _vm *vm;
	struct _vmcb *vmcb, old_vmcb;

	RSTATE_LOCALS;

	/* Load the snapshot over the network one time */
	if(is_bsp()){
		rstate = net_map_remote(current_cpu->net_queue, "word03_pf.img", 4096,
				(void**)&word_snapshot, &word_snapshot_len);
		RSCHECK_NESTED("Failed to map word snapshot");

		fuzz_start = rdtsc_uptime();

		ready_for_aps = 1;
	} else {
		while(!ready_for_aps) _mm_pause();
	}

	rstate = phalloc(fuzz_input_len, (void**)&fuzz_input);
	RSCHECK_NESTED("Failed to allocate room for fuzz_input");

	rstate = vm_x86_create(&vm, X86_SVM);
	RSCHECK_NESTED("Failed to create x86 VM");
	vm->npf_handler = x86_fuzz_npf_handler;
	vmcb = vm->state.svm_state->vmcb;

	/* Save off the newly created vmcb */
	memcpy(&old_vmcb, vmcb, sizeof(struct _vmcb));

fuzz_again:
	/* Restore the snapshot vmcb */
	memcpy(vmcb, word_snapshot->vmcb, 4096);

	/* Restore the snapshot xsave */
	memcpy(vm->state.svm_state->xsave, word_snapshot->xsave, 4096);

	/* Restore our new VMCB n_cr3, iopm, and msrpm */
	vmcb->n_cr3 = old_vmcb.n_cr3;
	vmcb->iopm  = old_vmcb.iopm;
	vmcb->msrpm = old_vmcb.msrpm;

	/* Restore register state from snapshot */
	vm->regs.x86_regs.rbx.rbx = word_snapshot->rbx;
	vm->regs.x86_regs.rcx.rcx = word_snapshot->rcx;
	vm->regs.x86_regs.rdx.rdx = word_snapshot->rdx;
	vm->regs.x86_regs.rsi.rsi = word_snapshot->rsi;
	vm->regs.x86_regs.rdi.rdi = word_snapshot->rdi;
	vm->regs.x86_regs.rbp.rbp = word_snapshot->rbp;
	vm->regs.x86_regs.r8.r8  = word_snapshot->r8;
	vm->regs.x86_regs.r9.r9  = word_snapshot->r9;
	vm->regs.x86_regs.r10.r10 = word_snapshot->r10;
	vm->regs.x86_regs.r11.r11 = word_snapshot->r11;
	vm->regs.x86_regs.r12.r12 = word_snapshot->r12;
	vm->regs.x86_regs.r13.r13 = word_snapshot->r13;
	vm->regs.x86_regs.r14.r14 = word_snapshot->r14;
	vm->regs.x86_regs.r15.r15 = word_snapshot->r15;
	
	/* Clear out breakpoints */
	/*vmcb->dr6 = 0;
	vmcb->dr7 = 0;*/
	
	writedr0(word_snapshot->dr0);
	writedr1(word_snapshot->dr1);
	writedr2(word_snapshot->dr2);
	writedr3(word_snapshot->dr3);

	/* Create the generic segregs copy */
	svm_exit_regsegs(vm);

	/* Mask all interrupts */
	vmcb->vint = (1 << 24);

	/* Don't allow reads or writes to CRs */
	vmcb->CR_icpt = 0;

	/* Don't allow reads or writes to DRs */
	vmcb->DR_icpt = 0;

	/* Intercept all exceptions */
	vmcb->except_icpt = 0xFFFFFFFF;

	/* Intercept shutdown, ferr_freeze, task switches, IO, HLT, and all
	 * interrupts.
	 */
	vmcb->icpt_set_1 = (1 << 31) | (1 << 30) | (1 << 29) | (1 << 27) |
		(1 << 24) | 0x1f;

	/* Intercept everything but RDTSCP */
	vmcb->icpt_set_2 = 0x3F7F;

	mm_for_each_dirty_page(vmcb->n_cr3, 0, -1, restore_page, vm);

	/* Generate modlist */
	rstate = win32_gen_modlist(vm);
	RSCHECK_NESTED("Failed to generate modlist");

	/* Make PMC overflows trigger NMIs */
	*(volatile uint32_t*)(current_cpu->apic + 0x340) = (4 << 8) | (1 << 17);

	create_corrupt_rtf(fuzz_input, fuzz_input_len);

	vm_timeout  = rdtsc_future(10000000);
	vmexits     = 0;
	single_step = 0;
handled_vmexit:
	/* Enable LBR for the guest */
	vmcb->lbr_virt_en = 1;
	vmcb->dbgctrl     = 1;
	
	/* Clear debug status */
	vmcb->dr6 = 0;

	vm->regs.x86_regs.rfl.u.tf = 0;

	if(single_step){
		vm->regs.x86_regs.rfl.u.tf  = 1;
		vmcb->dbgctrl              |= 2;

		single_step--;
	}

#if 1
	/* PMC based code coverage */
	wrmsr(0xc0010202, 0);
	wrmsr(0xc0010203, 0x1000000000000 - (aes_rand() % 512 + 1));
	wrmsr(0xc0010202, (1UL << 40) | (1UL << 20) | (1UL << 22) | (3UL << 16) | 0x83);
#endif

	vmcb->br_from = vmcb->br_to = 0;

	rstate = vm->step(vm);
	RSCHECK_NESTED("Failed to step VM");
	vmexits++;

	if(__rdtsc() >= vm_timeout){
		vmcb->exitcode = 0x1337;
		goto unhandled_vmexit;
	}

	if(vmcb->br_from && vmcb->br_to){
		int new;

		/* Report the code coverage information */
		rstate = fuzz_cc_report(vm, vmcb->br_from, vmcb->br_to,
				fuzz_input, fuzz_input_len, &new);
		RSCHECK_NESTED("Failed to report ode coverage information");

		if(new){
			/* Enable single stepping on new coverage */
			single_step = 2048;
			vm_timeout  = rdtsc_future(10000000);
		}
	}

	if(vmcb->exitcode == 0x60){
		/* External interrupt, ignore */
		goto handled_vmexit;
	} else if(vmcb->exitcode == 0x41){
		/* #DB */
		if(vmcb->dr6 & (1 << 14)){
			/* Eat single steps */
			goto handled_vmexit;
		}

#if 1
		if(contains(vm->regs.x86_regs.rdi.rdi, vm->regs.x86_regs.rdi.rdi + 511,
					0, fuzz_input_len)){
			vm_write_virt(vm, vm->regs.x86_regs.rax.rax,
					&fuzz_input[vm->regs.x86_regs.rdi.rdi], 512);
		}
#endif

		vm->regs.x86_regs.rfl.u.rf = 1;
		goto handled_vmexit;
	} else if(vmcb->exitcode == 0x4e){
		/* Inject a page fault, see if it's an actual crash or just a
		 * normal page fault
		 */
		memcpy(&pf_regs, &vm->regs.x86_regs, sizeof(struct _x86_regs));
		memcpy(&pf_vmcb, vmcb, sizeof(struct _vmcb));
		memcpy(pf_xsave, vm->state.svm_state->xsave, 4096);
		hit_pf = 1;

		/* Inject the page fault into the guest */
		vmcb->eventinj = (vmcb->exitinfo1 << 32UL) |
			(1UL << 31) | (1 << 11) | (3 << 8) | 0xe;
		vmcb->cr2 = vmcb->exitinfo2;

		goto handled_vmexit;
	} else if(vmcb->exitcode == 0x43){
		if(hit_pf && vm->regs.x86_regs.rip.rip & 0x8000000000000000UL){
			/* We hit our page fault breakpoint */
			memcpy(&vm->regs.x86_regs, &pf_regs, sizeof(struct _x86_regs));
			memcpy(vmcb, &pf_vmcb, sizeof(struct _vmcb));
			memcpy(vm->state.svm_state->xsave, pf_xsave, 4096);
			goto unhandled_vmexit;
		}
	} else if(vmcb->exitcode == 0x61){
		/* NMI from PMC overflow ignore */
		goto handled_vmexit;
	}

unhandled_vmexit:
	__sync_fetch_and_add(&sum_vmexits, vmexits);

	if(vmcb->exitcode >= 0x40 && vmcb->exitcode < 0x60){
		int new_crash;

		if(vm_read_virt(vm,
					vm->regs.x86_regs.cs_base + vm->regs.x86_regs.rip.rip,
					vmcb->guest_inst, 16) != RSTATE_SUCCESS){
			memset(vmcb->guest_inst, 0x90, 16);
		}

		/* Report crash */
		rstate = fuzz_report_crash(vm, fuzz_input, fuzz_input_len, &new_crash);
		RSCHECK_NESTED("Failed to report crash");

		if(new_crash){
			vm->dump_state(vm);
		}
	}

	__sync_fetch_and_add(&fuzzes, 1);

	if(is_bsp()){
		struct _hash_table *cc_db, *crash_db, *input_db;

		rstate = fuzz_get_cc_db(&cc_db);
		RSCHECK_NESTED("Failed to get cc_db");
		
		rstate = fuzz_get_crash_db(&crash_db);
		RSCHECK_NESTED("Failed to get crash_db");
		
		rstate = fuzz_get_input_db(&input_db);
		RSCHECK_NESTED("Failed to get input_db");

		printf("fuzzes %10lu | fcps %10lu | ccdb %10lu | "
				"crashes %10lu | vmepfc %10lu | inputs %10lu | "
				"mem %10lu",
				fuzzes, fuzzes * 1000000 / (rdtsc_uptime() - fuzz_start),
				cc_db->entries, crash_db->entries,
				sum_vmexits / fuzzes, input_db->entries,
				mm_mem_consumed() / 1024 / 1024);
	}

	goto fuzz_again;

	rstate_ret = RSTATE_SUCCESS;
cleanup:
	RSTATE_RETURN;
}

