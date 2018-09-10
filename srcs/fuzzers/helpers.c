#include <grilled_cheese.h>
#include <dstruc/hash_table.h>
#include <generic/stdlib.h>
#include <mm/mm.h>
#include <time/time.h>
#include <net/net.h>
#include <disp/disp.h>
#include <vm/vm.h>
#include <vm/svm.h>
#include <fuzzers/helpers.h>

rstate_t
fuzzer_create(struct _fuzzer **fuzzer_out)
{
	struct _fuzzer *fuzzer;

	RSTATE_LOCALS;

	rstate = phalloc(sizeof(struct _fuzzer), (void**)&fuzzer);
	RSCHECK_NESTED("Failed to allocate room for fuzzer");

	*fuzzer_out = fuzzer;
	rstate_ret  = RSTATE_SUCCESS;
cleanup:
	RSTATE_RETURN;
}

void
rand_ftar(
		const void  *ftar,
		uint64_t     ftar_len,
		uint8_t    **entry,
		uint64_t    *entry_len)
{
	struct _ftar {
		uint64_t num_entries;

		struct {
			uint64_t off;
			uint64_t len;
		} entry[1];
	} *level1 = (struct _ftar*)ftar;

	uint8_t *uftar = (uint8_t*)ftar;

	uint64_t rand_ent, rand_off, rand_len;

	if(ftar_len < sizeof(uint64_t)){
		panic("ftar too small, header");
	}

	if(!level1->num_entries || level1->num_entries > 1000000){
		panic("ftar invalid");
	}

	if(((level1->num_entries * 16) + 8) > ftar_len){
		panic("ftar too small, entries");
	}

	rand_ent = aes_rand() % level1->num_entries;
	rand_off = level1->entry[rand_ent].off;
	rand_len = level1->entry[rand_ent].len;

	if(!contains((uint64_t)uftar+rand_off, (uint64_t)uftar+rand_off+rand_len-1,
				(uint64_t)uftar, (uint64_t)uftar+ftar_len-1)){
		panic("ftar entry is OOB");
	}

	*entry     = uftar+rand_off;
	*entry_len = rand_len;
	return;
}

rstate_t
fuzz_get_cc_db(struct _hash_table **db)
{
	static struct _hash_table *volatile cc_db = NULL;

	RSTATE_LOCALS;

	if(!__sync_val_compare_and_swap(&cc_db, NULL, (void*)1)){
		rstate = ht_create(24, (struct _hash_table**)&cc_db);
		RSCHECK_NESTED("Failed to create cc_db hash table");
	} else {
		/* We lost the race, wait for the value to get allocated */
		while((uint64_t)cc_db <= 1);
	}

	*db = cc_db;

	rstate_ret = RSTATE_SUCCESS;
cleanup:
	RSTATE_RETURN;
}

rstate_t
fuzz_get_input_db(struct _hash_table **db)
{
	static struct _hash_table *volatile input_db = NULL;

	RSTATE_LOCALS;

	if(!__sync_val_compare_and_swap(&input_db, NULL, (void*)1)){
		rstate = ht_create(24, (struct _hash_table**)&input_db);
		RSCHECK_NESTED("Failed to create input_db hash table");
	} else {
		/* We lost the race, wait for the value to get allocated */
		while((uint64_t)input_db <= 1);
	}

	*db = input_db;

	rstate_ret = RSTATE_SUCCESS;
cleanup:
	RSTATE_RETURN;
}

rstate_t
fuzz_get_crash_db(struct _hash_table **db)
{
	static struct _hash_table *volatile crash_db = NULL;

	RSTATE_LOCALS;

	if(!__sync_val_compare_and_swap(&crash_db, NULL, (void*)1)){
		rstate = ht_create(24, (struct _hash_table**)&crash_db);
		RSCHECK_NESTED("Failed to create crash_db hash table");
	} else {
		/* We lost the race, wait for the value to get allocated */
		while((uint64_t)crash_db <= 1);
	}

	*db = crash_db;

	rstate_ret = RSTATE_SUCCESS;
cleanup:
	RSTATE_RETURN;
}

struct _input_ent*
fuzz_get_input(__m128i input_hash)
{
	struct _hash_table *input_db;

	if(fuzz_get_input_db(&input_db) != RSTATE_SUCCESS){
		return NULL;
	}

	return ht_probe(input_db, input_hash);
}

rstate_t
fuzz_input_create(const void *buf, uint64_t len, __m128i *out_hash,
		int *new_entry)
{
	void **hte;
	__m128i hash;

	struct _hash_table *input_db;

	RSTATE_LOCALS;

	rstate = fuzz_get_input_db(&input_db);
	RSCHECK_NESTED("Failed to create input in input db");

	hash = falkhash(buf, len);
	if(ht_fetch_or_lock(input_db, hash, (void**)&hte)){
		struct _input_ent *input;

		rstate = phalloc(offsetof(struct _input_ent, buf) + len,
				(void**)&input);
		RSCHECK_NESTED("Failed to allocate input backing for input_db");

		input->len = len;
		memcpy(input->buf, buf, len);
		
		*hte = input;

		if(new_entry) *new_entry = 1;
	} else {
		if(new_entry) *new_entry = 0;
	}

	*out_hash = hash;

	rstate_ret = RSTATE_SUCCESS;
cleanup:
	RSTATE_RETURN;
}

rstate_t
fuzz_cc_report(
		struct _vm *vm,
		uint64_t    from,
		uint64_t    to,
		const void *buf,
		uint64_t    len,
		int        *new_ent)
{
	void **hte;
	__m128i hash, from_hash, to_hash;

	struct _hash_table *cc_db, *input_db, *crash_db;

	struct _modlist *from_mod, *to_mod;

	RSTATE_LOCALS;

	from_mod = win32_resolve_module(vm, from);
	to_mod   = win32_resolve_module(vm, to);

#if 0
	/* Only do coverage on addresses we can resolve modules for */
	if(!from_mod || !to_mod){
		if(new_ent) *new_ent = 0;
		rstate_ret = RSTATE_SUCCESS;
		goto cleanup;
	}
#endif

	rstate = fuzz_get_cc_db(&cc_db);
	RSCHECK_NESTED("Failed to get cc db");
	rstate = fuzz_get_input_db(&input_db);
	RSCHECK_NESTED("Failed to get input db");
	rstate = fuzz_get_crash_db(&crash_db);
	RSCHECK_NESTED("Failed to get crash db");

	win32_symhash(vm, from, &from_hash);
	win32_symhash(vm, to, &to_hash);

	hash = _mm_aesenc_si128(from_hash, to_hash);
	if(ht_fetch_or_lock(cc_db, hash, (void**)&hte)){
		int input_new_entry;

		struct _cc_entry *cc_ent;

		__m128i input_hash;

		rstate = phalloc(sizeof(*cc_ent), (void**)&cc_ent);
		RSCHECK_NESTED("Failed to allocate room for cc entry");
		
		fuzz_input_create(buf, len, &input_hash, &input_new_entry);
		cc_ent->hash = input_hash;

		*hte = cc_ent;

		{
			struct _coverage_info ci;
			extern uint64_t fuzzes;

			rstate = net_start(current_cpu->net_queue);
			RSCHECK_NESTED("Failed to start networking");

			ci.magic        = NET_COVERAGE_INFO;
			ci.fuzzes       = fuzzes;
			ci.cc_count     = cc_db->entries;
			ci.uniq_crashes = crash_db->entries;
			rstate = net_send_udp(current_cpu->net_queue,
					&ci, sizeof(ci), 0, 0);
			RSCHECK_NESTED("Failed to send UDP packet");

			net_stop(current_cpu->net_queue);
		}

		if(new_ent) *new_ent = 1;
	} else {
		if(new_ent) *new_ent = 0;
	}

	rstate_ret = RSTATE_SUCCESS;
cleanup:
	RSTATE_RETURN;
}

rstate_t
fuzz_report_crash(struct _vm *vm, void *buf, size_t len, int *new_entry)
{
	__m128i hash = win32_classify_crash(vm);
	void **hte;
	int do_report = 0;
	uint64_t stack = 0;
	struct _crash_entry *crash;
	struct _hash_table *crash_db;

	RSTATE_LOCALS;

	vm_read_virt(vm, vm->regs.x86_regs.rsp.rsp, &stack, 8);

	rstate = fuzz_get_crash_db(&crash_db);
	RSCHECK_NESTED("Failed to get crash db");

	if(ht_fetch_or_lock(crash_db, hash, (void**)&hte)){
		do_report = 1;

		rstate = phalloc(sizeof(*crash), (void**)&crash);
		RSCHECK_NESTED("Failed to allocate room for crash entry");

		rstate = fuzz_input_create(buf, len, &crash->hash, NULL);
		RSCHECK_NESTED("Failed to create input for crash");

		*hte = crash;

		if(new_entry) *new_entry = 1;
	} else {
		crash = (void*)hte;
		if(new_entry) *new_entry = 0;
	}

	{
		struct _input_ent *input;

		input = fuzz_get_input(crash->hash);
		RSCHECK(input, "Failed to get crashing input");

		if(nonnullcount(input->buf, input->len) > nonnullcount(buf, len)){
			rstate = fuzz_input_create(buf, len, &crash->hash, NULL);
			RSCHECK_NESTED("Failed to create input for crash");

			do_report = 1;
		}
	}

	if(do_report){
		char fn[256], statebuf[8192];
		uint64_t bwritten;
		struct _x86_regs *r = &vm->regs.x86_regs;

		snprintf(fn, sizeof(fn), "crash_%.16lx%.16lx.rtf",
				(unsigned long)_mm_extract_epi64(hash, 1),
				(unsigned long)_mm_extract_epi64(hash, 0));
		
		rstate = net_upload(current_cpu->net_queue, fn, buf, len);
		RSCHECK_NESTED("Failed to upload crashing input");

		bwritten = snprintf(statebuf, sizeof(statebuf),
			"EC: %.16lx EI1: %.16lx EI2: %.16lx Inst bytes: %.16lx%.16lx\n"
			"nnc %.16lx\n"
			"rax %.16lx rbx %.16lx rcx %.16lx rdx %.16lx\n"
			"rsi %.16lx rdi %.16lx rbp %.16lx rsp %.16lx\n"
			"r8  %.16lx r9  %.16lx r10 %.16lx r11 %.16lx\n"
			"r12 %.16lx r13 %.16lx r14 %.16lx r15 %.16lx\n"
			"rfl %.16lx\n"
			"rsp %.16lx (%.16lx)\n"
			"rip %.4x:%.16lx (%.16lx)\n",
			vm->state.svm_state->vmcb->exitcode, vm->state.svm_state->vmcb->exitinfo1,
			vm->state.svm_state->vmcb->exitinfo2,
			byteswap(vm->state.svm_state->vmcb->guest_inst[0]),
			byteswap(vm->state.svm_state->vmcb->guest_inst[1]),
			nonnullcount(buf, len),
			r->rax.rax, r->rbx.rbx, r->rcx.rcx, r->rdx.rdx,
			r->rsi.rsi, r->rdi.rdi, r->rbp.rbp, r->rsp.rsp,
			r->r8.r8, r->r9.r9, r->r10.r10, r->r11.r11,
			r->r12.r12, r->r13.r13, r->r14.r14, r->r15.r15,
			r->rfl.rfl,
			r->rsp.rsp, stack,
			r->cs_sel, r->rip.rip, r->cs_base + r->rip.rip);

		bwritten += snprintf(statebuf, sizeof(statebuf)-bwritten,
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
		
		snprintf(fn, sizeof(fn), "crash_%.16lx%.16lx.state",
				(unsigned long)_mm_extract_epi64(hash, 1),
				(unsigned long)_mm_extract_epi64(hash, 0));

		rstate = net_upload(current_cpu->net_queue, fn, statebuf, bwritten);
		RSCHECK_NESTED("Failed to upload crashing state");
	}

	rstate_ret = RSTATE_SUCCESS;
cleanup:
	RSTATE_RETURN;
}

rstate_t
win32_gen_modlist(struct _vm *vm)
{
	uint64_t peb, ldr, blink, table_entry, num_ents = 0;

	struct _modlist *modlist;

	RSTATE_LOCALS;

	if(!vm->modlist){
		rstate = phalloc(sizeof(struct _modlist) * MAX_MODULES,
				(void**)&modlist);
		RSCHECK_NESTED("Failed to allocate room for the module list");
		vm->modlist = modlist;
	}
	modlist = vm->modlist;

	/* TEB->ProcessEnvironmentBlock */
	rstate = vm_read_virt(vm, vm->state.svm_state->vmcb->gs_base + 0x60, &peb, 8);
	RSCHECK_NESTED("Failed to read PEB from TEB");

	/* PEB->Ldr (struct _PEB_LDR_DATA) */
	rstate = vm_read_virt(vm, peb + 0x18, &ldr, 8);
	RSCHECK_NESTED("Failed to read PEB_LDR_DATA");

	/* ldr->InLoadOrderLinks.Blink (struct _LDR_DATA_TABLE_ENTRY) */
	rstate = vm_read_virt(vm, ldr + 0x18, &blink, 8);
	RSCHECK_NESTED("Failed to read LDR_DATA_TABLE_ENTRY");

	RSCHECK(blink, "Blink entry is null");

	/* ldr->InLoadOrderLinks.Flink */
	rstate = vm_read_virt(vm, ldr + 0x10, &table_entry, 8);
	RSCHECK_NESTED("Failed to read InLoadOrderLinks.Flink");

	while(table_entry){
		uint64_t name_ptr;

		RSCHECK(num_ents < MAX_MODULES,
				"Too many modules in listing, static buffer too small");

		rstate = vm_read_virt(vm, table_entry + 0x30, &modlist[num_ents].base, 8);
		RSCHECK_NESTED("Failed to read base");

		rstate = vm_read_virt(vm, table_entry + 0x40, &modlist[num_ents].len, 8);
		RSCHECK_NESTED("Failed to read len");

		modlist[num_ents].end = modlist[num_ents].base + modlist[num_ents].len;

		rstate = vm_read_virt(vm, table_entry + 0x58, &modlist[num_ents].namelen, 4);
		RSCHECK_NESTED("Failed to read namelen");

		RSCHECK(modlist[num_ents].namelen,
				"Module name size is zero");

		modlist[num_ents].namelen &= 0xffff;

		RSCHECK(modlist[num_ents].namelen < sizeof(modlist[num_ents].name),
				"Module name length too large");

		RSCHECK(!(modlist[num_ents].namelen & 1),
				"Module name length not 2-byte aligned for utf16");

		rstate = vm_read_virt(vm, table_entry + 0x60, &name_ptr, 8);
		RSCHECK_NESTED("Failed to read name_ptr");

		rstate = vm_read_virt(vm, name_ptr, modlist[num_ents].name, modlist[num_ents].namelen);
		if(rstate == RSTATE_SUCCESS){
			/* Convert the utf16 to utf8 */
			{
				unsigned int jj;

				for(jj = 0; jj < modlist[num_ents].namelen; jj += 2){
					modlist[num_ents].name[jj/2] = modlist[num_ents].name[jj];
				}
				modlist[num_ents].name[jj/2]  = 0;
				modlist[num_ents].namelen    /= 2;
			}

			modlist[num_ents].hash = falkhash(modlist[num_ents].name, modlist[num_ents].namelen);
			num_ents++;
		}

		if(table_entry == blink)
			break;

		/* table_entry->Flink */
		rstate = vm_read_virt(vm, table_entry, &table_entry, 8);
		RSCHECK_NESTED("Failed to read table_entry->Flink");
	}

	vm->modlist_ents = num_ents;

	rstate_ret = RSTATE_SUCCESS;
cleanup:
	RSTATE_RETURN;
}

struct _modlist*
win32_resolve_module(struct _vm *vm, uint64_t rip)
{
	uint64_t i;

	for(i = 0; i < vm->modlist_ents; i++){
		if(rip >= vm->modlist[i].base && rip < vm->modlist[i].end)
			return &vm->modlist[i];
	}

	return NULL;
}

int
win32_symhash(struct _vm *vm, uint64_t rip, __m128i *hash)
{
	uint64_t offset[2] = { 0 }, deadhash[2] = { 0x1337, 0x1338 };

	struct _modlist *mod;

	mod = win32_resolve_module(vm, rip);
	if(!mod){
		if(rip & 0x8000000000000000){
			_mm_storeu_si128(hash, _mm_cvtsi64_si128(rip));
		} else {
			_mm_storeu_si128(hash, _mm_loadu_si128((__m128i*)deadhash));
		}

		return 0;
	}

	offset[0] = rip - mod->base;

	_mm_storeu_si128(hash, _mm_add_epi64(mod->hash, _mm_loadu_si128((__m128i*)offset)));

	return 1;
}

__m128i
win32_classify_crash(struct _vm *vm)
{
	uint64_t class[2] = { 0 };

	__m128i ret;

	if(vm->state.svm_state->vmcb->exitcode == 0x4d){
		class[0] = 7;
	} else if(vm->state.svm_state->vmcb->exitcode == 0x4e){
		if(vm->state.svm_state->vmcb->exitinfo2 < (1024 * 1024))
			class[0] = 1;
		else if(vm->state.svm_state->vmcb->exitinfo2 > 0xFFFFFFFFFFF00000UL)
			class[0] = 2;
		else
			class[0] = 3;
	} else {
		class[0] = 32;
	}

	win32_symhash(vm, vm->state.svm_state->vmcb->rip, &ret);
	ret = _mm_cvtsi64_si128(vm->state.svm_state->vmcb->rip);
	ret = _mm_add_epi64(ret, _mm_loadu_si128((__m128i*)class));
	ret = _mm_aesenc_si128(ret, ret);
	ret = _mm_aesenc_si128(ret, ret);
	ret = _mm_aesenc_si128(ret, ret);
	ret = _mm_aesenc_si128(ret, ret);
	ret = _mm_aesenc_si128(ret, ret);

	return ret;
}

