#include <grilled_cheese.h>
#include <mm/mm.h>
#include <net/net.h>
#include <disp/disp.h>
#include <interrupts/interrupts.h>
#include <emu/mips.h>
#include <time/time.h>
#include <generic/stdlib.h>
#include <dstruc/hash_table.h>

#define FUZZ_INPUT_LEN 4096

void
syscall_entry(void);

void
dirty_func(void *c, uint64_t vaddr, uint64_t paddr)
{
	struct {
		uint64_t ram_base;
		uint8_t *ram_copy;
	} *ctxt = c;

	memcpy((void*)vaddr, ctxt->ram_copy + (vaddr - ctxt->ram_base), 4096);

	return;
}

uint8_t *ram_image;
uint64_t ram_image_size;

uint8_t *regs_image;
uint64_t regs_image_size;

void **pc_to_jit;

uintptr_t  jit_image;
uint8_t   *jit_map;
uint64_t   jit_image_size, jit_map_key;

struct _hash_table *cc_db = NULL;
struct _hash_table *crash_db = NULL;
			
static uint64_t crashes = 0;

rstate_t
emu_mips_create(void)
{
	void *ram;
	struct _emu_mips *emu;
	static volatile int ready_for_aps = 0;

	void     *jit_coverage_map;
	uint64_t  jit_coverage_key = 0;

	RSTATE_LOCALS;

	if(is_bsp()){
		uintptr_t pc_to_jit_phys;
		uint64_t  pc_to_jit_key;

		rstate = ht_create(24, &cc_db);
		RSCHECK_NESTED("Failed to create cc_db hash table");
		
		rstate = ht_create(24, &crash_db);
		RSCHECK_NESTED("Failed to create crash_db hash table");

		/* Download the MIPS ram image */
		rstate = net_map_remote(current_cpu->net_queue,
				"mipsram", 1024 * 1024, (void**)&ram_image, &ram_image_size);
		RSCHECK_NESTED("Failed to download MIPS RAM image");
		RSCHECK(!(ram_image_size & 0xfff),
				"RAM base or RAM size not page aligned");

		/* Download the MIPS regs image */
		rstate = net_map_remote(current_cpu->net_queue,
				"mipsreg", 4096, (void**)&regs_image, &regs_image_size);
		RSCHECK_NESTED("Failed to download MIPS reg image");
		RSCHECK(regs_image_size == (37*4), "MIPS reg file incorrect size");

		jit_image_size = ram_image_size * 32;

		rstate = phalloc(ram_image_size * sizeof(void*), (void**)&pc_to_jit);
		RSCHECK_NESTED("Failed to allocate room for PC to JIT buffer");

		/* Allocate room for the PC to it translation table */
		rstate = alloc_phys(ram_image_size * sizeof(void*),
				&pc_to_jit_phys);
		RSCHECK_NESTED("Failed to allocate pc to JIT");

		/* Reserve room for the pc to JIT buffer */
		rstate = mm_reserve_random(readcr3(),
				ram_image_size * sizeof(void*),
				(void*)&pc_to_jit, 0, &pc_to_jit_key);
		RSCHECK_NESTED("Failed to reserve pc to JIT address space");

		/* Map in the pc to JIT buffer */
		rstate = mm_map_contig(readcr3(),
				(uintptr_t)pc_to_jit,
				pc_to_jit_phys | 7,
				ram_image_size * sizeof(void*), pc_to_jit_key);
		RSCHECK_NESTED("Failed to map in pc to JIT space");

		memset(pc_to_jit, 0, ram_image_size * sizeof(void*));

		/* Allocate a JIT buffer for the RAM image with MIPS_JIT_SIZE bytes per
		 * instruction.
		 */
		rstate = alloc_phys(jit_image_size, &jit_image);
		RSCHECK_NESTED("Failed to create JIT space");

		/* Reserve room for the JIT buffer */
		rstate = mm_reserve_random(readcr3(), jit_image_size,
				(void**)&jit_map, 0, &jit_map_key);
		RSCHECK_NESTED("Failed to reserve JIT address space");

		/* Map in the JIT buffer */
		rstate = mm_map_contig(readcr3(),
				(uintptr_t)jit_map,
				(uintptr_t)jit_image | 7,
				(jit_image_size + 0xfff) & ~0xfff, jit_map_key);
		RSCHECK_NESTED("Failed to map in JIT space");

		memset(jit_map, 0xcc, jit_image_size);

		printf("JIT starts at: %p\nImage starts at: %p\npc_to_jit at: %p",
				(void*)jit_map, (void*)ram_image, (void*)pc_to_jit);

		/* Translate from MIPS to x86 */
		rstate = emu_mips_translate(ram_image, ram_image_size, jit_map);
		RSCHECK_NESTED("Failed to translate MIPS instructions");

		ready_for_aps = 1;
	} else {
		while(!ready_for_aps) _mm_pause();
	}

	/* Allocate room for the MIPS emulator state */
	rstate = phalloc(sizeof(struct _emu_mips), (void**)&emu);
	RSCHECK_NESTED("Failed to allocate room for MIPS emulator");

	{
		uint64_t key;

		rstate = mm_reserve_random(readcr3(), 4UL * 1024 * 1024 * 1024,
				(void**)&emu->address_space, 0, &key);
		RSCHECK_NESTED("Failed to reserve backing memory");
	
		/* Create a copy of the ram image */
		rstate = mm_create_cow(ram_image, ram_image_size,
				emu->address_space + 0x80000000, key, &ram);
		RSCHECK_NESTED("Failed to create COW of ram image");
	}

	{
		uintptr_t phys;

		rstate = alloc_phys(10000000*8, &phys);
		RSCHECK_NESTED("Failed to allocate physical memory for coverage");

		/* Reserve room for the JIT buffer */
		rstate = mm_reserve_random(readcr3(), 10000000*8,
				(void**)&jit_coverage_map, 0, &jit_coverage_key);
		RSCHECK_NESTED("Failed to reserve JIT address space");

		/* Map in the JIT buffer */
		rstate = mm_map_contig(readcr3(),
				(uintptr_t)jit_coverage_map,
				(uintptr_t)phys | 7,
				10000000*8, jit_coverage_key);
		RSCHECK_NESTED("Failed to map in JIT space");
	}

	/* Create a copy of the regs image */
	rstate = mm_create_cow(regs_image, regs_image_size, NULL, 0,
			(void**)&emu->regs);
	RSCHECK_NESTED("Failed to create COW of regs image");

	for( ; ; ){
		int had_yield = 0;

		struct _iret iret;

		uint64_t start_ticks, timeout;

		struct _fuzz_input {
			uint64_t  no_yields;
			int       replace;
			uint8_t  *cc_location;
			char      input[FUZZ_INPUT_LEN];
		};

		static uint64_t start = 0, next = 0, runs = 0, irs = 0, icms = 0, ticks = 0;

		char fuzz_input[FUZZ_INPUT_LEN] = { 0 };

		if(is_bsp() && !start){
			start = rdtsc_uptime();
			next  = rdtsc_future(1000000);
		}

		/* Set up the PC */
		emu->regs[MIPS_REG_PC] = 0x80000000;
		current_cpu->um_exception.iret.rip    = (uintptr_t)MIPS_PC_TO_JIT(emu->regs[MIPS_REG_PC]);
		current_cpu->um_exception.iret.rflags = (1 << 9);

		/* XXX: Mutate fuzz_input and inject here */

		start_ticks = __rdtsc();
		timeout     = rdtsc_future(1000000);

		emu->r10 = 0; /* PC */
		emu->r11 = 0; /* Instructions execed */
		emu->r12 = (uint64_t)jit_coverage_map;
		emu->rbp = (uint64_t)emu->regs;
		emu->r9  = (uint64_t)pc_to_jit;

		for( ; ; ){
			iret.rip    = current_cpu->um_exception.iret.rip;
			iret.cs     = 0x40 | 3;
			iret.rflags = current_cpu->um_exception.iret.rflags;
			iret.rsp    = (uintptr_t)emu->address_space;
			iret.ss     = 0x38 | 3;

			enter_um_guest(&iret, &current_cpu->um_exception_handler, &emu->rax);
			emu->regs[MIPS_REG_PC]         = (uint32_t)emu->r10;
			emu->regs[MIPS_REG_COP0_COUNT] = (uint32_t)emu->r11;

			if(current_cpu->um_exception.vector == 6){
				/*printf("Undefined %.8x", emu->regs[MIPS_REG_PC]);*/
				break;
			} else if(current_cpu->um_exception.vector == 1){
				break;
			} else if(current_cpu->um_exception.vector == 69){
				if(__rdtsc() >= timeout){
					break;
				}

				continue;
			} else if(current_cpu->um_exception.vector == 3){
				{
					int fetch_res;
					void **ent;
					__m128i hash;

					hash = _mm_aesenc_si128(
							_mm_cvtsi64_si128(emu->regs[MIPS_REG_PC]),
							_mm_cvtsi64_si128(emu->regs[MIPS_REG_PC]));
					fetch_res = ht_fetch_or_lock(cc_db, hash, (void**)&ent);

					if(fetch_res){
						struct _fuzz_input *entry;

						rstate = phalloc(sizeof(*entry), (void**)&entry);
						RSCHECK_NESTED("Failed to allocate room for cc entry");

						memcpy(entry->input, fuzz_input, FUZZ_INPUT_LEN);

						entry->cc_location = (uint8_t*)(current_cpu->um_exception.iret.rip - 1);

						{
#pragma pack(push, 1)
							struct {
								uint64_t magic;
								uint64_t req_id;
								uint64_t fuzz_cases;
								uint64_t cc_count;
							} fuzz_status = { 0 };
#pragma pack(pop)
							rstate = net_start(current_cpu->net_queue);
							RSCHECK_NESTED("Failed to start networking");

							fuzz_status.magic      = NET_REPORT_COVERAGE_STATUS;
							fuzz_status.fuzz_cases = runs;
							fuzz_status.cc_count   = cc_db->entries;
							rstate = net_send_udp(current_cpu->net_queue,
									&fuzz_status, sizeof(fuzz_status), 0, 0);
							RSCHECK_NESTED("Failed to send fuzz status");

							net_stop(current_cpu->net_queue);
						}
						
						*ent = (void*)entry;

						had_yield = 1;
					}
					
					*(uint8_t*)(current_cpu->um_exception.iret.rip - 1) = 0x90;
				}

				continue;
			} else {
				crashes++;

				{
					void **ent;
					__m128i hash;

					hash = _mm_aesenc_si128(
							_mm_cvtsi64_si128(emu->regs[MIPS_REG_PC]),
							_mm_cvtsi64_si128(emu->regs[MIPS_REG_PC]));
					if(ht_fetch_or_lock(crash_db, hash, (void**)&ent)){
						*ent = (void*)10;

						printf(
								"Exception:          %lu\n"
								"Faulting MIPS addr: %.16lx",
								current_cpu->um_exception.vector,
								current_cpu->um_exception.cr2 - (uintptr_t)emu->address_space);
						emu_mips_print(emu->regs);
					}
				}

				break;
			}
		}

#if 1
		{
			uint64_t ii, *pcs = (uint64_t*)emu->r12;

			for(ii = 0; emu->r11 >= 2 && ii < emu->r11-1; ii++){
				void **ent;
				__m128i hash;

				hash = falkhash(&pcs[ii], 2 * 8);
				if(ht_fetch_or_lock(cc_db, hash, (void**)&ent)){
					struct _fuzz_input *entry;

					rstate = phalloc(sizeof(*entry), (void**)&entry);
					RSCHECK_NESTED("Failed to allocate room for cc entry");

					memcpy(entry->input, fuzz_input, FUZZ_INPUT_LEN);

					*ent = entry;
				}
			}
		}
#endif

		{
			struct {
				uint64_t ram_base;
				void *ram_copy;
			} ctxt;

			ctxt.ram_base = (uintptr_t)emu->address_space + 0x80000000;
			ctxt.ram_copy = ram_image;

			mm_for_each_dirty_page(readcr3(),
					(uintptr_t)emu->address_space + 0x80000000,
					(uintptr_t)emu->address_space + 0x80000000 + ram_image_size,
					dirty_func, &ctxt);

			memcpy(emu->regs, regs_image, regs_image_size);
		}

		__sync_fetch_and_add(&irs,  rdpmc(0));
		__sync_fetch_and_add(&icms, rdpmc(1));
		__sync_fetch_and_add(&ticks, __rdtsc() - start_ticks);
		__sync_fetch_and_add(&runs, 1);

		if(is_bsp() && __rdtsc() > next){
			/* runs  = number of fuzz runs done
			 * fcps  = number of fuzz cases per second
			 * irpr  = instructions retired per run
			 * icmpr = instruction cache misses per run
			 */
			printf("%10lu runs | %7lu fcps | %10lu crash | %10lu uniq | %.4lu icmpr | %6lu cc",
					runs, runs * 1000000 / (rdtsc_uptime() - start),
					crashes, crash_db->entries, icms * 1000 / ticks, cc_db->entries);

			next = rdtsc_future(1000000);
		}
	}

	rstate_ret = RSTATE_SUCCESS;
cleanup:
	RSTATE_RETURN;
}

rstate_t
emu_mips_translate(
		const uint8_t *instructions,
		uint64_t       length,
		uint8_t       *jitbuf)
{
	int in_delay = 0;
	union _emu_mips_inst delay_inst = { 0 };

	uint64_t cur_inst;

	uint64_t num_instructions = 0, jit_size = 0;

	struct _emu_mips_reloc *relocs;
	uint64_t num_relocs = 0;
	const uint64_t max_relocs = 1024 * 1024;

	RSTATE_LOCALS;

	rstate = phalloc(max_relocs * sizeof(struct _emu_mips_reloc),
			(void**)&relocs);
	RSCHECK_NESTED("Failed to allocation relocation buffer");

	/* 4-byte align length by rounding down */
	length &= ~0x3;
	
	RSCHECK(length, "No MIPS code to translate");

	for(cur_inst = 0; cur_inst < length; ){
		uint32_t pc;
		uint8_t *orig_jitbuf;
		union _emu_mips_inst inst;

		orig_jitbuf = jitbuf;
		pc = 0x80000000 + (uint32_t)cur_inst;

		if(in_delay != 2){
			inst.backing = htonl(*(uint32_t*)(instructions + cur_inst));

			pc_to_jit[pc - 0x80000000] = jitbuf;

			JIT_MOV_R10_IMM32(pc);

			*(uint16_t*)jitbuf = 0x310f;
			jitbuf += 2;
			*(uint16_t*)jitbuf = 0x050f;
			jitbuf += 2;

			/**(uint8_t*)jitbuf++ = 0xcc;*/

			if(!in_delay){
				cur_inst += 4;
			} else {
				in_delay++;
			}
		} else {
			JIT_STORE_PC_R12_QWORD();
			JIT_UPDATE_COUNT(10000000);

			inst.backing = delay_inst.backing;
			cur_inst += 4;
		}

		if(inst.i.opcode == 9){
			/* ADDIU rt, rs, immediate */
			
			if(!inst.i.rt){
				goto not_decoded;
			}

			JIT_READ_REG_INTO_EAX(inst.i.rs);
			JIT_ADD_EAX_IMM32((int32_t)(int16_t)inst.i.imm);
			JIT_WRITE_REG_FROM_EAX(inst.i.rt);
		} else if(inst.i.opcode == 8){
			/* ADDI rt, rs, immediate */
			
			if(!inst.i.rt){
				goto not_decoded;
			}

			/* TODO: Should inject exception on overflow */

			JIT_READ_REG_INTO_EAX(inst.i.rs);
			JIT_ADD_EAX_IMM32((int32_t)(int16_t)inst.i.imm);
			JIT_WRITE_REG_FROM_EAX(inst.i.rt);
		} else if(inst.i.opcode == 0x2B){
			/* SW rt, offset(base) */

			JIT_READ_REG_INTO_EAX(inst.i.rs);
			JIT_ADD_EAX_IMM32((int32_t)(int16_t)inst.i.imm);
			JIT_READ_REG_INTO_EBX(inst.i.rt);
			JIT_WRITE_MEM();
		} else if(inst.i.opcode == 0x28){
			/* SB rt, offset(base) */

			JIT_READ_REG_INTO_EAX(inst.i.rs);
			JIT_ADD_EAX_IMM32((int32_t)(int16_t)inst.i.imm);
			JIT_READ_REG_INTO_EBX(inst.i.rt);
			JIT_WRITE_MEM_BYTE();
		} else if(inst.i.opcode == 0x29){
			/* SH rt, offset(base) */

			JIT_READ_REG_INTO_EAX(inst.i.rs);
			JIT_ADD_EAX_IMM32((int32_t)(int16_t)inst.i.imm);
			JIT_READ_REG_INTO_EBX(inst.i.rt);
			JIT_WRITE_MEM_WORD();
		} else if(inst.i.opcode == 0x22){
			/* LWL rt, offset(base) */

			if(!inst.i.rt){
				goto not_decoded;
			}

			JIT_READ_REG_INTO_EAX(inst.i.rs);
			JIT_ADD_EAX_IMM32((int32_t)(int16_t)inst.i.imm);
			JIT_READ_MEM_WORD_ZX();
			JIT_READ_REG_INTO_EAX(inst.i.rt);
			JIT_AND_EAX_IMM32(0x0000ffff);
			JIT_XCHG_EAX_EBX();
			JIT_SHL_EAX(16);
			JIT_OR_EAX_EBX();
			JIT_WRITE_REG_FROM_EAX(inst.i.rt);
		} else if(inst.i.opcode == 0x26){
			/* LWR rt, offset(base) */

			if(!inst.i.rt){
				goto not_decoded;
			}

			JIT_READ_REG_INTO_EAX(inst.i.rs);
			JIT_ADD_EAX_IMM32((int32_t)(int16_t)inst.i.imm - 1);
			JIT_READ_MEM_WORD_ZX();
			JIT_READ_REG_INTO_EAX(inst.i.rt);
			JIT_AND_EAX_IMM32(0xffff0000);
			JIT_OR_EAX_EBX();
			JIT_WRITE_REG_FROM_EAX(inst.i.rt);
		} else if(inst.i.opcode == 0x2a){
			/* SWL rt, offset(base) */

			JIT_READ_REG_INTO_EAX(inst.i.rt);
			JIT_SHR_EAX(16);
			JIT_XCHG_EAX_EBX();
			JIT_READ_REG_INTO_EAX(inst.i.rs);
			JIT_ADD_EAX_IMM32((int32_t)(int16_t)inst.i.imm);
			JIT_WRITE_MEM_WORD();
		} else if(inst.i.opcode == 0x2e){
			/* SWR rt, offset(base) */

			JIT_READ_REG_INTO_EAX(inst.i.rt);
			JIT_AND_EAX_IMM32(0xffff);
			JIT_XCHG_EAX_EBX();
			JIT_READ_REG_INTO_EAX(inst.i.rs);
			JIT_ADD_EAX_IMM32((int32_t)(int16_t)inst.i.imm - 1);
			JIT_WRITE_MEM_WORD();
		} else if(inst.i.opcode == 0x23){
			/* LW rt, offset(base) */

			if(!inst.i.rt){
				goto not_decoded;
			}

			JIT_READ_REG_INTO_EAX(inst.i.rs);
			JIT_ADD_EAX_IMM32((int32_t)(int16_t)inst.i.imm);
			JIT_READ_MEM();
			JIT_WRITE_REG_FROM_EBX(inst.i.rt);
		} else if(inst.i.opcode == 0x20){
			/* LB rt, offset(base) */

			if(!inst.i.rt){
				goto not_decoded;
			}

			JIT_READ_REG_INTO_EAX(inst.i.rs);
			JIT_ADD_EAX_IMM32((int32_t)(int16_t)inst.i.imm);
			JIT_READ_MEM_BYTE_SX();
			JIT_WRITE_REG_FROM_EBX(inst.i.rt);
		} else if(inst.i.opcode == 0x24){
			/* LBU rt, offset(base) */

			if(!inst.i.rt){
				goto not_decoded;
			}

			JIT_READ_REG_INTO_EAX(inst.i.rs);
			JIT_ADD_EAX_IMM32((int32_t)(int16_t)inst.i.imm);
			JIT_READ_MEM_BYTE_ZX();
			JIT_WRITE_REG_FROM_EBX(inst.i.rt);
		} else if(inst.i.opcode == 0x21){
			/* LH rt, offset(base) */

			if(!inst.i.rt){
				goto not_decoded;
			}

			JIT_READ_REG_INTO_EAX(inst.i.rs);
			JIT_ADD_EAX_IMM32((int32_t)(int16_t)inst.i.imm);
			JIT_READ_MEM_WORD_SX();
			JIT_WRITE_REG_FROM_EBX(inst.i.rt);
		} else if(inst.i.opcode == 0x25){
			/* LHU rt, offset(base) */

			if(!inst.i.rt){
				goto not_decoded;
			}

			JIT_READ_REG_INTO_EAX(inst.i.rs);
			JIT_ADD_EAX_IMM32((int32_t)(int16_t)inst.i.imm);
			JIT_READ_MEM_WORD_ZX();
			JIT_WRITE_REG_FROM_EBX(inst.i.rt);
		} else if(inst.r.opcode == 0 && inst.r.shamt == 0 && inst.r.func == 0x21){
			/* ADDU rd, rs, rt */

			if(!inst.r.rd){
				goto not_decoded;
			}

			JIT_READ_REG_INTO_EAX(inst.r.rs);
			JIT_READ_REG_INTO_EBX(inst.r.rt);
			JIT_ADD_EAX_EBX();
			JIT_WRITE_REG_FROM_EAX(inst.r.rd);
		} else if(inst.r.opcode == 0 && inst.r.shamt == 0 && inst.r.func == 0x24){
			/* AND rd, rs, rt */

			if(!inst.r.rd){
				goto not_decoded;
			}

			JIT_READ_REG_INTO_EAX(inst.r.rs);
			JIT_READ_REG_INTO_EBX(inst.r.rt);
			JIT_AND_EAX_EBX();
			JIT_WRITE_REG_FROM_EAX(inst.r.rd);
		} else if(inst.r.opcode == 0 && inst.r.shamt == 0 && inst.r.func == 0x25){
			/* OR rd, rs, rt */

			if(!inst.r.rd){
				goto not_decoded;
			}

			JIT_READ_REG_INTO_EAX(inst.r.rs);
			JIT_READ_REG_INTO_EBX(inst.r.rt);
			JIT_OR_EAX_EBX();
			JIT_WRITE_REG_FROM_EAX(inst.r.rd);
		} else if(inst.r.opcode == 0 && inst.r.shamt == 0 && inst.r.func == 0x26){
			/* XOR rd, rs, rt */

			if(!inst.r.rd){
				goto not_decoded;
			}

			JIT_READ_REG_INTO_EAX(inst.r.rs);
			JIT_READ_REG_INTO_EBX(inst.r.rt);
			JIT_XOR_EAX_EBX();
			JIT_WRITE_REG_FROM_EAX(inst.r.rd);
		} else if(inst.r.opcode == 0 && inst.r.shamt == 0 && inst.r.func == 0x27){
			/* NOR rd, rs, rt */

			if(!inst.r.rd){
				goto not_decoded;
			}

			JIT_READ_REG_INTO_EAX(inst.r.rs);
			JIT_READ_REG_INTO_EBX(inst.r.rt);
			JIT_OR_EAX_EBX();
			JIT_NOT_EAX();
			JIT_WRITE_REG_FROM_EAX(inst.r.rd);
		} else if(inst.i.opcode == 0xC){
			/* ANDI rt, rs, imm */

			if(!inst.i.rt){
				goto not_decoded;
			}

			JIT_READ_REG_INTO_EAX(inst.i.rs);
			JIT_AND_EAX_IMM32((uint32_t)inst.i.imm);
			JIT_WRITE_REG_FROM_EAX(inst.i.rt);
		} else if(inst.i.opcode == 0xe){
			/* XORI rt, rs, imm */

			if(!inst.i.rt){
				goto not_decoded;
			}

			JIT_READ_REG_INTO_EAX(inst.i.rs);
			JIT_XOR_EAX_IMM32((int32_t)(int16_t)inst.i.imm);
			JIT_WRITE_REG_FROM_EAX(inst.i.rt);
		} else if(inst.i.opcode == 0x1 && inst.i.rt == 1){
			/* BGEZ rs, offset */

			if(in_delay){
				uint64_t offset;

				/* Calculate mips offset of the branch, in bytes */
				offset   = (int32_t)(int16_t)inst.i.imm;
				offset <<= 2;

				JIT_CMP_ESI_IMM32(0);
				JIT_JGE();
				RSCHECK(num_relocs < max_relocs, "Out of relocation slots");
				relocs[num_relocs].mips_src  = pc;
				relocs[num_relocs].mips_dest = (uint32_t)(pc + offset);
				relocs[num_relocs].jit_broff = jitbuf - 4;
				num_relocs++;
				JIT_JMP();
				RSCHECK(num_relocs < max_relocs, "Out of relocation slots");
				relocs[num_relocs].mips_src  = pc;
				relocs[num_relocs].mips_dest = pc + 4;
				relocs[num_relocs].jit_broff = jitbuf - 4;
				num_relocs++;
				in_delay = 0;
			} else {
				JIT_READ_REG_INTO_ESI(inst.i.rs);
				delay_inst.backing = inst.backing;
				in_delay = 1;
			}
		} else if(inst.i.opcode == 0x6 && inst.i.rt == 0){
			/* BLEZ rs, offset */

			if(in_delay){
				uint64_t offset;

				/* Calculate mips offset of the branch, in bytes */
				offset   = (int32_t)(int16_t)inst.i.imm;
				offset <<= 2;

				JIT_CMP_ESI_IMM32(0);
				JIT_JLE();
				RSCHECK(num_relocs < max_relocs, "Out of relocation slots");
				relocs[num_relocs].mips_src  = pc;
				relocs[num_relocs].mips_dest = (uint32_t)(pc + offset);
				relocs[num_relocs].jit_broff = jitbuf - 4;
				num_relocs++;
				JIT_JMP();
				RSCHECK(num_relocs < max_relocs, "Out of relocation slots");
				relocs[num_relocs].mips_src  = pc;
				relocs[num_relocs].mips_dest = pc + 4;
				relocs[num_relocs].jit_broff = jitbuf - 4;
				num_relocs++;
				in_delay = 0;
			} else {
				JIT_READ_REG_INTO_ESI(inst.i.rs);
				delay_inst.backing = inst.backing;
				in_delay = 1;
			}
		} else if(inst.i.opcode == 0x1 && inst.i.rt == 0){
			/* BLTZ rs, offset */

			if(in_delay){
				uint64_t offset;

				/* Calculate mips offset of the branch, in bytes */
				offset   = (int32_t)(int16_t)inst.i.imm;
				offset <<= 2;

				JIT_CMP_ESI_IMM32(0);
				JIT_JL();
				RSCHECK(num_relocs < max_relocs, "Out of relocation slots");
				relocs[num_relocs].mips_src  = pc;
				relocs[num_relocs].mips_dest = (uint32_t)(pc + offset);
				relocs[num_relocs].jit_broff = jitbuf - 4;
				num_relocs++;
				JIT_JMP();
				RSCHECK(num_relocs < max_relocs, "Out of relocation slots");
				relocs[num_relocs].mips_src  = pc;
				relocs[num_relocs].mips_dest = pc + 4;
				relocs[num_relocs].jit_broff = jitbuf - 4;
				num_relocs++;
				in_delay = 0;
			} else {
				JIT_READ_REG_INTO_ESI(inst.i.rs);
				delay_inst.backing = inst.backing;
				in_delay = 1;
			}
		} else if(inst.i.opcode == 0x7 && inst.i.rt == 0){
			/* BGTZ rs, offset */

			if(in_delay){
				uint64_t offset;

				/* Calculate mips offset of the branch, in bytes */
				offset   = (int32_t)(int16_t)inst.i.imm;
				offset <<= 2;

				JIT_CMP_ESI_IMM32(0);
				JIT_JG();
				RSCHECK(num_relocs < max_relocs, "Out of relocation slots");
				relocs[num_relocs].mips_src  = pc;
				relocs[num_relocs].mips_dest = (uint32_t)(pc + offset);
				relocs[num_relocs].jit_broff = jitbuf - 4;
				num_relocs++;
				JIT_JMP();
				RSCHECK(num_relocs < max_relocs, "Out of relocation slots");
				relocs[num_relocs].mips_src  = pc;
				relocs[num_relocs].mips_dest = pc + 4;
				relocs[num_relocs].jit_broff = jitbuf - 4;
				num_relocs++;
				in_delay = 0;
			} else {
				JIT_READ_REG_INTO_ESI(inst.i.rs);
				delay_inst.backing = inst.backing;
				in_delay = 1;
			}
		} else if(inst.r.opcode == 0 && inst.r.rs == 0 && inst.r.func == 0){
			/* SLL rd, rt, sa */

			/* Allow a SLL zero, zero, sa, as it's a nop */
			if(!inst.r.rd && inst.r.rt){
				goto not_decoded;
			}

			JIT_READ_REG_INTO_EAX(inst.r.rt);
			JIT_SHL_EAX(inst.r.shamt);
			JIT_WRITE_REG_FROM_EAX(inst.r.rd);
		} else if(inst.r.opcode == 0 && inst.r.rs == 0 && inst.r.func == 3){
			/* SRA rd, rt, sa */

			if(!inst.r.rd){
				goto not_decoded;
			}

			JIT_READ_REG_INTO_EAX(inst.r.rt);
			JIT_SAR_EAX(inst.r.shamt);
			JIT_WRITE_REG_FROM_EAX(inst.r.rd);
		} else if(inst.r.opcode == 0 && inst.r.rs == 0 && inst.r.func == 2){
			/* SRL rd, rt, sa */

			if(!inst.r.rd){
				goto not_decoded;
			}

			JIT_READ_REG_INTO_EAX(inst.r.rt);
			JIT_SHR_EAX(inst.r.shamt);
			JIT_WRITE_REG_FROM_EAX(inst.r.rd);
		} else if(inst.r.opcode == 0 && inst.r.shamt == 0 && inst.r.func == 7){
			/* SRAV rd, rt, rs */

			if(!inst.r.rd){
				goto not_decoded;
			}

			JIT_READ_REG_INTO_EAX(inst.r.rt);
			JIT_READ_REG_INTO_ECX(inst.r.rs);
			JIT_SAR_EAX_CL();
			JIT_WRITE_REG_FROM_EAX(inst.r.rd);
		} else if(inst.r.opcode == 0 && inst.r.shamt == 0 && inst.r.func == 6){
			/* SRLV rd, rt, rs */

			if(!inst.r.rd){
				goto not_decoded;
			}

			JIT_READ_REG_INTO_EAX(inst.r.rt);
			JIT_READ_REG_INTO_ECX(inst.r.rs);
			JIT_SHR_EAX_CL();
			JIT_WRITE_REG_FROM_EAX(inst.r.rd);
		} else if(inst.r.opcode == 0 && inst.r.shamt == 0 && inst.r.func == 4){
			/* SLLV rd, rt, rs */

			if(!inst.r.rd){
				goto not_decoded;
			}

			JIT_READ_REG_INTO_EAX(inst.r.rt);
			JIT_READ_REG_INTO_ECX(inst.r.rs);
			JIT_SHL_EAX_CL();
			JIT_WRITE_REG_FROM_EAX(inst.r.rd);
		} else if(inst.r.opcode == 0 && inst.r.shamt == 0 && inst.r.func == 0x23){
			/* SUBU rd, rs, rt */
			
			if(!inst.r.rd){
				goto not_decoded;
			}

			JIT_READ_REG_INTO_EAX(inst.r.rs);
			JIT_READ_REG_INTO_EBX(inst.r.rt);
			JIT_SUB_EAX_EBX();
			JIT_WRITE_REG_FROM_EAX(inst.r.rd);
		} else if(inst.i.opcode == 0xB){
			/* SLTIU rt, rs, immediate */
			
			if(!inst.i.rt){
				goto not_decoded;
			}

			JIT_READ_REG_INTO_EAX(inst.i.rs);
			JIT_CMP_EAX_IMM32((int32_t)(int16_t)inst.i.imm);
			JIT_MOV_EAX_IMM32(0);
			JIT_SETB_AL();
			JIT_WRITE_REG_FROM_EAX(inst.i.rt);
		} else if(inst.i.opcode == 0xA){
			/* SLTI rt, rs, immediate */
			
			if(!inst.i.rt){
				goto not_decoded;
			}

			JIT_READ_REG_INTO_EAX(inst.i.rs);
			JIT_CMP_EAX_IMM32((int32_t)(int16_t)inst.i.imm);
			JIT_MOV_EAX_IMM32(0);
			JIT_SETL_AL();
			JIT_WRITE_REG_FROM_EAX(inst.i.rt);
		} else if(inst.r.opcode == 0 && inst.r.shamt == 0 && inst.r.func == 0x2a){
			/* SLT rd, rs, rt */

			if(!inst.r.rd){
				goto not_decoded;
			}

			JIT_READ_REG_INTO_EAX(inst.r.rs);
			JIT_READ_REG_INTO_EBX(inst.r.rt);
			JIT_CMP_EAX_EBX();
			JIT_MOV_EAX_IMM32(0);
			JIT_SETL_AL();
			JIT_WRITE_REG_FROM_EAX(inst.r.rd);
		} else if(inst.r.opcode == 0 && inst.r.shamt == 0 && inst.r.func == 0x2b){
			/* SLTU rd, rs, rt */

			if(!inst.r.rd){
				goto not_decoded;
			}

			JIT_READ_REG_INTO_EAX(inst.r.rs);
			JIT_READ_REG_INTO_EBX(inst.r.rt);
			JIT_CMP_EAX_EBX();
			JIT_MOV_EAX_IMM32(0);
			JIT_SETB_AL();
			JIT_WRITE_REG_FROM_EAX(inst.r.rd);
		} else if(inst.i.opcode == 0x4){
			/* BEQ rs, rt, offset */

			if(in_delay){
				uint64_t offset;

				/* Calculate mips offset of the branch, in bytes */
				offset   = (int32_t)(int16_t)inst.i.imm;
				offset <<= 2;

				JIT_CMP_ESI_EDI();
				JIT_JZ();
				RSCHECK(num_relocs < max_relocs, "Out of relocation slots");
				relocs[num_relocs].mips_src  = pc;
				relocs[num_relocs].mips_dest = (uint32_t)(pc + offset);
				relocs[num_relocs].jit_broff = jitbuf - 4;
				num_relocs++;
				JIT_JMP();
				RSCHECK(num_relocs < max_relocs, "Out of relocation slots");
				relocs[num_relocs].mips_src  = pc;
				relocs[num_relocs].mips_dest = pc + 4;
				relocs[num_relocs].jit_broff = jitbuf - 4;
				num_relocs++;
				in_delay = 0;
			} else {
				JIT_READ_REG_INTO_ESI(inst.i.rs);
				JIT_READ_REG_INTO_EDI(inst.i.rt);
				delay_inst.backing = inst.backing;
				in_delay = 1;
			}
		} else if(inst.i.opcode == 0x5){
			/* BNE rs, rt, offset */

			if(in_delay){
				uint64_t offset;

				/* Calculate mips offset of the branch, in bytes */
				offset   = (int32_t)(int16_t)inst.i.imm;
				offset <<= 2;

				JIT_CMP_ESI_EDI();
				JIT_JNZ();
				RSCHECK(num_relocs < max_relocs, "Out of relocation slots");
				relocs[num_relocs].mips_src  = pc;
				relocs[num_relocs].mips_dest = (uint32_t)(pc + offset);
				relocs[num_relocs].jit_broff = jitbuf - 4;
				num_relocs++;
				JIT_JMP();
				RSCHECK(num_relocs < max_relocs, "Out of relocation slots");
				relocs[num_relocs].mips_src  = pc;
				relocs[num_relocs].mips_dest = pc + 4;
				relocs[num_relocs].jit_broff = jitbuf - 4;
				num_relocs++;
				in_delay = 0;
			} else {
				JIT_READ_REG_INTO_ESI(inst.i.rs);
				JIT_READ_REG_INTO_EDI(inst.i.rt);
				delay_inst.backing = inst.backing;
				in_delay = 1;
			}
		} else if(inst.j.opcode == 0x3){
			/* JAL target */

			if(in_delay){
				uintptr_t target;

				target  = pc;
				target &= 0xF0000000;
				target |= ((uintptr_t)inst.j.addr << 2);

				JIT_JMP();
				RSCHECK(num_relocs < max_relocs, "Out of relocation slots");
				relocs[num_relocs].mips_src  = pc;
				relocs[num_relocs].mips_dest = (uint32_t)target;
				relocs[num_relocs].jit_broff = jitbuf - 4;
				num_relocs++;
				in_delay = 0;
			} else {
				JIT_MOV_EAX_IMM32(pc + 8);
				JIT_WRITE_REG_FROM_EAX(MIPS_REG_RA);
				delay_inst.backing = inst.backing;
				in_delay = 1;
			}
		} else if(inst.j.opcode == 0x2){
			/* J target */

			if(in_delay){
				uintptr_t target;

				target  = pc;
				target &= 0xF0000000;
				target |= ((uintptr_t)inst.j.addr << 2);

				JIT_JMP();
				RSCHECK(num_relocs < max_relocs, "Out of relocation slots");
				relocs[num_relocs].mips_src  = pc;
				relocs[num_relocs].mips_dest = (uint32_t)target;
				relocs[num_relocs].jit_broff = jitbuf - 4;
				num_relocs++;
				in_delay = 0;
			} else {
				delay_inst.backing = inst.backing;
				in_delay = 1;
			}
		} else if(inst.i.opcode == 0xf && inst.i.rs == 0){
			/* LUI rt, immediate */

			if(!inst.i.rt){
				goto not_decoded;
			}

			JIT_MOV_EAX_IMM32((uint32_t)inst.i.imm << 16);
			JIT_WRITE_REG_FROM_EAX(inst.i.rt);
		} else if(inst.r.opcode == 0 && inst.r.rd == 0 && inst.r.shamt == 0 &&
				inst.r.func == 0x1a){
			/* DIV rs, rt */

			JIT_READ_REG_INTO_EAX(inst.r.rs);
			JIT_READ_REG_INTO_EBX(inst.r.rt);
			JIT_IDIV_EAX_EBX();
			JIT_WRITE_REG_FROM_EDX(MIPS_REG_HI);
			JIT_WRITE_REG_FROM_EAX(MIPS_REG_LO);
		} else if(inst.r.opcode == 0 && inst.r.rd == 0 && inst.r.shamt == 0 &&
				inst.r.func == 0x1b){
			/* DIVU rs, rt */

			JIT_READ_REG_INTO_EAX(inst.r.rs);
			JIT_READ_REG_INTO_EBX(inst.r.rt);
			JIT_DIV_EAX_EBX();
			JIT_WRITE_REG_FROM_EDX(MIPS_REG_HI);
			JIT_WRITE_REG_FROM_EAX(MIPS_REG_LO);
		} else if(inst.r.opcode == 0x1c && inst.r.shamt == 0 && inst.r.func == 2){
			/* MUL rd, rs, rt */
			
			if(!inst.r.rd){
				goto not_decoded;
			}

			JIT_READ_REG_INTO_EAX(inst.r.rs);
			JIT_READ_REG_INTO_EBX(inst.r.rt);
			JIT_IMUL_EAX_EBX();
			JIT_WRITE_REG_FROM_EAX(inst.r.rd);
		} else if(inst.r.opcode == 0x1c && inst.r.rd == 0 && inst.r.shamt == 0 &&
				inst.r.func == 0){
			/* MADD rs, rt */
			
			JIT_READ_REG_INTO_EAX(inst.r.rs);
			JIT_READ_REG_INTO_EBX(inst.r.rt);
			JIT_MADD_SPECIAL();
			JIT_WRITE_REG_FROM_EDX(MIPS_REG_HI);
			JIT_WRITE_REG_FROM_EAX(MIPS_REG_LO);
		} else if(inst.r.opcode == 0 && inst.r.rd == 0 && inst.r.shamt == 0 &&
				inst.r.func == 0x18){
			/* MULT rs, rt */

			JIT_READ_REG_INTO_EAX(inst.r.rs);
			JIT_READ_REG_INTO_EBX(inst.r.rt);
			JIT_IMUL_EAX_EBX();
			JIT_WRITE_REG_FROM_EDX(MIPS_REG_HI);
			JIT_WRITE_REG_FROM_EAX(MIPS_REG_LO);
		} else if(inst.r.opcode == 0 && inst.r.rd == 0 && inst.r.shamt == 0 &&
				inst.r.func == 0x19){
			/* MULTU rs, rt */

			JIT_READ_REG_INTO_EAX(inst.r.rs);
			JIT_READ_REG_INTO_EBX(inst.r.rt);
			JIT_MUL_EAX_EBX();
			JIT_WRITE_REG_FROM_EDX(MIPS_REG_HI);
			JIT_WRITE_REG_FROM_EAX(MIPS_REG_LO);
		} else if(inst.r.opcode == 0 && inst.r.rs == 0 && inst.r.rt == 0 &&
				inst.r.shamt == 0 && inst.r.func == 0x10){
			/* MFHI rd */

			if(!inst.r.rd){
				goto not_decoded;
			}

			JIT_READ_REG_INTO_EAX(MIPS_REG_HI);
			JIT_WRITE_REG_FROM_EAX(inst.r.rd);
		} else if(inst.r.opcode == 0 && inst.r.rs == 0 && inst.r.rt == 0 &&
				inst.r.shamt == 0 && inst.r.func == 0x12){
			/* MFLO rd */

			if(!inst.r.rd){
				goto not_decoded;
			}

			JIT_READ_REG_INTO_EAX(MIPS_REG_LO);
			JIT_WRITE_REG_FROM_EAX(inst.r.rd);
		} else if(inst.r.opcode == 0 && inst.r.rd == 0 && inst.r.rt == 0 &&
				inst.r.shamt == 0 && inst.r.func == 0x11){
			/* MTHI rs */

			JIT_READ_REG_INTO_EAX(inst.r.rs);
			JIT_WRITE_REG_FROM_EAX(MIPS_REG_HI);
		} else if(inst.r.opcode == 0 && inst.r.rd == 0 && inst.r.rt == 0 &&
				inst.r.shamt == 0 && inst.r.func == 0x13){
			/* MTLO rs */

			JIT_READ_REG_INTO_EAX(inst.r.rs);
			JIT_WRITE_REG_FROM_EAX(MIPS_REG_LO);
		} else if(inst.r.opcode == 0 && inst.r.rt == 0 && inst.r.rd == 0 &&
				inst.r.func == 0x8){
			/* JR rs */

			if(in_delay){
				JIT_REG_JMP_EDI();
				in_delay = 0;
			} else {
				JIT_READ_REG_INTO_EDI(inst.r.rs);
				delay_inst.backing = inst.backing;
				in_delay = 1;
			}
		} else if(inst.r.opcode == 0 && inst.r.rt == 0 && inst.r.func == 0x9){
			/* JALR rd, rs */

			if(in_delay){
				JIT_REG_JMP_EDI();
				in_delay = 0;
			} else {
				JIT_READ_REG_INTO_EDI(inst.r.rs);
				JIT_MOV_EAX_IMM32(pc + 8);
				JIT_WRITE_REG_FROM_EAX(inst.r.rd);
				delay_inst.backing = inst.backing;
				in_delay = 1;
			}
		} else if(inst.i.opcode == 0xd){
			/* ORI rt, rs, immediate */
			
			if(!inst.i.rt){
				goto not_decoded;
			}

			JIT_READ_REG_INTO_EAX(inst.i.rs);
			JIT_OR_EAX_IMM32((uint32_t)inst.i.imm);
			JIT_WRITE_REG_FROM_EAX(inst.i.rt);
		} else if(inst.r.opcode == 0 && inst.r.shamt == 0 && inst.r.func == 0xa){
			/* MOVZ rd, rs, rt */

			if(!inst.r.rd){
				goto not_decoded;
			}

			JIT_READ_REG_INTO_EAX(inst.r.rt);
			JIT_CMP_EAX_IMM32(0);
			JIT_READ_REG_INTO_EAX(inst.r.rd);
			JIT_READ_REG_INTO_EBX(inst.r.rs);
			JIT_CMOVZ_EAX_EBX();
			JIT_WRITE_REG_FROM_EAX(inst.r.rd);
		} else if(inst.r.opcode == 0 && inst.r.shamt == 0 && inst.r.func == 0xb){
			/* MOVN rd, rs, rt */

			if(!inst.r.rd){
				goto not_decoded;
			}

			JIT_READ_REG_INTO_EAX(inst.r.rt);
			JIT_CMP_EAX_IMM32(0);
			JIT_READ_REG_INTO_EAX(inst.r.rd);
			JIT_READ_REG_INTO_EBX(inst.r.rs);
			JIT_CMOVNZ_EAX_EBX();
			JIT_WRITE_REG_FROM_EAX(inst.r.rd);
		} else if(inst.cop.inst == 0x10 && inst.cop.mf == 0 && inst.cop.zero == 0){
			/* MFC0 rt, rd */

			if(!inst.cop.rt){
				goto not_decoded;
			}

			if(inst.cop.rd == 12 && inst.cop.sel == 0){
				JIT_READ_REG_INTO_EAX(MIPS_REG_COP0_STATUS);
				JIT_WRITE_REG_FROM_EAX(inst.cop.rt);
			} else if(inst.cop.rd == 9 && inst.cop.sel == 0){
				JIT_READ_REG_INTO_EAX(MIPS_REG_COP0_COUNT);
				JIT_WRITE_REG_FROM_EAX(inst.cop.rt);
			} else {
				/* Unimplemented coprocessor register */
				goto not_decoded;
			}
		} else if(inst.cop.inst == 0x10 && inst.cop.mf == 0x4 &&
				inst.cop.zero == 0){
			/* MTC0 rt, rd */

			if(inst.cop.rd == 12 && inst.cop.sel == 0){
				JIT_READ_REG_INTO_EAX(inst.cop.rt);
				JIT_WRITE_REG_FROM_EAX(MIPS_REG_COP0_STATUS);
			} else if(inst.cop.rd == 7 && inst.cop.sel == 0){
				/* TODO: Implement me */
			} else if(inst.cop.rd == 14 && inst.cop.sel == 0){
				/* TODO: Implement me */
			} else {
				/* Unimplemented coprocessor register */
				goto not_decoded;
			}
		} else if(inst.r.opcode == 0 && inst.r.rs == 0 && inst.r.rt == 0 &&
				inst.r.rd == 0 && inst.r.func == 0xf){
			/* SYNC do nothing */
			*(uint8_t*)jitbuf = 0x90;
			jitbuf++;
		} else {
not_decoded:
			/* ud2 */
			*(uint16_t*)jitbuf = 0x0b0f;
			jitbuf += 2;
		}

		num_instructions++;
		jit_size += jitbuf - orig_jitbuf;
	}

	{
		uint64_t ii;

		for(ii = 0; ii < num_relocs; ii++){
			uint8_t *orig;
			uint8_t *target;

			struct _emu_mips_reloc *reloc = &relocs[ii];

			orig   = MIPS_PC_TO_JIT(reloc->mips_src);
			target = MIPS_PC_TO_JIT(reloc->mips_dest);

			RSCHECK(orig, "Source location for relocation invalid");

			if(!target){
				/* Unknown target location, make the instruction fault */
				*(uint16_t*)orig = 0x0b0f;
				continue;
			}

			*(uint32_t*)reloc->jit_broff = (uint32_t)(target - (reloc->jit_broff + 4));
		}
	}

	printf("%lu instructions %lu size", num_instructions, jit_size);

	rstate_ret = RSTATE_SUCCESS;
cleanup:
	RSTATE_RETURN;
}

void
emu_mips_print(const uint32_t *regs)
{
	printf(
			" 0 zero %.8x  1   at %.8x  2   v0 %.8x  3   v1 %.8x\n"
			" 4   a0 %.8x  5   a1 %.8x  6   a2 %.8x  7   a3 %.8x\n"
			" 8   t0 %.8x  9   t1 %.8x 10   t2 %.8x 11   t3 %.8x\n"
			"12   t4 %.8x 13   t5 %.8x 14   t6 %.8x 15   t7 %.8x\n"
			"16   s0 %.8x 17   s1 %.8x 18   s2 %.8x 19   s3 %.8x\n"
			"20   s4 %.8x 21   s5 %.8x 22   s6 %.8x 23   s7 %.8x\n"
			"24   t8 %.8x 25   t9 %.8x 26   k0 %.8x 27   k1 %.8x\n"
			"28   gp %.8x 29   sp %.8x 30   s8 %.8x 31   ra %.8x\n"
			"32   pc %.8x 33   hi %.8x 34   lo %.8x\n",
			regs[ 0],  regs[ 1], regs[ 2],  regs[ 3], regs[ 4],  regs[ 5],
			regs[ 6],  regs[ 7], regs[ 8],  regs[ 9], regs[10],  regs[11],
			regs[12],  regs[13], regs[14],  regs[15], regs[16],  regs[17],
			regs[18],  regs[19], regs[20],  regs[21], regs[22],  regs[23],
			regs[24],  regs[25], regs[26],  regs[27], regs[28],  regs[29],
			regs[30],  regs[31], regs[32],  regs[33], regs[34]);

	return;
}

