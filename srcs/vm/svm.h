#pragma once

#include <vm/vm.h>

#pragma pack(push, 1)
struct _vmcb {
	uint32_t CR_icpt;
	uint32_t DR_icpt;
	uint32_t except_icpt;
	uint32_t icpt_set_1;
	uint32_t icpt_set_2;
	uint32_t reserved_1[10];
	uint16_t pause_flt_thr;
	uint16_t pause_flt_cnt;
	uint64_t iopm;
	uint64_t msrpm;
	uint64_t tsc_offset;
	uint64_t tlb_and_asid;
	uint64_t vint;
	uint64_t int_shadow;
	uint64_t exitcode;
	uint64_t exitinfo1;
	uint64_t exitinfo2;
	uint64_t exitintinfo;
	uint64_t np_enabled;
	uint64_t apic_bar;
	uint64_t reserved_2;
	uint64_t eventinj;
	uint64_t n_cr3;
	uint64_t lbr_virt_en;
	uint64_t vmcb_clean;
	uint64_t nrip;
	uint64_t guest_inst[2];
	uint64_t apic_backing;
	uint64_t reserved_3;
	uint64_t logical_table;
	uint64_t avig_phys_tbl;

	uint8_t reserved_4[0x300];

	uint16_t es_sel;
	uint16_t es_attrib;
	uint32_t es_limit;
	uint64_t es_base;

	uint16_t cs_sel;
	uint16_t cs_attrib;
	uint32_t cs_limit;
	uint64_t cs_base;

	uint16_t ss_sel;
	uint16_t ss_attrib;
	uint32_t ss_limit;
	uint64_t ss_base;

	uint16_t ds_sel;
	uint16_t ds_attrib;
	uint32_t ds_limit;
	uint64_t ds_base;

	uint16_t fs_sel;
	uint16_t fs_attrib;
	uint32_t fs_limit;
	uint64_t fs_base;

	uint16_t gs_sel;
	uint16_t gs_attrib;
	uint32_t gs_limit;
	uint64_t gs_base;

	uint16_t gdtr_sel;
	uint16_t gdtr_attrib;
	uint32_t gdtr_limit;
	uint64_t gdtr_base;

	uint16_t ldtr_sel;
	uint16_t ldtr_attrib;
	uint32_t ldtr_limit;
	uint64_t ldtr_base;

	uint16_t idtr_sel;
	uint16_t idtr_attrib;
	uint32_t idtr_limit;
	uint64_t idtr_base;

	uint16_t tr_sel;
	uint16_t tr_attrib;
	uint32_t tr_limit;
	uint64_t tr_base;

	uint8_t reserved_5[0x2b];

	uint8_t cpl;

	uint32_t reserved_6;

	uint64_t efer;

	uint8_t reserved_7[0x70];

	uint64_t cr4;
	uint64_t cr3;
	uint64_t cr0;
	uint64_t dr7;
	uint64_t dr6;
	uint64_t rfl;
	uint64_t rip;

	uint8_t reserved_8[0x58];

	uint64_t rsp;

	uint8_t reserved_9[0x18];

	uint64_t rax;

	uint64_t star;
	uint64_t lstar;
	uint64_t cstar;
	uint64_t sfmask;
	uint64_t kern_gs_base;

	uint64_t sysenter_cs;
	uint64_t sysenter_esp;
	uint64_t sysenter_eip;

	uint64_t cr2;

	uint8_t reserved_a[0x20];

	uint64_t g_pat;
	uint64_t dbgctrl;
	uint64_t br_from;
	uint64_t br_to;
	uint64_t last_except_from;
	uint64_t last_except_to;
};

struct _svm_legacy_snapshot {
	uint64_t rcx;
	uint64_t rdx;
	uint64_t rbx;
	uint64_t rbp;
	uint64_t rsi;
	uint64_t rdi;
	uint64_t r8;
	uint64_t r9;
	uint64_t r10;
	uint64_t r11;
	uint64_t r12;
	uint64_t r13;
	uint64_t r14;
	uint64_t r15;

	uint64_t cr8;
	uint64_t xcr0;

	uint64_t dr0;
	uint64_t dr1;
	uint64_t dr2;
	uint64_t dr3;

	uint64_t pmem_size;

	uint8_t padding_1[0xF58];

	uint8_t xsave[0x1000];
	uint8_t vmcb[0x1000];
	uint8_t physical_memory[1];
};

struct _svm_vm {
	struct _vmcb *host_vmcb;
	struct _vmcb *vmcb;

	uintptr_t host_vmcb_pa;
	uintptr_t vmcb_pa;

	void *host_xsave;
	void *xsave;

	uintptr_t iopm;
	uintptr_t msrpm;
};
#pragma pack(pop)

rstate_t
svm_init(void);

rstate_t
svm_create(struct _vm *vm);

void
svm_enter_regsegs(struct _vm *vm);

void
svm_exit_regsegs(struct _vm *vm);

rstate_t
svm_step(struct _vm *vm);

void
svm_dump_state(struct _vm *vm);

rstate_t
svm_map_phys(struct _vm *vm, uint64_t address,
		int readable, int writable, int executable,
		uint64_t backing_page);

rstate_t
svm_guest_phys_to_host_phys(
		struct _vm *vm,
		uint64_t    guest_paddr,
		int         is_read,
		int         is_write,
		int         is_exec,
		uint64_t   *host_paddr);

rstate_t
svm_guest_virt_to_host_phys(
		struct _vm *vm,
		uint64_t    guest_vaddr,
		int         is_read,
		int         is_write,
		int         is_exec,
		uint64_t   *host_paddr);

/* Assembly implementation of the SVM step */
void
svm_asm_step(struct _svm_vm *svm_vm, struct _x86_regs *regs);

