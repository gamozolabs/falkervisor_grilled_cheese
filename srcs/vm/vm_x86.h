#pragma once

#pragma pack(push, 1)
struct _x86_regs {
	/* Do not move these GPR definitions, as we use hardcoded offsets in
	 * assembly.
	 */
	union {
		struct {
			uint8_t al;
			uint8_t ah;
		} b;
		uint16_t ax;
		uint32_t eax;
		uint64_t rax;
	} rax;
	union {
		struct {
			uint8_t bl;
			uint8_t bh;
		} b;
		uint16_t bx;
		uint32_t ebx;
		uint64_t rbx;
	} rbx;
	union {
		struct {
			uint8_t cl;
			uint8_t ch;
		} b;
		uint16_t cx;
		uint32_t ecx;
		uint64_t rcx;
	} rcx;
	union {
		struct {
			uint8_t dl;
			uint8_t dh;
		} b;
		uint16_t dx;
		uint32_t edx;
		uint64_t rdx;
	} rdx;
	union {
		uint8_t  dil;
		uint16_t di;
		uint32_t edi;
		uint64_t rdi;
	} rdi;
	union {
		uint8_t  sil;
		uint16_t si;
		uint32_t esi;
		uint64_t rsi;
	} rsi;
	union {
		uint8_t  bpl;
		uint16_t bp;
		uint32_t ebp;
		uint64_t rbp;
	} rbp;
	union {
		uint8_t  spl;
		uint16_t sp;
		uint32_t esp;
		uint64_t rsp;
	} rsp;
	union {
		uint8_t  r8b;
		uint16_t r8w;
		uint32_t r8d;
		uint64_t r8;
	} r8;
	union {
		uint8_t  r9b;
		uint16_t r9w;
		uint32_t r9d;
		uint64_t r9;
	} r9;
	union {
		uint8_t  r10b;
		uint16_t r10w;
		uint32_t r10d;
		uint64_t r10;
	} r10;
	union {
		uint8_t  r11b;
		uint16_t r11w;
		uint32_t r11d;
		uint64_t r11;
	} r11;
	union {
		uint8_t  r12b;
		uint16_t r12w;
		uint32_t r12d;
		uint64_t r12;
	} r12;
	union {
		uint8_t  r13b;
		uint16_t r13w;
		uint32_t r13d;
		uint64_t r13;
	} r13;
	union {
		uint8_t  r14b;
		uint16_t r14w;
		uint32_t r14d;
		uint64_t r14;
	} r14;
	union {
		uint8_t  r15b;
		uint16_t r15w;
		uint32_t r15d;
		uint64_t r15;
	} r15;

	union {
		uint16_t ip;
		uint32_t eip;
		uint64_t rip;
	} rip;

	union {
		struct {
			uint64_t cf:1;
			uint64_t resvd1:1;
			uint64_t pf:1;
			uint64_t resvd2:1;
			uint64_t af:1;
			uint64_t resvd3:1;
			uint64_t zf:1;
			uint64_t sf:1;
			uint64_t tf:1;
			uint64_t intf:1;
			uint64_t df:1;
			uint64_t of:1;
			uint64_t iopl:2;
			uint64_t nt:1;
			uint64_t resvd4:1;
			uint64_t rf:1;
			uint64_t vm:1;
			uint64_t ac:1;
			uint64_t vif:1;
			uint64_t vip:1;
			uint64_t id:1;
		} u;

		uint64_t rfl;
	} rfl;

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
};
#pragma pack(pop)

rstate_t
vm_x86_create(_Outptr_ struct _vm **out_vm, _In_ enum _vm_subtype type);

void
vm_x86_dump_state(struct _vm *vm);

