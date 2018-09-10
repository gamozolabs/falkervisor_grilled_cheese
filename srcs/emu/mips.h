#pragma once

#define MIPS_REG_ZERO 0
#define MIPS_REG_AT   1
#define MIPS_REG_V0   2
#define MIPS_REG_V1   3
#define MIPS_REG_A0   4
#define MIPS_REG_A1   5
#define MIPS_REG_A2   6
#define MIPS_REG_A3   7
#define MIPS_REG_T0   8
#define MIPS_REG_T1   9
#define MIPS_REG_T2   10
#define MIPS_REG_T3   11
#define MIPS_REG_T4   12
#define MIPS_REG_T5   13
#define MIPS_REG_T6   14
#define MIPS_REG_T7   15
#define MIPS_REG_S0   16
#define MIPS_REG_S1   17
#define MIPS_REG_S2   18
#define MIPS_REG_S3   19
#define MIPS_REG_S4   20
#define MIPS_REG_S5   21
#define MIPS_REG_S6   22
#define MIPS_REG_S7   23
#define MIPS_REG_T8   24
#define MIPS_REG_T9   25
#define MIPS_REG_K0   26
#define MIPS_REG_K1   27
#define MIPS_REG_GP   28
#define MIPS_REG_SP   29
#define MIPS_REG_S8   30
#define MIPS_REG_FP   30
#define MIPS_REG_RA   31

/* Non-traditional numbering */
#define MIPS_REG_PC   32
#define MIPS_REG_HI   33
#define MIPS_REG_LO   34

#define MIPS_REG_COP0_STATUS 35
#define MIPS_REG_COP0_COUNT  36

#define MIPS_ADDRESS_SPACE_SIZE (4UL * 1024 * 1024 * 1024)
#define MIPS_RAM_BASE           0x80000000UL
#define MIPS_RAM_END            (MIPS_RAM_BASE + 128 * 1024 * 1024)

#define MIPS_PC_TO_JIT(pc) \
	(((pc) >= MIPS_RAM_BASE && (pc) < MIPS_RAM_END) ? \
		((uint8_t*)pc_to_jit[(pc) - MIPS_RAM_BASE]) : NULL);

#define JIT_XCHG_EAX_EBX() \
	*jitbuf++ = 0x93;

#define JIT_READ_REG_INTO_EAX(reg) \
	*(uint16_t*)(jitbuf + 0) = 0x858b; /* mov eax, dword [rbp + imm32] */ \
	*(uint32_t*)(jitbuf + 2) = (reg)*4; \
	jitbuf += 6;

#define JIT_READ_REG_INTO_EBX(reg) \
	*(uint16_t*)(jitbuf + 0) = 0x9d8b; /* mov ebx, dword [rbp + imm32] */ \
	*(uint32_t*)(jitbuf + 2) = (reg)*4; \
	jitbuf += 6;

#define JIT_READ_REG_INTO_ECX(reg) \
	*(uint16_t*)(jitbuf + 0) = 0x8d8b; /* mov ecx, dword [rbp + imm32] */ \
	*(uint32_t*)(jitbuf + 2) = (reg)*4; \
	jitbuf += 6;

#define JIT_READ_REG_INTO_ESI(reg) \
	*(uint16_t*)(jitbuf + 0) = 0xb58b; /* mov esi, dword [rbp + imm32] */ \
	*(uint32_t*)(jitbuf + 2) = (reg)*4; \
	jitbuf += 6;

#define JIT_READ_REG_INTO_EDI(reg) \
	*(uint16_t*)(jitbuf + 0) = 0xbd8b; /* mov edi, dword [rbp + imm32] */ \
	*(uint32_t*)(jitbuf + 2) = (reg)*4; \
	jitbuf += 6;

#define JIT_WRITE_REG_FROM_EAX(reg) \
	*(uint16_t*)(jitbuf + 0) = 0x8589; /* mov dword [rbp + imm32], eax */ \
	*(uint32_t*)(jitbuf + 2) = (reg)*4; \
	jitbuf += 6;

#define JIT_WRITE_REG_FROM_EBX(reg) \
	*(uint16_t*)(jitbuf + 0) = 0x9d89; /* mov dword [rbp + imm32], ebx */ \
	*(uint32_t*)(jitbuf + 2) = (reg)*4; \
	jitbuf += 6;

#define JIT_WRITE_REG_FROM_EDX(reg) \
	*(uint16_t*)(jitbuf + 0) = 0x9589; /* mov dword [rbp + imm32], edx */ \
	*(uint32_t*)(jitbuf + 2) = (reg)*4; \
	jitbuf += 6;

#define JIT_ADD_EAX_IMM32(imm32) \
	*(uint8_t* )(jitbuf + 0) = 0x05; /* add eax, imm32 */ \
	*(uint32_t*)(jitbuf + 1) = (imm32); \
	jitbuf += 5;

#define JIT_MOV_EAX_IMM32(imm32) \
	*(uint8_t* )(jitbuf + 0) = 0xb8; /* mov eax, imm32 */ \
	*(uint32_t*)(jitbuf + 1) = (imm32); \
	jitbuf += 5;

#define JIT_ADD_EAX_EBX() \
	*(uint16_t*)jitbuf = 0xd801; /* add eax, ebx */ \
	jitbuf += 2;

#define JIT_AND_EAX_EBX() \
	*(uint16_t*)jitbuf = 0xd821; /* and eax, ebx */ \
	jitbuf += 2;

#define JIT_OR_EAX_EBX() \
	*(uint16_t*)jitbuf = 0xd809; /* or eax, ebx */ \
	jitbuf += 2;

#define JIT_XOR_EAX_EBX() \
	*(uint16_t*)jitbuf = 0xd831; /* xor eax, ebx */ \
	jitbuf += 2;

#define JIT_NOT_EAX() \
	*(uint16_t*)jitbuf = 0xd0f7; /* not eax */ \
	jitbuf += 2;

#define JIT_SUB_EAX_EBX() \
	*(uint16_t*)jitbuf = 0xd829; /* sub eax, ebx */ \
	jitbuf += 2;

#define JIT_CMP_EAX_EBX() \
	*(uint16_t*)jitbuf = 0xd839; /* cmp eax, ebx */ \
	jitbuf += 2;

#define JIT_SETB_AL() \
	memcpy(jitbuf, "\x0f\x92\xc0", 3); /* setb al */ \
	jitbuf += 3;

#define JIT_SETL_AL() \
	memcpy(jitbuf, "\x0f\x9c\xc0", 3); /* setl al */ \
	jitbuf += 3;

#define JIT_AND_EAX_IMM32(imm32) \
	*(uint8_t* )(jitbuf + 0) = 0x25; /* and eax, imm32 */ \
	*(uint32_t*)(jitbuf + 1) = (imm32); \
	jitbuf += 5;

#define JIT_XOR_EAX_IMM32(imm32) \
	*(uint8_t* )(jitbuf + 0) = 0x35; /* xor eax, imm32 */ \
	*(uint32_t*)(jitbuf + 1) = (imm32); \
	jitbuf += 5;

#define JIT_OR_EAX_IMM32(imm32) \
	*(uint8_t* )(jitbuf + 0) = 0x0d; /* and eax, imm32 */ \
	*(uint32_t*)(jitbuf + 1) = (imm32); \
	jitbuf += 5;

#define JIT_CMP_EAX_IMM32(imm32) \
	*(uint8_t* )(jitbuf + 0) = 0x3d; /* cmp eax, imm32 */ \
	*(uint32_t*)(jitbuf + 1) = (imm32); \
	jitbuf += 5;

#define JIT_CMP_ESI_IMM32(imm32) \
	*(uint16_t*)(jitbuf + 0) = 0xfe81; /* cmp esi, imm32 */ \
	*(uint32_t*)(jitbuf + 2) = (imm32); \
	jitbuf += 6;

#define JIT_CMP_ESI_EDI() \
	*(uint16_t*)(jitbuf + 0) = 0xfe39; /* cmp esi, edi */ \
	jitbuf += 2;

#define JIT_JMP() \
	*(uint8_t* )(jitbuf + 0) = 0xe9; /* jmp near imm32 */ \
	*(uint32_t*)(jitbuf + 1) = 0; \
	jitbuf += 5;

#define JIT_JLE() \
	*(uint16_t*)(jitbuf + 0) = 0x8e0f; /* jle near imm32 */ \
	*(uint32_t*)(jitbuf + 2) = 0; \
	jitbuf += 6;

#define JIT_JG() \
	*(uint16_t*)(jitbuf + 0) = 0x8f0f; /* jg near imm32 */ \
	*(uint32_t*)(jitbuf + 2) = 0; \
	jitbuf += 6;

#define JIT_JL() \
	*(uint16_t*)(jitbuf + 0) = 0x8c0f; /* jl near imm32 */ \
	*(uint32_t*)(jitbuf + 2) = 0; \
	jitbuf += 6;

#define JIT_JGE() \
	*(uint16_t*)(jitbuf + 0) = 0x8d0f; /* jge near imm32 */ \
	*(uint32_t*)(jitbuf + 2) = 0; \
	jitbuf += 6;

#define JIT_JZ() \
	*(uint16_t*)(jitbuf + 0) = 0x840f; /* jz near imm32 */ \
	*(uint32_t*)(jitbuf + 2) = 0; \
	jitbuf += 6;

#define JIT_JNZ() \
	*(uint16_t*)(jitbuf + 0) = 0x850f; /* jnz near imm32 */ \
	*(uint32_t*)(jitbuf + 2) = 0; \
	jitbuf += 6;

#define JIT_SHL_EAX(shamt) \
	*(uint16_t*)(jitbuf + 0) = 0xe0c1; /* shl eax, shamt */ \
	*(uint8_t* )(jitbuf + 2) = shamt; \
	jitbuf += 3;

#define JIT_SHR_EAX(shamt) \
	*(uint16_t*)(jitbuf + 0) = 0xe8c1; /* shr eax, shamt */ \
	*(uint8_t* )(jitbuf + 2) = shamt; \
	jitbuf += 3;

#define JIT_SHR_EAX_CL() \
	*(uint16_t*)(jitbuf + 0) = 0xe8d3; /* shr eax, cl */ \
	jitbuf += 2;

#define JIT_SAR_EAX_CL() \
	*(uint16_t*)(jitbuf + 0) = 0xf8d3; /* sar eax, cl */ \
	jitbuf += 2;

#define JIT_SHL_EAX_CL() \
	*(uint16_t*)(jitbuf + 0) = 0xe0d3; /* shl eax, cl */ \
	jitbuf += 2;

#define JIT_SAR_EAX(shamt) \
	*(uint16_t*)(jitbuf + 0) = 0xf8c1; /* sar eax, shamt */ \
	*(uint8_t* )(jitbuf + 2) = shamt; \
	jitbuf += 3;

#define JIT_CMOVZ_EAX_EBX() \
	memcpy(jitbuf, "\x0f\x44\xc3", 3); /* cmovz eax, ebx */ \
	jitbuf += 3;

#define JIT_CMOVNZ_EAX_EBX() \
	memcpy(jitbuf, "\x0f\x45\xc3", 3); /* cmovnz eax, ebx */ \
	jitbuf += 3;

#define JIT_DIV_EAX_EBX() \
	memcpy(jitbuf, "\x31\xd2\xf7\xf3", 4); /* xor edx, edx ; div ebx */ \
	jitbuf += 4;

#define JIT_IDIV_EAX_EBX() \
	memcpy(jitbuf, "\x31\xd2\xf7\xfb", 4); /* xor edx, edx ; idiv ebx */ \
	jitbuf += 4;

#define JIT_MUL_EAX_EBX() \
	memcpy(jitbuf, "\x31\xd2\xf7\xe3", 4); /* xor edx, edx ; mul ebx */ \
	jitbuf += 4;

#define JIT_IMUL_EAX_EBX() \
	memcpy(jitbuf, "\x31\xd2\xf7\xeb", 4); /* xor edx, edx ; imul ebx */ \
	jitbuf += 4;

#define JIT_WRITE_MEM_BYTE() \
	memcpy(jitbuf, "\x88\x1c\x04", 3); /* mov byte [rsp + rax], bl */\
	jitbuf += 3;

#define JIT_WRITE_MEM_WORD() \
	memcpy(jitbuf, "\x86\xdf\x66\x89\x1c\x04", 6); /* xchg bl, bh ; mov word [rsp + rax], bx */\
	jitbuf += 6;

#define JIT_WRITE_MEM() \
	memcpy(jitbuf, "\x0f\xcb\x89\x1c\x04", 5); /* bswap ebx
												  mov dword [rsp + rax], ebx */\
	jitbuf += 5;

#define JIT_READ_MEM_BYTE_ZX() \
	memcpy(jitbuf, "\x0f\xb6\x1c\x04", 4); /* movzx ebx, byte [rsp + rax] */\
	jitbuf += 4;

#define JIT_READ_MEM_BYTE_SX() \
	memcpy(jitbuf, "\x0f\xbe\x1c\x04", 4); /* movsx ebx, byte [rsp + rax]  */\
	jitbuf += 4;

#define JIT_READ_MEM_WORD_ZX() \
	memcpy(jitbuf, "\x0f\xb7\x1c\x04\x86\xdf", 6); /* movzx ebx, word [rsp + rax] ; xchg bl, bh  */\
	jitbuf += 6;

#define JIT_READ_MEM_WORD_SX() \
	memcpy(jitbuf, "\x0f\xbf\x1c\x04\x86\xdf", 6); /* movzx ebx, word [rsp + rax] ; xchg bl, bh  */\
	jitbuf += 6;

#define JIT_READ_MEM() \
	memcpy(jitbuf, "\x8b\x1c\x04\x0f\xcb", 5); /* mov ebx, dword [rsp + rax]
												  bswap ebx */\
	jitbuf += 5;

#define JIT_MOV_R10_IMM32(x) \
	*(uint16_t*)(jitbuf + 0) = 0xba41; \
	*(uint32_t*)(jitbuf + 2) = x; \
	jitbuf += 6;

/* inc  r11
 * cmp  r11, imm32
 * jnae short .good
 * icebp
 * .good:
 */
#define JIT_UPDATE_COUNT(x) \
	memcpy(jitbuf, "\x49\xff\xc3\x49\x81\xfb\x41\x41\x41\x41\x72\x01\xf1", 13); \
	*(uint32_t*)(jitbuf + 6) = x; \
	jitbuf += 13;

/* inc r11 */
#define JIT_UPDATE_COUNT_UNSAFE(x) \
	memcpy(jitbuf, "\x49\xff\xc3", 3); \
	jitbuf += 3;

/* xor  edx, edx
 * imul ebx
 * add  eax, dword [rbp + 34*4]
 * adc  edx, dword [rbp + 33*4]
 */
#define JIT_MADD_SPECIAL() \
	memcpy(jitbuf, "\x31\xd2\xf7\xeb\x03\x85\x88\x00\x00\x00\x13\x95\x84\x00\x00\x00", 16); \
	jitbuf += 16;

/* mov edx, 0x80000000
 * sub rdi, rdx
 * jmp qword [r9 + rdi*8]
 */
#define JIT_REG_JMP_EDI() \
	memcpy(jitbuf, "\xba\x00\x00\x00\x80\x48\x29\xd7\x41\xff\x24\xf9", 12); \
	jitbuf += 12;

/* mov dword [r12+r11*4], r10d */
#define JIT_STORE_PC_R12_DWORD() \
	memcpy(jitbuf, "\x47\x89\x14\x9c", 4); \
	jitbuf += 4;

/* mov qword [r12+r11*8], r10 */
#define JIT_STORE_PC_R12_QWORD() \
	memcpy(jitbuf, "\x4f\x89\x14\xdc", 4); \
	jitbuf += 4;

/* jit calling convention:
 *
 * rbp - Points to register state
 * rsp - Points to memory base (PA: 0x00000000)
 * r9  - Points to PC to JIT translation array
 * r10 - PC, stored on each instruction
 * r11 - Instruction count
 * r12 - Pointer to PC buffer
 */

struct _emu_mips {
	/* 4GB reserved memory range */
	uint8_t  *address_space;
	uint64_t  address_space_key;

	/* MIPS register state */
	uint32_t *regs;
	uint64_t  regs_map_key;

	/* x86 register state */
	uint64_t rax;
	uint64_t rbx;
	uint64_t rcx;
	uint64_t rdx;
	uint64_t rsi;
	uint64_t rdi;
	uint64_t rbp;
	uint64_t r9;
	uint64_t r10;
	uint64_t r11;
	uint64_t r12;
};

union _emu_mips_inst {
	uint32_t backing;

	struct {
		uint32_t imm:16;
		uint32_t rt:5;
		uint32_t rs:5;
		uint32_t opcode:6;
	} i;

	struct {
		uint32_t func:6;
		uint32_t shamt:5;
		uint32_t rd:5;
		uint32_t rt:5;
		uint32_t rs:5;
		uint32_t opcode:6;
	} r;

	struct {
		uint32_t addr:26;
		uint32_t opcode:6;
	} j;

	struct {
		uint32_t sel:3;
		uint32_t zero:8;
		uint32_t rd:5;
		uint32_t rt:5;
		uint32_t mf:5;
		uint32_t inst:6;
	} cop;
};

struct _emu_mips_reloc {
	uint32_t  mips_src;  /* Address of the mips branch instruction */
	uint32_t  mips_dest; /* Desired target of the branch */
	uint8_t  *jit_broff; /* Pointer to the JIT branch 32-bit offset. For
							example if the instruction was 'jmp target' the
							op would be e9 41 41 41 41. This would point to the
							41 41 41 41. */
};

rstate_t
emu_mips_create(void);

rstate_t
emu_mips_translate(
		const uint8_t *instructions,
		uint64_t       length,
		uint8_t       *jit_output);

void
emu_mips_print(const uint32_t *regs);

