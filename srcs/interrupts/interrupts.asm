[bits 64]

%macro YMMPUSH 1
	sub     rsp, 32
	vmovdqu [rsp], %1
%endmacro

%macro YMMPOP 1
	vmovdqu %1, [rsp]
	add     rsp, 32
%endmacro

section .data

global dacount
dacount: dq 0

section .text

extern interrupt_handler

global syscall_entry
syscall_entry:
	o64 sysret

; perform an iret
;
; struct {
; 	uint64_t rip;
;	uint64_t cs;
;	uint64_t rflags;
;	uint64_t rsp;
; 	uint64_t ss;
; };
;
global enter_um_guest
enter_um_guest:
	push rax
	push rbx
	push rcx
	push rdx
	push rsi
	push rdi
	push rbp
	push r8
	push r9
	push r10
	push r11
	push r12
	push r13
	push r14
	push r15

	lea r12, [rel .return_dest]
	mov qword [rsi + 0x00], r12
	mov qword [rsi + 0x08], cs
	pushfq
	pop qword [rsi + 0x10]
	mov qword [rsi + 0x18], rsp
	mov qword [rsi + 0x20], ss

	push qword [rdi + 0x20] ; ss
	push qword [rdi + 0x18] ; rsp
	push qword [rdi + 0x10] ; rflags
	push qword [rdi + 0x08] ; cs
	push qword [rdi + 0x00] ; rip

	mov r8, rdx

	mov rax, qword [r8 + 0x00]
	mov rbx, qword [r8 + 0x08]
	mov rcx, qword [r8 + 0x10]
	mov rdx, qword [r8 + 0x18]
	mov rsi, qword [r8 + 0x20]
	mov rdi, qword [r8 + 0x28]
	mov rbp, qword [r8 + 0x30]
	mov r9,  qword [r8 + 0x38]
	mov r10, qword [r8 + 0x40]
	mov r11, qword [r8 + 0x48]
	mov r11, qword [r8 + 0x48]
	mov r12, qword [r8 + 0x50]

	iretq

.return_dest:
	mov qword [r8 + 0x00], rax
	mov qword [r8 + 0x08], rbx
	mov qword [r8 + 0x10], rcx
	mov qword [r8 + 0x18], rdx
	mov qword [r8 + 0x20], rsi
	mov qword [r8 + 0x28], rdi
	mov qword [r8 + 0x30], rbp
	mov qword [r8 + 0x38], r9
	mov qword [r8 + 0x40], r10
	mov qword [r8 + 0x48], r11
	mov qword [r8 + 0x50], r12

	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop rbp
	pop rdi
	pop rsi
	pop rdx
	pop rcx
	pop rbx
	pop rax
	ret

enter_c:
	push rax
	push rbx
	push rcx
	push rdx
	push rsi
	push rdi
	push rbp
	push r8
	push r9
	push r10
	push r11
	push r12
	push r13
	push r14
	push r15

	YMMPUSH ymm0
	YMMPUSH ymm1
	YMMPUSH ymm2
	YMMPUSH ymm3
	YMMPUSH ymm4
	YMMPUSH ymm5
	YMMPUSH ymm6
	YMMPUSH ymm7
	YMMPUSH ymm8
	YMMPUSH ymm9
	YMMPUSH ymm10
	YMMPUSH ymm11
	YMMPUSH ymm12
	YMMPUSH ymm13
	YMMPUSH ymm14
	YMMPUSH ymm15

	; Call the rust interrupt handler
	call interrupt_handler

	YMMPOP ymm15
	YMMPOP ymm14
	YMMPOP ymm13
	YMMPOP ymm12
	YMMPOP ymm11
	YMMPOP ymm10
	YMMPOP ymm9
	YMMPOP ymm8
	YMMPOP ymm7
	YMMPOP ymm6
	YMMPOP ymm5
	YMMPOP ymm4
	YMMPOP ymm3
	YMMPOP ymm2
	YMMPOP ymm1
	YMMPOP ymm0

	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop rbp
	pop rdi
	pop rsi
	pop rdx
	pop rcx
	pop rbx
	pop rax
	ret

%macro define_int_handler 2
global vec_interrupt_%1
vec_interrupt_%1:
	push rdi
	push rsi
	push rdx

%if %2
	mov  rdi, %1
	lea  rsi, [rsp+0x20]
	mov  rdx, [rsp+0x18]
	
	; 16-byte align the stack
	sub rsp, 8
%else
	mov rdi, %1
	lea rsi, [rsp+0x18]
	mov rdx, 0
%endif

	call enter_c
	
%if %2
	; Remove alignment from before
	add rsp, 8
%endif

	pop rdx
	pop rsi
	pop rdi

%if %2
	; 'pop' off the error code
	add rsp, 8
%endif

	iretq
%endmacro

define_int_handler 0, 0
define_int_handler 1, 0
define_int_handler 2, 0
define_int_handler 3, 0
define_int_handler 4, 0
define_int_handler 5, 0
define_int_handler 6, 0
define_int_handler 7, 0
define_int_handler 8, 1
define_int_handler 9, 0
define_int_handler 10, 1
define_int_handler 11, 1
define_int_handler 12, 1
define_int_handler 13, 1
define_int_handler 14, 1
define_int_handler 15, 0
define_int_handler 16, 0
define_int_handler 17, 1
define_int_handler 18, 0
define_int_handler 19, 0
define_int_handler 20, 0
define_int_handler 21, 0
define_int_handler 22, 0
define_int_handler 23, 0
define_int_handler 24, 0
define_int_handler 25, 0
define_int_handler 26, 0
define_int_handler 27, 0
define_int_handler 28, 0
define_int_handler 29, 0
define_int_handler 30, 0
define_int_handler 31, 0
define_int_handler 32, 0
define_int_handler 33, 0
define_int_handler 34, 0
define_int_handler 35, 0
define_int_handler 36, 0
define_int_handler 37, 0
define_int_handler 38, 0
define_int_handler 39, 0
define_int_handler 40, 0
define_int_handler 41, 0
define_int_handler 42, 0
define_int_handler 43, 0
define_int_handler 44, 0
define_int_handler 45, 0
define_int_handler 46, 0
define_int_handler 47, 0
define_int_handler 48, 0
define_int_handler 49, 0
define_int_handler 50, 0
define_int_handler 51, 0
define_int_handler 52, 0
define_int_handler 53, 0
define_int_handler 54, 0
define_int_handler 55, 0
define_int_handler 56, 0
define_int_handler 57, 0
define_int_handler 58, 0
define_int_handler 59, 0
define_int_handler 60, 0
define_int_handler 61, 0
define_int_handler 62, 0
define_int_handler 63, 0
define_int_handler 64, 0
define_int_handler 65, 0
define_int_handler 66, 0
define_int_handler 67, 0
define_int_handler 68, 0
define_int_handler 69, 0
define_int_handler 70, 0
define_int_handler 71, 0
define_int_handler 72, 0
define_int_handler 73, 0
define_int_handler 74, 0
define_int_handler 75, 0
define_int_handler 76, 0
define_int_handler 77, 0
define_int_handler 78, 0
define_int_handler 79, 0
define_int_handler 80, 0
define_int_handler 81, 0
define_int_handler 82, 0
define_int_handler 83, 0
define_int_handler 84, 0
define_int_handler 85, 0
define_int_handler 86, 0
define_int_handler 87, 0
define_int_handler 88, 0
define_int_handler 89, 0
define_int_handler 90, 0
define_int_handler 91, 0
define_int_handler 92, 0
define_int_handler 93, 0
define_int_handler 94, 0
define_int_handler 95, 0
define_int_handler 96, 0
define_int_handler 97, 0
define_int_handler 98, 0
define_int_handler 99, 0
define_int_handler 100, 0
define_int_handler 101, 0
define_int_handler 102, 0
define_int_handler 103, 0
define_int_handler 104, 0
define_int_handler 105, 0
define_int_handler 106, 0
define_int_handler 107, 0
define_int_handler 108, 0
define_int_handler 109, 0
define_int_handler 110, 0
define_int_handler 111, 0
define_int_handler 112, 0
define_int_handler 113, 0
define_int_handler 114, 0
define_int_handler 115, 0
define_int_handler 116, 0
define_int_handler 117, 0
define_int_handler 118, 0
define_int_handler 119, 0
define_int_handler 120, 0
define_int_handler 121, 0
define_int_handler 122, 0
define_int_handler 123, 0
define_int_handler 124, 0
define_int_handler 125, 0
define_int_handler 126, 0
define_int_handler 127, 0
define_int_handler 128, 0
define_int_handler 129, 0
define_int_handler 130, 0
define_int_handler 131, 0
define_int_handler 132, 0
define_int_handler 133, 0
define_int_handler 134, 0
define_int_handler 135, 0
define_int_handler 136, 0
define_int_handler 137, 0
define_int_handler 138, 0
define_int_handler 139, 0
define_int_handler 140, 0
define_int_handler 141, 0
define_int_handler 142, 0
define_int_handler 143, 0
define_int_handler 144, 0
define_int_handler 145, 0
define_int_handler 146, 0
define_int_handler 147, 0
define_int_handler 148, 0
define_int_handler 149, 0
define_int_handler 150, 0
define_int_handler 151, 0
define_int_handler 152, 0
define_int_handler 153, 0
define_int_handler 154, 0
define_int_handler 155, 0
define_int_handler 156, 0
define_int_handler 157, 0
define_int_handler 158, 0
define_int_handler 159, 0
define_int_handler 160, 0
define_int_handler 161, 0
define_int_handler 162, 0
define_int_handler 163, 0
define_int_handler 164, 0
define_int_handler 165, 0
define_int_handler 166, 0
define_int_handler 167, 0
define_int_handler 168, 0
define_int_handler 169, 0
define_int_handler 170, 0
define_int_handler 171, 0
define_int_handler 172, 0
define_int_handler 173, 0
define_int_handler 174, 0
define_int_handler 175, 0
define_int_handler 176, 0
define_int_handler 177, 0
define_int_handler 178, 0
define_int_handler 179, 0
define_int_handler 180, 0
define_int_handler 181, 0
define_int_handler 182, 0
define_int_handler 183, 0
define_int_handler 184, 0
define_int_handler 185, 0
define_int_handler 186, 0
define_int_handler 187, 0
define_int_handler 188, 0
define_int_handler 189, 0
define_int_handler 190, 0
define_int_handler 191, 0
define_int_handler 192, 0
define_int_handler 193, 0
define_int_handler 194, 0
define_int_handler 195, 0
define_int_handler 196, 0
define_int_handler 197, 0
define_int_handler 198, 0
define_int_handler 199, 0
define_int_handler 200, 0
define_int_handler 201, 0
define_int_handler 202, 0
define_int_handler 203, 0
define_int_handler 204, 0
define_int_handler 205, 0
define_int_handler 206, 0
define_int_handler 207, 0
define_int_handler 208, 0
define_int_handler 209, 0
define_int_handler 210, 0
define_int_handler 211, 0
define_int_handler 212, 0
define_int_handler 213, 0
define_int_handler 214, 0
define_int_handler 215, 0
define_int_handler 216, 0
define_int_handler 217, 0
define_int_handler 218, 0
define_int_handler 219, 0
define_int_handler 220, 0
define_int_handler 221, 0
define_int_handler 222, 0
define_int_handler 223, 0
define_int_handler 224, 0
define_int_handler 225, 0
define_int_handler 226, 0
define_int_handler 227, 0
define_int_handler 228, 0
define_int_handler 229, 0
define_int_handler 230, 0
define_int_handler 231, 0
define_int_handler 232, 0
define_int_handler 233, 0
define_int_handler 234, 0
define_int_handler 235, 0
define_int_handler 236, 0
define_int_handler 237, 0
define_int_handler 238, 0
define_int_handler 239, 0
define_int_handler 240, 0
define_int_handler 241, 0
define_int_handler 242, 0
define_int_handler 243, 0
define_int_handler 244, 0
define_int_handler 245, 0
define_int_handler 246, 0
define_int_handler 247, 0
define_int_handler 248, 0
define_int_handler 249, 0
define_int_handler 250, 0
define_int_handler 251, 0
define_int_handler 252, 0
define_int_handler 253, 0
define_int_handler 254, 0
define_int_handler 255, 0

