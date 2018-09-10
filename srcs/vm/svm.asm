[bits 64]

section .text

struc vm
	.host_vmcb: resq 1
	.vmcb:      resq 1

	.host_vmcb_pa: resq 1
	.vmcb_pa:      resq 1

	.host_xsave: resq 1
	.xsave:      resq 1
endstruc

struc gprs
	.rax: resq 1
	.rbx: resq 1
	.rcx: resq 1
	.rdx: resq 1
	.rdi: resq 1
	.rsi: resq 1
	.rbp: resq 1
	.rsp: resq 1
	.r8:  resq 1
	.r9:  resq 1
	.r10: resq 1
	.r11: resq 1
	.r12: resq 1
	.r13: resq 1
	.r14: resq 1
	.r15: resq 1
	.rip: resq 1
	.rfl: resq 1
endstruc

global svm_asm_step
svm_asm_step:
	clgi

	; Save all non-volatile registers
	push rbx
	push rbp
	push rsi
	push rdi
	push r12
	push r13
	push r14
	push r15

	; Save the vm pointer and regs
	push rdi
	push rsi

	; r15 - Pointer to struct _svm_vm
	; r14 - Pointer to gprs
	mov r15, rdi
	mov r14, rsi

	; Save host state
	mov edx, 0x40000000
	mov eax, 0x00000007
	xor ecx, ecx
	xsetbv
	mov rbx, [r15 + vm.host_xsave]
	xsave [rbx]
	mov rax, [r15 + vm.host_vmcb_pa]
	vmsave

	; Load guest xsave
	mov edx, 0x40000000
	mov eax, 0x00000007
	mov rbx, [r15 + vm.xsave]
	xrstor [rbx]

	; Load guest vmsave
	mov rax, [r15 + vm.vmcb_pa]
	vmload

	mov rbx, [r14 + gprs.rbx]
	mov rcx, [r14 + gprs.rcx]
	mov rdx, [r14 + gprs.rdx]
	mov rdi, [r14 + gprs.rdi]
	mov rsi, [r14 + gprs.rsi]
	mov rbp, [r14 + gprs.rbp]
	mov  r8, [r14 + gprs.r8]
	mov  r9, [r14 + gprs.r9]
	mov r10, [r14 + gprs.r10]
	mov r11, [r14 + gprs.r11]
	mov r12, [r14 + gprs.r12]
	mov r13, [r14 + gprs.r13]
	mov r15, [r14 + gprs.r15]
	mov r14, [r14 + gprs.r14]

	vmrun

	; Restore gprs
	mov rax, [rsp]

	mov [rax + gprs.rbx], rbx
	mov [rax + gprs.rcx], rcx
	mov [rax + gprs.rdx], rdx
	mov [rax + gprs.rsi], rsi
	mov [rax + gprs.rdi], rdi
	mov [rax + gprs.rbp], rbp
	mov [rax + gprs.r8],  r8
	mov [rax + gprs.r9],  r9
	mov [rax + gprs.r10], r10
	mov [rax + gprs.r11], r11
	mov [rax + gprs.r12], r12
	mov [rax + gprs.r13], r13
	mov [rax + gprs.r14], r14
	mov [rax + gprs.r15], r15

	; Get the gprs and vm pointer
	pop r14
	pop r15

	; Save guest state
	mov edx, 0x40000000
	mov eax, 0x00000007
	xor ecx, ecx
	xsetbv
	mov rbx, [r15 + vm.xsave]
	xsave [rbx]
	mov rax, [r15 + vm.vmcb_pa]
	vmsave

	; Load host xsave
	mov edx, 0x40000000
	mov eax, 0x00000007
	mov rbx, [r15 + vm.host_xsave]
	xrstor [rbx]

	; Load host vmsave
	mov rax, [r15 + vm.host_vmcb_pa]
	vmload

	; Restore all non-volatile registers
	pop r15
	pop r14
	pop r13
	pop r12
	pop rdi
	pop rsi
	pop rbp
	pop rbx
	stgi
	ret

