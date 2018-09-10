[org  0x7c00]
[bits 16]

%macro rm_printstr 1
	jmp %%branch_point
	%%string_name: db %1
	%%string_len:  equ ($-%%string_name)
%%branch_point:
	push ebx
	push ecx
	mov  ebx, %%string_name
	mov  ecx, %%string_len
	call rm_puts
	pop  ecx
	pop  ebx
%endmacro

%macro rm_assert 2
	j%1 %%no_error_branch
%strcat %%assert_string "Assertion failed: ", %2
	rm_printstr %%assert_string
	jmp rm_halt
%%no_error_branch:
%endmacro

%macro lm_printstr 1
	jmp %%branch_point
	%%string_name: db %1
	%%string_len:  equ ($-%%string_name)
%%branch_point:
	push rbx
	push rcx
	mov  rbx, %%string_name
	mov  rcx, %%string_len
	call lm_puts
	pop  rcx
	pop  rbx
%endmacro

%macro lm_assert 2
	j%1 %%no_error_branch
%strcat %%assert_string "Assertion failed: ", %2
	lm_printstr %%assert_string
	jmp lm_halt
%%no_error_branch:
%endmacro

; While still in real-mode we will extract the E820 table and put it in a
; well known format at a fixed offset.
; It will be downloaded to e820_map (physical address) and will store
; at most E820_MAP_MAX entries.
;
; The maximum size of this structure is 4 + (20 * E820_MAP_MAX). Each entry is
; 20-bytes in size, and there is a 4-byte entry count out front. The structure
; is packed and no padding is present.
;
; e820_map structure
;
; struct e820_map {
;     uint32_t map_entries; /* Number of entries present in the map */
;     
;     struct {
;         /* Raw information from E820. Not validated, only fetched. */
;         uint64_t base_address;
;         uint64_t length;
;         uint32_t type;
;     } entry[map_entries];
; };
;
%define E820_MAP_MAX 128 ; Maximum number of e820 entries allowed. Each
                         ; entry is 20 bytes.

; Start and size of the linear allocator. The base address must be 4k-aligned.
%define RM_LINEAR_ALLOC_BASE 0x10000
%define RM_LINEAR_ALLOC_SIZE (512 * 1024)

%define LM_LINEAR_ALLOC_BASE 0x100000
%define LM_LINEAR_ALLOC_SIZE (256 * 1024 * 1024)

%define DOWNLOAD_MAX_SIZE (256 * 1024)
%define LOAD_MAX_SIZE     (16 * 1024 * 1024)

; boot_bsp
;
; Summary:
;
;
; Optimization:
;
; Readability
;
rm_entry_bsp:
	; Disable interrupts and direction flag
	cli
	cld

	; Zero out all segments
	xor ax, ax
	mov es, ax
	mov ds, ax
	mov fs, ax
	mov gs, ax
	mov ss, ax
	jmp 0x0000:.zero_cs
.zero_cs:

	; Set up a stack
	mov sp, top_of_stack

	; Reset segmentation
	call rm_reset_segmentation

	; Set the screen to 16-color 80x25 mode (also clears the screen)
	; Only do this on the first boot.
	mov ax, 0x0003
	int 0x10

	jmp rm_entry_next

rm_halt:
	cli
	hlt
	jmp short rm_halt

; eax -> 32-bit virtual address
;  es <- segment
;  di <- offset
conv_virt_to_segoff:
	push eax
	push ebx

	and eax, 0xfffff
	mov ebx, eax
	and ebx, ~0xf
	sub eax, ebx
	shr ebx, 4

	mov es, bx
	mov di, ax

	pop ebx
	pop eax
	ret

; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

times 510-($-$$) db 0
dw 0xAA55
times 0x400-($-$$) db 0

; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

rm_entry_ap:
	mov  eax, 1
	lock xadd dword [ap_lock], eax

.wait_for_lock:
	pause
	cmp eax, dword [ap_unlock]
	jne short .wait_for_lock

	; Set the A20 line
	in    al, 0x92
	or    al, 2
	out 0x92, al

	; Set up CR3
	mov edi, dword [orig_cr3]
	mov cr3, edi

	; Set NXE (NX enable), LME (long mode enable), and SCE (syscall enable).
	mov edx, 0
	mov eax, 0x00000901
	mov ecx, 0xc0000080
	wrmsr

	; Set OSXSAVE, OSXMMEXCPT, OSFXSR, PAE, and DE
	mov eax, 0x40628
	mov cr4, eax

	; Set paging enable, write protect, extension type, monitor coprocessor,
	; and protection enable
	mov eax, 0x80010013
	mov cr0, eax

	; Load the 64-bit long mode GDT
	lgdt [lmgdt]

	; Long jump to enable long mode!
	jmp 0x0008:lm_entry

; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

rm_entry_next:
	; Print out our version string
	rm_printstr "=== grilled_cheese bootloader v6 ==="

	; Walk the e820 map and save off the contents to a known format
	call load_e820
	rm_printstr "E820 map successfully generated"

	; Check that our entire linear allocation range is marked as available
	; by the e820 table.
	mov  ebx, RM_LINEAR_ALLOC_BASE
	mov  ecx, RM_LINEAR_ALLOC_SIZE
	call rm_e820_is_avail
	test eax, eax
	rm_assert nz, "Failed to find enough free space for rm linear allocator"

	; Check that our entire linear allocation range is marked as available
	; by the e820 table.
	mov  ebx, LM_LINEAR_ALLOC_BASE
	mov  ecx, LM_LINEAR_ALLOC_SIZE
	call rm_e820_is_avail
	test eax, eax
	rm_assert nz, "Failed to find enough free space for lm linear allocator"

	; Set up the linear allocator
	mov dword [rm_linear_map_ptr], RM_LINEAR_ALLOC_BASE
	rm_printstr "Real mode linear map initialized"

	; Download the stage 2 via PXE.
	call pxe_download
	rm_printstr "PXE download complete"

	; Set the A20 line
	in    al, 0x92
	or    al, 2
	out 0x92, al

	; Print that we're entering long mode
	rm_printstr "Entering long mode"

	; Allocate room for the page table and one PDP
	mov  ecx, 4096 + 4096
	call rm_alloc
	mov  eax, edx
	call conv_virt_to_segoff

	; Set up a page table with the first 4GB of memory identity mapped
	lea ebx, [edx + 0x1003]
	mov dword [es:di + 0x0000], ebx
	mov dword [es:di + 0x1000], 0x83 | (0 * 1024 * 1024 * 1024)
	mov dword [es:di + 0x1008], 0x83 | (1 * 1024 * 1024 * 1024)
	mov dword [es:di + 0x1010], 0x83 | (2 * 1024 * 1024 * 1024)
	mov dword [es:di + 0x1018], 0x83 | (3 * 1024 * 1024 * 1024)
	mov cr3, edx

	; Save off this CR3
	mov dword [orig_cr3], edx

	; Set NXE (NX enable), LME (long mode enable), and SCE (syscall enable).
	mov edx, 0
	mov eax, 0x00000901
	mov ecx, 0xc0000080
	wrmsr

	; Set OSXSAVE, OSXMMEXCPT, OSFXSR, PAE, and DE
	mov eax, 0x40628
	mov cr4, eax

	; Set paging enable, write protect, extension type, monitor coprocessor,
	; and protection enable
	mov eax, 0x80010013
	mov cr0, eax

	; Load the 64-bit long mode GDT
	lgdt [lmgdt]

	; Long jump to enable long mode!
	jmp 0x0008:lm_entry

rm_reset_segmentation:
	push eax

	; Load real mode GDT
	lgdt [rmgdt]

	; Set the protection bit
	mov eax, cr0
	bts eax, 0
	mov cr0, eax

	; Normalize the CS descriptor by loading a standard 16-bit code segment
	; with a limit of 0xffff.
	jmp 0x0008:.set_cs
.set_cs:
	; Set all segment registers to apply unreal mode limit of 0xffffffff
	mov ax, 0x10
	mov es, ax
	mov ds, ax
	mov fs, ax
	mov gs, ax
	mov ss, ax

	; Clear the protection bit
	mov eax, cr0
	btr eax, 0
	mov cr0, eax

	; Clear all segments
	xor ax, ax
	mov es, ax
	mov ds, ax
	mov fs, ax
	mov gs, ax
	mov ss, ax
	jmp 0x0000:.clear_cs
.clear_cs:

	pop eax
	ret

ap_lock:   dd 0
ap_unlock: dd 0

; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

; ecx -> Size to allocate
; edx <- Allocation
rm_alloc:
	push eax
	push ebx
	push ecx
	push edi

	test ecx, ecx
	rm_assert nz, "Attempted to allocate zero bytes"

	; Page align the length
	add ecx,  0xfff
	and ecx, ~0xfff
	mov edx,  ecx

	lock xadd dword [rm_linear_map_ptr], edx

	; ecx - Allocation length
	; edx - Alloction

	; Check for OOM
	mov eax, RM_LINEAR_ALLOC_BASE + RM_LINEAR_ALLOC_SIZE
	lea ebx, [edx + ecx]
	cmp ebx, eax
	rm_assert be, "Linear allocator out of memory"

	; Zero out the memory
	mov eax, edx
.lewp:
	push es
	call conv_virt_to_segoff
	mov  byte [es:di], 0
	pop  es

	inc eax
	dec ecx
	jnz short .lewp

	pop edi
	pop ecx
	pop ebx
	pop eax
	ret

; This function returns 1 if [x1, x2] and [y1, y2] have any overlap and 0
; if there is no overlap.
; eax -> x1
; ebx -> x2
; ecx -> y1
; edx -> y2
; eax <- Overlap?
rm_overlaps:
	cmp eax, edx
	ja  short .no_overlap

	cmp ecx, ebx
	ja  short .no_overlap

	mov eax, 1
	ret

.no_overlap:
	xor eax, eax
	ret

; This function returns 1 if the entirety of [x1, x2] is contained inside
; of [y1, y2], else returns 0.
; eax -> x1
; ebx -> x2
; ecx -> y1
; edx -> y2
; eax <- Contains?
rm_contains:
	cmp  eax, ecx
	jnae short .no_contains

	cmp  ebx, edx
	jnbe short .no_contains

	mov eax, 1
	ret

.no_contains:
	xor eax, eax
	ret

; ebx -> Address of memory to test
; ecx -> Size of memory to test
; eax <- 1 if memory is free for use, 0 otherwise
rm_e820_is_avail:
	pushad

	; If the e820 map is empty, return as not available
	cmp dword [e820_map], 0
	je  .not_avail

	; Get the number of e820 map entries and a pointer to the base
	mov esi, [e820_map]
	lea ebp, [e820_map + 4]
.lewp:
	; Make sure that the high parts of the qwords for the base and length are
	; zero. If they are not, skip to the next entry
	cmp dword [ebp + 0x04], 0
	jne short .next_entry
	cmp dword [ebp + 0x0c], 0
	jne short .next_entry

	; Make sure that the range is describing a non-available range
	cmp dword [ebp + 0x10], 1
	je  short .next_entry

	push ebx
	push ecx
	mov  eax, ebx
	lea  ebx, [ebx + ecx - 1]
	mov  ecx, [ebp]
	mov  edx, [ebp + 8]
	lea  edx, [ecx + edx - 1]
	call rm_overlaps
	pop  ecx
	pop  ebx
	test eax, eax
	jnz  short .not_avail

.next_entry:
	add ebp, 20
	dec esi
	jnz short .lewp

	; Get the number of e820 map entries and a pointer to the base
	mov esi, [e820_map]
	lea ebp, [e820_map + 4]
.lewp2:
	; Make sure that the high parts of the qwords for the base and length are
	; zero. If they are not, skip to the next entry
	cmp dword [ebp + 0x04], 0
	jne short .next_entry2
	cmp dword [ebp + 0x0c], 0
	jne short .next_entry2

	; Make sure that the range is describing an available range
	cmp dword [ebp + 0x10], 1
	jne short .next_entry2

	push ebx
	push ecx
	mov  eax, ebx
	lea  ebx, [ebx + ecx - 1]
	mov  ecx, [ebp]
	mov  edx, [ebp + 8]
	lea  edx, [ecx + edx - 1]
	call rm_contains
	pop  ecx
	pop  ebx
	test eax, eax
	jnz  short .avail

.next_entry2:
	add ebp, 20
	dec esi
	jnz short .lewp2

.not_avail:
	popad
	mov eax, 0
	ret

.avail:
	popad
	mov eax, 1
	ret

; Fetch the e820 tables to physical address e820_map. See the top of this
; file for more information on the structure.
;
load_e820:
	pushad

	; Set up for the E820 loop
	mov dword [e820_map], 0 ; Initialize the e820 map entry count to 0
	xor ebx, ebx            ; Continuation number, zero to start

.for_each_entry:
	; Bounds check the e820 array
	cmp dword [e820_map], E820_MAP_MAX
	rm_assert b, "E820 map too large for buffer"

	; Calculate the e820 entry destination
	mov  di, word [e820_map]
	imul di, 20
	add  di, (e820_map + 4)
	
	mov eax, 0xe820 ; Command number, E820
	mov edx, 'PAMS' ; Magic signature
	mov ecx, 20     ; Size of an entry
	int 0x15

	rm_assert nc, "E820 error, carry flag set"
	cmp eax, 'PAMS' ; eax contains 'SMAP' on success
	rm_assert e, "E820 'SMAP' signature not present"
	cmp ecx, 20     ; Returned size should be 20 bytes
	rm_assert e, "E820 entry size not 20 bytes"

	; Increment the number of e820 entries
	inc dword [e820_map]

	; If the returned continuation number is 0, we're done!
	test ebx, ebx
	jz   short .e820_done

	; Loop to the next entry
	jmp .for_each_entry

.e820_done:
	popad
	ret

; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

; Scroll up the screen one line, and then print out the string pointed to by
; ds:bx with length cx at the bottom.
;
; ds:bx -> String to print
; cx    -> Length of string to print
rm_puts:
	pushad
	push es

	; Set es:di to point to the screen.
	mov di, 0xb800
	mov es, di

	; Save off count and ds, as we will restore them after the move and clear.
	push cx
	push ds

	push es                ; Copy es into ds
	pop  ds
	mov  si, (80 * 2)      ; Point the source to the second line of the screen
	xor  di, di            ; Point the dest to the top of of the screen
	mov  cx, (80 * 2 * 24) ; Copy the remaining 24 lines up
	rep  movsb

	; Clear out the last line on the screen
	mov di, (80 * 2 * 24)
	mov cx, (80 * 2)
	xor ax, ax
	rep stosb

	; Restore original count and ds.
	pop ds
	pop cx

	; If the string is of zero length, don't attempt to print it.
	test cx, cx
	jz   short .end

	; Cap the string length at 80 bytes
	mov   ax, 80
	cmp   cx, ax
	cmova cx, ax

	; Print out the string to the last line of the screen.
	mov di, (80 * 2 * 24)
	mov ah, 0xf
.lewp:
	mov al, byte [bx]
	stosw

	inc bx
	dec cx
	jnz short .lewp

.end:
	pop es
	popad
	ret

pxe_download:
	pushad

	; Set up the download base
	mov  ecx, DOWNLOAD_MAX_SIZE
	call rm_alloc
	mov  dword [download_base], edx

	; Save GS and ES as we'll use them with the PXE API during init
	push gs
	push es

	; PXE installation check
	mov ax, 0x5650
	int 0x1a
	rm_assert nc, "PXE installation check failed, CF set"
	cmp ax, 0x564e
	rm_assert e, "PXE installation check failed, PXE magic not present"

	; Print that we found PXE
	rm_printstr "PXE installation detected"

	; Check for PXENV+ signature
	cmp dword [es:bx], 'PXEN'
	rm_assert e, "PXENV+ signature not found"
	cmp word [es:bx+4], 'V+'
	rm_assert e, "PXENV+ signature not found"

	; Print that we found PXENV+
	rm_printstr "Found PXENV+ structure"

	; Pull out the seg:off of the !PXE structure
	mov di, [es:bx+0x28]
	mov gs, [es:bx+0x2a]

	; Check the 4-byte '!PXE' signature
	cmp dword [gs:di], '!PXE'
	rm_assert e, "!PXE structure not present"

	; Print that we found !PXE
	rm_printstr "Found !PXE structure"

	; Extract and save off the !PXE real mode API entry point
	mov ax, [gs:di+0x10]
	mov [pxe_off], ax
	mov ax, [gs:di+0x12]
	mov [pxe_seg], ax

	; PXENV_GET_CACHED_INFO. Will retreive the DHCPACK packet
	mov  bx, 0x71
	mov  di, pxe_cached_info
	call pxecall
	cmp  ax, 0
	rm_assert e, "PXENV_GET_CACHED_INFO returned failure"

	rm_printstr "Got cached PXE information"

	; Get the pointer to the cached DHCPACK packet into es:bx
	mov bx, [pxe_cached_info.buffer_seg]
	mov es, bx
	mov bx, [pxe_cached_info.buffer_off]

	; Get the next server IP field from the DHCPACK packet and place it into
	; the pxenv_tftp_read_file.server_ip field to be used for the TFTP
	; transaction.
	mov eax, dword [es:bx + 0x14]
	mov dword [pxenv_tftp_read_file.server_ip], eax

	; Restore ES and GS
	pop es
	pop gs

	; Populate the buffer and size in the read file structure
	mov edx, dword [download_base]
	mov dword [pxenv_tftp_read_file.buffer],      edx
	mov dword [pxenv_tftp_read_file.buffer_size], DOWNLOAD_MAX_SIZE

	; Download the entire file
	mov  bx, 0x23
	mov  di, pxenv_tftp_read_file
	call pxecall
	cmp  ax, 0
	rm_assert e, "PXENV_TFTP_READ_FILE returned failure"
	
	popad
	ret

; ds:di -> PXE API input buffer
; bx    -> PXE API opcode
pxecall:
	; Push the parameters on the stack and call into PXE
	push ds
	push di
	push bx
	call far [pxe_off]
	add  sp, 6

	; Reset segmentation. PXE APIs frequently screw with segmentation.
	call rm_reset_segmentation

	ret

; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
; 64-bit starts here
; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

[bits 64]

align 8
new_rip:    dq 0
orig_cr3:   dq 0

struc boot_parameters
	.screen:       resq 1
	.top_of_stack: resq 1

	.e820: resq 1

	.phy_window_page_table: resq 1
	.phy_window_base:       resq 1

	.free_memory_base: resq 1

	.soft_reboot: resq 1

	.download_base:     resq 1
	.download_size_ptr: resq 1
	.download_max_size: resq 1

	.boot_parameters: resq 1

	.load_base: resq 1
	.load_size: resq 1

	.apic_id: resq 1
endstruc

%define STACK_SIZE (128 * 1024)

; rcx - Number of cycles to spin for
rdtsc_sleep:
	push rax
	push rcx
	push rdx
	push rsi

	rdtsc
	mov rsi, rdx
	shl rsi, 32
	or  rsi, rax

	add rsi, rcx

.wait:
	rdtsc
	shl  rdx, 32
	or   rdx, rax
	cmp  rdx, rsi
	jnae short .wait

	pop rsi
	pop rdx
	pop rcx
	pop rax
	ret

lm_entry:
	cli
	cld

	; Reset segmentation
	mov ax, 0x10
	mov es, ax
	mov ds, ax
	mov fs, ax
	mov gs, ax
	mov ss, ax

	; Set up xcr0 to enable AVX, SSE, and FPU
	mov edx, 0
	mov eax, 7
	mov ecx, 0
	xsetbv

	; Reload the cr3
	mov rax, qword [orig_cr3]
	mov cr3, rax

	; Get whether this CPU is the BSP or not, and store it into r14
	mov ecx, 0x1b
	rdmsr
	shr  eax, 8
	and  eax, 1
	mov r14d, eax
	
	; If we're an AP, skip over the page table init
	test r14, r14
	jz   .is_ap

	; Reset AP lock
	mov dword [ap_lock],   1
	mov dword [ap_unlock], 0

	; Reload a safe stack
	mov rsp, top_of_stack

	; Reset the linear allocator
	mov qword [lm_linear_map_ptr], LM_LINEAR_ALLOC_BASE

	; Zero out all but the first PML4E in the page table and then reload cr3
	; to flush TLBs.
	; This will remove all mappings besides the 4GB identity map.
	mov rdi, cr3
	add rdi, 8
	mov rcx, 4096 - 8
	xor eax, eax
	rep stosb
	mov rdi, cr3
	mov cr3, rdi

	lm_printstr "Entered long mode"

	; Create a new cr3 with a a 4GB identity map not-present at the PML4 level
	; We can reliably enable this identity map later by just setting the	
	; present bit on the first PML4.
	mov  rcx, 4096 + 4096
	call lm_alloc
	mov  qword [new_cr3], rdx

	; Create the PML4 to a 4GB identity map, marked not present.
	lea rbx, [rdx + 0x1002]
	mov qword [rdx + 0x0000], rbx
	mov dword [rdx + 0x1000], 0x83 | (0 * 1024 * 1024 * 1024)
	mov dword [rdx + 0x1008], 0x83 | (1 * 1024 * 1024 * 1024)
	mov dword [rdx + 0x1010], 0x83 | (2 * 1024 * 1024 * 1024)
	mov dword [rdx + 0x1018], 0x83 | (3 * 1024 * 1024 * 1024)

	; Generate a random address for the ELF to load at
	mov  rcx, LOAD_MAX_SIZE
	call reserve_random
	mov  qword [load_base], rax

	; Load the ELF
	call lm_elf_load
	mov  qword [new_rip], rax

	; Allocate room for stacks
	mov  rcx, STACK_SIZE * 256
	call lm_alloc
	mov [lm_stacks], rdx

.is_ap:
	; Get the APIC ID. Get a unique stack for this CPU.
	mov  eax, 1
	cpuid
	shr  ebx, 24
	imul rbx, STACK_SIZE
	mov  rsp, [lm_stacks]
	add  rsp, rbx
	add  rsp, STACK_SIZE

	; Map in boot parameters
	mov  rcx, boot_parameters_size
	call lm_alloc
	mov  r15, rdx
	mov  rcx, boot_parameters_size
	call reserve_random
	mov  rbx, qword [new_cr3]
	mov  rcx, rax
	bts  rdx, 63 ; NX
	bts  rdx, 0  ; Present
	mov  rdi, boot_parameters_size
	call mm_map_4k_range
	mov  qword [r15 + boot_parameters.boot_parameters], rcx

	; Map in a stack
	mov  rcx, STACK_SIZE
	call lm_alloc
	mov  rcx, STACK_SIZE
	call reserve_random
	mov  rbx, qword [new_cr3]
	mov  rcx, rax
	bts  rdx, 63 ; NX
	bts  rdx, 1  ; Writable
	bts  rdx, 0  ; Present
	mov  rdi, STACK_SIZE
	call mm_map_4k_range
	add  rax, STACK_SIZE
	mov  qword [r15 + boot_parameters.top_of_stack], rax

	; Map in the screen
	mov  rcx, (80 * 25 * 2)
	call reserve_random
	mov  rbx, qword [new_cr3]
	mov  rcx, rax
	mov  rdx, 0xb8000
	bts  rdx, 63 ; NX
	bts  rdx, 1  ; Writable
	bts  rdx, 0  ; Present
	mov  rdi, (80 * 25 * 2)
	call mm_map_4k_range
	mov  qword [r15 + boot_parameters.screen], rax

	; Map in the e820 table
	mov  rcx, ((E820_MAP_MAX * 20) + 4)
	call reserve_random
	mov  rbx, qword [new_cr3]
	mov  rcx, rax
	lea  rdx, [e820_map]
	bts  rdx, 63 ; NX
	bts  rdx, 0  ; Present
	mov  rdi, ((E820_MAP_MAX * 20) + 4)
	call mm_map_4k_range
	mov  qword [r15 + boot_parameters.e820], rax

	; Map in the pivot
	mov  rcx, pivot_size
	call lm_alloc
	mov  rdi, rdx
	lea  rsi, [pivot]
	mov  rcx, pivot_size
	rep  movsb
	mov  rcx, pivot_size
	call reserve_random
	mov  rbx, qword [new_cr3]
	mov  rcx, rax
	bts  rdx, 0  ; Present
	mov  rdi, pivot_size
	call mm_map_4k_range
	mov  rbx, cr3
	call mm_map_4k_range

	; Create the physical mapping window
	call create_phywin

	; Set up some boot parameters
	mov rbx, LM_LINEAR_ALLOC_BASE + LM_LINEAR_ALLOC_SIZE
	mov qword [r15 + boot_parameters.free_memory_base], rbx

	lea rbx, [lm_entry]
	mov qword [r15 + boot_parameters.soft_reboot], rbx
	
	mov rbx, qword [download_base]
	mov qword [r15 + boot_parameters.download_base], rbx
	mov qword [r15 + boot_parameters.download_max_size], DOWNLOAD_MAX_SIZE
	lea rbx, [pxenv_tftp_read_file.buffer_size]
	mov qword [r15 + boot_parameters.download_size_ptr], rbx

	mov rbx, qword [load_base]
	mov qword [r15 + boot_parameters.load_base], rbx
	mov qword [r15 + boot_parameters.load_size], LOAD_MAX_SIZE

	mov rbx, 0xfee00020
	mov ebx, dword [rbx]
	shr ebx, 24
	mov qword [r15 + boot_parameters.apic_id], rbx

	lock inc dword [ap_unlock]

	mov rcx, qword [new_cr3]
	mov rdx, qword [r15 + boot_parameters.top_of_stack]
	mov  r8, qword [new_rip]
	mov  r9, qword [r15 + boot_parameters.boot_parameters]
	jmp rax

; -----------------------------------------------------------------------

create_phywin:
	push rax
	push rbx
	push rcx
	push rdx
	push rdi
	push rbp

	; Get a 2MB-aligned random address
.try_another_addr:
	mov  rcx, (2 * 1024 * 1024)
	call reserve_random
	test rax, 0x1FFFFF
	jnz  short .try_another_addr

	; Reserve the memory
	mov  rbx, qword [new_cr3]
	mov  rcx, rax
	mov  rdx, 0xcdf957edc7fb0dd6
	mov  rdi, (2 * 1024 * 1024)
	call mm_map_4k_range_int
	mov qword [r15 + boot_parameters.phy_window_base], rax

	; Map in the window
	mov  rcx, 4096
	call reserve_random
	mov  rbx, qword [new_cr3]
	mov  rcx, rax
	mov  rdx, rbp
	bts  rdx, 63 ; NX
	bts  rdx, 1  ; Writable
	bts  rdx, 0  ; Present
	mov  rdi, 4096
	call mm_map_4k_range
	mov qword [r15 + boot_parameters.phy_window_page_table], rax

	pop rbp
	pop rdi
	pop rdx
	pop rcx
	pop rbx
	pop rax
	ret
	
; -----------------------------------------------------------------------

; rcx -> New cr3
; rdx -> New rsp
; r8  -> New rip
; r9  -> New param
pivot:
	mov cr3, rcx
	mov rsp, rdx

	; Make room for the 'return address' and parameter homing on the stack
	sub rsp, 0x28

	; Set up one parameter to the function, which is the boot_parameters
	; structure.
	mov rdi, r9

	; Zero out all registers as we don't want to give any sensitive information
	; to the next stage.
	xor rax, rax
	mov rbx, rax
	mov rcx, rax
	mov rdx, rax
	mov rsi, rax
	mov rbp, rax
	mov  r9, rax
	mov r10, rax
	mov r11, rax
	mov r12, rax
	mov r13, rax
	mov r14, rax
	mov r15, rax
	jmp r8
pivot_size: equ ($-pivot)

; -----------------------------------------------------------------------

lm_halt:
	cli
	hlt
	jmp short lm_halt

; -----------------------------------------------------------------------

struc elf_shdr
	.sh_name:      resd 1
	.sh_type:      resd 1
	.sh_flags:     resq 1
	.sh_addr:      resq 1
	.sh_offset:    resq 1
	.sh_size:      resq 1
	.sh_link:      resd 1
	.sh_info:      resd 1
	.sh_addralign: resq 1
	.sh_entsize:   resq 1
endstruc

struc elf_phdr
	.p_type:   resd 1
	.p_flags:  resd 1
	.p_offset: resq 1
	.p_vaddr:  resq 1
	.p_paddr:  resq 1
	.p_filesz: resq 1
	.p_memsz:  resq 1
	.p_align:  resq 1
endstruc

struc elf_rela
	.r_offset: resq 1
	.r_info:   resq 1
	.r_addend: resq 1
endstruc

%define PT_LOAD 1

%define SHT_RELA 4

lm_elf_load:
	push rbx
	push rcx
	push rdx
	push rsi
	push rdi
	push r8
	push r9
	push r10
	push r11
	push r12
	push r13
	push r14

	; rbx - Pointer to ELF
	; rcx - Length of ELF
	mov rbx, qword [download_base]
	mov ecx, dword [pxenv_tftp_read_file.buffer_size]

	; Make sure file is large enough for ELF pointer
	cmp ecx, 0x40
	lm_assert ae, "ELF file too small"

	; Check for ELF header
	cmp dword [rbx], 0x464c457f
	lm_assert e, "ELF magic not found"

	; ELF must be 64-bit
	cmp byte [rbx+4], 2
	lm_assert e, "ELF was not 64-bit"

	; ELF must be little endian
	cmp byte [rbx+5], 1
	lm_assert e, "ELF was not little endian"

	; ELF must be version 1
	cmp byte [rbx+6], 1
	lm_assert e, "ELF was not version 1"

	; ELF must be a shared object
	cmp byte [rbx+0x10], 3
	lm_assert e, "ELF was not a shared object"
	
	; ELF must be for x86-64
	cmp byte [rbx+0x12], 0x3e
	lm_assert e, "ELF was not built for x86-64"

	; Make sure the ELF program entry size is what we expect
	cmp word [rbx+0x36], elf_phdr_size
	lm_assert e, "ELF program header entry size is not what we expected"

	; Get the offset to program headers and number of headers
	mov    r9, qword [rbx+0x20] ; Offset to program headers
	movzx rax,  word [rbx+0x38] ; Number of program headers

	; Make sure number of program headers is nonzero
	cmp rax, 0
	lm_assert a, "ELF had 0 program header entries"

	; Make sure program header offset is in bounds of file
	cmp r9, rcx
	lm_assert b, "ELF program header offset out of bounds"

	; Calculate the total program headers size
	imul r8, rax, elf_phdr_size

	; Calculate the length of header offset + total header size and check
	; for carry (unsigned overflow)
	add r8, r9
	lm_assert nc, "ELF overflow on phdr offset + phdr size"

	; Calculate ELF program headers are in bounds
	cmp r8, rcx
	lm_assert be, "ELF phdr offset + size is out of bounds"

.lewp:
	cmp dword [rbx + r9 + elf_phdr.p_type], PT_LOAD
	jne .next_phdr

	; Validate that the virtual size is >= the file size
	mov r10, qword [rbx + r9 + elf_phdr.p_memsz]
	cmp r10, qword [rbx + r9 + elf_phdr.p_filesz]
	lm_assert ae, "ELF virtual size is less than file size"

	; Get and page align the virtual address
	mov r11, qword [rbx + r9 + elf_phdr.p_vaddr]
	and r11, ~0xfff

	; Get and page align the ending address
	mov r10, qword [rbx + r9 + elf_phdr.p_vaddr]
	add r10, qword [rbx + r9 + elf_phdr.p_memsz]
	add r10,  0xfff
	and r10, ~0xfff
	sub r10, r11
	
	add r11, qword [load_base]

	push rbx
	push rcx

	; Allocate room for the memory
	mov  rcx, r10
	call lm_alloc

	mov r12, qword [rbx + r9 + elf_phdr.p_vaddr]
	and r12, 0xfff
	lea rdi, [rdx + r12]
	mov r12, qword [rbx + r9 + elf_phdr.p_offset]
	lea rsi, [rbx + r12]
	mov rcx, qword [rbx + r9 + elf_phdr.p_filesz]
	rep movsb

	; Map in this memory into the next stage's VM
	mov  rbx, qword [new_cr3]
	mov  rcx, r11
	mov  rdx, rdx
	or   rdx, 3
	mov  rdi, r10
	call mm_map_4k_range
	mov  rbx, cr3
	call mm_map_4k_range

	pop rcx
	pop rbx

.next_phdr:
	add r9, elf_phdr_size
	dec rax
	jnz .lewp

	mov    r9, qword [rbx+0x28] ; Offset to section headers
	movzx rax,  word [rbx+0x3c] ; Number of section headers

.lewp2:
	cmp dword [rbx + r9 + elf_shdr.sh_type], SHT_RELA
	jne .next_shdr

	cmp qword [rbx + r9 + elf_shdr.sh_entsize], elf_rela_size
	lm_assert e, "RELA size was not what was expected"

	push rax
	xor  rdx, rdx
	mov  rax, qword [rbx + r9 + elf_shdr.sh_size]
	mov  r12, elf_rela_size
	div  r12
	mov  r13, rax
	pop  rax

	test rdx, rdx
	lm_assert z, "Section size remainder"

	mov r12, qword [rbx + r9 + elf_shdr.sh_offset]

.relo_loop:
	mov r11, qword [rbx + r12 + elf_rela.r_offset]
	mov r14, qword [rbx + r12 + elf_rela.r_addend]

	mov rdi, qword [load_base]
	lea rsi, [rdi + r14]
	mov qword [rdi + r11], rsi

	add r12, elf_rela_size
	dec r13
	jnz short .relo_loop

.next_shdr:
	add r9, elf_shdr_size
	dec rax
	jnz .lewp2

	lm_printstr "Loaded ELF file!"

	mov rax, qword [rbx + 0x18]
	add rax, qword [load_base]

	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop rdi
	pop rsi
	pop rdx
	pop rcx
	pop rbx
	ret

; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

; Get a random 64-bit value into rax
; rax <- Random 64-bit value
rand:
	rdtsc
	pinsrq xmm0, rdx, 1
	pinsrq xmm0, rax, 0

	aesenc xmm0, xmm0
	aesenc xmm0, xmm0
	aesenc xmm0, xmm0
	aesenc xmm0, xmm0

	movq rax, xmm0
	ret

; Get a random page-aligned canonical 64-bit address
; rax <- Random 64-bit canon address
; rcx <- Size of range needed
reserve_random:
	push rbx
	push rcx
	push rdx
	push rsi
	push rbp

	; Page align the size
	add rcx,  0xfff
	and rcx, ~0xfff
	mov rsi, rcx

.regen_address:
	; Generate a random address
	call rand

	; Mask off the address to 48-bits, page aligned
	mov rbx, 0x0000FFFFFFFFF000
	and rax, rbx

	; Check to see if we should sign extend
	bt  rax, 47
	jnc short .no_sign_extend

	; Sign extend
	mov rbx, 0xFFFF000000000000
	or  rax, rbx

.no_sign_extend:
	; Save off address
	mov rbp, rax

	; Check for integer overflow
	lea rdx, [rbp + rsi]
	cmp rdx, rbp
	jbe .regen_address

	; See if the range fits within the first canon range
	mov  rax, rbp
	lea  rbx, [rbp + rsi - 1]
	mov  rcx, 0x0000008000000000
	mov  rdx, 0x00007FFFFFFFFFFF
	call lm_contains
	test eax, eax
	jnz  .address_good

	; See if the range fits within the second canon range
	mov  rax, rbp
	lea  rbx, [rbp + rsi - 1]
	mov  rcx, 0xFFFF800000000000
	mov  rdx, 0xFFFFFF7FFFFFFFFF
	call lm_contains
	test eax, eax
	jnz  .address_good

	; Address was bad, try another
	jmp .regen_address

.address_good:
	mov rax, rbp

	pop rbp
	pop rsi
	pop rdx
	pop rcx
	pop rbx
	ret

; rcx -> Size to allocate
; rdx -> Allocation
lm_alloc:
	push rax
	push rbx
	push rcx
	push rdi

	test rcx, rcx
	lm_assert nz, "Attempted to allocate zero bytes"

	; Page align the length
	add rcx,  0xfff
	and rcx, ~0xfff
	mov rdx,  rcx

	lock xadd qword [lm_linear_map_ptr], rdx

	; rcx - Allocation length
	; rdx - Alloction

	; Check for OOM
	mov rax, LM_LINEAR_ALLOC_BASE + LM_LINEAR_ALLOC_SIZE
	lea rbx, [rdx + rcx]
	cmp rbx, rax
	lm_assert be, "Linear allocator out of memory"

	; Zero out the memory
	mov rdi, rdx
	xor rax, rax
	rep stosb

	pop rdi
	pop rcx
	pop rbx
	pop rax
	ret

; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

; rbx -> cr3 to operate on
; rcx -> Virtual address to map
; rdx -> Entry to populate with
; rdi -> Size (in bytes) to map
; rbp <- Pointer to page table that describes last entry
mm_map_4k_range_int:
	push rcx
	push rdx
	push rdi

	test rdi, rdi
	lm_assert nz, "Attempted to map range of zero bytes"

	; Page-align the size
	add rdi,  0xfff
	and rdi, ~0xfff

.lewp:
	call mm_map_4k

	add rcx, 0x1000
	add rdx, 0x1000
	sub rdi, 0x1000
	jnz short .lewp

	pop rdi
	pop rdx
	pop rcx
	ret

mm_map_4k_range:
	push rbp
	call mm_map_4k_range_int
	pop  rbp
	ret

; rbx -> cr3 to operate on
; rcx -> Virtual address to map
; rdx -> Entry to populate with
; rbp <- Pointer to page table that describes last entry
mm_map_4k:
	push rax
	push rbx
	push rsi
	push rdi
	sub  rsp, 4*8

	; Create the mask we use to mask out the next table addresses
	mov rax, 0x0000FFFFFFFFF000

	; Get the physical memory address of the page table base
	and rbx, rax
	
	; Get all the subcomponents of the virtual address
	mov rbp, rcx
	shr rbp, 39
	and rbp, 0x1ff
	mov [rsp + 3*8], rbp
	mov rbp, rcx
	shr rbp, 30
	and rbp, 0x1ff
	mov [rsp + 2*8], rbp
	mov rbp, rcx
	shr rbp, 21
	and rbp, 0x1ff
	mov [rsp + 1*8], rbp
	mov rbp, rcx
	shr rbp, 12
	and rbp, 0x1ff
	mov [rsp + 0*8], rbp

	; Loop 3 times, for each table except for the final one
	mov rbp, 3
.lewp:
	; Check if this page table entry already exists
	mov  rsi, [rsp + rbp*8]
	mov  rdi, [rbx + rsi*8]
	test rdi, rdi
	jnz  short .next_entry

	; Allocate a next level page table
	push rcx
	push rdx
	mov  rcx, 4096
	call lm_alloc
	mov  rdi, rdx
	or   rdi, 7
	mov  [rbx + rsi*8], rdi
	pop  rdx
	pop  rcx

.next_entry:
	; Make sure that this entry is present
	test rdi, 1
	lm_assert nz, "Page table entry not present"

	; Make sure that this entry describes a table and not an entry
	test rdi, 0x80
	lm_assert z, "Page table entry describes large page, not supported"

	; Mask off the entry to get the next level address
	and rdi, rax
	mov rbx, rdi

	dec rbp
	jnz .lewp

	; For the final table check if there is an entry present. If there is
	; error out.
	mov rsi, [rsp]
	cmp qword [rbx + rsi*8], 0
	lm_assert e, "Page table entry already present"

	; Fill in the entry with what was requested
	mov [rbx + rsi*8], rdx
	mov rbp, rbx

	; Invalidate the page tables for this virtual address
	invlpg [rcx]

	add rsp, 4*8
	pop rdi
	pop rsi
	pop rbx
	pop rax	
	ret

; -----------------------------------------------------------------------

; Scroll up the screen one line, and then print out the string pointed to by
; rbx with length rcx at the bottom.
;
; rbx -> String to print
; rcx -> Length of string to print
lm_puts:
	push rax
	push rbx
	push rcx
	push rsi
	push rdi

	; Save off count
	push rcx

	; Copy up the bottom 24 lines of the screen one line up
	mov rdi, 0xb8000
	mov rsi, 0xb8000 + (80 * 2)
	mov rcx, (80 * 2 * 24) / 4
	rep movsd

	; Clear out the last line on the screen
	mov rdi, 0xb8000 + (80 * 2 * 24)
	mov rcx, (80 * 2) / 4
	xor rax, rax
	rep stosd

	; Restore the count
	pop rcx

	; If the string is of zero length, don't attempt to print it.
	test rcx, rcx
	jz   short .end

	; Cap the string length at 80 bytes
	mov   rax, 80
	cmp   rcx, rax
	cmova rcx, rax

	; Print out the string to the last line of the screen.
	mov rdi, 0xb8000 + (80 * 2 * 24)
	mov  ah, 0xf
.lewp:
	mov al, byte [rbx]
	stosw

	inc rbx
	dec rcx
	jnz short .lewp

.end:
	pop rdi
	pop rsi
	pop rcx
	pop rbx
	pop rax
	ret

; This function returns 1 if [x1, x2] and [y1, y2] have any overlap and 0
; if there is no overlap.
; rax -> x1
; rbx -> x2
; rcx -> y1
; rdx -> y2
; eax <- Overlap?
lm_overlaps:
	cmp rax, rdx
	ja  short .no_overlap

	cmp rcx, rbx
	ja  short .no_overlap

	mov eax, 1
	ret

.no_overlap:
	xor eax, eax
	ret

; This function returns 1 if the entirety of [x1, x2] is contained inside
; of [y1, y2], else returns 0.
; rax -> x1
; rbx -> x2
; rcx -> y1
; rdx -> y2
; eax <- Contains?
lm_contains:
	cmp  rax, rcx
	jnae short .no_contains

	cmp  rbx, rdx
	jnbe short .no_contains

	mov eax, 1
	ret

.no_contains:
	xor eax, eax
	ret

; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
; Data starts here
; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
align 16
data_section:

; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

; 16-bit real mode GDT

align 8
rmgdt_base:
	dq 0x0000000000000000 ; Null descriptor
	dq 0x00009a000000ffff ; 16-bit RO code, base 0, limit 0x0000ffff
	dq 0x000092000000ffff ; 16-bit RW data, base 0, limit 0x0000ffff

rmgdt:
	dw (rmgdt - rmgdt_base) - 1
	dq rmgdt_base

; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

; 64-bit long mode GDT

align 8
lmgdt_base:
	dq 0x0000000000000000 ; Null descriptor
	dq 0x00209a0000000000 ; 64-bit, present, code
	dq 0x0000920000000000 ; Present, data r/w

lmgdt:
	dw (lmgdt - lmgdt_base) - 1
	dq lmgdt_base

; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

align 16
rm_linear_map_ptr: dq 0
lm_linear_map_ptr: dq 0
load_base:         dq 0
new_cr3:           dq 0
lm_stacks:         dq 0

; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

; Used for storage of the !PXE real mode API entry seg:off
pxe_off: dw 0
pxe_seg: dw 0

pxenv_tftp_read_file:
	.status:   dw 0
	.filename: db "grilled_cheese.kern"
	times (128-($-.filename)) db 0
	.buffer_size:       dd 0
	.buffer:            dd 0
	.server_ip:         dd 0
	.gateway_ip:        dd 0
	.mcast_ip:          dd 0
	.udp_client_port:   dw 0x4500
	.udp_server_port:   dw 0x4500
	.tftp_open_timeout: dw 5
	.tftp_reopen_delay: dw 5

pxe_cached_info:
	.status:     dw 0
	.packettype: dw 2 ; DHCKACK packet

	.buffer_size:  dw 0
	.buffer_off:   dw 0
	.buffer_seg:   dw 0
	.buffer_limit: dw 0

download_base: dq 0

; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

align 16
stack: times 4096 db 0
top_of_stack:

times 0x6400-($-$$) db 0
e820_map: times ((E820_MAP_MAX * 20) + 4) db 0

