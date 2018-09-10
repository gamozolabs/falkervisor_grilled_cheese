#pragma once

struct _x86_user_state {
	uintptr_t guest_cr3;

	void *pivot_addr;
};

rstate_t
x86_user_create(_In_ struct _vm *vm);

rstate_t
x86_user_step(_In_ struct _vm *vm);

rstate_t
x86_user_map_phys(
		_In_ struct _vm *vm,
		_In_ uint64_t    address,
		_In_ int         readable,
		_In_ int         writable,
		_In_ int         executable,
		_In_ uint64_t    backing_page);

void
x86_user_dump_state(_In_ struct _vm *vm);

rstate_t
x86_user_guest_virt_to_host_phys(
		_In_  struct _vm *vm,
		_In_  uint64_t    guest_vaddr,
		_In_  int         is_read,
		_In_  int         is_write,
		_In_  int         is_exec,
		_Out_ uintptr_t  *host_paddr);

