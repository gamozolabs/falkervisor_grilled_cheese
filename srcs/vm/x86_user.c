#include <grilled_cheese.h>
#include <vm/vm.h>

rstate_t
x86_user_create(_In_ struct _vm *vm)
{
	vm->step       = x86_user_step;
	vm->map_phys   = x86_user_map_phys;
	vm->dump_state = x86_user_dump_state;
	vm->guest_phys_to_host_phys = x86_user_guest_virt_to_host_phys;
	vm->guest_virt_to_host_phys = x86_user_guest_virt_to_host_phys;

	return RSTATE_SUCCESS;
}

rstate_t
x86_user_step(_In_ struct _vm *vm)
{
	return RSTATE_SUCCESS;
}

rstate_t
x86_user_map_phys(
		_In_ struct _vm *vm,
		_In_ uint64_t    address,
		_In_ int         readable,
		_In_ int         writable,
		_In_ int         executable,
		_In_ uint64_t    backing_page)
{
	return RSTATE_SUCCESS;
}

void
x86_user_dump_state(_In_ struct _vm *vm)
{
	vm_x86_dump_state(vm);
	return;
}

rstate_t
x86_user_guest_virt_to_host_phys(
		_In_  struct _vm *vm,
		_In_  uint64_t    guest_vaddr,
		_In_  int         is_read,
		_In_  int         is_write,
		_In_  int         is_exec,
		_Out_ uintptr_t  *host_paddr)
{
	return RSTATE_SUCCESS;
}

