#pragma once

struct _vm;

enum _vm_type {
	GUEST_X86
};

enum _vm_subtype {
	X86_USER,
	X86_SVM,
	X86_VTX
};

#include <vm/vm_x86.h>
#include <vm/x86_user.h>
#include <fuzzers/helpers.h>

struct _vm {
	enum _vm_type    type;
	enum _vm_subtype subtype;

	/* Register state for each arch */
	union {
		struct _x86_regs x86_regs;
	} regs;

	union {
		/* State for SVM based x86 VMs */
		struct _svm_vm *svm_state;
	} state;

	struct _modlist *modlist;
	uint64_t modlist_ents;

	rstate_t (*step)(struct _vm *vm);

	rstate_t (*map_phys)(struct _vm *vm, uint64_t address,
			int readable, int writable, int executable,
			uint64_t backing_page);

	rstate_t (*npf_handler)(struct _vm *vm, uint64_t address,
			int read_access, int write_access, int exec_access,
			int *handled);

	rstate_t (*guest_phys_to_host_phys)(
		struct _vm *vm,
		uint64_t    guest_paddr,
		int         is_read,
		int         is_write,
		int         is_exec,
		uint64_t   *host_paddr);

	rstate_t (*guest_virt_to_host_phys)(
		struct _vm *vm,
		uint64_t    guest_vaddr,
		int         is_read,
		int         is_write,
		int         is_exec,
		uint64_t   *host_paddr);

	void (*dump_state)(struct _vm *vm);
};

rstate_t
vm_create(const char *core_fn, struct _vm **out_vm);

rstate_t
vm_read_phys(
		struct _vm *vm,
		uint64_t    guest_paddr,
		void       *buf,
		uint64_t    len);

rstate_t
vm_write_phys(
		struct _vm *vm,
		uint64_t    guest_paddr,
		const void *buf,
		uint64_t    len);

rstate_t
vm_read_virt(
		struct _vm *vm,
		uint64_t    guest_vaddr,
		void       *buf,
		uint64_t    len);

rstate_t
vm_write_virt(
		struct _vm *vm,
		uint64_t    guest_vaddr,
		const void *buf,
		uint64_t    len);

