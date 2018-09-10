#include <grilled_cheese.h>
#include <vm/vm.h>
#include <vm/svm.h>
#include <disp/disp.h>
#include <time/time.h>
#include <mm/mm.h>
#include <generic/stdlib.h>
#include <disk/ide.h>

static uint64_t VM_MEMORY_SIZE = (4UL * 1024 * 1024 * 1024);

rstate_t
x86_passthrough_npf_handler(struct _vm *vm, uint64_t address,
		int read_access, int write_access, int exec_access,
		int *handled)
{
	uintptr_t page;

	RSTATE_LOCALS;

	if(address >= VM_MEMORY_SIZE){
		*handled = 0;
		return RSTATE_SUCCESS;
	}

	rstate = alloc_phys_4k(&page);
	RSCHECK_NESTED("Failed to allocate 4k page");

	rstate = vm->map_phys(vm, address & ~0xfff, 1, 1, 1, page);
	RSCHECK_NESTED("Failed to map in physical memory");

	*handled = 1;
	rstate_ret = RSTATE_SUCCESS;
cleanup:
	RSTATE_RETURN;
}

rstate_t
iommu_init(struct _vm *vm)
{
	int ii;

	uint8_t *dev_table;

	uint64_t  iommu_addr, key;
	uintptr_t device_table;
	uint64_t  device_table_entry = (1UL << 62) | (1UL << 61) | \
								   (4 << 9) | (1 << 1) | (1 << 0);

	RSTATE_LOCALS;

	device_table_entry |= vm->state.svm_state->vmcb->n_cr3;

	outd(0xcf8, (0x00 << 16) | (0x00 << 11) | (0x02 << 8) | (1 << 31) | 0x44);
	iommu_addr = ind(0xcfc) & ~0x3FFF;
	outd(0xcf8, (0x00 << 16) | (0x00 << 11) | (0x02 << 8) | (1 << 31) | 0x48);
	iommu_addr |= (uint64_t)ind(0xcfc) << 32;

	rstate = alloc_phys(2 * 1024 * 1024, &device_table);
	RSCHECK_NESTED("Failed to map in device table");

	rstate = mm_reserve_random(readcr3(), 2 * 1024 * 1024,
			(void*)&dev_table, 0, &key);
	RSCHECK_NESTED("Failed to reserve room to map in IOMMU device table");

	rstate = mm_map_contig(readcr3(), (uintptr_t)dev_table,
			device_table | 3 | (1UL << 63), 2 * 1024 * 1024, key);
	RSCHECK_NESTED("Failed to map in IOMMU device table");

	memset(dev_table, 0, 2 * 1024 * 1024);

	for(ii = 0; ii < (2 * 1024 * 1024); ii += 32){
		*(volatile uint64_t*)(dev_table + ii) = device_table_entry;
	}

	{
		uint8_t *tmp;

		tmp = mm_get_phys_mapping(iommu_addr);
		*(volatile uint64_t*)(tmp + 0x00)  = device_table | 0x1ff;
		*(volatile uint64_t*)(tmp + 0x18) |= 1;
		mm_release_phys_mapping(tmp);
	}

	rstate_ret = RSTATE_SUCCESS;
cleanup:
	RSTATE_RETURN;
}

rstate_t
x86_passthrough_start(void)
{
	struct _vm *vm;
	struct _vmcb *vmcb;

	RSTATE_LOCALS;

	rstate = vm_x86_create(&vm, X86_SVM);
	RSCHECK_NESTED("Failed to create x86 VM");

	vm->npf_handler = x86_passthrough_npf_handler;

	vmcb = vm->state.svm_state->vmcb;

	vmcb->CR_icpt = 0xFFE6FFE6;
	vmcb->DR_icpt = 0xffffffff;

	/* Intercept #DBs */
	vmcb->except_icpt = (1 << 1);

	/* Intercept software interrupts */
	vmcb->icpt_set_1 = (1 << 21) | (1 << 27) | (0 << 28) | (1 << 30) |
		(1 << 31) | 0x1f;

	/* Intercept VMRUN */
	vmcb->icpt_set_2 = 1;

	{
		uint8_t buf[512];

		rstate = ide_pio_read_sectors(0, buf, sizeof(buf));
		RSCHECK_NESTED("Failed to read MBR");

		rstate = vm_write_phys(vm, 0x7c00, buf, sizeof(buf));
		RSCHECK_NESTED("Failed to write MBR ot 0x7c00");
	}

	printf("VM created");

do_more:
	rstate = vm->step(vm);
	RSCHECK_NESTED("Failed to step VM");

	vm_read_phys(vm, vm->regs.x86_regs.cs_base + vm->regs.x86_regs.rip.rip,
			&vmcb->guest_inst[0], 8);

	if(vmcb->exitcode == 0x75){
		if(vmcb->exitinfo1 == 0x13){
			if(vm->regs.x86_regs.rax.b.ah == 0x41){
				/* BIOS extensions check */
				vm->regs.x86_regs.rbx.bx   = 0xaa55;
				vm->regs.x86_regs.rcx.cx   = 3;
				vm->regs.x86_regs.rfl.u.cf = 0;
				vm->regs.x86_regs.rax.rax  = 0x100;
				vm->regs.x86_regs.rip.rip += 2;
				goto do_more;
			} else if(vm->regs.x86_regs.rax.b.ah == 0x42){
				/* Int 13,42 - Extended read
				 * ah    - 0x42
				 * dl    - Drive number
				 * ds:si - Disk packet address
				 */

#pragma pack(push, 1)
				struct {
					uint8_t  packet_size;
					uint8_t  reserved;
					uint16_t block_count;
					uint16_t offset;
					uint16_t segment;
					uint64_t lba;
					uint64_t buffer64;
				} disk_packet;
#pragma pack(pop)

				uint64_t addr;
				uint64_t packet_addr = vm->regs.x86_regs.ds_base + vm->regs.x86_regs.rsi.si;

				rstate = vm_read_phys(vm, packet_addr, &disk_packet,
						sizeof(disk_packet));
				RSCHECK_NESTED("Failed to read disk packet for BIOS 13,42");

				addr = ((uint64_t)disk_packet.segment << 4) +
					(uint64_t)disk_packet.offset;

				printf("Reading %.16lx to %.16lx %u", disk_packet.lba,
						addr, disk_packet.block_count);

				while(disk_packet.block_count){
					uint8_t sector[512];

					rstate = ide_pio_read_sectors(disk_packet.lba,
							sector, sizeof(sector));
					RSCHECK_NESTED("Failed to read sector");

					rstate = vm_write_phys(vm, addr, sector, sizeof(sector));
					RSCHECK_NESTED("Failed to write sector into guest");

					disk_packet.lba++;
					addr += 512;
					disk_packet.block_count--;
				}

				vm->regs.x86_regs.rax.b.ah  = 0;
				vm->regs.x86_regs.rfl.u.cf  = 0;
				vm->regs.x86_regs.rip.rip  += 2;
				goto do_more;
			} else if(vm->regs.x86_regs.rax.b.ah == 0x48){
				/* Int 13,48 - Get drive parameters
				 * ah    - 48
				 * dl    - Drive
				 * ds:si - Buffer to get drive parameters.
				 */

#pragma pack(push, 1)
				struct {
					uint16_t size;
					uint16_t info;
					uint32_t num_cyls;
					uint32_t num_heads;
					uint32_t num_sectors_per_track;
					uint64_t num_sectors;
					uint16_t bytes_per_sector;
				} disk_params;
#pragma pack(pop)

				uint64_t params_addr =
					vm->regs.x86_regs.ds_base + vm->regs.x86_regs.rsi.si;

				disk_params.size                  = sizeof(disk_params);
				disk_params.info                  = 0;
				disk_params.num_cyls              = 0;
				disk_params.num_heads             = 0;
				disk_params.num_sectors_per_track = 0;
				disk_params.num_sectors           = (900UL * 1024 * 1024 * 1024) / 512;
				disk_params.bytes_per_sector      = 512;

				rstate = vm_write_phys(vm, params_addr, &disk_params,
						sizeof(disk_params));
				RSCHECK_NESTED("Failed to write drive parameters into guest");

				vm->regs.x86_regs.rax.rax   = 0;
				vm->regs.x86_regs.rfl.u.cf  = 0;
				vm->regs.x86_regs.rip.rip  += 2;
				goto do_more;
			} else if(vm->regs.x86_regs.rax.b.ah == 0x08){
				/* Int 13,08 - Get drive parameters */

				vm->regs.x86_regs.rax.b.ah  = 0x00; /* Success */
				vm->regs.x86_regs.rbx.b.bl  = 0x00; /* Drive type */
				vm->regs.x86_regs.rcx.b.ch  = 0xff; /* Max cylinder number */
				vm->regs.x86_regs.rcx.b.cl  = 0xff; /* Max sector number */
				vm->regs.x86_regs.rdx.b.dh  = 0xff; /* Max head number */
				vm->regs.x86_regs.rdx.b.dl  = 0x01; /* Number of drives */
				vm->regs.x86_regs.rfl.u.cf  = 0;
				vm->regs.x86_regs.rip.rip  += 2;
				goto do_more;
			} else if(vm->regs.x86_regs.rax.b.ah == 0x15){
				/* Int 13,15 - Get disk type */

				vm->regs.x86_regs.rax.b.ah  = 3;
				vm->regs.x86_regs.rcx.cx    = 0xffff;
				vm->regs.x86_regs.rdx.dx    = 0xffff;
				vm->regs.x86_regs.rfl.u.cf  = 0;
				vm->regs.x86_regs.rip.rip  += 2;
				goto do_more;
			}

			goto unhandled_vmexit;
		} else if(vmcb->exitinfo1 == 0x15){
			if(vm->regs.x86_regs.rax.ax == 0xe820){
				struct {
					uint64_t base;
					uint64_t size;
					uint32_t type;
					uint32_t cont;
				} e820_table[3] = {
					{ 0x000000000, 0x000009e000, 1, 1 },
					{ 0x000100000, 0x0000600000, 1, 2 },
					{ 0x000e10000, 0x00cf04f000, 1, 0 },
				};

				uint64_t addr = vm->regs.x86_regs.es_base + vm->regs.x86_regs.rdi.di;

				RSCHECK(vm->regs.x86_regs.rbx.ebx <= 2, "E820 access out of bounds");

				rstate = vm_write_phys(vm, addr,
						&e820_table[vm->regs.x86_regs.rbx.ebx], 20);
				RSCHECK_NESTED("Failed to write E820 table to guest");

				vm->regs.x86_regs.rbx.ebx   = e820_table[vm->regs.x86_regs.rbx.ebx].cont;
				vm->regs.x86_regs.rcx.ecx   = 20;
				vm->regs.x86_regs.rax.eax   = 0x534d4150;
				vm->regs.x86_regs.rfl.u.cf  = 0;
				vm->regs.x86_regs.rip.rip  += 2;
				goto do_more;
			} else {
				vm->regs.x86_regs.rfl.u.cf  = 1; /* Error */
				vm->regs.x86_regs.rip.rip  += 2;
				goto do_more;
			}
		} else if(vmcb->exitinfo1 == 0x1a){
			if(vm->regs.x86_regs.rax.b.ah == 0){
				/* Get system time
				 * cx:dx - Clock ticks since midnight (18.2 ticks per second)
				 */

				uint64_t time = rdtsc_uptime() / 54945;

				vm->regs.x86_regs.rcx.cx = (uint16_t)(time >> 16);
				vm->regs.x86_regs.rdx.dx = (uint16_t)(time >>  0);

				vm->regs.x86_regs.rip.rip += 2;
				goto do_more;
			} else if(vm->regs.x86_regs.rax.b.ah == 0xbb){
				/* Some seemingly undocumented TPM function. Return error */
				vm->regs.x86_regs.rfl.u.cf  = 1; /* Error */
				vm->regs.x86_regs.rip.rip  += 2;
				goto do_more;
			}
		} else if(vmcb->exitinfo1 == 0x10){
			vm->regs.x86_regs.rfl.u.cf  = 1; /* Error */
			vm->regs.x86_regs.rip.rip  += 2;
			goto do_more;
		} else if(vmcb->exitinfo1 == 0x16){
			if(vm->regs.x86_regs.rax.b.ah == 0x11){
				/* Check for enhanced keystroke, return no key */
				vm->regs.x86_regs.rfl.u.zf  = 0;
				vm->regs.x86_regs.rip.rip  += 2;
				goto do_more;
			} else if(vm->regs.x86_regs.rax.b.ah == 0x10){
				/* Keystroke */
				vm->regs.x86_regs.rax.b.ah  = 0x0a;
				vm->regs.x86_regs.rax.b.al  = 0x0a;
				vm->regs.x86_regs.rip.rip  += 2;
				goto do_more;
			}
		}

		goto unhandled_vmexit;
	} else if(vmcb->exitcode == 0x7b){
		uint16_t port = (vmcb->exitinfo1 >> 16) & 0xffff;

		if(port == 0x64 || port == 0x60){
			vm->regs.x86_regs.rip.rip = vmcb->exitinfo2;
			goto do_more;
		}
	} else if(vmcb->exitcode == 0x60){
		/* External interrupt, this is our timer interrupt,
		 * does not affect VM
		 */
		goto do_more;
	}

unhandled_vmexit:
	vm->dump_state(vm);
	rstate_ret = RSTATE_SUCCESS;
cleanup:
	RSTATE_RETURN;
}

