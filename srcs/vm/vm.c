#include <grilled_cheese.h>
#include <generic/stdlib.h>
#include <mm/mm.h>
#include <vm/vm.h>
#include <vm/svm.h>
#include <net/net.h>
#include <disp/disp.h>

enum _elf_bitness {
	ELF_32BIT = 1,
	ELF_64BIT = 2
};

enum _elf_endianness {
	ELF_LITTLE_ENDIAN = 1,
	ELF_BIG_ENDIAN = 2
};

#define ELF_READ_FIELD(name) \
	((elf32->endianness == ELF_LITTLE_ENDIAN) ? elf32->name : byteswap(elf32->name))

#pragma pack(push, 1)
struct _elf_header32 {
	uint8_t  sig[4];
	uint8_t  bitness;
	uint8_t  endianness;
	uint8_t  version;
	uint8_t  abi;
	uint8_t  abi_version;
	uint8_t  padding[7];
	uint16_t type;
};

struct _elf_header64 {
	uint8_t  sig[4];
	uint8_t  bitness;
	uint8_t  endianness;
	uint8_t  version;
	uint8_t  abi;
	uint8_t  abi_version;
	uint8_t  padding[7];
	uint16_t type;
};
#pragma pack(pop)

rstate_t
vm_create(const char *core_fn, struct _vm **out_vm)
{
	uint8_t  *core_file;
	uint64_t  core_file_len;

	struct _vm *vm;

	struct _elf_header32 *elf32 = NULL;

	RSTATE_LOCALS;

	/* Allocate room for the VM structure */
	rstate = phalloc(sizeof(struct _vm), (void**)&vm);
	RSCHECK_NESTED("Failed to allocate memory for VM structure");

	/* Map in the core file */
	rstate = net_map_remote(current_cpu->net_queue, core_fn, 0,
			(void**)&core_file, &core_file_len);
	RSCHECK_NESTED("Failed to map remote core file");

	/* Make sure we have room for the smallest possible header */
	RSCHECK(core_file_len >= sizeof(struct _elf_header32),
			"Core file too small for 32-bit ELF header");

	/* Cast the core file to an ELF header */
	elf32 = (struct _elf_header32*)core_file;

	/* Validate the ELF signature */
	RSCHECK(!memcmp(elf32->sig, "\x7f\x45\x4c\x46", 4),
			"Core file did not have ELF signature");

	/* Make sure the bitness of the ELF is 32-bit or 64-bit */
	RSCHECK(elf32->bitness == ELF_32BIT || elf32->bitness == ELF_64BIT,
			"Core file bitness was not 32bit or 64bit");

	/* If it's a 64-bit file, it has a larger ELF header, thus do another
	 * bounds check for the new size.
	 */
	if(elf32->bitness == ELF_64BIT){
		RSCHECK(core_file_len >= sizeof(struct _elf_header64),
				"Core file too small for 64-bit ELF header");
	}

	/* Make sure the endianness of the ELF is little or big */
	RSCHECK(elf32->endianness == ELF_LITTLE_ENDIAN ||
			elf32->endianness == ELF_BIG_ENDIAN,
			"Core file endianness was neither big or little");

	/* Check the ELF version to be 1 */
	RSCHECK(elf32->version == 1, "Core file version was not 1");

	printf("Core file is %s-bit %s-endian %.4lx",
			(elf32->bitness == ELF_64BIT) ? "64" : "32",
			(elf32->endianness == ELF_LITTLE_ENDIAN) ? "little" : "big",
			byteswap(elf32->type));

	*out_vm = vm;

	rstate_ret = RSTATE_SUCCESS;
cleanup:
	RSTATE_RETURN;
}

/* vm_read_phys()
 *
 * Summary:
 *
 * Read memory from the guest vm at physical address guest_paddr into the
 * caller allocated buffer specified by buf and len.
 */
rstate_t
vm_read_phys(
		struct _vm *vm,
		uint64_t    guest_paddr,
		void       *buf,
		uint64_t    len)
{
	uint8_t  *ubuf = buf, *vaddr, *cur_map = NULL;
	uint64_t  paddr = 0;

	RSTATE_LOCALS;

	while(len){
		if(!(paddr & 0xfff)){
			rstate = vm->guest_phys_to_host_phys(vm, guest_paddr,
					1, 0, 0, &paddr);
			RSCHECK_NESTED("Could not get backing for guest address");

			if(cur_map){
				mm_release_phys_mapping(cur_map);
			}

			vaddr = cur_map = mm_get_phys_mapping(paddr);
		}

		*ubuf = *vaddr;

		ubuf++;
		paddr++;
		vaddr++;
		guest_paddr++;
		len--;
	}

	rstate_ret = RSTATE_SUCCESS;
cleanup:
	if(cur_map){
		mm_release_phys_mapping(cur_map);
	}

	RSTATE_RETURN;
}

/* vm_write_phys()
 *
 * Summary:
 *
 * Write the vm's physical memory at guest_paddr with the contents of buf
 * for len bytes.
 */
rstate_t
vm_write_phys(
		struct _vm *vm,
		uint64_t    guest_paddr,
		const void *buf,
		uint64_t    len)
{
	uint8_t  *vaddr, *cur_map = NULL;
	uint64_t  paddr = 0;
	const uint8_t *ubuf = buf;

	RSTATE_LOCALS;

	while(len){
		if(!(paddr & 0xfff)){
			rstate = vm->guest_phys_to_host_phys(vm, guest_paddr,
					0, 1, 0, &paddr);
			RSCHECK_NESTED("Could not get backing for guest address");

			if(cur_map){
				mm_release_phys_mapping(cur_map);
			}

			vaddr = cur_map = mm_get_phys_mapping(paddr);
		}

		*vaddr = *ubuf;

		ubuf++;
		paddr++;
		vaddr++;
		guest_paddr++;
		len--;
	}

	rstate_ret = RSTATE_SUCCESS;
cleanup:
	if(cur_map){
		mm_release_phys_mapping(cur_map);
	}

	RSTATE_RETURN;
}

rstate_t
vm_read_virt(
		struct _vm *vm,
		uint64_t    guest_vaddr,
		void       *buf,
		uint64_t    len)
{
	uint8_t *ubuf = buf, *vaddr, *cur_map = NULL;
	uint64_t paddr = 0;

	RSTATE_LOCALS;

	while(len){
		if(!(paddr & 0xfff)){
			rstate = vm->guest_virt_to_host_phys(vm, guest_vaddr,
					1, 0, 0, &paddr);
			RSCHECK_NESTED("Could not get backing for guest address");

			if(cur_map){
				mm_release_phys_mapping(cur_map);
			}

			vaddr = cur_map = mm_get_phys_mapping(paddr);
		}

		*ubuf = *vaddr;

		ubuf++;
		paddr++;
		vaddr++;
		guest_vaddr++;
		len--;
	}

	rstate_ret = RSTATE_SUCCESS;
cleanup:
	if(cur_map){
		mm_release_phys_mapping(cur_map);
	}

	RSTATE_RETURN;
}

rstate_t
vm_write_virt(
		struct _vm *vm,
		uint64_t    guest_vaddr,
		const void *buf,
		uint64_t    len)
{
	uint8_t *vaddr, *cur_map = NULL;
	uint64_t paddr = 0;
	const uint8_t *ubuf = buf;

	RSTATE_LOCALS;

	while(len){
		if(!(paddr & 0xfff)){
			rstate = vm->guest_virt_to_host_phys(vm, guest_vaddr,
					0, 1, 0, &paddr);
			RSCHECK_NESTED("Could not get backing for guest address");

			if(cur_map){
				mm_release_phys_mapping(cur_map);
			}

			vaddr = cur_map = mm_get_phys_mapping(paddr);
		}

		*vaddr = *ubuf;

		ubuf++;
		paddr++;
		vaddr++;
		guest_vaddr++;
		len--;
	}

	rstate_ret = RSTATE_SUCCESS;
cleanup:
	if(cur_map){
		mm_release_phys_mapping(cur_map);
	}

	RSTATE_RETURN;
}

