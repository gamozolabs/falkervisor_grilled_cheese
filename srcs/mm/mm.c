#include <grilled_cheese.h>
#include <mm/mm.h>
#include <disp/disp.h>
#include <generic/stdlib.h>
#include <interrupts/interrupts.h>
#include <cpu/acpi.h>

#pragma pack(push, 1)
static struct _e820_map {
	uint32_t num_entries;

	struct {
		uint64_t base;
		uint64_t size;
		uint32_t type;
	} entries[256];
} *e820_map = NULL;
#pragma pack(pop)

/* Linked list containing the memory managment keys. When a page fault occurs
 * the keys are walked to determine if there is a handler for the faulted
 * page. If so, the handler is invoked.
 */
static struct _mm_key  mm_keys_base = { 0 };
static struct _mm_key *mm_keys_end  = &mm_keys_base;

static struct {
	/* Amount of memory currently in use by the OS, in bytes.
	 * Grows when allocations are made.
	 * Shrinks when frees are made.
	 */
	volatile uint64_t inuse_memory;

	/* Amount of physical memory consumed by the OS, in bytes.
	 * Grows when a freelist is empty, forcing a new allocation from the
	 * physical pool.
	 */
	volatile uint64_t consumed_memory;

	/* Amount of memory reported as free by the e820 map, in bytes.
	 * This value is constant.
	 */
	uint64_t usable_memory;

	/* Amount of memory reported by the e820 map, all categories, in bytes.
	 * This value is constant.
	 */
	uint64_t total_memory;
} mem_stats = { 0 };

static rstate_t
mm_map_4k_nolock_int(
		_In_  uintptr_t  cr3,
		_In_  uintptr_t  addr,
		_In_  uint64_t   value,
		_In_  uint64_t   key,
		_Out_ uintptr_t *pte_addr);

/* mm_acquire_paging_lock()
 *
 * Summary:
 *
 * This function disables interrupts and then acquires the global lock on
 * paging related structures.
 */
void
mm_acquire_paging_lock(void)
{
	interrupts_disable();
	spinlock_acquire(PAGE_TABLE_LOCK);
	return;
}

/* mm_release_paging_lock()
 *
 * Summary:
 *
 * This function releases the global paging lock and then enables interrupts.
 */
void
mm_release_paging_lock(void)
{
	spinlock_release(PAGE_TABLE_LOCK);
	interrupts_enable();
	return;
}

/* page_fault()
 *
 * Summary:
 *
 * This function is the handler for page fault exceptions. It is responsible
 * for walking the keys linked list to find a specific handler for a page
 * fault or returning a failure on an unhandled page fault.
 *
 * Parameters:
 *
 * _In_ vector - Exception vector. Should always be 14 for a page fault.
 * _In_ iret   - Pointer to iret frame.
 * _In_ error  - Error code pushed to the stack for the page fault exception.
 * _In_ cr2    - Page fault linear address
 *
 * Returns:
 *
 * RSTATE_SUCCESS on success, otherwise error.
 */
rstate_t
page_fault(
		_In_ uintptr_t     vector,
		_In_ struct _iret *iret,
		_In_ uintptr_t     error,
		_In_ uintptr_t     cr2)
{
	int       lock_held = 1;
	uint64_t  entry;
	uintptr_t phys_page;

	struct _mm_key *key;

	RSTATE_LOCALS;

	mm_acquire_paging_lock();

	/* Get the physical page of the faulting address */
	phys_page = mm_get_phys_nolock(readcr3(), cr2 & ~0xfff, &entry);

	/* If the page fault error occured because the page wasn't present, but
	 * the page is present, return success. This can occur because another
	 * core maps in the page between when the page fault occurs and when we
	 * grab the page table lock.
	 */
	if((entry & 1) && !(error & 1)){
		rstate_ret = RSTATE_SUCCESS;
		goto cleanup;
	}

	/* Walk the key linked list looking for a handler for this page fault */
	key = mm_keys_base.next;
	while(key){
		/* If the key matches the key stored in the page table for this page */
		if(key->key == entry){
			/* Make sure the page fault address is in bounds of the key range
			 */
			RSCHECK(!(cr2 < key->base_addr ||
						cr2 >= (key->base_addr + key->length)),
				"Key match out of bounds");

			/* Release the paging lock */
			mm_release_paging_lock();
			lock_held = 0;

			/* Invoke the page fault handler */
			rstate = key->pf_handler(key, key->param, cr2, 1, error & (1 << 1),
						error & (1 << 4));
			RSCHECK_NESTED("pf_handler() indicated failure");
			
			/* Return success */
			rstate_ret = RSTATE_SUCCESS;
			goto cleanup;
		}

		key = key->next;
	}

	/* If we had a write fault on a present page, and it is a COW page, create
	 * a writable copy.
	 */
	if((error & 3) == 3 && (entry & PT_BIT_COW)){
		uintptr_t  new_page;
		void      *new_map, *old_map;

		/* Allocate a new backing page */
		rstate = alloc_phys_4k(&new_page);
		RSCHECK_NESTED("Failed to allocate writable COW page");

		/* Create a copy of the old page into the new backing */
		new_map = mm_get_phys_mapping(new_page);
		old_map = mm_get_phys_mapping(phys_page);
		memcpy(new_map, old_map, 4096);
		mm_release_phys_mapping(old_map);
		mm_release_phys_mapping(new_map);

		/* Map in the new page as RW */
		rstate = mm_map_4k_nolock(readcr3(), cr2 & ~0xfff,
				new_page | (entry & 4) | 3 | (1UL << 63), entry);
		RSCHECK_NESTED("Failed to map in cow writable page");

		/* Return success */
		rstate_ret = RSTATE_SUCCESS;
		goto cleanup;
	}

	/* Page was neither COW nor handled by a key handler. Return failure */
	RSCHECK(1 == 0, "Unhandled page fault");

cleanup:
	if(lock_held) mm_release_paging_lock();
	RSTATE_RETURN;
}

/* mm_init()
 *
 * Summary:
 *
 * This function is responsible for initiailzing memory for the OS. It prepares
 * the allocator for use.
 *
 * Returns:
 *
 * RSTATE_SUCCESS on success, otherwise error.
 */
rstate_t
mm_init(void)
{
	uint32_t i;

	static struct _e820_map e820_map_sorted = { 0 };

	RSTATE_LOCALS;

	/* Save off the e820 map base */
	e820_map = current_cpu->boot_params->e820_map;
	
	RSCHECK(e820_map->num_entries &&
			e820_map->num_entries <= 256,
			"Too few/many entries in the e820 map");

	/* Sort the memory map by base address, and also gather memory size
	 * statistics.
	 */
	for(i = 0; i < e820_map->num_entries; i++){
		uint32_t insert_loc;

		/* Find the insertion point */
		for(insert_loc = 0; insert_loc <
				e820_map_sorted.num_entries; insert_loc++){
			if(e820_map->entries[i].base <
					e820_map_sorted.entries[insert_loc].base){
				break;
			}
		}

		/* Move the end of the list back one entry to make room for the
		 * new one.
		 */
		memcpy(&e820_map_sorted.entries[insert_loc + 1],
				&e820_map_sorted.entries[insert_loc],
				(e820_map_sorted.num_entries - insert_loc) *
				sizeof(*e820_map_sorted.entries));

		/* Insert the entry */
		e820_map_sorted.entries[insert_loc] = e820_map->entries[i];
		e820_map_sorted.num_entries++;

		/* If the memory is marked as available, update statistics */
		if(e820_map->entries[i].type == 1){
			mem_stats.usable_memory += e820_map->entries[i].size;
		}

		/* Update statistics */
		mem_stats.total_memory += e820_map->entries[i].size;
	}

	/* Replace the e820 map with the sorted e820 map */
	e820_map = &e820_map_sorted;

	rstate_ret = rstate = RSTATE_SUCCESS;
cleanup:
	RSTATE_RETURN;
}

/* mm_dump_stats()
 *
 * Summary:
 *
 * This function prints out the current memory usage information on the system.
 */
void
mm_dump_stats(void)
{
	printf(
			"Memory stats:\n"
			"    In use memory:   %lu MiB (%lu bytes)\n"
			"    Consumed memory: %lu MiB (%lu bytes)\n"
			"    Usable memory:   %lu MiB (%lu bytes)\n"
			"    Total memory:    %lu MiB (%lu bytes)",
			mem_stats.inuse_memory / 1024 / 1024, mem_stats.inuse_memory,
			mem_stats.consumed_memory / 1024 / 1024, mem_stats.consumed_memory,
			mem_stats.usable_memory / 1024 / 1024, mem_stats.usable_memory,
			mem_stats.total_memory / 1024 / 1024, mem_stats.total_memory);

	return;
}

/* mm_mem_consumed()
 *
 * Summary:
 *
 * Return the amount of physical memory consumed on the system. See mem_stats
 * definition for more information.
 */
uint64_t
mm_mem_consumed(void)
{
	return mem_stats.consumed_memory;
}

/* mm_mem_inuse()
 *
 * Summary:
 *
 * Return the number of bytes of memory currently in use. See mem_stats
 * definition for more information.
 */
uint64_t
mm_mem_inuse(void)
{
	return mem_stats.inuse_memory;
}

/* mm_init_cpu()
 *
 * Summary:
 *
 * This function initializes the currently running CPU. This function should
 * only be called once for each core during bootup.
 *
 * Parameters:
 *
 * _In_ params - Pointer to boot_parameters structure passed in from the
 *               bootloader.
 */
void
mm_init_cpu(_In_ const struct _boot_parameters *params)
{
	static struct _cpu cpus[256] = { { 0 } };
	static volatile uint32_t cpus_active = 0;

	uint32_t apic_id;
	struct _cpu *tmp;

	/* Get the current CPU's APIC ID */
	apic_id = params->apic_id;

	/* Get a cpu local structure for this CPU */
	tmp = &cpus[apic_id];

	/* Set up GS to point to the CPU locals */
	tmp->gs_base = tmp;

	/* Initialize CPU information */
	tmp->apic_id = apic_id;
	tmp->cpu_id  = __sync_fetch_and_add(&cpus_active, 1);
	tmp->node_id = 0;
	tmp->is_bsp  = (rdmsr(0x1b) & (1 << 8)) ? 1 : 0;

	/* Initialize the physical windows */
	tmp->phy_window_page_table = params->phy_window_page_table;
	tmp->phy_window_base       = params->phy_window_base;

	/* Interrupts start off disabled */
	tmp->interrupt_level = 1;

	/* Initialize the AES RNG */
	{
		int ii;
		tmp->rng_seed = _mm_insert_epi64(tmp->rng_seed, __rdtsc(), 0);
		tmp->rng_seed = _mm_insert_epi64(tmp->rng_seed, tmp->apic_id, 1);
		for(ii = 0; ii < 32; ii++){
			tmp->rng_seed = _mm_aesenc_si128(tmp->rng_seed, tmp->rng_seed);
		}
	}

	/* Save off a pointer to the boot parameters */
	tmp->boot_params = params;

	/* Set up gs_base to point to this structure */
	wrmsr(0xc0000101, (uint64_t)tmp);

	return;
}

/* mm_init_apic()
 *
 * Summary:
 *
 * This function maps in the APIC for the current running core and stores
 * the mapping in current_cpu->apic.
 *
 * Returns:
 *
 * RSTATE_SUCCESS on success, otherwise error.
 */
rstate_t
mm_init_apic(void)
{
	void     *apic;
	uint64_t  key;

	RSTATE_LOCALS;

	/* Map in the APIC for this CPU as RW */
    rstate = mm_reserve_random(readcr3(), 4096, &apic, 0, &key);
    RSCHECK_NESTED("Failed to reserve random page for apic");
    rstate = mm_map_4k(readcr3(), (uintptr_t)apic,
            0xfee00000 | 3 | (1UL << 63), key);
    RSCHECK_NESTED("Failed to map in apic");

	current_cpu->apic = apic;

	rstate_ret = RSTATE_SUCCESS;
cleanup:
	RSTATE_RETURN;
}

/* mm_get_phys_mapping()
 *
 * Summary:
 *
 * This function creates a temporary virtual mapping of a physical page. This
 * is our core method for accessing physical memory directly, and is needed
 * for our memory managment system.
 *
 * Page offsets are preserved, meaning if you map in vaddr 0x1337, you will
 * get a virtual address ending in 337. Since we only map one page, this
 * means the amount of bytes accessible from the returned result could be
 * less than 4k. For example, mapping in 0x1fff would return a virtual address
 * ending in 0xfff, and only one byte would be valid.
 *
 * The temporary mapping has RW access rights.
 *
 * Parameters:
 *
 * _In_ paddr - Physical address to map
 *
 * Returns:
 *
 * Temporary virtual address pointing to the physical address specified
 * by paddr
 *
 * Cleanup:
 *
 * Call mm_release_phys_mapping() with the return value of this function
 * when you are done with the temporary mapping.
 *
 * Security risks:
 *
 * The mm_get_phys_mapping() and mm_release_phys_mapping() are prone to
 * use after frees and overflows/underflows. These virtual addresses are
 * reused and mappings can change if you do not own the mapping. There are
 * also no guard pages around the mappings, meaning an overflow would overwrite
 * unknown physical memory.
 */
void*
mm_get_phys_mapping(_In_ uintptr_t paddr)
{
	uintptr_t uaddr = paddr, base_addr = 0, uhash, try_entry, scan;
	uintptr_t rem   = uaddr & 0xfff;

	/* 4k-align the address */
	uaddr &= ~0xfff;

	/* Compute the entry index in the hash */
	uhash = (uaddr >> 12) % 512;

	/* Try up to 512 times to obtain a mapping */
	for(scan = 0; scan < 512; scan++){
		/* Calculate a hash to look up in the phywin table */
		try_entry = (uhash + scan) % 512;

		/* Attempt to acquire the lock for this window, if we fail, try the
		 * next entry in the table.
		 */
		if(!__sync_bool_compare_and_swap(
					&current_cpu->phy_window_inuse[try_entry], 0, 1)){
			continue;
		}

		/* We got the lock, calculate the vaddr for this entry */
		base_addr = current_cpu->phy_window_base + try_entry * 4096;

		/* Check if this entry already maps what we want, if it does not,
		 * map it to what we want.
		 */
		if((current_cpu->phy_window_page_table[try_entry] & 0xFFFFFFFFFF003) !=
				(uaddr | 3)){
			/* Create a mapping to this physical address as RW NX */
			current_cpu->phy_window_page_table[try_entry] =
				uaddr | 3 | (1UL << 63);
			invlpg((void*)base_addr);
		}

		/* Return virtual address of mapping + page offset */
		return (void*)(base_addr + rem);
	}

	/* Panic if we could not map */
	panic("Could not get a physical mapping!");
	return NULL;
}

/* mm_release_phys_mapping()
 *
 * Summary:
 *
 * This function releases a temporary mapping created by mm_get_phys_mapping().
 *
 * Parameters:
 *
 * _In_ vaddr - Virtual address returned from a call to mm_get_phys_mapping()
 */
void
mm_release_phys_mapping(_In_ void *vaddr)
{
	uintptr_t ent;

	/* Calculate phy window to release */
	ent = ((uint64_t)vaddr - (uint64_t)current_cpu->phy_window_base) / 4096;
	if(ent >= 512){
		panic("Physical memory entry out of bounds");
	}

	current_cpu->phy_window_inuse[ent] = 0;
	return;
}

/* mm_phys_read_qword()
 *
 * Summary:
 *
 * This function returns the 64-bit value contained by physical address
 * paddr. paddr must be 8-byte aligned.
 *
 * Parameters:
 *
 * _In_ paddr - Physical address to read 64-bit value from. Must be 8-byte
 *              aligned.
 *
 * Returns:
 *
 * 64-bit value pointed to by paddr.
 */
uint64_t
mm_phys_read_qword(_In_ uintptr_t paddr)
{
	void     *vaddr;
	uint64_t  val;

	if(paddr & 0x7){
		panic("mm_phys_read_qword() paddr was not 8-byte aligned");
	}

	/* Create temporary mapping, read value, release mapping */
	vaddr = mm_get_phys_mapping(paddr);
	val = *(volatile uint64_t*)vaddr;
	mm_release_phys_mapping(vaddr);

	return val;
}

/* mm_phys_write_qword()
 *
 * Summary:
 *
 * This function writes the 64-bit value val, to the physical address specified
 * by paddr. paddr must be 8-byte aligned.
 *
 * Parameters:
 *
 * _In_ paddr - Physical address to write 64-bit value to. Must be 8-byte
 *              aligned.
 * _In_ val   - Value to write at paddr
 */
void
mm_phys_write_qword(_In_ uintptr_t paddr, _In_ uint64_t val)
{
	void *vaddr;

	if(paddr & 0x7){
		panic("mm_phys_write_qword() paddr was not 8-byte aligned");
	}

	/* Create temporary mapping, write value, release mapping */
	vaddr = mm_get_phys_mapping(paddr);
	*(volatile uint64_t*)vaddr = val;
	mm_release_phys_mapping(vaddr);

	return;
}

/* mm_read_phys()
 *
 * Summary:
 *
 * This function reads len bytes at physical address paddr into buf.
 *
 * Parameters:
 *
 * _In_  paddr - Physical address to read memory from
 * _Out_ buf   - Buffer to read memory into
 * _In_  len   - Length (in bytes) of memory to read
 */
void
mm_read_phys(
        _In_                        uintptr_t  paddr,
        _Out_writes_bytes_all_(len) void      *buf,
        _In_                        size_t     len)
{
    uint8_t *ubuf = buf, *vaddr, *cur_map = NULL;

    while(len){
		/* If we haven't mapped yet, or we have crossed onto a new page,
		 * create a new mapping.
		 */
        if(!cur_map || !(paddr & 0xfff)){
			/* If we already had a mapping, release it */
            if(cur_map){
                mm_release_phys_mapping(cur_map);
				cur_map = NULL;
            }

			/* Create a new mapping */
            vaddr = cur_map = mm_get_phys_mapping(paddr);
        }

		/* Copy byte by byte */
        *ubuf = *vaddr;

        ubuf++;
        vaddr++;
        paddr++;
        len--;
    }

	/* Release any mapping held */
    if(cur_map){
        mm_release_phys_mapping(cur_map);
    }

	return;
}

/* mm_is_avail()
 *
 * Summary:
 *
 * This function returns whether or not the physical address specified by
 * paddr refers to available memory or not. It returns 1 if the memory
 * specified by paddr is contained entirely by an available e820 entry.
 * Otherwise it returns 0.
 *
 * Parameters:
 *
 * _In_ paddr - Physical address describing memory to check if it is available
 *              or not.
 * _In_ size  - Size of memory to check (in bytes)
 *
 * Returns:
 *
 * If memory range [paddr, paddr+size) is marked available by the e820, returns
 * 1. Otherwise, returns 0.
 */
int
mm_is_avail(_In_ uintptr_t paddr, _In_ size_t size)
{
	uint32_t ii;

	for(ii = 0; ii < e820_map->num_entries; ii++){
		/* If the e820 entry refers to neither an available region nor
		 * a previously available region, skip it.
		 */
		if(e820_map->entries[ii].type != 1 &&
				e820_map->entries[ii].type != 1337){
			continue;
		}

		/* If the page is contained entirely in an available e820 entry,
		 * return 1.
		 */
		if(contains(paddr, paddr + size - 1, e820_map->entries[ii].base,
					e820_map->entries[ii].base +
					e820_map->entries[ii].size - 1)){
			return 1;
		}
	}

	return 0;
}

/* alloc_phys()
 *
 * Summary:
 *
 * This function allocates length bytes of physical memory and returns it
 * out via allocation. Allocations are always page aligned, and the length
 * is rounded up to the nearest page boundry.
 *
 * If you want an individual physical page, call alloc_phys_4k() instead.
 *
 * Parameters:
 *
 * _In_  length     - Length (in bytes) of physical memory to allocate
 * _Out_ allocation - Caller allocated storage to receive physical address
 *                    of allocated memory on success.
 *
 * Returns:
 *
 * RSTATE_SUCCESS on success, otherwise error.
 *
 * Cleanup:
 *
 * Invoke free_phys_4k() on each physical page returned.
 *
 * Security:
 *
 * Memory returned from this function is not zeroed out.
 */
rstate_t
alloc_phys(_In_ size_t length, _Out_ uintptr_t *allocation)
{
	RSTATE_LOCALS;

	rstate = acpi_get_node_memory(current_cpu->node_id, length, allocation);
	RSCHECK_NESTED("Failed to get node local physical memory");

	rstate_ret = RSTATE_SUCCESS;
cleanup:
	RSTATE_RETURN;
}

/* alloc_phys_4k()
 *
 * Summary:
 *
 * This function allocates a 4kb zeroed out physical page and returns it out
 * via allocation.
 *
 * Parameters:
 *
 * _Out_ allocation - Caller allocated storage to receive physical address
 *                    of allocated memory on success.
 *
 * Returns:
 *
 * RSTATE_SUCCESS on success, otherwise error.
 *
 * Cleanup:
 *
 * Invoke free_phys_4k() on the returned page when done with it.
 *
 * Security:
 *
 * The alloc_phys_4k() and free_phys_4k() routines are prone to use after
 * frees.
 *
 * The physical memory returned from this function is zeroed out.
 */
rstate_t
alloc_phys_4k(_Out_ uintptr_t *allocation)
{
	uintptr_t addr;
	
	RSTATE_LOCALS;

	/* Check if we have any free memory in the free list */
	if(current_task->free_list_entries){
		*allocation = current_task->free_list;
		current_task->free_list_entries--;

		current_task->free_list = mm_phys_read_qword(current_task->free_list);
		goto success;
	}

	/* No pages in the free list, allocate new memory */
	rstate = alloc_phys(4096, &addr);
	RSCHECK_NESTED("Failed to allocate new physical page");

	*allocation = addr;

success:
	/* Open a window to the physical page and zero it out */
	{
		void *vaddr = mm_get_phys_mapping(*allocation);
		memset(vaddr, 0, 4096);
		mm_release_phys_mapping(vaddr);
	}

	rstate_ret = RSTATE_SUCCESS;
cleanup:
	RSTATE_RETURN;
}

/* free_phys_4k()
 *
 * Summary:
 *
 * This function frees a page of physical memory by adding it to the current
 * task's free list.
 *
 * Parameters:
 *
 * _In_ allocation - Address of physical page to free.
 *
 * Security:
 *
 * The alloc_phys_4k() and free_phys_4k() routines are prone to use after
 * frees.
 */
void
free_phys_4k(_In_ uintptr_t allocation)
{
	/* Physical page must be page aligned */
	if(allocation & 0xfff){
		panic("Attempted to free non-page-aligned physical page");
	}

	/* Fast path, if there is nothing in the free list, we become the
	 * free list.
	 */
	if(!current_task->free_list_entries){
		current_task->free_list = allocation;
		current_task->free_list_entries++;
		goto end;
	}

	/* Chain this new entry to point to the old entry. Replace head of the
	 * free list with us, increment free list entry count.
	 */
	mm_phys_write_qword(allocation, current_task->free_list);
	current_task->free_list = allocation;
	current_task->free_list_entries++;

end:
	return;
}

/* mm_reserve()
 *
 * Summary:
 *
 * This function reserves a region of memory starting at vaddr for size bytes
 * in the page table specified by cr3. If req_key is nonzero, it will reserve
 * the memory with the req_key. Otherwise a random key will be generated and
 * returned out from 'key'.
 *
 * The key system is our way of reserving memory. In place of the virtual
 * address in the page table, the key is place with the present bit set to
 * zero. In the future when the memory is mapped, this key must be provided.
 * If the key does not match, the mapping fails. This helps us detect some
 * copy-and-paste bugs when we accidentially fail to reserve memory, or map
 * into someone elses reservation.
 *
 * Parameters:
 *
 * _In_     cr3     - Page table to reserve memory in
 * _In_     vaddr   - Virtual address to reserve memory at. Must be page
 *                    aligned, otherwise the reservation will fail.
 * _In_     size    - Size (in bytes) of the reservation. Size is rounded
 *                    up to the nearest page size.
 * _In_opt_ req_key - Requested key for mapping. If this is zero, a key is
 *                    automaticially generated.
 * _Out_    key     - Key used to reserve memory. Needed in subsequent attempts
 *                    to map the memory which has been reserved.
 *
 * Returns:
 *
 * RSTATE_SUCCESS on success, otherwise error.
 */
static rstate_t
mm_reserve(
		_In_     uintptr_t  cr3,
		_In_     uintptr_t  vaddr,
		_In_     size_t     size,
		_In_opt_ uint64_t   req_key,
		_Out_    uint64_t  *key)
{
	uint32_t lock_held = 0;
	uint64_t tmp;

	RSTATE_LOCALS;

	/* Present bit cannot be set in the requested key */
	RSCHECK(!(req_key & 1),
			"Attempted to reserve memory with a key with the present bit set");

	/* vaddr must be page aligned */
	RSCHECK(!(vaddr & 0xfff), "Attempted to reserve non-page-aligned vaddr");

	/* Must reserve *something* */
	RSCHECK(size, "Attempted to reserve memory of zero length");

	/* Page align the size */
	size +=  0xfff;
	size &= ~0xfff;

	/* Check for integer overflow */
	RSCHECK((vaddr + size) >= vaddr,
			"Virtual address + size integer overflow");

	/* The virtual address range must fall entirely in the unsigned or
	 * signed portion of the virtual address space. This prevents us
	 * from returning an address that straddles the signed-unsigned
	 * boundry.
	 *
	 * We also make sure the address doesn't fall in the bottom or top 512GB of
	 * memory to make sure null derefs fail hard. This makes the first and
	 * last PML4 entries to be empty and unmapped entirely.
	 */
	RSCHECK(
			contains(vaddr, vaddr + size - 1,
				0x0000008000000000, 0x00007FFFFFFFFFFF) ||
			contains(vaddr, vaddr + size - 1,
				0xFFFF800000000000, 0xFFFFFF7FFFFFFFFF),
			"Virtual address range is not canon");

	/* Acquire the global paging lock */
	mm_acquire_paging_lock();
	lock_held = 1;

	/* First, make sure that for the size specified, at the random virtual
	 * address generated, there are no currently in use pages.
	 */
	for(tmp = vaddr; tmp < (vaddr + size); tmp += 4096){
		uint64_t entry;

		/* Look up the address in the table */
		mm_get_phys_nolock(cr3, tmp, &entry);

		/* If the entry is not completely zero, it's in use, fail */
		RSCHECK(!entry, "Memory requested for reservation already in use");
	}
	
	/* Generate a random key for the reservation with the present bit not set.
	 */
	if(!req_key){
		*key = aes_rand() & ~1;
	} else {
		*key = req_key;
	}
	
	/* Virtual address range is free, lock it down! */
	for(tmp = vaddr; tmp < (vaddr + size); tmp += 4096){
		uintptr_t pte_addr;

		/* Lock the entry by setting some bits, but not marking it
		 * present.
		 */
		rstate = mm_map_4k_nolock_int(cr3, tmp, *key, 0, &pte_addr);
		RSCHECK_NESTED("Failed to mark memory as reserved");
	}

	rstate_ret = RSTATE_SUCCESS;
cleanup:
	if(lock_held) mm_release_paging_lock();
	RSTATE_RETURN;
}

/* mm_reserve_random()
 *
 * Summary:
 *
 * This function reserve room for size bytes at a random address in the page
 * table specified by cr3. The virtual address reserved is returned via addr.
 *
 * The virtual address reserved will always be page aligned.
 *
 * If req_key is nonzero it will be used as the key for the reservation,
 * otherwise a random key will be generated and returned via key.
 *
 * Parameters:
 *
 * _In_     cr3     - Page table to reserve memory in
 * _In_     size    - Size (in bytes) of the reservation. Size is rounded
 *                    up to the nearest page size.
 * _Outptr_ addr    - Virtual address that was reserved.
 * _In_opt_ req_key - Requested key for mapping. If this is zero, a key is
 *                    automaticially generated.
 * _Out_    key     - Key used to reserve memory. Needed in subsequent attempts
 *                    to map the memory which has been reserved.
 *
 * Returns:
 *
 * RSTATE_SUCCESS on success, otherwise error.
 */
rstate_t
mm_reserve_random(
		_In_     uintptr_t    cr3,
		_In_     size_t       size,
		_Outptr_ void       **addr,
		_In_opt_ uint64_t     req_key,
		_Out_    uint64_t    *key)
{
	RSTATE_LOCALS;

	/* If the size is zero, return failure */
	RSCHECK(size, "Tried to reserve memory of zero size");

	/* Page-align the size */
	size +=  0xfff;
	size &= ~0xfff;

	/* Keep trying forever to find a free slot in the virtual address space */
	for( ; ; ){
		uint64_t vaddr;

		/* Generate a random 48-bit page-aligned address */
		vaddr = aes_rand() & 0x0000FFFFFFFFF000;

		/* Perform sign extension of the address */
		if(vaddr & 0x0000800000000000){
			vaddr |= 0xFFFF000000000000;
		}

		/* Attempt to reserve the memory. If it fails, try another random
		 * address.
		 */
		if(mm_reserve(cr3, vaddr, size, req_key, key) != RSTATE_SUCCESS){
			continue;
		}

		*addr = (void*)vaddr;
		rstate_ret = rstate = RSTATE_SUCCESS;
		goto cleanup;
	}

cleanup:
	RSTATE_RETURN;
}

/* mm_map_contig()
 *
 * Summary:
 *
 * This function maps in value to the virtual address specified by addr in the
 * page table cr3 for length bytes using key.
 *
 * Value is automatically incremented by 4k for each page mapped.
 *
 * Parameters:
 *
 * _In_ cr3    - Page table to map into
 * _In_ addr   - Virtual address to create map at
 * _In_ value  - Value to map for the pages
 * _In_ length - Size (in bytes) of the mapping. Rounded up to the nearest
 *               page size.
 * _In_ key    - Key used to reserve the memory. If the memory was not reserved
 *               then the key should be 0.
 *
 * Returns:
 *
 * RSTATE_SUCCESS on success, otherwise error.
 */
rstate_t
mm_map_contig(
		_In_ uintptr_t  cr3,
		_In_ uintptr_t  addr,
		_In_ uint64_t   value,
		_In_ size_t     length,
		_In_ uint64_t   key)
{
	RSTATE_LOCALS;

	/* 4k-align the length */
	length +=  0xfff;
	length &= ~0xfff;

	/* Validate that the address is 4k-aligned */
	RSCHECK(!(addr & 0xfff), "Mapping attempted on non-4k aligned address");

	/* Map all 4k pages described by this [addr, addr+length) combination */
	while(length){
		rstate = mm_map_4k(cr3, addr, value, key);
		RSCHECK_NESTED("Failed to map individual page");

		addr   += 4096;
		value  += 4096;
		length -= 4096;
	}

	rstate_ret = RSTATE_SUCCESS;
cleanup:
	RSTATE_RETURN;
}

/* mm_map_4k_nolock_int()
 *
 * Summary:
 *
 * This function adds a mapping at virtual address addr in the table specified
 * by cr3 as value. Value is set directly, so it must include a present bit
 * and friends if you want to actually use the page.
 *
 * Page table lock is not acquired.
 *
 * Parameters:
 *
 * _In_  cr3      - Page table to map into
 * _In_  addr     - Virtual address to map
 * _In_  value    - Value to map into page table
 * _In_  key      - Key returned from a reservation of the memory. 0 if no
 *                  reservation was done.
 * _Out_ pte_addr - Physical address of the PTE that this mapping was done in.
 *
 * Returns:
 *
 * RSTATE_SUCCESS on success, otherwise error.
 */
static rstate_t
mm_map_4k_nolock_int(
		_In_  uintptr_t  cr3,
		_In_  uintptr_t  addr,
		_In_  uint64_t   value,
		_In_  uint64_t   key,
		_Out_ uintptr_t *pte_addr)
{
	uintptr_t cr_offsets[4], cr_depth;
	uintptr_t cur;

	RSTATE_LOCALS;

#if 0
	RSCHECK(value & (1UL << 63),
			"Attempted to map page as executable");
#endif

	/* Extract the PML4 address from cr3 */
	cur = MASK((uint64_t)cr3, 51, 12);

	/* Get each part of the address used in translation */
	cr_offsets[3] = BEXTR(addr, 47, 39);
	cr_offsets[2] = BEXTR(addr, 38, 30);
	cr_offsets[1] = BEXTR(addr, 29, 21);
	cr_offsets[0] = BEXTR(addr, 20, 12);

	for(cr_depth = 3; cr_depth >= 1; cr_depth--){
		uintptr_t cur_offset = cr_offsets[cr_depth];

		if(!mm_phys_read_qword(cur + cur_offset*8)){
			/* If there is no entry present, make a table and map it in RWXU */
			uintptr_t tmp;

			rstate = alloc_phys_4k(&tmp);
			RSCHECK_NESTED("Failed to allocate page table entry");

			mm_phys_write_qword(cur + cur_offset*8, tmp | (cr_depth << 9) | 7);

			cur = tmp;
		} else {
			/* If there is an entry present, get the pointer to it */
			cur = MASK(mm_phys_read_qword(cur + cur_offset*8), 51, 12);
		}
	}

	/* In order to perform this allocation we must have the key (previous
	 * value). This will be zero for free pages, and will be a random key
	 * value for reserved pages. This mechanism prevents multiple maps of
	 * memory as well as prevents accidental mappings of someone elses reserved
	 * memory.
	 */
	RSCHECK(mm_phys_read_qword(cur + cr_offsets[0]*8) == key,
			"Key did not match for mapping");

	/* Map in the value */
	mm_phys_write_qword(cur + cr_offsets[0]*8, value);

	/* Return the address where the entry resides */
	*pte_addr = cur;

	/* Flush the TLB for this page */
	invlpg((void*)addr);

	rstate_ret = RSTATE_SUCCESS;
cleanup:
	RSTATE_RETURN;
}

/* mm_map_4k_int()
 *
 * Summary:
 *
 * This function adds a mapping at virtual address addr in the table specified
 * by cr3 as value. Value is set directly, so it must include a present bit
 * and friends if you want to actually use the page.
 *
 * Page table lock is acquired.
 *
 * Parameters:
 *
 * _In_  cr3      - Page table to map into
 * _In_  addr     - Virtual address to map
 * _In_  value    - Value to map into page table
 * _In_  key      - Key returned from a reservation of the memory. 0 if no
 *                  reservation was done.
 * _Out_ pte_addr - Physical address of the PTE that this mapping was done in.
 *
 * Returns:
 *
 * RSTATE_SUCCESS on success, otherwise error.
 */
rstate_t
mm_map_4k_int(
		_In_  uintptr_t  cr3,
		_In_  uintptr_t  addr,
		_In_  uint64_t   value,
		_In_  uint64_t   key,
		_Out_ uintptr_t *pte_addr)
{
	RSTATE_LOCALS;

	mm_acquire_paging_lock();

	rstate = mm_map_4k_nolock_int(cr3, addr, value, key, pte_addr);
	RSCHECK_NESTED("Failed to map page");

	rstate_ret = RSTATE_SUCCESS;
cleanup:
	mm_release_paging_lock();
	RSTATE_RETURN;
}

/* mm_map_4k_nolock()
 *
 * Summary:
 *
 * This function adds a mapping at virtual address addr in the table specified
 * by cr3 as value. Value is set directly, so it must include a present bit
 * and friends if you want to actually use the page.
 *
 * Page table lock is not acquired.
 *
 * Parameters:
 *
 * _In_  cr3      - Page table to map into
 * _In_  addr     - Virtual address to map
 * _In_  value    - Value to map into page table
 * _In_  key      - Key returned from a reservation of the memory. 0 if no
 *                  reservation was done.
 *
 * Returns:
 *
 * RSTATE_SUCCESS on success, otherwise error.
 */
rstate_t
mm_map_4k_nolock(
		_In_ uintptr_t cr3,
		_In_ uintptr_t addr,
		_In_ uint64_t  value,
		_In_ uint64_t  key)
{
	uintptr_t pte_addr;

	RSTATE_LOCALS;

	rstate = mm_map_4k_nolock_int(cr3, addr, value, key, &pte_addr);
	RSCHECK_NESTED("Failed to map page");

	rstate_ret = RSTATE_SUCCESS;
cleanup:
	RSTATE_RETURN;
}

/* mm_map_4k()
 *
 * Summary:
 *
 * This function adds a mapping at virtual address addr in the table specified
 * by cr3 as value. Value is set directly, so it must include a present bit
 * and friends if you want to actually use the page.
 *
 * Page table lock is acquired.
 *
 * Parameters:
 *
 * _In_  cr3      - Page table to map into
 * _In_  addr     - Virtual address to map
 * _In_  value    - Value to map into page table
 * _In_  key      - Key returned from a reservation of the memory. 0 if no
 *                  reservation was done.
 *
 * Returns:
 *
 * RSTATE_SUCCESS on success, otherwise error.
 */
rstate_t
mm_map_4k(
		_In_ uintptr_t  cr3,
		_In_ uintptr_t  addr,
		_In_ uint64_t   value,
		_In_ uint64_t   key)
{
	uintptr_t pte_addr;

	RSTATE_LOCALS;

	mm_acquire_paging_lock();

	rstate = mm_map_4k_nolock_int(cr3, addr, value, key, &pte_addr);
	RSCHECK_NESTED("Failed to map page");

	rstate_ret = RSTATE_SUCCESS;
cleanup:
	mm_release_paging_lock();
	RSTATE_RETURN;
}

/* mm_get_phys_nolock()
 *
 * Summary:
 *
 * This function looks up the virtual address in cr3 and returns the physical
 * address that it maps. Page-alignment of the address is preserved. If
 * the virtual address is not present, 0 is returned.
 *
 * The raw contents of the last translated table entry are returned in
 * out_entry. This allows us to get a key for a virtual address, or view
 * the page table state of an unmapped vaddr.
 *
 * Page table lock is not acquired.
 *
 * Parameters:
 *
 * _In_  cr3       - Page table to look up vaddr in
 * _In_  addr      - Virtual address to translate
 * _Out_ out_entry - Raw contents of last translated table entry
 *
 * Returns:
 *
 * On success: Physical address mapped by addr in cr3
 * On failure: 0 (out_entry still updated)
 */
uintptr_t
mm_get_phys_nolock(
        _In_  uintptr_t  cr3,
        _In_  uintptr_t  addr,
		_Out_ uint64_t  *out_entry)
{
    uint64_t  entry, pml4o, pdpo, pdo, pto;
	uintptr_t cur;

    /* Extract the PML4 address from cr3 */
    cur = MASK(cr3, 51, 12);

    /* Get each part of the address used in translation */
    pml4o = BEXTR(addr, 47, 39);
    pdpo  = BEXTR(addr, 38, 30);
    pdo   = BEXTR(addr, 29, 21);
    pto   = BEXTR(addr, 20, 12);

    /* PML4 */
	*out_entry = entry = mm_phys_read_qword(cur + pml4o*8);
    if(!(entry & 1))
        return 0;
    cur = MASK(entry, 51, 12);

    /* PDP */
	*out_entry = entry = mm_phys_read_qword(cur + pdpo*8);
    if(!(entry & 1))
        return 0;
    if(entry & (1 << 7)){
        return (MASK(entry, 51, 12) + MASK(addr, 29, 0));
    }
    cur = MASK(entry, 51, 12);

    /* PD */
	*out_entry = entry = mm_phys_read_qword(cur + pdo*8);
    if(!(entry & 1))
        return 0;
    if(entry & (1 << 7)){
        return (MASK(entry, 51, 12) + MASK(addr, 20, 0));
    }
    cur = MASK(entry, 51, 12);

    /* PT */
	*out_entry = entry = mm_phys_read_qword(cur + pto*8);
    if(!(entry & 1)){
        return 0;
    } else {
        return (MASK(entry, 51, 12) + MASK(addr, 11, 0));
    }
}

/* mm_get_phys()
 *
 * Summary:
 *
 * This function looks up the virtual address in cr3 and returns the physical
 * address that it maps. Page-alignment of the address is preserved. If
 * the virtual address is not present, 0 is returned.
 *
 * The raw contents of the last translated table entry are returned in
 * out_entry. This allows us to get a key for a virtual address, or view
 * the page table state of an unmapped vaddr.
 *
 * Page table lock is acquired.
 *
 * Parameters:
 *
 * _In_  cr3       - Page table to look up vaddr in
 * _In_  addr      - Virtual address to translate
 * _Out_ out_entry - Raw contents of last translated table entry
 *
 * Returns:
 *
 * On success: Physical address mapped by addr in cr3
 * On failure: 0 (out_entry still updated)
 */
uintptr_t
mm_get_phys(
        _In_  uintptr_t  cr3,
        _In_  uintptr_t  addr,
		_Out_ uint64_t  *out_entry)
{
	uintptr_t ret;

	/* Acquire the global paging lock */
	mm_acquire_paging_lock();

	ret = mm_get_phys_nolock(cr3, addr, out_entry);

	mm_release_paging_lock();
	return ret;
}

/* phalloc()
 *
 * Summary:
 *
 * This is our core virtual memory allocator. It returns 16-byte aligned
 * page heap allocations of size bytes. Allocation virtual address is returned
 * via allocation.
 *
 * The virtual address of the allocation is entirely random.
 *
 * The allocation is 16-byte aligned and as close as possible to the end of
 * the page while still preserving this alignment. This helps us catch heap
 * overflows.
 *
 * The returned virtual memory is zeroed out.
 *
 * Parameters:
 *
 * _In_     size       - Size (in bytes) to allocate
 * _Outptr_ allocation - Virtual address of allocated memory
 *
 * Returns:
 *
 * RSTATE_SUCCESS on success, otherwise error.
 *
 * Cleanup:
 *
 * Call phfree() with the virtual address of the allocation when you are done
 * using it.
 *
 * Security:
 *
 * phalloc() and phfree() are not vulnerable to use after frees due to the
 * random nature of the addresses. When the free occurs the memory is no
 * longer present, and future calls to phalloc() are extremely unlikely to
 * return the previous address used.
 *
 * The memory returned by this function is zeroed out.
 */
rstate_t
phalloc(_In_ size_t size, _Outptr_ void **allocation)
{
	void *vaddr;

	size_t backing_size, key, ii;

	RSTATE_LOCALS;

	/* 16-byte align the size */
	size +=  0xf;
	size &= ~0xf;

	/* Get a 4k-byte aligned size */
	backing_size  = size;
	backing_size +=  0xfff;
	backing_size &= ~0xfff;

	RSCHECK(size, "Attempted to allocate memory with zero size");

	/* Reserve a random chunk of virtual memory */
	rstate = mm_reserve_random(readcr3(), backing_size, &vaddr, 0, &key);
	RSCHECK_NESTED("Failed to reserve memory for allocation");

	/* For each page in the reservation commit a backing page */
	for(ii = 0; ii < backing_size; ii += 4096){
		uintptr_t phys_page;

		/* Allocate a backing page */
		rstate = alloc_phys_4k(&phys_page);
		RSCHECK_NESTED("Failed to allocate backing page for allocation");

		/* Commit the backing page as RW */
		rstate = mm_map_4k(readcr3(), (uint64_t)vaddr + ii,
				phys_page | 3 | (1UL << 63), key);
		RSCHECK_NESTED("Failed to commit backing page for allocation");
	}

	*allocation = (void*)((uint64_t)vaddr + backing_size - size);
	rstate_ret = RSTATE_SUCCESS;
cleanup:
	RSTATE_RETURN;
}

/* mm_reap_nolock()
 *
 * Summary:
 *
 * This function will walk the page table specified by cr3 for the virtual
 * address specified by addr and remove any page tables involved in the
 * translation that are entirely empty. This is used in our phfree() routine
 * to cleanup unused page tables after memory is freed.
 *
 * Parameters:
 * 
 * _In_ cr3  - Page table to walk to clean up
 * _In_ addr - Virtual address to walk to
 */
static void
mm_reap_nolock(
        _In_ uintptr_t cr3,
        _In_ uintptr_t addr)
{
	int in_use;

    uint64_t  pml4o, pdpo, pdo, pto;
	uint64_t  pml4e, pdpe, pde;
	uintptr_t pml4, pdp, pd, pt;

    /* Extract the PML4 address from cr3 */
    pml4 = MASK(cr3, 51, 12);

    /* Get each part of the address used in translation */
    pml4o = BEXTR(addr, 47, 39);
    pdpo  = BEXTR(addr, 38, 30);
    pdo   = BEXTR(addr, 29, 21);
    pto   = BEXTR(addr, 20, 12);

    /* PML4 */
	pml4e = mm_phys_read_qword(pml4 + pml4o*8);
    if(!(pml4e & 1))
        return;
    pdp = MASK(pml4e, 51, 12);

    /* PDP */
	pdpe = mm_phys_read_qword(pdp + pdpo*8);
    if(!(pdpe & 1))
        return;
    pd = MASK(pdpe, 51, 12);

    /* PD */
	pde = mm_phys_read_qword(pd + pdo*8);
    if(!(pde & 1))
        return;
    pt = MASK(pde, 51, 12);

	/* Walk the page table to see if it's empty */
	in_use = 0;
	for(pto = 0; pto < 512; pto++){
		if(mm_phys_read_qword(pt + pto*8) & 1) in_use++;
	}
	if(in_use) return;
	mm_phys_write_qword(pd + pdo*8, 0);
	free_phys_4k(pt);

	/* Walk the page directory to see if it's empty */
	in_use = 0;
	for(pdo = 0; pdo < 512; pdo++){
		if(mm_phys_read_qword(pd + pdo*8) & 1) in_use++;
	}
	if(in_use) return;
	mm_phys_write_qword(pdp + pdpo*8, 0);
	free_phys_4k(pd);

	/* Walk the page directory pointer table to see if it's empty */
	in_use = 0;
	for(pdpo = 0; pdpo < 512; pdpo++){
		if(mm_phys_read_qword(pdp + pdpo*8) & 1) in_use++;
	}
	if(in_use) return;
	mm_phys_write_qword(pml4 + pml4o*8, 0);
	free_phys_4k(pdp);

	/* PML4 can never be empty, no need to walk it */

	return;
}

/* phfree()
 *
 * Summary:
 *
 * This function frees memory previously allocated with phalloc().
 *
 * Parameters:
 *
 * _In_ allocation - Pointer to virtual memory previously allocated by
 *                   phalloc.
 * _In_ size       - Size (in bytes) to free
 *
 * Returns:
 *
 * RSTATE_SUCCESS on success, otherwise error.
 *
 * Security:
 *
 * phalloc() and phfree() are not vulnerable to use after frees due to the
 * random nature of the addresses. When the free occurs the memory is no
 * longer present, and future calls to phalloc() will extremely unlikely
 * return the previous address used.
 */
rstate_t
phfree(_In_ void *allocation, _In_ size_t size)
{
	uint8_t *ualc = allocation;

	RSTATE_LOCALS;

	/* Cannot free empty allocation */
	RSCHECK(size, "Attempted to free zero size allocation");

	/* Page align the size */
	size +=  0xfff;
	size &= ~0xfff;

	/* Get a page-aligned uint8_t pointer to the allocation base */
	ualc = (uint8_t*)((uint64_t)allocation & ~0xfff);

	while(size){
		uint64_t  entry;
		uintptr_t phys;

		/* We do 2 things here. First, we force a crash on invalid frees.
		 * Second, we force lazy allocations or network allocations to
		 * get invoked and thus fill in the backing page. This means we
		 * only ever have to operate on present pages. Attempts to free
		 * unmapped memory should fault.
		 */
		*(volatile int*)ualc = 0;

		/* Acquire the lock so we can atomically look up physical entry info
		 * and reap the page table.
		 */
		mm_acquire_paging_lock();

		/* Get the backing physical memory for this page */
		phys = mm_get_phys_nolock(readcr3(), (uintptr_t)ualc, &entry);
		if(!phys || !(entry & 1)){
			panic("Attempted to free something not present");
		}

		/* Unmap the entry */
		rstate = mm_map_4k_nolock(readcr3(),
				(uintptr_t)ualc, 0, entry);
		RSCHECK_NESTED("Failed to unmap free entry");

		/* Remove all empty page table entries associated with this */
		mm_reap_nolock(readcr3(), (uintptr_t)ualc);

		/* Release the lock */
		mm_release_paging_lock();

		/* Free the physical memory */
		free_phys_4k(phys);

		ualc += 4096;
		size -= 4096;
	}

	rstate_ret = RSTATE_SUCCESS;
cleanup:
	RSTATE_RETURN;
}

/* mm_for_each_dirty_page()
 *
 * Summary:
 *
 * This function invokes func with the virtual and physical address of every
 * dirty page in the table specified by cr3. It also passes along a context
 * for user use. Can only be used on page tables entirely composed of 4k pages.
 * start_addr and end_addr specify the start and end addreses to search in
 * the page tables.
 *
 * The page table entry is marked as no longer dirty after func() has been
 * invoked.
 *
 * No locks are held in this function. Caller must ensure proper locks are
 * acquired.
 *
 * Parameters:
 *
 * _In_ cr3        - Page table to walk for dirty pages
 * _In_ start_addr - Start address to start search at
 * _In_ end_addr   - End address to stop search at
 * _In_ func       - Function to invoke for each dirty page
 * _In_ ctxt       - Context to pass into func()
 */
void
mm_for_each_dirty_page(
		_In_ uintptr_t  cr3,
		_In_ uintptr_t  start_addr,
		_In_ uintptr_t  end_addr,
		_In_ void       (*func)(void *ctxt, uintptr_t vaddr, uintptr_t paddr),
		_In_ void      *ctxt)
{
	uintptr_t pml4o, pdpo, pdo, pto;
	uintptr_t pml4, pdp, pd, pt;
	uintptr_t addr;

	pml4 = MASK(cr3, 51, 12);
	for(pml4o = 0; pml4o < 512; pml4o++){
		addr = (pml4o << 39);
		if(addr & (1UL << 47)){
			addr |= 0xFFFF000000000000UL;
		}
		if(!overlaps(start_addr, end_addr - 1,
					addr, addr + (512UL * 1024 * 1024 * 1024) - 1)){
			continue;
		}

		/* Accessed and present? */
		if((mm_phys_read_qword(pml4 + pml4o*8) & 0x21) != 0x21)
			continue;

		pdp = MASK(mm_phys_read_qword(pml4 + pml4o*8), 51, 12);
		for(pdpo = 0; pdpo < 512; pdpo++){
			addr = (pml4o << 39) | (pdpo << 30);
			if(addr & (1UL << 47)){
				addr |= 0xFFFF000000000000UL;
			}
			if(!overlaps(start_addr, end_addr - 1,
						addr, addr + (1UL * 1024 * 1024 * 1024) - 1)){
				continue;
			}

			/* Accessed and present? */
			if((mm_phys_read_qword(pdp + pdpo*8) & 0x21) != 0x21)
				continue;

			pd = MASK(mm_phys_read_qword(pdp + pdpo*8), 51, 12);
			for(pdo = 0; pdo < 512; pdo++){
				addr = (pml4o << 39) | (pdpo << 30) | (pdo << 21);
				if(addr & (1UL << 47)){
					addr |= 0xFFFF000000000000UL;
				}
				if(!overlaps(start_addr, end_addr - 1,
							addr, addr + (2 * 1024 * 1024) - 1)){
					continue;
				}

				/* Accessed and present? */
				if((mm_phys_read_qword(pd + pdo*8) & 0x21) != 0x21)
					continue;

				pt = MASK(mm_phys_read_qword(pd + pdo*8), 51, 12);
				for(pto = 0; pto < 512; pto++){
					addr = (pml4o << 39) | (pdpo << 30) |
						(pdo << 21) | (pto << 12);
					if(addr & (1UL << 47)){
						addr |= 0xFFFF000000000000UL;
					}
					if(!overlaps(start_addr, end_addr - 1,
								addr, addr + 4096 - 1)){
						continue;
					}

					/* Dirty and present? */
					if((mm_phys_read_qword(pt + pto*8) & 0x41) != 0x41)
						continue;

					func(ctxt, addr,
							MASK(mm_phys_read_qword(pt + pto*8), 51, 12));

					/* Clear accessed and dirty flags */
					mm_phys_write_qword(
							pt + pto*8,
							mm_phys_read_qword(pt + pto*8) &
							0xFFFFFFFFFFFFFF9FUL);
					invlpg((void*)addr);
				}
			}
		}
	}
}

/* mm_cow_pf_handler()
 *
 * Summary:
 *
 * This is the page fault handler registered for COW mappings.
 *
 * Parameters:
 *
 * _In_ key        - Key that matched this page fault handler
 * _In_ param      - Context passed when the key was registered
 * _In_ fault_addr - Linear address thta caused the page fault
 * _In_ read_req   - Set if the request was a read
 * _In_ write_req  - Set if the request was a write
 * _In_ exec_req   - Set if the request was for execution
 *
 * Returns:
 *
 * RSTATE_SUCCESS on success, otherwise error.
 */
static rstate_t
mm_cow_pf_handler(
		_In_ struct _mm_key *key,
		_In_ void           *param,
		_In_ uintptr_t       fault_addr,
		_In_ int             read_req,
		_In_ int             write_req,
		_In_ int             exec_req)
{
	uint32_t  tmp;
	uint64_t  entry, offset;
	uintptr_t phys;
	struct _cow_map_state *cms = param;

	RSTATE_LOCALS;

	fault_addr &= ~0xfff;
	offset      = fault_addr - key->base_addr;

	/* Force an access of the backing memory. This will cause it to be pulled
	 * into memory if it's a lazy allocation or a remote page.
	 */
	tmp = *(volatile uint32_t*)cms->backing;

	mm_acquire_paging_lock();

	RSCHECK(exec_req == 0, "Attempted to execute COW memory");

	/* Validate that the fault is still valid now that we have acquired
	 * the paging lock. It's possible another cpu has already resolved
	 * this fault.
	 */
	mm_get_phys_nolock(readcr3(), fault_addr, &entry);
	if(entry != key->key){
		rstate_ret = RSTATE_SUCCESS;
		goto cleanup;
	}

	/* Get the physical memory of the backing corresponding to this
	 * fault.
	 */
	phys = mm_get_phys_nolock(readcr3(),
			((uintptr_t)cms->backing & ~0xfff) + offset, &entry);
	RSCHECK(phys, "Failed to get backing physical memory");

	if(write_req){
		void      *new_map, *old_map;
		uintptr_t  new_page;

		/* Allocate a new backing page */
		rstate = alloc_phys_4k(&new_page);
		RSCHECK_NESTED("Failed to allocate writable COW page");

		/* Create a copy of the backing memory */
		new_map = mm_get_phys_mapping(new_page);
		old_map = mm_get_phys_mapping(phys);
		memcpy(new_map, old_map, 4096);
		mm_release_phys_mapping(old_map);
		mm_release_phys_mapping(new_map);

		/* Map in the new page */
		rstate = mm_map_4k_nolock(readcr3(), fault_addr,
				new_page | (entry & 4) | 3 | (1UL << 63), key->key);
		RSCHECK_NESTED("Failed to map in cow writable page");
	} else {
		/* If there was no write request, it was just a read. Lazily map
		 * in the backing page as read only.
		 */
		rstate = mm_map_4k_nolock(readcr3(), fault_addr,
				(entry & ~3) | 1 | (1UL << 63) | PT_BIT_COW, key->key);
		RSCHECK_NESTED("Failed to map in cow readonly page");
	}

	rstate_ret = RSTATE_SUCCESS;
cleanup:
	mm_release_paging_lock();
	RSTATE_RETURN;
}

/* mm_create_cow()
 *
 * Summary:
 *
 * This function creates a COW copy of an already existing buffer. Further
 * it will lazily load even the read only pages.
 *
 * Execution of COW memory is not allowed and will result with an unhandled
 * page fault.
 *
 * If addr is provided the COW mapping is created at addr. This allows a COW
 * mapping to be made in a small section of a previously reserved large pool
 * of memory. This is something that is fairly common for our virtual machines.
 * This takes control of the memory specified at addr, and thus the memory
 * there is no longer reserved for regular use by the caller.
 *
 * Parameters:
 *
 * _In_reads_bytes_ orig_buf - Buffer to create a COW copy of
 * _In_             orig_len - Length (in bytes) of orig_buf
 * _In_opt_         addr     - Optional address to create COW mapping at. If
 *                             not specified a random one is chosen.
 * _In_opt_         key      - If addr is provided, this key is the key used
 *                             to unlock use of addr.
 * _Outptr_         out_buf  - Pointer to newly allocated COW buffer
 *
 * Returns:
 *
 * RSTATE_SUCCESS on success, otherwise error.
 */
rstate_t
mm_create_cow(
		_In_reads_bytes_(orig_len) const void  *orig_buf,
		_In_                       size_t       orig_len,
		_In_opt_                   void        *addr,
		_In_opt_                   uint64_t     key,
		_Outptr_                   void       **out_buf)
{
	uint8_t  *ubuf, *new_mem;
	uint64_t  new_mem_key, offset = 0;

	RSTATE_LOCALS;

	RSCHECK(orig_len, "Supplied length cannot be zero");

	/* Page align the length */
	orig_len +=  0xfff;
	orig_len &= ~0xfff;

	/* Page align the buffer */
	ubuf = (void*)((uintptr_t)orig_buf & ~0xfff);

	if(!addr){
		/* Create a new reservation */
		rstate = mm_reserve_random(readcr3(), orig_len,
				(void**)&new_mem, 0, &new_mem_key);
		RSCHECK_NESTED("Failed to reserve new COW region of memory");
	} else {
		uint64_t rem = orig_len;

		/* Map the range specified by addr, orig_len, and key to contain a new
		 * special key, used to identify the mapping.
		 */
		new_mem     = addr;
		new_mem_key = aes_rand() & ~1;

		while(rem){
			/* Map a new key for this region of memory */
			rstate = mm_map_4k(readcr3(), (uint64_t)new_mem + offset,
					new_mem_key, key);
			RSCHECK_NESTED("Failed to commit backing page for allocation");

			offset += 4096;
			rem    -= 4096;
		}
	}

	{
		struct _mm_key *mm_key;
		struct _cow_map_state *cms;

		/* Allocate a new key structure */
		rstate = phalloc(sizeof(struct _mm_key), (void**)&mm_key);
		RSCHECK_NESTED("Failed to allocate room for mm_key");
		
		/* Allocate a new cow map state context */
		rstate = phalloc(sizeof(struct _cow_map_state), (void**)&cms);
		RSCHECK_NESTED("Failed to allocate room for cow map state");

		cms->backing = orig_buf;

		/* Create a key with the cms as the context */
		mm_key->base_addr  = (uint64_t)new_mem;
		mm_key->length     = orig_len;
		mm_key->key        = new_mem_key;
		mm_key->pf_handler = mm_cow_pf_handler;
		mm_key->param      = cms;

		/* Register the key handler */
		mm_register_key_handler(mm_key);
	}

	*out_buf = (void*)((uintptr_t)new_mem + ((uintptr_t)orig_buf & 0xfff));

	rstate_ret = RSTATE_SUCCESS;
cleanup:
	RSTATE_RETURN;
}

/* alloc_physvirt_4k()
 *
 * Summary:
 *
 * This function allocates a 4k page and also maps it into a random virtual
 * address. Returns both physical and virtual addresses. Both physical and
 * virtual addresses are 4k aligned.
 *
 * The memory returned from this function is zeroed.
 *
 * Parameters:
 *
 * _Out_    phys - Physical address of the allocation
 * _Outptr_ virt - Virtual address mapping physical address
 *
 * Returns:
 *
 * RSTATE_SUCCESS on success, otherwise error.
 *
 * Security:
 *
 * Memoy returned from this function is zeroed.
 */
rstate_t
alloc_physvirt_4k(_Out_ uintptr_t *phys, _Outptr_ void **virt)
{
	void     *tmp_virt;
	uint64_t  key;
	uintptr_t tmp_phys;

	RSTATE_LOCALS;

	/* Allocate page */
	rstate = alloc_phys_4k(&tmp_phys);
	RSCHECK_NESTED("Failed to allocate backing physical memory");

	/* Pick random address for page */
	rstate = mm_reserve_random(readcr3(), 4096, &tmp_virt, 0, &key);
	RSCHECK_NESTED("Failed to reserve memory for physical memory");

	/* Map in page */
	rstate = mm_map_4k(readcr3(), (uint64_t)tmp_virt,
			(uint64_t)tmp_phys | 3 | (1UL << 63), key);
	RSCHECK_NESTED("Failed to map in physical memory to virtual page");

	*phys = tmp_phys;
	*virt = tmp_virt;

	rstate_ret = RSTATE_SUCCESS;
cleanup:
	RSTATE_RETURN;
}

/* mm_register_key_handler()
 *
 * Summary:
 *
 * This function registers a new key. Keys are used for caller created custom
 * page fault handlers to be invoked on the memory specified by the key.
 *
 * Parameters:
 *
 * _In_ key - Pointer to caller allocated key structure to insert into the
 *            linked list. This is inserted directly and not copied, so it
 *            must be a persistant allocation, not just a stack value.
 */
void
mm_register_key_handler(_In_ struct _mm_key *key)
{
	struct _mm_key *old_end;

	/* Force next to be NULL */
	key->next = NULL;

	/* Page align the base address */
	key->base_addr &= ~0xfff;

	/* Add new key to the global linked list */
	do {
		old_end = mm_keys_end;
	} while(!__sync_bool_compare_and_swap(&mm_keys_end, old_end, key));
	old_end->next = key;

	return;
}

