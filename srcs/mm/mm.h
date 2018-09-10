#pragma once

#define PT_BIT_COW (1UL << 52)

struct _mm_key {
	/* Page aligned address and length described by this memory area */
	uint64_t base_addr;
	uint64_t length;

	/* Key that identifies this memory area */
	uint64_t key;

	/* Private data by the creator of the key */
	void *param;

	/* Function to invoke when a pagefault occurs on this key. */
	rstate_t (*pf_handler)(
			_In_ struct _mm_key *key,
			_In_ void           *param,
			_In_ uintptr_t       fault_addr,
			_In_ int             read_req,
			_In_ int             write_req,
			_In_ int             exec_req);

	/* Next key in the linked list */
	struct _mm_key *next;
};

struct _cow_map_state {
	const void *backing;
};

void
mm_acquire_paging_lock(void);

void
mm_release_paging_lock(void);

rstate_t
page_fault(
		_In_ uintptr_t     vector,
		_In_ struct _iret *iret,
		_In_ uintptr_t     error,
		_In_ uintptr_t     cr2);

rstate_t
mm_init(void);

void
mm_dump_stats(void);

uint64_t
mm_mem_consumed(void);

uint64_t
mm_mem_inuse(void);

void
mm_init_cpu(_In_ const struct _boot_parameters *params);

rstate_t
mm_init_apic(void);

void*
mm_get_phys_mapping(_In_ uintptr_t paddr);

void
mm_release_phys_mapping(_In_ void *vaddr);

uint64_t
mm_phys_read_qword(_In_ uintptr_t paddr);

void
mm_phys_write_qword(_In_ uintptr_t paddr, _In_ uint64_t val);

void
mm_read_phys(
        _In_                        uintptr_t  paddr,
        _Out_writes_bytes_all_(len) void      *buf,
        _In_                        size_t     len);

int
mm_is_avail(_In_ uintptr_t paddr, _In_ size_t size);

rstate_t
alloc_phys(_In_ size_t length, _Out_ uintptr_t *allocation);

rstate_t
alloc_phys_4k(_Out_ uintptr_t *allocation);

void
free_phys_4k(_In_ uintptr_t allocation);

rstate_t
mm_reserve_random(
		_In_     uintptr_t    cr3,
		_In_     size_t       size,
		_Outptr_ void       **addr,
		_In_opt_ uint64_t     req_key,
		_Out_    uint64_t    *key);

rstate_t
mm_map_contig(
		_In_ uintptr_t  cr3,
		_In_ uintptr_t  addr,
		_In_ uint64_t   value,
		_In_ size_t     length,
		_In_ uint64_t   key);

rstate_t
mm_map_4k_int(
		_In_  uintptr_t  cr3,
		_In_  uintptr_t  addr,
		_In_  uint64_t   value,
		_In_  uint64_t   key,
		_Out_ uintptr_t *pte_addr);

rstate_t
mm_map_4k_nolock(
		_In_ uintptr_t cr3,
		_In_ uintptr_t addr,
		_In_ uint64_t  value,
		_In_ uint64_t  key);

rstate_t
mm_map_4k(
		_In_ uintptr_t  cr3,
		_In_ uintptr_t  addr,
		_In_ uint64_t   value,
		_In_ uint64_t   key);

uintptr_t
mm_get_phys_nolock(
        _In_  uintptr_t  cr3,
        _In_  uintptr_t  addr,
		_Out_ uint64_t  *out_entry);

uintptr_t
mm_get_phys(
        _In_  uintptr_t  cr3,
        _In_  uintptr_t  addr,
		_Out_ uint64_t  *out_entry);

rstate_t
phalloc(_In_ size_t size, _Outptr_ void **allocation);

rstate_t
phfree(_In_ void *allocation, _In_ size_t size);

void
mm_for_each_dirty_page(
		_In_ uintptr_t  cr3,
		_In_ uintptr_t  start_addr,
		_In_ uintptr_t  end_addr,
		_In_ void       (*func)(void *ctxt, uintptr_t vaddr, uintptr_t paddr),
		_In_ void      *ctxt);

rstate_t
mm_create_cow(
		_In_reads_bytes_(orig_len) const void  *orig_buf,
		_In_                       size_t       orig_len,
		_In_opt_                   void        *addr,
		_In_opt_                   uint64_t     key,
		_Outptr_                   void       **out_buf);

rstate_t
alloc_physvirt_4k(_Out_ uintptr_t *phys, _Outptr_ void **virt);

void
mm_register_key_handler(_In_ struct _mm_key *key);

