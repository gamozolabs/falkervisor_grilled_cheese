#include <grilled_cheese.h>
#include <disp/disp.h>
#include <generic/stdlib.h>
#include <mm/mm.h>
#include <cpu/acpi.h>

/* Array of _cpu_info structures to contain cpu information. This list is
 * indexed by the APIC ID of each CPU.
 */
struct _cpu_info cpus[256] = { { 0 } };

/* Number of CPUs detected to be present on the system */
uint32_t cpus_present = 0;

/* Array of _node_info structure to contain NUMA information. */
struct _node_info nodes[CPU_MAX_NUMA_ID] = { { 0 } };

/* Number of NUMA nodes present on the system */
uint32_t nodes_present = 0;

/* acpi_gen_checksum()
 *
 * Summary:
 *
 * This function computes the checksum for the data of length bytes using the
 * ACPI checksum algorithm.
 *
 * Parameters:
 *
 * _In_ data - Data to perform checksum on
 * _In_ len  - Length of checksum (in bytes)
 *
 * Returns:
 *
 * 8-bit checksum
 */
static uint8_t
acpi_gen_checksum(_In_reads_bytes_(len) const void *data, _In_ size_t len)
{
	const uint8_t *udata = data;
	uint8_t sum = 0;

	while(len){
		sum += *udata;

		udata++;
		len--;
	}

	return sum;
}

/* acpi_get_node_memory()
 *
 * Summary:
 *
 * This function returns amount bytes of contiguous physical memory for the
 * NUMA node specified by node_id.
 *
 * Parameters:
 *
 * _In_  node_id   - NUMA node ID to allocate memory on
 * _In_  amount    - Number of bytes to allocate
 * _Out_ out_paddr - Pointer to caller allocated storage to receive physical
 *                   address of allocation on success.
 *
 * Returns:
 *
 * RSTATE_SUCCESS on success, otherwise error.
 */
rstate_t
acpi_get_node_memory(
		_In_  uint32_t   node_id,
		_In_  size_t     amount,
		_Out_ uintptr_t *out_paddr)
{
	struct _node_info *node = &nodes[node_id];

	RSTATE_LOCALS;

	spinlock_acquire(NUMA_MEMORY_LOCK);

	/* Zero size check and overflow check */
	RSCHECK(amount && (amount + 4096) > amount,
			"Attempted to allocate zero byte or too many bytes");

	/* 4k-align the length */
	amount +=  0xfff;
	amount &= ~0xfff;

starved:
	/* Check if there is a current chunk of memory we are returning memory
	 * from.
	 */
	if(!node->cur_remain){
		uint32_t ii;

		/* There was no current chunk of memory. Grab the next available
		 * chunk of memory from the e820 table.
		 */
		for(ii = 0; ii < node->num_regions; ii++){
			if(node->regions[ii].avail){
				node->cur_base   = node->regions[ii].base;
				node->cur_remain = node->regions[ii].size;
				node->regions[ii].avail = 0;
				break;
			}
		}

		RSCHECK(ii < node->num_regions, "Out of memory on node");
	}

	for( ; ; ){
		/* Check if the length requested is greater than the size of the
		 * current allocation chunk.
		 */
		if(amount > node->cur_remain){
			/* Not enough memory in this chunk to satisfy allocation, consume
			 * it and move try to get another chunk
			 */
			node->cur_base   = 0;
			node->cur_remain = 0;
			goto starved;
		}

		/* If the allocation base is not aligned, go to the next alignment */
		if(node->cur_base & 0xfff){
			node->cur_base   += 1;
			node->cur_remain -= 1;
			continue;
		}

		/* Make sure that the allocation base is above the free_memory_base
		 * passed in from the bootloader.
		 */
		if(mm_is_avail(node->cur_base, amount) &&
			node->cur_base >= current_cpu->boot_params->free_memory_base){
			/* We're available! Break out and return the allocation */
			break;
		}

		/* Allocation was not available, go to the next page */
		node->cur_base   += 4096;
		node->cur_remain -= 4096;
	}

	/* Set the return value */
	*out_paddr = node->cur_base;

	/* Advance the base and remain */
	node->cur_base   += amount;
	node->cur_remain -= amount;

	rstate_ret = rstate = RSTATE_SUCCESS;
cleanup:
	spinlock_release(NUMA_MEMORY_LOCK);
	RSTATE_RETURN;
}

/* acpi_get_node_id()
 *
 * Summary:
 *
 * Return the node ID for a given APIC id.
 *
 * Parameters:
 *
 * _In_ apic_id - APIC ID of the core to query
 *
 * Returns:
 *
 * Node ID that the apic_id belongs to
 */
uint32_t
acpi_get_node_id(_In_ uint32_t apic_id)
{
	if(apic_id >= 0x100 || !cpus[apic_id].present){
		panic("APIC ID not present");
	}

	return cpus[apic_id].numa_id;
}

/* acpi_init()
 *
 * Summary:
 *
 * This function obtains the information we want from ACPI. This information
 * currently includes CPU information, and memory layout for NUMA operation.
 *
 * Returns:
 *
 * RSTATE_SUCCESS on success, otherwise error.
 */
rstate_t
acpi_init(void)
{
	int found_rsdp = 0, found_apic = 0, found_srat = 0;
	uint64_t offset, rsdt_ents, ii;
	struct _rsdp rsdp;
	struct _rsdt rsdt;

	RSTATE_LOCALS;

	/* Try to find the RSDP structure by scanning memory */
	for(offset = 0; offset < 0x100000; offset += 16){
		/* Read in the physical memory and treat it as an _rsdp structure */
		mm_read_phys(offset, &rsdp, sizeof(rsdp));

		/* Check if the signature matches */
		if(!memcmp(rsdp.signature, "RSD PTR ", 8)){
			/* If the checksum is 0, it matched the RSDP, save it off */
			if(acpi_gen_checksum(&rsdp, sizeof(rsdp)) == 0){
				found_rsdp = 1;
				break;
			}
		}
	}
	RSCHECK(found_rsdp == 1, "Failed to find RSDP structure");
	
	/* Grab a copy of the RSDT */
	mm_read_phys(rsdp.rsdt_addr, &rsdt, sizeof(rsdt));

	/* Make sure the signature matches the RSDT */
	RSCHECK(!memcmp(rsdt.hdr.signature, "RSDT", 4),
			"RSDT signature not found");

	/* Make sure the RSDT checksum is correct */
	RSCHECK(acpi_gen_checksum(&rsdt, rsdt.hdr.length) == 0,
			"RSDT checksum was incorrect");

	/* Make sure the length is at least big enough for the header, and no
	 * larger than our statically allocated payload.
	 */
	RSCHECK(rsdt.hdr.length <= sizeof(rsdt) &&
			rsdt.hdr.length >= sizeof(struct _acpi_standard_header),
			"RSDT length is malformed");

	/* Calculate the number of table entries in the RSDP */
	rsdt_ents = (rsdt.hdr.length - sizeof(struct _acpi_standard_header)) / 4;

	/* Loop through for each RSDT entry */
	for(ii = 0; ii < rsdt_ents; ii++){
		struct _acpi_standard_header tmp;

		/* Read the generic header from this table and then identify it */
		mm_read_phys(rsdt.tables[ii], &tmp, sizeof(tmp));

		/* Bounds check on the table */
		RSCHECK(tmp.length >= sizeof(struct _acpi_standard_header),
				"ACPI table length too short for standard header");

		/* Check for MADT table */
		if(!found_apic && !memcmp(tmp.signature, "APIC", 4)){
			uint8_t  *payload;
			uint32_t  payload_len;
			struct _madt madt;

			/* Bounds check on the MADT */
			RSCHECK(tmp.length >= offsetof(struct _madt, payload) &&
					tmp.length <= sizeof(struct _madt),
					"MADT too large for static allocation");

			/* Grab the MADT */
			mm_read_phys(rsdt.tables[ii], &madt, sizeof(madt));
			
			/* Validate the checksum */
			RSCHECK(acpi_gen_checksum(&madt, madt.hdr.length) == 0,
					"MADT checksum was incorrect");

			found_apic = 1;

			payload     = madt.payload;
			payload_len = madt.hdr.length - offsetof(struct _madt, payload);

			while(payload_len >= 2){
				uint32_t type, rec_len;

				/* Grab the type and record length */
				type    = *(payload + 0);
				rec_len = *(payload + 1);

				/* Make sure the record length is large enough to have the
				 * record header. Make sure it's not larger than the payload
				 * length.
				 */
				RSCHECK(rec_len >= 2 && payload_len >= rec_len,
						"MADT record size too large or too small");

				/* Local APIC */
				if(type == 0){
					uint8_t  apic_id;
					uint32_t flags;

					RSCHECK(rec_len == 8,
							"Invalid MADT local APIC record length");

					apic_id = *(payload + 3);
					flags   = *(uint32_t*)(payload + 4);

					/* If the APIC is enabled */
					if(flags & 1){
						/* Make sure that this is not marked present yet */
						RSCHECK(cpus[apic_id].present == 0,
								"Mulitple entries in the MADT describing the "
								"same APIC");

						cpus[apic_id].present = 1;
						cpus[apic_id].apic_id = apic_id;
						cpus[apic_id].numa_id = 0;
						cpus_present++;
					}
				} else {
					/* We don't handle any other types */
				}

				/* Go to the next record */
				payload     += rec_len;
				payload_len -= rec_len;
			}

			printf("Identified %u processors on the system", cpus_present);
		} else if(!found_srat && !memcmp(tmp.signature, "SRAT", 4)){
			uint8_t  *payload;
			uint32_t  payload_len;
			struct _srat srat;

			/* Bounds check on the SRAT */
			RSCHECK(tmp.length >= offsetof(struct _srat, payload) &&
					tmp.length <= sizeof(struct _srat),
					"SRAT too large for static allocation");

			/* Grab the SRAT */
			mm_read_phys(rsdt.tables[ii], &srat, sizeof(srat));

			/* Validate the checksum */
			RSCHECK(acpi_gen_checksum(&srat, srat.hdr.length) == 0,
					"SRAT checksum was incorrect");

			found_srat = 1;

			payload     = srat.payload;
			payload_len = srat.hdr.length - offsetof(struct _srat, payload);

			while(payload_len >= 2){
				uint32_t type, rec_len;

				/* Grab the type and record length */
				type    = *(payload + 0);
				rec_len = *(payload + 1);

				/* Make sure the record length is large enough to have the
				 * record header. Make sure it's not larger than the payload
				 * length.
				 */
				RSCHECK(rec_len >= 2 && payload_len >= rec_len,
						"SRAT record size too large or too small");

				if(type == 0){
					/* Local APIC/SAPIC affinity structure */
					uint32_t apic_id;
					uint32_t flags;
					uint32_t numa_id;

					/* Check that the record length is what we expect */
					RSCHECK(rec_len == 16,
							"SRAT APIC affinity structure size invalid");

					apic_id = *(payload + 3);
					flags   = *(uint32_t*)(payload + 4);
					numa_id = *(payload + 2) |
						(*(uint32_t*)(payload + 8) & 0xffffff00);

					/* Check if this entry is enabled */
					if(flags & 1){
						RSCHECK(numa_id < CPU_MAX_NUMA_ID,
								"NUMA ID larger than maximum");

						/* Associate the APIC with this NUMA node */
						cpus[apic_id].numa_id = numa_id;
					}
				} else if(type == 1){
					/* Memory affinity structure */
#pragma pack(push, 1)
					struct {
						uint8_t  type;
						uint8_t  length;
						uint32_t numa_id;
						uint16_t reserved1;
						uint64_t memory_base;
						uint64_t memory_size;
						uint32_t reserved2;
						uint32_t flags;
						uint64_t reserved3;
					} *entry = (void*)payload;
#pragma pack(pop)

					RSCHECK(rec_len == sizeof(*entry),
							"SRAT memory affinity structure size invalid");

					/* Check if the entry is enabled */
					if(entry->flags & 1){
						uint32_t numa_id = entry->numa_id;
						uint32_t region_id;

						RSCHECK(numa_id < CPU_MAX_NUMA_ID,
								"NUMA ID larger than maximum");

						RSCHECK(nodes[numa_id].num_regions < CPU_MAX_REGIONS,
								"Too many regions on NUMA node, increase "
								"CPU_MAX_REGIONS define");

						region_id = nodes[numa_id].num_regions++;

						/* If this is the first entry for this NUMA node,
						 * increment the number of NUMA nodes.
						 */
						if(!nodes[numa_id].present){
							nodes_present++;
						}

						/* Create the NUMA entry for this */
						nodes[numa_id].present    = 1;
						nodes[numa_id].numa_id    = numa_id;
						nodes[numa_id].cur_base   = 0;
						nodes[numa_id].cur_remain = 0;
						nodes[numa_id].regions[region_id].base =
							entry->memory_base;
						nodes[numa_id].regions[region_id].size =
							entry->memory_size;
						nodes[numa_id].regions[region_id].avail = 1;
					}
				}

				/* Go to the next record */
				payload     += rec_len;
				payload_len -= rec_len;
			}
		}
	}

	{
		uint32_t apic_id;

		/* Walk through all APICs to make sure they reference a valid
		 * NUMA node.
		 */
		for(apic_id = 0; apic_id < 256; apic_id++){
			uint32_t numa_id = cpus[apic_id].numa_id;

			if(!cpus[apic_id].present) continue;

			RSCHECK(numa_id < CPU_MAX_NUMA_ID, "NUMA ID larger than maximum");

			RSCHECK(nodes[numa_id].present == 1,
					"APIC references NUMA node not present");
		}
	}

	rstate_ret = rstate = RSTATE_SUCCESS;
cleanup:
	RSTATE_RETURN;
}

/* cpu_dump_topology()
 *
 * Summary:
 *
 * This function pretty prints the CPU topology information we obtained
 * from the ACPI tables in acpi_init().
 */
void
cpu_dump_topology(void)
{
	uint32_t numa_id;

	printf("CPU topology:");
	printf("    %u CPUs present", cpus_present);
	printf("    %u NUMA nodes present", nodes_present);

	for(numa_id = 0; numa_id < CPU_MAX_NUMA_ID; numa_id++){
		uint32_t region;

		if(!nodes[numa_id].present) continue;

		printf("    NUMA node %u", numa_id);

		for(region = 0; region < nodes[numa_id].num_regions; region++){
			printf("        Region %u: %.16lx %.16lx",
					region,
					nodes[numa_id].regions[region].base,
					nodes[numa_id].regions[region].size);
		}
	}
}

