#pragma once

#define CPU_MAX_NUMA_ID 256
#define CPU_MAX_REGIONS 8

struct _cpu_info {
	int present;

	uint32_t apic_id;
	uint32_t numa_id;
};

struct _node_info {
	int present;

	uint32_t numa_id;
	uint32_t num_regions;

	struct {
		uint64_t base;
		uint64_t size;
		int      avail;
	} regions[CPU_MAX_REGIONS];

	uint64_t cur_base;
	uint64_t cur_remain;
};

#pragma pack(push, 1)
struct _rsdp {
	char     signature[8];
	uint8_t  checksum;
	char     oem_id[6];
	uint8_t  revision;
	uint32_t rsdt_addr;
};

struct _acpi_standard_header {
	char     signature[4];
	uint32_t length;
	uint8_t  revision;
	uint8_t  checksum;
	char     oem_id[6];
	char     oem_table_id[8];
	uint32_t oem_revision;
	uint32_t creator_id;
	uint32_t creator_revision;
};

struct _rsdt {
	struct _acpi_standard_header hdr;

	uint32_t tables[128];
};

struct _madt {
	struct _acpi_standard_header hdr;

	uint32_t local_controller_addr;
	uint32_t flags;

	uint8_t payload[2048];
};

struct _srat {
	struct _acpi_standard_header hdr;

	uint32_t reserved1;
	uint64_t reserved2;

	uint8_t payload[8 * 1024];
};
#pragma pack(pop)

rstate_t
acpi_get_node_memory(
		_In_  uint32_t   node_id,
		_In_  size_t     amount,
		_Out_ uintptr_t *out_paddr);

uint32_t
acpi_get_node_id(_In_ uint32_t apic_id);

rstate_t
acpi_init(void);

void
cpu_dump_topology(void);

