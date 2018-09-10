#include <grilled_cheese.h>
#include <mm/mm.h>
#include <generic/stdlib.h>
#include <disp/disp.h>
#include <interrupts/interrupts.h>
#include <net/net.h>
#include <time/time.h>
#include <cpu/acpi.h>
#include <vm/svm.h>

/* __start()
 *
 * Summary:
 *
 * This is the entry point for our OS. We are passed in a read only
 * boot_parameters structure from the bootloader describing things about the
 * system.
 *
 * Parameters:
 *
 * _In_ params - Pointer to boot_parameters structure containing critical
 *               information from the bootloader. Read only.
 */
void
_start(_In_ const struct _boot_parameters *params)
{
	RSTATE_LOCALS;

	/* Set up CPU locals. This is the first thing we must do. */
	mm_init_cpu(params);

	/* Set up the init task. This is the second thing we must do. */
	task_create_init();

	if(is_bsp()){
		/* Calibrate the rate RDTSC runs at */
		rdtsc_calibrate();

		/* Initialize the ACPI system */
		rstate = acpi_init();
		RSCHECK_NESTED("Failed to initialize ACPI");
		printf("ACPI initialized");
	}

	/* Now that ACPI has been set up, we can set this cpu's node ID */
	current_cpu->node_id = acpi_get_node_id(current_cpu->apic_id);

	/* Do BSP specific initialization while APs sleep */
	if(is_bsp()){
		/* Initialize the mm subsystem */
		rstate = mm_init();
		RSCHECK_NESTED("Failed to initialize the mm subsystem");
		printf("MM subsystem initialized");

		/* Initialize the APIC */
		rstate = mm_init_apic();
		RSCHECK_NESTED("Failed to initialize APIC");
		printf("APIC initialized");

		/* Initialize the PIC */
		pic_init();
		printf("PIC initialized");

		/* Initialize interrupts */
		rstate = interrupts_init();
		RSCHECK_NESTED("Failed to intialize interrupts");
		printf("Interrupts initialized");

		/* Initialize networking */
		rstate = net_init();
		RSCHECK_NESTED("Failed to initialize networking subsystem");
		printf("Networking initialized");

		/* Create a default queue for this CPU */
		rstate = net_init_local_queue();
		RSCHECK_NESTED("Failed to create local network queue");
		printf("CPU local networking initialized");

		/* Create a default queue for this CPU */
		rstate = net_notify_server();
		RSCHECK_NESTED("Failed to notify grilled_cheese server");
		printf("Registered with grilled_cheese server");

		/* Dump out MM stats */
		mm_dump_stats();

		/* Display network devices */
		net_display_devices();

		/* Dump CPU topology */
		cpu_dump_topology();

#if 1
		/* Bring up APs */
		cpu_start_aps();
#endif
	} else {
		/* Initialize the APIC */
		rstate = mm_init_apic();
		RSCHECK_NESTED("Failed to initialize APIC");

		/* Initialize interrupts */
		rstate = interrupts_init();
		RSCHECK_NESTED("Failed to intialize interrupts");

		/* Create a default queue for this CPU */
		rstate = net_init_local_queue();
		RSCHECK_NESTED("Failed to create local network queue");
	}

	printf("Core %u node %u online",
			current_cpu->cpu_id, current_cpu->node_id);

#if 0
	if(is_bsp()){
		struct _vm *vm;

		rstate = vm_create("snapshot.core", &vm);
		RSCHECK_NESTED("Failed to create VM for snapshot");
		
		printf("VM created");
	}
#endif

#if 0
	{
#include <emu/mips.h>

		rstate = emu_mips_create();
		RSCHECK_NESTED("Failed to create mips emulator");

		printf("DONE!");
	}
#endif

#if 1
	/* Initialize SVM */
	rstate = svm_init();
	RSCHECK_NESTED("Failed to initialize SVM");

	{
#include <fuzzers/word.h>

		rstate = fuzz_word();
		RSCHECK_NESTED("Failed to fuzz word");
	}
#endif

	RSCHECK(1 == 0, "Returning from __start");
cleanup:
	RSTATE_PANIC;
}

