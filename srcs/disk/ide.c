#include <grilled_cheese.h>
#include <disp/disp.h>
#include <generic/stdlib.h>

#define IO_ADDR_BASE 0x1f0

#define IDE_DATA      (IO_ADDR_BASE + 0)
#define IDE_ERROR     (IO_ADDR_BASE + 1)
#define IDE_FEATURES  (IO_ADDR_BASE + 1)
#define IDE_SECCOUNT0 (IO_ADDR_BASE + 2)
#define IDE_SECCOUNT1 (IO_ADDR_BASE + 2)
#define IDE_LBA0      (IO_ADDR_BASE + 3)
#define IDE_LBA3      (IO_ADDR_BASE + 3)
#define IDE_LBA1      (IO_ADDR_BASE + 4)
#define IDE_LBA4      (IO_ADDR_BASE + 4)
#define IDE_LBA2      (IO_ADDR_BASE + 5)
#define IDE_LBA5      (IO_ADDR_BASE + 5)
#define IDE_HDDEVSEL  (IO_ADDR_BASE + 6)
#define IDE_COMMAND   (IO_ADDR_BASE + 7)
#define IDE_STATUS    (IO_ADDR_BASE + 7)

#define IDE_CONTROL 0x3f6

#define IDE_OUT_WAIT(port, byte) {outb(port, byte); ide_wait_busy();}

/* ide_wait_busy()
 *
 * Summary:
 *
 * This function waits until the busy bit is no longer set on the IDE drive.
 */
void
ide_wait_busy(void)
{
	while(inb(IDE_STATUS) & 0x80);
	return;
}

/* ide_pio_read_sectors()
 *
 * Summary:
 *
 * This function reads a single sector from the IDE drive starting at
 * an LBA. It does the read via PIO mode, thus this is extremely slow.
 * This code is NOT thread safe.
 *
 * Parameters:
 *
 * _In_  lba     - LBA of the data to read
 * _Out_ buf     - Pointer to caller allocated buffer to receive 1 sector (512
 *                 bytes).
 * _In_  buf_len - Length of the buffer provided (in bytes)
 *
 * Returns:
 *
 * RSTATE_SUCCESS on success, otherwise error.
 */
rstate_t
ide_pio_read_sectors(
		_In_ uint64_t                        lba,
		_Out_writes_bytes_all_(512) uint8_t *buf,
		_In_ size_t                          buf_len)
{
	int ii;

	static int reset = 0;

	RSTATE_LOCALS;

	RSCHECK(buf_len >= 512,
			"Buffer supplied not large enough for 512-byte sector");

	/* If the device is busy or this is our first entry of the function,
	 * reset the device.
	 */
	if(!reset || (inb(IDE_STATUS) & (1 << 7))){
		/* Reset the device */
		outb(IDE_CONTROL, (1 << 2));
		outb(IDE_CONTROL, 0);
		ide_wait_busy();

		reset = 1;
	}

	/* Disable interrupts */
	IDE_OUT_WAIT(IDE_CONTROL, 2);
	
	/* Select master drive with LBA addressing mode */
	IDE_OUT_WAIT(IDE_HDDEVSEL, 0xE0);

	/* Set up to read one sector with the LBA specified */
	IDE_OUT_WAIT(IDE_SECCOUNT1, 0);
	IDE_OUT_WAIT(IDE_LBA5, (lba >> (8 * 5)) & 0xff);
	IDE_OUT_WAIT(IDE_LBA4, (lba >> (8 * 4)) & 0xff);
	IDE_OUT_WAIT(IDE_LBA3, (lba >> (8 * 3)) & 0xff);
	IDE_OUT_WAIT(IDE_SECCOUNT0, 1);
	IDE_OUT_WAIT(IDE_LBA2, (lba >> (8 * 2)) & 0xff);
	IDE_OUT_WAIT(IDE_LBA1, (lba >> (8 * 1)) & 0xff);
	IDE_OUT_WAIT(IDE_LBA0, (lba >> (8 * 0)) & 0xff);

	/* Send the 48-bit LBA PIO read request command */
	outb(IDE_COMMAND, 0x24);

	/* Poll for busy to clear, check for errors as well. */
	for( ; ; ){
		uint8_t status = inb(IDE_STATUS);

		/* Check for an error */
		RSCHECK(!(status & (1 << 0)),
				"Error bit was set in status during IDE read");
		
		/* Check for a drive fault */
		RSCHECK(!(status & (1 << 5)),
				"Drive fault bit was set in status during IDE read");

		/* Check if we're still busy, if we're not, end the loop */
		if(!(status & (1 << 7))){
			break;
		}
	}

	/* Read in all 512 bytes of data */
	for(ii = 0; ii < 512; ii++){
		buf[ii] = inb(IDE_DATA);
	}

	rstate_ret = rstate = RSTATE_SUCCESS;
cleanup:
	RSTATE_RETURN;
}

