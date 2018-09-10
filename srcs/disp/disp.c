#include <grilled_cheese.h>
#include <generic/stdlib.h>
#include <interrupts/interrupts.h>
#include <net/net.h>

static uint8_t backing_screen[80*25*2] = { 0 };
static int backing_screen_init = 0;

static int screen_color = 0x0f00;

/* disp_err_mode()
 * 
 * Summary:
 *
 * Calling this function sets the screen color to be flashing text on a grey
 * background. This cannot be undone. This is used for when we panic or have
 * an error to change the screen output forever. Since we allow one core to
 * panic while still resuming execution on others, this allows a visual
 * reference to show that something occured, even if the panic output has
 * since been scrolled off screen.
 */
void
disp_err_mode(void)
{
	screen_color = 0xf000;
}

/* puts_nolock()
 *
 * Summary:
 *
 * This function prints the null terminated string specified by str to the
 * screen. Interrupts are disabled when this function occurs to allow for
 * interrupt handlers to use the screen. We also acquire a lock during prints
 * to allow multiple CPUs to print to the screen without clobbering
 * eachother.
 *
 * The print first goes to the backing_screen. When it is complete this buffer
 * replaces the entire contents of the existing screen. This is done due to
 * the cost of reading the MMIO space of the screen. This way all the screen
 * reads are done in RAM, and only writes are done via MMIO.
 *
 * Parameters:
 *
 * _In_z_ str - Null terminated string to display.
 */
void
puts_nolock(_In_z_ const char *str)
{
	uint8_t  *screen, *ptr, *end;
	uint64_t  len;

	screen = (uint8_t*)current_cpu->boot_params->screen;

	/* Get the length of the string. This should also fault here if the
	 * pointer or string is bad.
	 */
	len = strlen(str);

	/* If we have a networking queue associated with this CPU end the string
	 * over the network, with a maximum of 8192 bytes.
	 */
	if(current_cpu->net_queue){
		struct _net_print {
			uint64_t magic;
			uint64_t req_id;
			uint8_t  buf[8192];
		} net_print;

		uint64_t to_send;

		/* Max size is 8k */
		to_send = MIN(len, sizeof(net_print.buf));

		/* Set up the string print structure packet */
		net_print.magic  = NET_TERM_PRINTSTR;
		net_print.req_id = aes_rand();
		memcpy(net_print.buf, str, to_send);

		if(net_start(current_cpu->net_queue) == RSTATE_SUCCESS){
			/* Send the string to the server */
			if(net_send_udp(current_cpu->net_queue, &net_print,
					(uint32_t)offsetof(struct _net_print, buf)+to_send,
					0, 0) != RSTATE_SUCCESS){
				/* We cant really do anything in an error case. A panic would
				 * cause a recursive print. A halt would just be confusing.
				 */
			}

			net_stop(current_cpu->net_queue);
		}
	}

	/* On the first time we use puts(), copy the original screen conents */
	if(!backing_screen_init){
		memcpy(backing_screen, screen, 80 * 25 * 2);
		backing_screen_init = 1;
	}

	/* Copy up the bottom 24 lines of the screen one line */
	memcpy(backing_screen, backing_screen + 80 * 2, 80 * 2 * 24);

	/* Zero out the last line of the screen */
	memset(backing_screen + 80 * 2 * 24, 0, 80 * 2);

	/* Seek to the end of the screen */
	ptr = backing_screen + 80 * 2 * 24;
	end = ptr + 80 * 2;

	while(*str){
		if(ptr == end || *str == '\n'){
			/* Copy up the bottom 24 lines of the screen one line and zero out
			 * the last line
			 */
			memcpy(backing_screen, backing_screen + 80 * 2, 80 * 2 * 24);
			memset(backing_screen + 80 * 2 * 24, 0, 80 * 2);

			ptr = backing_screen + 80 * 2 * 24;
			end = ptr + 80 * 2;
		}

		/* If the character was not a newline, print it out to the screen */
		if(*str != '\n'){
			*(uint16_t*)ptr = screen_color | *str;
			ptr += 2;
		}

		str++;
	}

	/* Swap in the backing screen to the actual hardware screen */
	memcpy(screen, backing_screen, 80 * 25 * 2);

	return;
}

/* puts()
 *
 * Summary:
 *
 * This function outputs the null terminated string str to the screen. See
 * puts_nolock() for more information.
 *
 * Parameters:
 *
 * _In_z_ str - Null terminated string to display.
 */
static void
puts(_In_z_ const char *str)
{
	/* Disable interrupts */
	interrupts_disable();

	/* Acquire lock */
	spinlock_acquire(DISP_LOCK);

	puts_nolock(str);
	
	/* Release the lock */
	spinlock_release(DISP_LOCK);

	/* Re-enable interrupts */
	interrupts_enable();
}

/* printf()
 *
 * Summary:
 *
 * Print out a formatted string to the screen. The maximum printable size is
 * 4096.
 *
 * Parameters:
 *
 * _In_z_ format - printf format string
 */
void
printf(_In_z_ _Printf_format_string_ const char *format, ...)
{
	va_list ap;

	char     buf[4096];
	uint64_t len;

	va_start(ap, format);

	len = vsnprintf(buf, sizeof(buf), format, ap);
	if(len){
		puts(buf);
	} else {
		puts("!!! printf format error !!!");
	}

	va_end(ap);
	return;
}

