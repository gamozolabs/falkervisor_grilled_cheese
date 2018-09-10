#include <grilled_cheese.h>
#include <generic/stdlib.h>
#include <disp/disp.h>

/* Rate that the rdtsc increments at, in MHz. 2300 would indicate a 2.3GHz
 * processor. Set by rdtsc_calibrate() early in the boot process.
 */
static uint64_t rdtsc_inc_freq = 0;

/* rdtsc_calibrate()
 *
 * Summary:
 *
 * Using the PIT, determine the frequency of rdtsc. Round this frequency to
 * the nearest 100MHz and store it in the rdtsc_inc_freq global. This function
 * should only be used as part of the system init sequence.
 */
void
rdtsc_calibrate(void)
{
	uint64_t start, rounded_rate;
	double   elapsed, computed_rate;

	/* Store off the current rdtsc value */
	start = __rdtsc();

	/* Program the PIT to use mode 0 (interrupt after countdown) to count
	 * down from 65535. This causes an interrupt to occur after about
	 * 54.92 milliseconds (65535 / 1193182). We mask interrupts from the
	 * PIT, thus we poll by sending the read back command to check whether
	 * the output pin is set to 1, indicating the countdown completed.
	 */
	outb(0x43, 0x30);
	outb(0x40, 0xff);
	outb(0x40, 0xff);

	for( ; ; ){
		/* Send the read back command to latch status on channel 0 */
		outb(0x43, 0xe2);

		/* If the output pin is high, then we know the countdown is done.
		 * Break from the loop.
		 */
		if(inb(0x40) & 0x80){
			break;
		}
	}

	/* Compute the time, in seconds, that the countdown was supposed to take */
	elapsed = 65536.0 / 1193182.0;

	/* Compute MHz for the rdtsc */
	computed_rate = (double)(__rdtsc() - start) / elapsed / 1000000.0;

	/* Round to the nearest 100MHz value */
	rounded_rate = (((uint64_t)computed_rate + 50) / 100) * 100;

	printf("Calibrated rdtsc at %lu MHz, rounding to %lu MHz",
			(uint64_t)computed_rate, rounded_rate);

	/* Store the rounded rate in rdtsc_inc_freq */
	rdtsc_inc_freq = rounded_rate;
	return;
}

/* rdtsc_freq()
 *
 * Summary:
 *
 * This function returns the frequency of rdtsc in MHz. Panics if
 * rdtsc_inc_freq is not set, this will happen if rdtsc_calibrate() is not
 * used first.
 */
uint64_t
rdtsc_freq(void)
{
	if(!rdtsc_inc_freq){
		panic("rdtsc not calibrated, call rdtsc_calibrate() first");
	}

	return rdtsc_inc_freq;
}

/* rdtsc_future()
 *
 * Summary:
 *
 * This function returns the value that rdtsc for the current cpu will be
 * microseconds in the future. This is fairly cheap as it only requires an
 * imul, versus needing to do a div in rdtsc_uptime().
 *
 * Parameters:
 *
 * _In_ microseconds - Number of microseconds to add to the current rdtsc count
 *
 * Returns:
 *
 * Value of rdtsc microseconds in the future.
 */
uint64_t
rdtsc_future(_In_ uint64_t microseconds)
{
	return __rdtsc() + (microseconds * rdtsc_freq());
}

/* rdtsc_uptime()
 *
 * Summary:
 *
 * This returns the current system uptime in microseconds. This function is
 * fairly expensive as it does a divide. If you are polling for a timeout
 * you should use rdtsc_future() once rather than polling this function.
 */
uint64_t
rdtsc_uptime(void)
{
	return __rdtsc() / rdtsc_freq();
}

/* rdtsc_sleep()
 *
 * Summary:
 *
 * This function sleeps for the specified amount of microseconds. This is a
 * busy sleep.
 *
 * Parameters:
 *
 * _In_ microseconds - Number of microseconds to sleep for.
 */
void
rdtsc_sleep(_In_ uint64_t microseconds)
{
	uint64_t waitval;

	waitval = rdtsc_future(microseconds);
	while(__rdtsc() < waitval);

	return;
}

