#include <grilled_cheese.h>
#include <disp/disp.h>
#include <generic/stdlib.h>

/* overlaps()
 *
 * Summary:
 *
 * This function returns 1 if [x1, x2] and [y1, y2] have any overlap and 0
 * if there is no overlap.
 *
 * Parameters:
 *
 * _In_ [x1, x2] - First range
 * _In_ [y1, y2] - Second range
 *
 * Returns:
 *
 * 0 - No overlap exists between [x1, x2] and [y1, y2]
 * 1 - There is overlap between [x1, x2] and [y1, y2]
 */
int
overlaps(_In_ uint64_t x1, _In_ uint64_t x2, _In_ uint64_t y1,
		_In_ uint64_t y2)
{
	uint64_t tmp;

	/* Swap x1 and x2 to make sure x1 <= x2 */
	if(x1 > x2){
		tmp = x2;
		x2  = x1;
		x1  = tmp;
	}

	/* Swap y1 and y2 to make sure y1 <= y2 */
	if(y1 > y2){
		tmp = y2;
		y2  = y1;
		y1  = tmp;
	}

	if(x1 <= y2 && y1 <= x2)
		return 1;

	return 0;
}

/* contains()
 *
 * Summary:
 *
 * This function returns 1 if the entirety of [x1, x2] is contained inside
 * of [y1, y2], else returns 0.
 *
 * Parameters:
 *
 * _In_ [x1, x2] - 'needle' range
 * _In_ [y1, y2] - 'haystack' range
 *
 * Returns:
 *
 * 1 - If needle is contained entirely in haystack
 * 0 - If needle is not contained entirely in haystack
 */
int
contains(_In_ uint64_t x1, _In_ uint64_t x2, _In_ uint64_t y1,
		_In_ uint64_t y2)
{
	uint64_t tmp;

	/* Swap x1 and x2 to make sure x1 <= x2 */
	if(x1 > x2){
		tmp = x2;
		x2  = x1;
		x1  = tmp;
	}

	/* Swap y1 and y2 to make sure y1 <= y2 */
	if(y1 > y2){
		tmp = y2;
		y2  = y1;
		y1  = tmp;
	}

	if(x1 >= y1 && x2 <= y2)
		return 1;

	return 0;
}

/* memset()
 *
 * Summary:
 *
 * Sets the value c to all size positions in dest. This behaves the same as
 * memset() defined by the C standard.
 *
 * Parameters:
 *
 * _Out_ dest - Pointer to memory to set to 'c'
 * _In_  c    - Character set memory with
 * _In_  size - Number of bytes of c to write at dest
 *
 * Returns:
 *
 * The original value passed in via dest.
 */
void*
memset(
		_Out_writes_bytes_all_(size) void    *dest,
		_In_                         uint8_t  c,
		_In_                         size_t   size)
{
	uint8_t *udest = dest;

	while(size){
		*udest = c;
		udest++;
		size--;
	}

	return dest;
}

/* memcpy()
 *
 * Summary:
 *
 * Copies src to dest for size bytes. Works as a memmove() does and is safe
 * if there is overlap.
 *
 * Parameters:
 *
 * _Out_ dest - Destination to write to
 * _In_  src  - Source to read from
 * _In_  size - Number of bytes to read.
 *
 * Returns:
 *
 * Initial value of dest.
 */
void*
memcpy(
		_Out_writes_bytes_all_(size) void       *dest,
		_In_reads_bytes_(size)       const void *src,
		_In_                         size_t      size)
{
	uint8_t       *udest = dest;
	const uint8_t *usrc  = src;

	size_t ii;

	/* There is no copy to be done */
	if(src == dest || !size)
		return dest;

	/* Check if there is overlap */
	if(udest < (usrc + size) && usrc < (udest + size)){
		/* There was overlap, check which direction. */
		if(src < dest){
			/* Copy backwards */
			for(ii = size-1; ; ii--){
				udest[ii] = usrc[ii];

				if(!ii) break;
			}

			return dest;
		}
	}

	for(ii = 0; ii < size; ii++){
		udest[ii] = usrc[ii];
	}

	return dest;
}

/* memcmp()
 *
 * Summary:
 *
 * Returns 0 if both memory regions match for size, else returns 1. This
 * violates the C standard, as we don't return the difference between the
 * first encountered differing byte. We only return 0 on match, and 1 on
 * no match.
 *
 * Parameters:
 *
 * _In_ a    - Pointer to memory to compare against
 * _In_ b    - Pointer to memory to compare against
 * _In_ size - Number of bytes to compare
 *
 * Returns:
 *
 * 0 - If a and b match
 * 1 - If a and b do not match
 */
int
memcmp(
		_In_reads_bytes_(size) const void *a,
		_In_reads_bytes_(size) const void *b,
		_In_                   size_t      size)
{
	const uint8_t *ua = a;
	const uint8_t *ub = b;

	while(size){
		if(*ua != *ub){
			return 1;
		}

		ua++;
		ub++;
		size--;
	}

	return 0;
}

/* strlen()
 *
 * Summary:
 *
 * Returns the length of the null-terminated string str.
 *
 * Parameters:
 *
 * _In_z_ str - Pointer to null terminated string to count number of characters
 *              in.
 *
 * Returns:
 *
 * Number of non-null bytes contained in str.
 */
size_t
strlen(_In_z_ const void *str)
{
	const uint8_t *ustr = str;
	size_t len = 0;

	while(*ustr){
		len++;
		ustr++;
	}

	return len;
}

/* falkhash()
 *
 * Summary:
 *
 * Performs a falkhash and returns the result.
 *
 * Parameters:
 *
 * _In_ pbuf - Pointer to memory to generate a hash of
 * _In_ len  - Number of bytes pointed to by pbuf to hash
 *
 * Returns:
 *
 * Hash of pbuf for len bytes.
 */
__m128i
falkhash(_In_reads_bytes_(len) const void *pbuf, _In_ size_t len)
{
	uint8_t *buf = (uint8_t*)pbuf;

	uint64_t iv[2], pseed;

	__m128i hash, seed;

	/* Create the 128-bit seed. Low 64-bits gets seed, high 64-bits gets
	 * seed + len + 1. The +1 ensures that both 64-bits values will never be
	 * the same (with the exception of a length of -1. If you have that much
	 * ram, send me some).
	 */
	pseed = 0x1337133713371337;
	iv[0] = pseed;
	iv[1] = pseed + len + 1;

	/* Load the IV into a __m128i */
	seed = _mm_loadu_si128((__m128i*)iv);

	/* Hash starts out with the seed */
	hash = seed;

	while(len){
		uint8_t tmp[0x50];

		__m128i piece[5];

		/* If the data is smaller than one chunk, pad it with zeros */
		if(len < 0x50){
			memset(tmp, 0, 0x50);
			memcpy(tmp, buf, len);
			buf = tmp;
			len = 0x50;
		}

		/* Load up the data into __m128is */
		piece[0] = _mm_loadu_si128((__m128i*)(buf + 0*0x10));
		piece[1] = _mm_loadu_si128((__m128i*)(buf + 1*0x10));
		piece[2] = _mm_loadu_si128((__m128i*)(buf + 2*0x10));
		piece[3] = _mm_loadu_si128((__m128i*)(buf + 3*0x10));
		piece[4] = _mm_loadu_si128((__m128i*)(buf + 4*0x10));

		/* xor each piece against the seed */
		piece[0] = _mm_xor_si128(piece[0], seed);
		piece[1] = _mm_xor_si128(piece[1], seed);
		piece[2] = _mm_xor_si128(piece[2], seed);
		piece[3] = _mm_xor_si128(piece[3], seed);
		piece[4] = _mm_xor_si128(piece[4], seed);

		/* aesenc all into piece[0] */
		piece[0] = _mm_aesenc_si128(piece[0], piece[1]);
		piece[0] = _mm_aesenc_si128(piece[0], piece[2]);
		piece[0] = _mm_aesenc_si128(piece[0], piece[3]);
		piece[0] = _mm_aesenc_si128(piece[0], piece[4]);

		/* Finalize piece[0] by aesencing against seed */
		piece[0] = _mm_aesenc_si128(piece[0], seed);

		/* aesenc the piece into the hash */
		hash = _mm_aesenc_si128(hash, piece[0]);

		buf += 0x50;
		len -= 0x50;
	}

	/* Finalize hash by aesencing against seed four times */
	hash = _mm_aesenc_si128(hash, seed);
	hash = _mm_aesenc_si128(hash, seed);
	hash = _mm_aesenc_si128(hash, seed);
	hash = _mm_aesenc_si128(hash, seed);

	return hash;
}

/* aes_rand()
 *
 * Summary:
 *
 * Return a random 64-bit number.
 *
 * Returns:
 *
 * Random 64-bit value from 128-bit seed for this CPU.
 */
uint64_t
aes_rand(void)
{
	__m128i seed;

	seed = current_cpu->rng_seed;
	seed = _mm_aesenc_si128(seed, seed);
	seed = _mm_aesenc_si128(seed, seed);
	seed = _mm_aesenc_si128(seed, seed);
	seed = _mm_aesenc_si128(seed, seed);
	current_cpu->rng_seed = seed;

	return _mm_cvtsi128_si64(seed);
}

/* vsnprintf()
 *
 * Summary:
 *
 * This function outprintf to 'buf' the formatted string specified by format
 * and the variable arguments. The length of 'buf' is specified by the 'len'
 * parameter (in bytes). This function ensures that the output never exceeds
 * this buffer size and also always includes a null terminator. If there is
 * not enough room for the formatted string or the null terminator, a
 * parsing failure occurs and the function fails gracefully
 * (see "Parsing failure behaviour").
 *
 * Deviations from the standard:
 *
 * Currently only 's', 'x', 'u', '%' 'p', and 'd' format types are allowed. Any
 * others result in a parsing failure.
 * Currently the '-' flag is parsed but unused
 * Currently the '+' flag is parsed but unused
 * Currently the '#' flag is parsed but unused
 * Currently the ' ' flag is parsed but unused
 * Currently the '0' flag is only used for strings. If you want to have zeros
 *   on your numbers, use the precision flag like you should.
 * This function guarantees the returned string is null terminated. If there
 *   is not enough room for the output including the null terminator a
 *   parsing failure occurs.
 *
 * Parsing failure behaviour:
 *
 * Any invalid printf format specifier or output buffer overflow results in
 *   graceful termination yielding a return value of 0. Unlike standard
 *   implementations which will output up until the end of the buffer.
 *   While the function returns 0, the buffer may have actually been changed,
 *   however it will never overflow.
 *
 * Supported printf() format (mimics MSVC format):
 *
 * %[flags] [width] [.precision] [{h | l | ll | w | I | I32 | I64}] type
 *
 * Flags:
 *
 * '-' - Left align result
 * '+' - Prepend a + or - prefix on a signed type
 * '0' - Leading zeros until maximum width
 *       If '0' and '-' are present, the '0' is ignored.
 *       0 is ignored if precision specification is present.
 * ' ' - Blank prefix if output value is signed and positive
 *       this makes sure ' 100' and '-100' both are the same length.
 * '#' - When it's used with the o, x, or X format, the # flag uses 0, 0x,
 *       or 0X, respectively, to prefix any nonzero output value. Zero values
 *       get no prefix
 *
 * Width:
 *
 * Minimum number of characters to output. '*' decodes an int from the stack.
 *
 * Precision:
 *
 * Maximum number of characters for strings. Number of significant digits
 * or number of digits after decimal for floating point, and minimum number
 * of digits for integer values. '*' decodes and int from the stack.
 *
 * Size:
 *
 * h   - int16_t
 * l   - int64_t
 * w   - Wide string / wide character / int32_t
 *
 * Parameters:
 *
 * _Out_ buf    - Buffer to write formatted string to
 * _In_  len    - Number of bytes available for storage pointed to by buf.
 * _In_  format - printf format string
 * _In_  ap     - va_list describing the parameters to pass in for the format
 *                string.
 *
 * Returns:
 *
 * Number of bytes written into buf (excluding null terminator)
 */
size_t
vsnprintf(
		_Out_writes_bytes_(len)       char       *buf,
		_In_                          size_t      len,
		_In_z_ _Printf_format_string_ const char *format,
		_In_                          va_list     ap)
{
	char       *outptr = buf;
	const char *hexlut = "0123456789abcdef";

	while(*format){
		/* If we found a '%' character, we're doing a format! */
		if(*format == '%'){
			struct {
				int left_align;
				int prepend_sign;
				int leading_zero;
				int blank_prefix;
				int hex_octal_prefix;
			} flags = { 0 };

			int width = 0, precision = 0, size = 32, type = 0;

			/* Move past the '%' character */
			format++;

			/* Check for a flag, '-', '+', '0', ' ', '#' */
			while(*format == '-' || *format == '+' || *format == '0' ||
					*format == ' ' || *format == '#'){
				switch(*format){
					case '-':
						flags.left_align = 1;
						break;
					case '+':
						flags.prepend_sign = 1;
						break;
					case '0':
						flags.leading_zero = 1;
						break;
					case ' ':
						flags.blank_prefix = 1;
						break;
					case '#':
						flags.hex_octal_prefix = 1;
						break;
				}

				/* Consume the flag */
				format++;
			}

			/* Parse out the width, or a variable width '*' */
			if(*format == '*'){
				/* Variable width, pulled from stack as int */
				width = va_arg(ap, int);
				format++;
			} else {
				/* Parse out the width */
				while(*format >= '0' && *format <= '9'){
					width *= 10;
					width += (*format - '0');
					format++;
				}
			}
			
			/* Width is not allowed to be negative */
			if(width < 0){
				goto fail_parsing;
			}

			/* Potentially parse out a precision */
			if(*format == '.'){
				/* Consume the '.' */
				format++;

				/* Parse out the precision, or the variable precision '*' */
				if(*format == '*'){
					/* Variable precision, pulled from stack as int */
					precision = va_arg(ap, int);
					format++;
				} else {
					/* Parse out the precision */
					while(*format >= '0' && *format <= '9'){
						precision *= 10;
						precision += (*format - '0');
						format++;
					}
				}
			}

			/* Precision is not allowed to be negative */
			if(precision < 0){
				goto fail_parsing;
			}

			/* Parse out a size [{h | l | ll | w}] */
			if(*format == 'h'){
				size = 16; /* h */
				format++;
			} else if(*format == 'l'){
				format++;
				size = 64; /* l */
			} else if(*format == 'w'){
				size = 16; /* w */
				format++;
			}

			/* Grab the actual format type */
			type = *format;
			format++;

			/* Turn 'p's into '.16I64x's */
			if(type == 'p'){
				type      = 'x';
				size      = 64;
				precision = 16;
			}

			/* We only support these types */
			if(type != 's' && type != 'd' && type != 'u' && type != 'x' &&
					type != '%'){
				goto fail_parsing;
			}

			/* All integer types are parsed together */
			if(type == 'd' || type == 'u' || type == 'x'){
				int  tmp_len = 0, to_write, base = 10;
				char tmp[32], *ptr, negative = 0;

				int64_t  sval = 0;
				uint64_t val  = 0;

				val = va_arg(ap, uint64_t);

				/* Grab the right size argument */
				if(size == 16){
					val  &= 0xffff;
					sval  = (int16_t)val;
				} else if(size == 32){
					val  &= 0xffffffff;
					sval  = (int32_t)val;
				} else if(size == 64){
					sval  = (int64_t)val;
				}

				/* Change the base for hex prints */
				if(type == 'x'){
					base = 16;
				}

				/* If it's signed, set the negative flag and make it not
				 * negative.
				 */
				if(type == 'd' && sval < 0){
					negative = 1;
					val = -sval;
				}

				/* Print out the number */
				ptr = &tmp[sizeof(tmp)];
				do {
					ptr--;
					*ptr = hexlut[val % base];
					tmp_len++;

					val /= base;
				} while(val);

				/* Calculate the number of characters to write. This includes
				 * room for the negative flag (if there is one), and then
				 * either the precision (which will be padded with zeros) or
				 * the actual number size.
				 */
				to_write = negative;
				if(tmp_len > precision){
					to_write += tmp_len;
				} else {
					to_write += precision;
				}

				/* Determine the number of space padding characters to put
				 * out front to ensure we at least hit the minimum width
				 * specified.
				 */
				if(to_write < width){
					uint64_t fill_count;

					/* Determine the number of fill characters we need */
					fill_count = width - to_write;

					/* Make sure we have enough room for the fill */
					if(len < fill_count){
						goto fail_parsing;
					}

					memset(outptr, ' ', fill_count);
					outptr += fill_count;
					len    -= fill_count;
				}

				/* Output the '-' sign if it's a negative value */
				if(negative){
					/* Make sure there is room for the '-' character */
					if(!len){
						goto fail_parsing;
					}

					*outptr++ = '-';
					len--;
				}

				/* Determine the number of leading zeros to print out.
				 * This is specified by the precision argument.
				 */
				if(tmp_len < precision){
					uint64_t fill_count;

					/* Determine the number of fill characters we need */
					fill_count = precision - tmp_len;

					/* Make sure we have enough room for the fill */
					if(len < fill_count){
						goto fail_parsing;
					}

					memset(outptr, '0', fill_count);
					outptr += fill_count;
					len    -= fill_count;
				}

				/* Make sure there is enough room in the output buffer */
				if(len < tmp_len){
					goto fail_parsing;
				}

				memcpy(outptr, ptr, tmp_len);
				outptr += tmp_len;
				len    -= tmp_len;
			} else if(type == 's'){
				char fill_char;
				const char *str;
				const char *null = "(null)";
				uint64_t str_len = 0;
				
				/* Pop off an argument, this time it's a pointer to a string */
				str = va_arg(ap, const char*);

				/* In a null case gracefully handle it by printing out
				 * '(null)'. Just replace the null pointer with a pointer to
				 * the '(null)' string. This then gets treated as the input so
				 * things like precision still are respected.
				 */
				if(!str){
					str = (char*)null;
				}

				/* If no precision is specified, make the precision
				 * nearly unlimited (-1).
				 */
				if(!precision){
					precision = -1;
				}

				/* Compute the length of the string, but only up until
				 * precision.
				 */
				for(str_len = 0; str_len < precision; str_len++){
					if(!str[str_len]){
						break;
					}
				}

				/* Determine if we need to print out padding to reach the
				 * minimum amount of space specified by the width parameter.
				 */
				if(str_len < width){
					uint64_t fill_count;

					/* Determine the number of fill characters we need */
					fill_count = width - str_len;

					/* Determine whether we want to fill with '0's or spaces */
					fill_char = flags.leading_zero ? '0' : ' ';

					/* Make sure we have enough room for the fill */
					if(len < fill_count){
						goto fail_parsing;
					}

					memset(outptr, fill_char, fill_count);
					outptr += fill_count;
					len    -= fill_count;
				}

				/* Must have room for the string to print */
				if(len < str_len){
					goto fail_parsing;
				}

				memcpy(outptr, str, str_len);
				outptr += str_len;
				len    -= str_len;
			} else if(type == '%'){
				/* Must have room to write one byte */
				if(!len){
					goto fail_parsing;
				}

				*outptr++ = '%';
				len--;
			} else {
				/* Unsupported type */
				goto fail_parsing;
			}
		} else { /* we we not a '%' */
			/* Must have room to write one byte */
			if(!len){
				goto fail_parsing;
			}

			*outptr++ = *format++;
			len--;
		}
	}

	/* Make sure we have enough room for the null terminator */
	if(!len){
		goto fail_parsing;
	}
	*outptr = 0;

	goto done;

fail_parsing:
	/* Reset outptr to buf so that we return 0 */
	outptr = buf;

done:
	return (size_t)(outptr - buf);
}

/* snprintf()
 *
 * Summary:
 *
 * This function formats the data described by format and ... and writes
 * it into the buffer pointed to by buf. A null terminator is always inserted
 * into buf, unless len provided is 0.
 *
 * Parameters:
 *
 * _Out_ buf    - Buffer to write formatted string to
 * _In_  len    - Number of bytes available for storage pointed to by buf.
 * _In_  format - printf format string
 * _In_  ...    - Arguments to use in format string
 *
 * Returns:
 *
 * Number of bytes written into buf, excluding null terminator.
 */
size_t
snprintf(
		_Out_writes_bytes_(len)       char       *buf,
		_In_                          size_t      len,
		_In_z_ _Printf_format_string_ const char *format,
		...)
{
	size_t  ret;
	va_list ap;

	va_start(ap, format);
	ret = vsnprintf(buf, len, format, ap);
	va_end(ap);
	return ret;
}

/* memrmem()
 *
 * Summary:
 *
 * This function finds the last occuring instance of needle in haystack.
 *
 * Parameters:
 *
 * _In_ haystack     - Pointer to haystack
 * _In_ haystack_len - Length of haystack (in bytes)
 * _In_ needle       - Pointer to needle
 * _In_ needle_len   - Length of needle (in bytes)
 *
 * Returns:
 *
 * Pointer to last occurance of needle in haystack if found.
 * NULL if no occurance of needle is found in haystack.
 */
void*
memrmem(
		_In_reads_bytes_(haystack_len) const void *haystack,
		_In_                           size_t      haystack_len,
		_In_reads_bytes_(needle_len)   const void *needle,
		_In_                           size_t      needle_len)
{
	uint8_t *ptr = ((uint8_t*)haystack + haystack_len - needle_len);

	if(!haystack || !needle || !haystack_len || !needle_len ||
			haystack_len < needle_len)
		return NULL;

	while(ptr >= (uint8_t*)haystack){
		if(!memcmp(ptr, needle, needle_len))
			return ptr;

		ptr--;
	}

	return NULL;
}

/* isalnum()
 *
 * Summary:
 *
 * This function returns 1 if the character 'c' is alphanumeric. Otherwise
 * returns 0.
 */
int
isalnum(_In_ uint8_t c)
{
	return ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9')) ? 1 : 0;
}

/* isdigit()
 *
 * Summary:
 *
 * This function returns 1 if the character 'c' is a number. Otherwise
 * returns 0.
 */
int
isdigit(_In_ uint8_t c)
{
	return (c >= '0' && c <= '9') ? 1 : 0;
}

/* isxdigit()
 *
 * Summary:
 *
 * This function returns 1 if the character 'c' is a hex digit. Otherwise
 * returns 0.
 */
int
isxdigit(_In_ uint8_t c)
{
	return ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') ||
			(c >= 'a' && c <= 'f')) ? 1 : 0;
}

/* atoi()
 *
 * Summary:
 *
 * This function converts the null-terminated string pointed to by buf into
 * an unsigned integer. This function stops on the first non-digit encounter
 * in the string. buf is interpreted as a base-10 number.
 *
 * Parameters:
 *
 * _In_z_ buf - Pointer to string representation of base-10 number
 *
 * Returns:
 *
 * Unsigned integer represented by base-10 string buf
 */
size_t
atoi(_In_z_ const char *buf)
{
	size_t ret = 0;

	while(buf && isdigit(*buf)){
		ret *= 10;
		ret += *buf - '0';

		buf++;
	}

	return ret;
}

/* nonnullcount()
 *
 * Summary:
 *
 * This function counts the number of non-null bytes contained in buf for
 * length bytes.
 *
 * Parameters:
 *
 * _In_ buf - Pointer to memory to count non-null bytes in
 * _In_ len - Number of bytes pointed to by buf.
 *
 * Returns:
 *
 * Number of non-null bytes pointed to by buf.
 */
size_t
nonnullcount(_In_reads_bytes_(len) const uint8_t *buf, _In_ size_t len)
{
	size_t count = 0;

	while(len){
		if(*buf) count++;

		buf++;
		len--;
	}

	return count;
}

/* nonnulllast()
 *
 * Summary:
 *
 * This function returns the length of buf given all trailing null characeters
 * are stripped off. However it returns 1 the string is all nulls. It only
 * returns 0 if len is 0.
 *
 * Parameters:
 *
 * _In_ buf - Pointer to memory to get truncated length of
 * _In_ len - Size of buf (in bytes)
 */
size_t
nonnulllast(_In_reads_bytes_(len) const uint8_t *buf, _In_ size_t len)
{
	size_t ii = 0;

	if(!len){
		return 0;
	}

	for(ii = (len - 1); ii > 0; ii--){
		if(buf[ii]){
			return ii + 1;
		}
	}

	return 1;
}

/* hasheq()
 *
 * Summary:
 *
 * This function returns 1 if the hashes equal, otherwise returns 0.
 */
int
hasheq(_In_ __m128i a, _In_ __m128i b)
{
	__m128i tmp;

	tmp = _mm_xor_si128(a, b);
	return _mm_test_all_zeros(tmp, tmp);
}

/* hashnull()
 *
 * Summary:
 *
 * This function returns 1 if the hash is 0, otherwise returns 0.
 */
int
hashnull(_In_ __m128i hash)
{
	return _mm_test_all_zeros(hash, hash);
}

