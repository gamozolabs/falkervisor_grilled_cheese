#pragma once

int
overlaps(_In_ uint64_t x1, _In_ uint64_t x2, _In_ uint64_t y1,
		_In_ uint64_t y2);

int
contains(_In_ uint64_t x1, _In_ uint64_t x2, _In_ uint64_t y1,
		_In_ uint64_t y2);

void*
memset(
		_Out_writes_bytes_all_(size) void    *dest,
		_In_                         uint8_t  c,
		_In_                         size_t   size);

void*
memcpy(
		_Out_writes_bytes_all_(size) void       *dest,
		_In_reads_bytes_(size)       const void *src,
		_In_                         size_t      size);

int
memcmp(
		_In_reads_bytes_(size) const void *a,
		_In_reads_bytes_(size) const void *b,
		_In_                   size_t      size);

size_t
strlen(_In_z_ const void *str);

__m128i
falkhash(_In_reads_bytes_(len) const void *pbuf, _In_ size_t len);

uint64_t
aes_rand(void);

size_t
vsnprintf(
		_Out_writes_bytes_(len)       char       *buf,
		_In_                          size_t      len,
		_In_z_ _Printf_format_string_ const char *format,
		_In_                          va_list     ap);

size_t
snprintf(
		_Out_writes_bytes_(len)       char       *buf,
		_In_                          size_t      len,
		_In_z_ _Printf_format_string_ const char *format,
		...)
	__attribute__((format(printf, 3, 4)));

void*
memrmem(
		_In_reads_bytes_(haystack_len) const void *haystack,
		_In_                           size_t      haystack_len,
		_In_reads_bytes_(needle_len)   const void *needle,
		_In_                           size_t      needle_len);

int
isalnum(_In_ uint8_t c);

int
isdigit(_In_ uint8_t c);

int
isxdigit(_In_ uint8_t c);

size_t
atoi(_In_z_ const char *buf);

size_t
nonnullcount(_In_reads_bytes_(len) const uint8_t *buf, _In_ size_t len);

size_t
nonnulllast(_In_reads_bytes_(len) const uint8_t *buf, _In_ size_t len);

int
hasheq(_In_ __m128i a, _In_ __m128i b);

int
hashnull(_In_ __m128i hash);

