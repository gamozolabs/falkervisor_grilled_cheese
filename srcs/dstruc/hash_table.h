#pragma once

struct _hash_table {
	uint64_t bits;
	uint64_t entries;

	void ***seq_data;

	struct {
		__m128i  hash;
		void    *data;
	} entry[1];
};

rstate_t
ht_create(_In_ uint64_t size, _Outptr_ struct _hash_table **out_ht);

void*
ht_rand(_In_ volatile struct _hash_table *ht);

int
ht_fetch_or_lock(
		_In_     volatile struct _hash_table  *ht,
		_In_     __m128i                       hash,
		_Outptr_ void                        **ret);

void*
ht_probe(
		_In_ volatile struct _hash_table *ht,
		_In_ __m128i                      hash);

