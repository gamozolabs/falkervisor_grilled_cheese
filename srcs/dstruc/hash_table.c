#include <grilled_cheese.h>
#include <mm/mm.h>
#include <dstruc/hash_table.h>
#include <generic/stdlib.h>

/* ht_create()
 *
 * Summary:
 *
 * This function creates a new hash table capable of holding 2^size entries.
 *
 * Parameters:
 *
 * _In_ size       - Order of the hash table (can hold 2^size entries)
 * _Outptr_ out_ht - Caller allocated storage to receive pointer to newly
 *                   allocated hash table.
 *
 * Returns:
 *
 * RSTATE_SUCCESS on success, otherwise error.
 */
rstate_t
ht_create(_In_ uint64_t size, _Outptr_ struct _hash_table **out_ht)
{
	struct _hash_table *ht;

	RSTATE_LOCALS;

	rstate = phalloc(offsetof(struct _hash_table, entry) +
			(1UL << size) * sizeof(ht->entry), (void**)&ht);
	RSCHECK_NESTED("Failed to allocate room for hash table");

	rstate = phalloc(8 * (1UL << size), (void**)&ht->seq_data);
	RSCHECK_NESTED("Failed to allocate room for hash table seq data");

	ht->bits = size;

	*out_ht = ht;

	rstate_ret = RSTATE_SUCCESS;
cleanup:
	RSTATE_RETURN;
}

/* ht_rand()
 *
 * Summary:
 * 
 * This function selects and returns a random entry in a hash table. Note that
 * hash tables don't necessaraly contain pointers to things. Use this only
 * if you know the entries of the hash table are pointers.
 *
 * Parmeters:
 *
 * _In_ ht - Hash table to select random entry from
 *
 * Returns:
 *
 * Pointer to random hash table entry on success
 * NULL if the hash table is empty
 */
void*
ht_rand(_In_ volatile struct _hash_table *ht)
{
	uint64_t ent;

	if(!ht->entries)
		return NULL;

	for( ; ; ){
		ent = aes_rand() % ht->entries;
		if(!ht->seq_data[ent])
			continue;

		if(!ht->seq_data[ent][0])
			continue;

		return ht->seq_data[ent][0];
	}
}

/* ht_fetch_or_lock()
 *
 * Summary:
 *
 * This function either returns out the entry indexed by hash, or acquires
 * a lock on the entry allowing the caller to insert an entry.
 *
 * This function is a bit strange, in that the 'ret' parameter can either
 * receive the contents of the entry in the hash table (if this function
 * returns 0. Or if this function returns 1, it returns a pointer to the
 * location in the hash table itself that needs to be populated.
 *
 * The value inserted into the page table must never be NULL, as the NULL state
 * indicates a lock is held and the entry is waiting to be populated. Inserting
 * a NULL may result in a deadlock.
 *
 * There is also no protection if the table grows to maximum size, in this case
 * it'll get stuck in an infinite loop. In the future we may change this, but
 * until then, just make a large enough hash table for what you theoretically
 * will store.
 *
 * Parameters:
 *
 * _In_     ht   - Hash table to operate on
 * _In_     hash - Hash to use to index the hash table
 * _Outptr_ ret  - If function returns 1:
 *                     Pointer to location to populate with hash table entry
 *                     this entry is locked until it is populated, and other
 *                     accesses to this entry spin until it has been filled in.
 *                 If function returns 0:
 *                     Hash table entry
 *
 * Returns:
 *
 * 0 - If the hash table entry is returned
 * 1 - If a pointer to the hash table entry to populate is returned
 */
int
ht_fetch_or_lock(
		_In_     volatile struct _hash_table  *ht,
		_In_     __m128i                       hash,
		_Outptr_ void                        **ret)
{
	uint64_t ent, qhash[2], nullhash[2];

	/* A hash value of 0 is not allowed! */
	if(hashnull(hash))
		return -1;

	/* Copy the 128-bit hash to 2 64-bit ints for convience */
	_mm_storeu_si128((void*)qhash, hash);

	/* Mask the hash against the mask of the hash table */
	ent = qhash[0] & ((1UL << ht->bits) - 1);

	for( ; ; ){
		if(!hashnull(ht->entry[ent].hash)){
			/* If the entry matches our hash, we're done! */
			if(hasheq(ht->entry[ent].hash, hash)){
				goto wait_for_data;
			}

			/* Hash did not match ours, go to the next one */
			ent++;
			continue;
		}

		/* Zero out the value for the compare exchange */
		memset(nullhash, 0, 16);

		/* Hash was empty, try to win the race */
		if(sync_bool_compare_and_swap_si128(&ht->entry[ent].hash,
					_mm_setzero_si128(), hash)){
			uint64_t seq_id;

			/* We won the race, return a pointer to the value to fill in */
			seq_id = __sync_fetch_and_add((volatile int64_t*)&ht->entries, 1);
			ht->seq_data[seq_id] = (void*)&ht->entry[ent].data;

			*ret = (void*)&ht->entry[ent].data;
			return 1;
		} else {
			/* We may have lost the race to a colliding input, verify
			 * that the hash matches.
			 */
			if(!hasheq(ht->entry[ent].hash, hash)){
				/* Hash did not match, try the next entry */
				ent++;
				continue;
			}

wait_for_data:
			/* We lost the race to a matching hash, wait until the entry
			 * is filled in.
			 */
			while(!ht->entry[ent].data) _mm_pause();

			/* Sadly we need this to please /analyze */
			if(!ht->entry[ent].data){
				return -1;
			}

			*ret = (void*)ht->entry[ent].data;
			return 0;
		}
	}
}

/* ht_probe()
 *
 * Summary:
 *
 * Attempts to fetch the entry in the hash table ht indexed by hash. If there
 * is no entry matching hash, NULL is returned. Otherwise, the entry itself
 * is returned.
 *
 * Parameters:
 *
 * _In_ ht   - Hash table to operate on
 * _In_ hash - Hash to index hash table with
 *
 * Returns:
 *
 * NULL if no entry is present in the hash table
 * Otherwise returns entry corresponding to hash in the hash table.
 */
void*
ht_probe(
		_In_ volatile struct _hash_table *ht,
		_In_ __m128i                      hash)
{
	uint64_t ent, qhash[2];

	/* A hash value of 0 is not allowed! */
	if(hashnull(hash)){
		return NULL;
	}

	/* Copy the 128-bit hash to 2 64-bit ints for convience */
	_mm_storeu_si128((void*)qhash, hash);

	/* Mask the hash against the mask of the hash table */
	ent = qhash[0] & ((1UL << ht->bits) - 1);

	for( ; ; ){
		if(!hashnull(ht->entry[ent].hash)){
			/* If the entry matches our hash, we're done! */
			if(hasheq(ht->entry[ent].hash, hash)){
				return ht->entry[ent].data;
			}

			/* Hash did not match ours, go to the next one */
			ent++;
			continue;
		}

		return NULL;
	}
}

