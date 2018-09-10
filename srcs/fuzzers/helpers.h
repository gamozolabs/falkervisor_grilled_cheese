#pragma once

#define MAX_MODULES 128

struct _modlist {
	uint64_t base;
	uint64_t len;
	uint64_t end;

	__m128i hash;

	unsigned int namelen;
	uint8_t      name[256];
};

struct _input_ent {
	uint64_t len;
	uint8_t  buf[1];
};

struct _cc_entry {
	__m128i hash;
};

struct _crash_entry {
	__m128i hash;
};

struct _fuzzer {
	struct _hash_table *cc_db;
	struct _hash_table *input_db;
	struct _hash_table *crash_db;
};

rstate_t
fuzzer_create(struct _fuzzer **fuzzer_out);

void
rand_ftar(
		const void  *ftar,
		uint64_t     ftar_len,
		uint8_t    **entry,
		uint64_t    *entry_len);

rstate_t
fuzz_get_cc_db(struct _hash_table **db);

rstate_t
fuzz_get_input_db(struct _hash_table **db);

rstate_t
fuzz_get_crash_db(struct _hash_table **db);

struct _input_ent*
fuzz_get_input(__m128i input_hash);

rstate_t
fuzz_input_create(const void *buf, uint64_t len, __m128i *out_hash,
		int *new_entry);

rstate_t
fuzz_cc_report(
		struct _vm *vm,
		uint64_t    from,
		uint64_t    to,
		const void *buf,
		uint64_t    len,
		int        *new_ent);

rstate_t
fuzz_report_crash(struct _vm *vm, void *buf, size_t len, int *new_entry);

rstate_t
win32_gen_modlist(struct _vm *vm);

struct _modlist*
win32_resolve_module(struct _vm *vm, uint64_t rip);

int
win32_symhash(struct _vm *vm, uint64_t rip, __m128i *hash);

__m128i
win32_classify_crash(struct _vm *vm);

