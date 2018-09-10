#pragma once

#define PDF_OBJECTS_MAX 500

enum _pdf_type {
	INVALID,
	DICT,
	NAME,
	NUMBER,
	REFERENCE,
	HEXSTR,
	ARRAY,
	STRING,
	OBJECT,
	BOOLEAN,
	STREAM,
	PDF_FILE,
	NULL_OBJ
};

struct _pdf_xref {
	uint64_t obj_num;
	uint64_t gen_num;
	uint8_t  type;
};

struct _pdf_dict {
	uint64_t num_objects;
	struct _pdf_object *objects[PDF_OBJECTS_MAX];
};

struct _pdf_array {
	uint64_t num_objects;
	struct _pdf_object *objects[PDF_OBJECTS_MAX];
};

struct _pdf_name {
	char name[1024];
	struct _pdf_object *object;
};

struct _pdf_boolean {
	int val;
};

struct _pdf_reference {
	uint64_t obj_num;
	uint64_t gen_num;
};

struct _pdf_hexstr {
	uint8_t  *str;
	uint64_t  len;
};

struct _pdf_str {
	uint8_t  *str;
	uint64_t  len;
};

struct _pdf_stream {
	uint8_t  *payload;
	uint64_t  length;
};

struct _pdf_indirect_object {
	uint64_t obj_num;
	uint64_t gen_num;

	struct _pdf_object *object;
	struct _pdf_object *stream;
};

struct _pdf_number {
	int64_t  number;
	uint64_t decimal;

	int is_float;
};

struct _pdf_file {
	uint64_t num_objects;
	struct _pdf_object *objects[PDF_OBJECTS_MAX];
	struct _pdf_object *trailer;
};

struct _pdf_object {
	enum _pdf_type type;

	union {
		struct _pdf_name name;
		struct _pdf_number number;
		struct _pdf_reference reference;
		struct _pdf_hexstr hexstr;
		struct _pdf_dict dict;
		struct _pdf_array array;
		struct _pdf_str str;
		struct _pdf_indirect_object indirect;
		struct _pdf_boolean boolean;
		struct _pdf_stream stream;
		struct _pdf_file file;
	} u;
};

char*
pdf_type_to_str(enum _pdf_type type);

void
pdf_free(struct _pdf_object *object);

void
pdf_digest(struct _pdf_object *object);

void
pdf_corrupt(struct _pdf_object *object);

uint64_t
pdf_genpdf(
		char                     *buf,
		uint64_t                  len,
		const struct _pdf_object *object);

rstate_t
pdf_parse_object(
		const uint8_t       *object_str,
		uint64_t             object_str_len,
		const uint8_t      **out_object_str,
		struct _pdf_object **out_object);

rstate_t
loadpdf(
		const uint8_t       *pdf,
		uint64_t             pdf_len,
		struct _pdf_object **out_object);

