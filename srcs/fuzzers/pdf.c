#include <grilled_cheese.h>
#include <generic/stdlib.h>
#include <disp/disp.h>
#include <mm/mm.h>
#include <fuzzers/pdf.h>

static int
pdf_is_whitespace(uint8_t c)
{
	if(c == 0x00 || c == 0x09 || c == 0x0a || c == 0x0c || c == 0x0d ||
			c == 0x20){
		return 1;
	} else {
		return 0;
	}
}

static int
pdf_is_delim(uint8_t c)
{
	if(c == '(' || c == ')' || c == '<' || c == '>' || c == '[' || c == ']' ||
			c == '{' || c == '}' || c == '/' || c == '%'){
		return 1;
	} else {
		return 0;
	}
}

static
pdf_is_whitespace_or_delim(uint8_t c)
{
	return (pdf_is_whitespace(c) || pdf_is_delim(c)) ? 1 : 0;
}

static const void*
pdf_consume_whitespace(
		const uint8_t *start, 
		uint64_t       length)
{
	if(!start || !length)
		return NULL;

	while(length){
		if(!pdf_is_whitespace(*start)){
			return start;
		}

		start++;
		length--;
	}

	return NULL;
}

#if 0
static void
pdf_dump(const struct _pdf_object *object, int depth)
{
	char depthstr[128] = { 0 };

	memset(depthstr, ' ', depth);

	if(!object){
		return;
	}

	if(object->type == DICT){
		uint64_t entry;

		printf("%s Dictionary %lu entries", depthstr,
				object->u.dict.num_objects);
		for(entry = 0; entry < object->u.dict.num_objects; entry++){
			pdf_dump(object->u.dict.objects[entry], depth + 1);
		}
	} else if(object->type == NAME){
		printf("%s Name '%s'", depthstr, object->u.name.name);
		pdf_dump(object->u.name.object, depth + 1);
	} else if(object->type == NUMBER){
		if(object->u.number.is_float){
			printf("%s Number %I64d.%lu", depthstr, object->u.number.number,
					object->u.number.decimal);
		} else {
			printf("%s Number %I64d", depthstr, object->u.number.number);
		}
	} else if(object->type == REFERENCE){
		printf("%s Reference %lu %lu", depthstr,
				object->u.reference.obj_num,
				object->u.reference.gen_num);
	} else if(object->type == HEXSTR){
		printf("%s Hexstr %.*s", depthstr,
				(unsigned int)object->u.hexstr.len, object->u.hexstr.str);
	} else if(object->type == ARRAY){
		uint64_t entry;

		printf("%s Array %lu entries", depthstr, object->u.array.num_objects);
		for(entry = 0; entry < object->u.array.num_objects; entry++){
			pdf_dump(object->u.array.objects[entry], depth + 1);
		}
	} else if(object->type == STRING){
		printf("%s String %.*s", depthstr, (unsigned int)object->u.str.len,
				object->u.str.str);
	} else if(object->type == OBJECT){
		printf("%s Indirect object %lu %lu", depthstr,
				object->u.indirect.obj_num, object->u.indirect.gen_num);

		pdf_dump(object->u.indirect.object, depth + 1);
		pdf_dump(object->u.indirect.stream, depth + 1);
	} else if(object->type == BOOLEAN){
		printf("%s Bool %s", depthstr, object->u.boolean.val ? "true" : "false");
	} else if(object->type == STREAM){
		printf("%s Stream length %lu", depthstr, object->u.stream.length);
	} else if(object->type == NULL_OBJ){
		printf("%s Null", depthstr);
	} else {
		panic("Unhandled object type");
	}

	return;
}
#endif

void
pdf_free(struct _pdf_object *object)
{
	if(!object){
		return;
	}

	if(object->type == DICT){
		uint64_t entry;

		for(entry = 0; entry < object->u.dict.num_objects; entry++){
			pdf_free(object->u.dict.objects[entry]);
		}
	} else if(object->type == NAME){
		pdf_free(object->u.name.object);
	} else if(object->type == NUMBER){
	} else if(object->type == REFERENCE){
	} else if(object->type == HEXSTR){
		if(phfree(object->u.hexstr.str, object->u.hexstr.len + 1) !=
				RSTATE_SUCCESS){
			panic("Failed to free hex string");
		}
	} else if(object->type == ARRAY){
		uint64_t entry;

		for(entry = 0; entry < object->u.array.num_objects; entry++){
			pdf_free(object->u.array.objects[entry]);
		}
	} else if(object->type == STRING){
		if(phfree(object->u.str.str, object->u.str.len + 1) !=
				RSTATE_SUCCESS){
			panic("Failed to free string");
		}
	} else if(object->type == OBJECT){
		pdf_free(object->u.indirect.object);
		pdf_free(object->u.indirect.stream);
	} else if(object->type == BOOLEAN){
	} else if(object->type == STREAM){
		if(phfree(object->u.stream.payload, object->u.stream.length) !=
				RSTATE_SUCCESS){
			panic("Failed to free stream payload");
		}
	} else if(object->type == NULL_OBJ){
	} else if(object->type == PDF_FILE){
		uint64_t entry;

		for(entry = 0; entry < object->u.file.num_objects; entry++){
			pdf_free(object->u.file.objects[entry]);
		}

		pdf_free(object->u.file.trailer);
	} else {
		/*printf("Object %d", object->type);
		panic("Unhandled object type");*/
	}

	if(phfree(object, sizeof(struct _pdf_object)) != RSTATE_SUCCESS){
		panic("Failed to free pdf object");
	}
	return;
}

char*
pdf_type_to_str(enum _pdf_type type)
{
	if(type == DICT)
		return "dict";
	else if(type == NAME)
		return "name";
	else if(type == NUMBER)
		return "number";
	else if(type == REFERENCE)
		return "reference";
	else if(type == HEXSTR)
		return "hexstr";
	else if(type == ARRAY)
		return "array";
	else if(type == STRING)
		return "string";
	else if(type == OBJECT)
		return "object";
	else if(type == BOOLEAN)
		return "boolean";
	else if(type == STREAM)
		return "stream";
	else if(type == PDF_FILE)
		return "pdf_file";
	else if(type == NULL_OBJ)
		return "null";
	else
		return "unknown";
}

static struct _pdf_object*
pdf_clone(const struct _pdf_object *object)
{
	struct _pdf_object *out_object;

	if(!object){
		return NULL;
	}

	if(phalloc(sizeof(struct _pdf_object), (void**)&out_object) !=
			RSTATE_SUCCESS){
		return NULL;
	}

	memcpy(out_object, object, sizeof(struct _pdf_object));

	if(object->type == DICT){
		uint64_t entry;

		for(entry = 0; entry < object->u.dict.num_objects; entry++){
			out_object->u.dict.objects[entry] = pdf_clone(object->u.dict.objects[entry]);
		}
	} else if(object->type == NAME){
		out_object->u.name.object = pdf_clone(object->u.name.object);
	} else if(object->type == NUMBER){
	} else if(object->type == REFERENCE){
	} else if(object->type == HEXSTR){
		if(phalloc(object->u.hexstr.len + 1, (void**)&out_object->u.hexstr.str) != RSTATE_SUCCESS){
			pdf_free(out_object);
			return NULL;
		}
		memcpy(out_object->u.hexstr.str, object->u.hexstr.str, object->u.hexstr.len);
	} else if(object->type == ARRAY){
		uint64_t entry;

		for(entry = 0; entry < object->u.array.num_objects; entry++){
			out_object->u.array.objects[entry] = pdf_clone(object->u.array.objects[entry]);
		}
	} else if(object->type == STRING){
		if(phalloc(object->u.str.len + 1, (void**)&out_object->u.str.str) != RSTATE_SUCCESS){
			pdf_free(out_object);
			return NULL;
		}
		memcpy(out_object->u.str.str, object->u.str.str, object->u.str.len);
	} else if(object->type == OBJECT){
		out_object->u.indirect.object = pdf_clone(object->u.indirect.object);
		out_object->u.indirect.stream = pdf_clone(object->u.indirect.stream);
	} else if(object->type == BOOLEAN){
	} else if(object->type == STREAM){
		if(phalloc(object->u.stream.length, (void**)&out_object->u.stream.payload) != RSTATE_SUCCESS){
			pdf_free(out_object);
			return NULL;
		}
		memcpy(out_object->u.stream.payload, object->u.stream.payload, object->u.stream.length);
	} else if(object->type == NULL_OBJ){
	} else if(object->type == PDF_FILE){
		uint64_t entry;

		for(entry = 0; entry < object->u.file.num_objects; entry++){
			out_object->u.file.objects[entry] = pdf_clone(object->u.file.objects[entry]);
		}

		out_object->u.file.trailer = pdf_clone(object->u.file.trailer);
	} else {
		panic("Unhandled object type");
	}

	return out_object;
}

#define PDF_MAX_DIGEST_OBJECTS (1024 * 1024 * 1024)

struct _pdf_object **digest_objects = NULL;
uint64_t digested_objects = 0;

static struct _pdf_object*
pdf_rand_object(void)
{
	if(!digested_objects) return NULL;

	return digest_objects[aes_rand() % digested_objects];
}

void
pdf_digest(struct _pdf_object *object)
{
	if(!object){
		return;
	}

	if(!digest_objects){
		if(phalloc(PDF_MAX_DIGEST_OBJECTS * sizeof(void*),
					(void**)&digest_objects) != RSTATE_SUCCESS){
			panic("Failed to allocate room for PDF digest objects");
		}
	}

	if(object->type == DICT){
		uint64_t entry;

		for(entry = 0; entry < object->u.dict.num_objects; entry++){
			pdf_digest(object->u.dict.objects[entry]);
		}
	} else if(object->type == NAME){
		pdf_digest(object->u.name.object);
	} else if(object->type == NUMBER){
	} else if(object->type == REFERENCE){
	} else if(object->type == HEXSTR){
	} else if(object->type == ARRAY){
		uint64_t entry;

		for(entry = 0; entry < object->u.array.num_objects; entry++){
			pdf_digest(object->u.array.objects[entry]);
		}
	} else if(object->type == STRING){
	} else if(object->type == OBJECT){
		pdf_digest(object->u.indirect.object);
		pdf_digest(object->u.indirect.stream);
	} else if(object->type == BOOLEAN){
	} else if(object->type == STREAM){
	} else if(object->type == NULL_OBJ){
	} else if(object->type == PDF_FILE){
		uint64_t entry;

		for(entry = 0; entry < object->u.file.num_objects; entry++){
			pdf_digest(object->u.file.objects[entry]);
		}

		pdf_digest(object->u.file.trailer);
	} else {
		panic("Unhandled object type");
	}

	if(digested_objects >= PDF_MAX_DIGEST_OBJECTS) return;
	digest_objects[digested_objects++] = object;

	return;
}

void
pdf_corrupt(struct _pdf_object *object)
{
	if(!object){
		return;
	}

	if(object->type == DICT){
		uint64_t entry;

		for(entry = 0; entry < object->u.dict.num_objects; entry++){
			pdf_corrupt(object->u.dict.objects[entry]);
		}
	} else if(object->type == NAME){
		pdf_corrupt(object->u.name.object);
	} else if(object->type == NUMBER){
	} else if(object->type == REFERENCE){
	} else if(object->type == HEXSTR){
	} else if(object->type == ARRAY){
		uint64_t entry;

		for(entry = 0; entry < object->u.array.num_objects; entry++){
			pdf_corrupt(object->u.array.objects[entry]);
		}
	} else if(object->type == STRING){
	} else if(object->type == OBJECT){
		pdf_corrupt(object->u.indirect.object);
		pdf_corrupt(object->u.indirect.stream);
	} else if(object->type == BOOLEAN){
	} else if(object->type == STREAM){
	} else if(object->type == NULL_OBJ){
	} else if(object->type == PDF_FILE){
		uint64_t entry;

		for(entry = 0; entry < object->u.file.num_objects; entry++){
			pdf_corrupt(object->u.file.objects[entry]);
		}

		pdf_corrupt(object->u.file.trailer);
	} else {
		panic("Unhandled object type");
	}

	if(!(aes_rand() % 1024)){
		struct _pdf_object *rand_obj;

		rand_obj = pdf_clone(pdf_rand_object());
		if(rand_obj){
			memcpy(object, rand_obj, sizeof(struct _pdf_object));
		}
	}

	return;
}

uint64_t
pdf_genpdf(
		char                     *buf,
		uint64_t                  len,
		const struct _pdf_object *object)
{
	char *ptr, *end;

	ptr = buf;
	end = buf + len;

	if(!object) return 0;

	if(object->type == DICT){
		uint64_t entry;

		memcpy(ptr, "<<", 2);
		ptr += 2;

		for(entry = 0; entry < object->u.dict.num_objects; entry++){
			ptr += pdf_genpdf(ptr, end - ptr, object->u.dict.objects[entry]);
		}

		memcpy(ptr, ">>", 2);
		ptr += 2;
		*ptr++ = ' ';
	} else if(object->type == NAME){
		*ptr++ = '/';
		memcpy(ptr, object->u.name.name, strlen(object->u.name.name));
		ptr += strlen(object->u.name.name);
		*ptr++ = ' ';

		ptr += pdf_genpdf(ptr, end - ptr, object->u.name.object);
	} else if(object->type == NUMBER){
		if(object->u.number.is_float){
			ptr += snprintf(ptr, end - ptr, "%ld.%lu",
					object->u.number.number,
					object->u.number.decimal);
		} else {
			ptr += snprintf(ptr, end - ptr, "%ld", object->u.number.number);
		}
		*ptr++ = ' ';
	} else if(object->type == REFERENCE){
		ptr += snprintf(ptr, end - ptr, "%lu %lu R ",
				object->u.reference.obj_num, object->u.reference.gen_num);
	} else if(object->type == HEXSTR){
		*ptr++ = '<';
		memcpy(ptr, object->u.hexstr.str, object->u.hexstr.len);
		ptr += object->u.hexstr.len;
		*ptr++ = '>';
		*ptr++ = ' ';
	} else if(object->type == ARRAY){
		uint64_t entry;

		memcpy(ptr, "[", 1);
		ptr += 1;

		for(entry = 0; entry < object->u.array.num_objects; entry++){
			ptr += pdf_genpdf(ptr, end - ptr, object->u.array.objects[entry]);
		}

		memcpy(ptr, "]", 1);
		ptr += 1;
		*ptr++ = ' ';
	} else if(object->type == STRING){
		*ptr++ = '(';
		memcpy(ptr, object->u.str.str, object->u.str.len);
		ptr += object->u.str.len;
		*ptr++ = ')';
		*ptr++ = ' ';
	} else if(object->type == BOOLEAN){
		ptr += snprintf(ptr, end - ptr, "%s ",
				object->u.boolean.val ? "true" : "false");

		return (ptr - buf);
	} else if(object->type == OBJECT){
		ptr += snprintf(ptr, end - ptr, "%lu %lu obj\r\n",
				object->u.indirect.obj_num, object->u.indirect.gen_num);
		ptr += pdf_genpdf(ptr, end - ptr, object->u.indirect.object);
		ptr += snprintf(ptr, end - ptr, "\r\n");
		ptr += pdf_genpdf(ptr, end - ptr, object->u.indirect.stream);
		ptr += snprintf(ptr, end - ptr, "endobj\r\n");
	} else if(object->type == STREAM){
		ptr += snprintf(ptr, end - ptr, "stream\r\n");
		memcpy(ptr, object->u.stream.payload, object->u.stream.length);
		ptr += object->u.stream.length;
		ptr += snprintf(ptr, end - ptr, "\r\nendstream\r\n");
	} else if(object->type == PDF_FILE){
		uint64_t entry, offsets[PDF_OBJECTS_MAX] = { 0 }, xref_addr;

		ptr += snprintf(ptr, end - ptr, "%%PDF-1.7\r\n%%\xb5\xb5\xb5\xb5\r\n");

		for(entry = 0; entry < object->u.file.num_objects; entry++){
			offsets[entry] = ptr - buf;
			ptr += pdf_genpdf(ptr, end - ptr, object->u.file.objects[entry]);
		}
		xref_addr = ptr - buf;
		ptr += snprintf(ptr, end - ptr, "xref\r\n");
		for(entry = 0; entry < PDF_OBJECTS_MAX; entry++){
			if(object->u.file.objects[entry] &&
					object->u.file.objects[entry]->type == OBJECT){
				ptr += snprintf(ptr, end - ptr, "%lu 1\r\n",
						object->u.file.objects[entry]->u.indirect.obj_num);
				ptr += snprintf(ptr, end - ptr, "%.10lu 00000 n\r\n",
						offsets[entry]);
			}
		}
		ptr += snprintf(ptr, end - ptr, "trailer\r\n");
		ptr += pdf_genpdf(ptr, end - ptr, object->u.file.trailer);
		ptr += snprintf(ptr, end - ptr, "\r\nstartxref\r\n%lu\r\n",
				xref_addr);
		ptr += snprintf(ptr, end - ptr, "%%EOF");
	} else if(object->type == NULL_OBJ){
		ptr += snprintf(ptr, end - ptr, "null ");
	} else {
		panic("UNHANDLED");
	}

	return (ptr - buf);
}

rstate_t
pdf_parse_object(
		const uint8_t       *object_str,
		uint64_t             object_str_len,
		const uint8_t      **out_object_str,
		struct _pdf_object **out_object)
{
	const uint8_t *object_str_end, *soo;
			
	struct _pdf_object *object = NULL;

	RSTATE_LOCALS;

	/* Construct a pointer to the end of the string for pointer math */
	object_str_end = object_str + object_str_len;

	/* Consume all whitespace */
	soo = pdf_consume_whitespace(object_str, object_str_len);
	RSCHECK(soo, "Failed to consume whitespace in object string");

	RSCHECK(object_str_end - soo, "Object string empty");

	if(soo[0] == '<'){
		/* Alright, we have either encoutered a hexstr, or a dictionary.
		 * Check by checking the next character.
		 */
		if((object_str_end - soo) >= 2 && soo[1] == '<'){
			/* Dictionary */
			int ii = 0;

			soo += 2;

			rstate = phalloc(sizeof(struct _pdf_object), (void**)&object);
			RSCHECK_NESTED("Failed to allocate room for dict object");

			object->type = DICT;

			for( ; ; ){
				RSCHECK(ii < PDF_OBJECTS_MAX, "Too many objects in dict");

				soo = pdf_consume_whitespace(soo, object_str_end - soo);
				RSCHECK(soo, "Failed to consume whitespace while processing "
						"dictionary");

				/* Check for end of dictionary */
				if((object_str_end - soo) >= 2 && !memcmp(soo, ">>", 2)){
					break;
				}

				rstate = pdf_parse_object(soo, object_str_end - soo, &soo,
						&object->u.dict.objects[ii]);
				RSCHECK_NESTED("Failed to read object out of dictionary");

				object->u.dict.num_objects++;

				ii++;
			}

			*out_object_str = soo + 2;
			*out_object     = object;
		} else {
			const uint8_t *hex_start;

			soo++;

			hex_start = soo;

			/* Hex string */
			while((object_str_end - soo) && isxdigit(soo[0])){
				soo++;
			}

			rstate = phalloc(sizeof(struct _pdf_object), (void**)&object);
			RSCHECK_NESTED("Failed to allocate room for hex string object");

			rstate = phalloc(soo - hex_start + 1, (void**)&object->u.hexstr.str);
			RSCHECK_NESTED("Failed to allocate room for hex string");

			object->type = HEXSTR;
			object->u.hexstr.len = soo - hex_start;
			memcpy(object->u.hexstr.str, hex_start, object->u.hexstr.len);

			RSCHECK((object_str_end - soo) && soo && soo[0] == '>',
					"Hex string terminated unexpectedly");

			*out_object_str = soo + 1;
			*out_object     = object;
		}
	} else if(soo[0] == '('){
		int paren = 1, escaping = 0;

		const uint8_t *sos;

		/* Consume the '(' */
		soo++;

		sos = soo;

		while(paren){
			RSCHECK(object_str_end - soo, "String ended unexpectedly");

			if(!escaping){
				if(soo[0] == '('){
					paren++;
				}

				if(soo[0] == ')'){
					paren--;
				}

				if(soo[0] == '\\'){
					RSCHECK((object_str_end - soo) >= 2,
							"Escaping at end of string");

					if(soo[1] >= '0' && soo[1] <= '7'){
						escaping = 3;
					} else {
						escaping = 1;
					}
				}
			} else {
				escaping--;
			}

			soo++;
		}

		/* Unwind so we're point to the closing paren of the string */
		soo--;

		rstate = phalloc(sizeof(struct _pdf_object), (void**)&object);
		RSCHECK_NESTED("Failed to allocate room for string object");

		rstate = phalloc(soo - sos + 1, (void**)&object->u.str.str);
		RSCHECK_NESTED("Failed to allocate room for string");

		object->type    = STRING;
		object->u.str.len = soo - sos;
		memcpy(object->u.str.str, sos, soo - sos);

		*out_object_str = soo + 1;
		*out_object     = object;
	} else if(soo[0] == '/'){
		int ii;

		/* Consume the '/' */
		soo++;

		rstate = phalloc(sizeof(struct _pdf_object), (void**)&object);
		RSCHECK_NESTED("Failed to allocate room for name object");

		object->type = NAME;

		for(ii = 0; ii < 128; ii++){
			RSCHECK(ii < (object_str_end - soo),
					"End of object before name finished");

			if(pdf_is_whitespace_or_delim(soo[ii])){
				break;
			}

			object->u.name.name[ii] = soo[ii];
		}

		soo = pdf_consume_whitespace(&soo[ii], object_str_end - &soo[ii]);
		RSCHECK(soo, "Failed to consume whitespace after name");

		/* If we're followed directly by a name, it's a null entry. Otherwise
		 * attempt to parse out the next object.
		 */
		if(soo[0] != '/' && soo[0] != '>' && soo[0] != ']'){
			rstate = pdf_parse_object(soo, object_str_end - soo,
					&soo, &object->u.name.object);
			RSCHECK_NESTED("Failed to get object associated with name");
		} else {
			object->u.name.object = NULL;
		}

		*out_object_str = soo;
		*out_object     = object;
	} else if(soo[0] == '['){
		int ii = 0;

		soo++;

		rstate = phalloc(sizeof(struct _pdf_object), (void**)&object);
		RSCHECK_NESTED("Failed to allocate room for array object");

		object->type = ARRAY;

		for( ; ; ){
			RSCHECK(ii < PDF_OBJECTS_MAX, "Too many objects in array");

			soo = pdf_consume_whitespace(soo, object_str_end - soo);
			RSCHECK(soo, "Failed to consume whitespace while processing "
					"array");

			if(soo[0] == ']'){
				break;
			}

			rstate = pdf_parse_object(soo, object_str_end - soo,
					&soo, &object->u.array.objects[ii]);
			RSCHECK_NESTED("Failed to parse out array object");
		
			object->u.array.num_objects++;
			
			ii++;
		}

		*out_object_str = soo + 1;
		*out_object     = object;
	} else if(soo[0] == '-' || soo[0] == '+' || isdigit(soo[0])){
		/* Either we're parsing a number or a reference */

		int      special = 0, negative = 1, is_float = 0;
		uint64_t number = 0, number2 = 0;
		const uint8_t *number_end;

		rstate = phalloc(sizeof(struct _pdf_object), (void**)&object);
		RSCHECK_NESTED("Failed to allocate room for number object");

		if((object_str_end - soo) && soo[0] == '-'){
			negative = -1;
			special  = 1;
			soo++;
		}
		if((object_str_end - soo) && soo[0] == '+'){
			negative = 1;
			special  = 1;
			soo++;
		}

		RSCHECK((object_str_end - soo), "Number terminated unexpecedly");

		/* Parse out the first number */
		while(isdigit(soo[0])){
			number *= 10;
			number += soo[0] - '0';

			soo++;

			RSCHECK(object_str_end - soo, "Hit end of object string before "
					"number parsing complete");
		}

		if(soo[0] == '.'){
			special = 1;

			soo++;
			is_float = 1;

			RSCHECK((object_str_end - soo), "Float terminated unexpecedly");

			while(isdigit(soo[0])){
				number2 *= 10;
				number2 += soo[0] - '0';

				soo++;

				RSCHECK(object_str_end - soo, "Hit end of object string before "
						"number parsing complete");
			}

		}
		number_end = soo;

		if(!special){
			soo = pdf_consume_whitespace(soo, object_str_end - soo);
			RSCHECK(soo, "Failed to consume whitespace while processing number");

			/* Parse out the second number */
			if(isdigit(soo[0])){
				while(isdigit(soo[0])){
					number2 *= 10;
					number2 += soo[0] - '0';

					soo++;

					RSCHECK(object_str_end - soo, "Hit end of object string before "
							"number2 parsing complete");
				}

				soo = pdf_consume_whitespace(soo, object_str_end - soo);
				RSCHECK(soo, "Failed to consume whitespace while processing number2");

				if(soo[0] == 'R'){
					object->type = REFERENCE;
				} else if((object_str_end - soo) >= 3 && !memcmp(soo, "obj", 3)){
					object->type = OBJECT;
				}
			}
		}

		if(object->type == INVALID){
			object->type            = NUMBER;
			object->u.number.number   = (int64_t)number * (int64_t)negative;
			object->u.number.decimal  = number2;
			object->u.number.is_float = is_float;

			*out_object_str = number_end;
			*out_object     = object;
		} else if(object->type == REFERENCE){
			object->type              = REFERENCE;
			object->u.reference.obj_num = number;
			object->u.reference.gen_num = number2;

			*out_object_str = soo + 1;
			*out_object     = object;
		} else if(object->type == OBJECT){
			object->type             = OBJECT;
			object->u.indirect.obj_num = number;
			object->u.indirect.gen_num = number2;

			soo += 3;

			rstate = pdf_parse_object(soo, object_str_end - soo,
					&soo, &object->u.indirect.object);
			RSCHECK_NESTED("Failed to parse indirect object");

			*out_object_str = soo;
			*out_object     = object;
		} else {
			RSCHECK(1 == 0, "This should not be possible");
		}
	} else if((object_str_end - soo) >= 4 && !memcmp(soo, "true", 4)){
		rstate = phalloc(sizeof(struct _pdf_object), (void**)&object);
		RSCHECK_NESTED("Failed to allocate room for number object");

		object->type        = BOOLEAN;
		object->u.boolean.val = 1;

		*out_object_str = soo + 4;
		*out_object     = object;
	} else if((object_str_end - soo) >= 5 && !memcmp(soo, "false", 5)){
		rstate = phalloc(sizeof(struct _pdf_object), (void**)&object);
		RSCHECK_NESTED("Failed to allocate room for number object");

		object->type        = BOOLEAN;
		object->u.boolean.val = 0;

		*out_object_str = soo + 5;
		*out_object     = object;
	} else if((object_str_end - soo) >= 4 && !memcmp(soo, "null", 4)){
		rstate = phalloc(sizeof(struct _pdf_object), (void**)&object);
		RSCHECK_NESTED("Failed to allocate room for number object");

		object->type = NULL_OBJ;

		*out_object_str = soo + 4;
		*out_object     = object;
	} else {
		RSCHECK(1 == 0, "Unhandled PDF object");
	}

	rstate_ret = RSTATE_SUCCESS;
cleanup:
	if(rstate_ret != RSTATE_SUCCESS){
		if(object) pdf_free(object);
	}
	RSTATE_RETURN;
}

static struct _pdf_object*
pdf_dict_lookup(struct _pdf_object *dict, char *name)
{
	int ii;

	if(!dict || dict->type != DICT)
		return NULL;

	for(ii = 0; ii < dict->u.dict.num_objects; ii++){
		struct _pdf_object *ent;

		ent = dict->u.dict.objects[ii];

		if(ent->type == NAME && strlen(ent->u.name.name) == strlen(name) &&
				!memcmp(ent->u.name.name, name, strlen(name))){
			return ent->u.name.object;
		}
	}
	
	return NULL;
}

rstate_t
loadpdf(
		const uint8_t       *pdf,
		uint64_t             pdf_len,
		struct _pdf_object **out_object)
{
	const uint8_t *eof, *ptr;
	uint64_t       pdf_file_entries = 0;

	struct _pdf_object *pdf_file = NULL;

	RSTATE_LOCALS;

	rstate = phalloc(sizeof(struct _pdf_object), (void**)&pdf_file);
	RSCHECK_NESTED("Failed to allocate room for PDF file");
	pdf_file->type = PDF_FILE;

	/* First validate that %PDF-1. is the start of the file */
	RSCHECK(pdf_len >= 7 && !memcmp(pdf, "%PDF-1.", 7),
			"File is not PDF, invalid file");

	/* Look for the %%EOF marker */
	eof = pdf + pdf_len;
	ptr = pdf;

	for(ptr = pdf; ptr < eof; ptr++){
		struct _pdf_object *object;

		if((eof - ptr) >= 4 && !memcmp(ptr, " obj", 4)){
			RSCHECK(pdf_file_entries < PDF_OBJECTS_MAX,
					"Too many objects in PDF file");

			while(ptr >= pdf && (isdigit(*ptr) || *ptr == ' ')) ptr--;
			ptr++;

			rstate = pdf_parse_object(ptr, eof - ptr, &ptr, &object);
			RSCHECK_NESTED("Failed to parse object");
			
			pdf_file->u.file.objects[pdf_file_entries++] = object;
			pdf_file->u.file.num_objects++;

			RSCHECK(object->type == OBJECT,
					"Expected indirect object");
			
			ptr = pdf_consume_whitespace(ptr, eof - ptr);
			RSCHECK(ptr, "Failed to consume whitespace after indirect");

			if((eof - ptr) >= 6 && !memcmp(ptr, "stream", 6)){
				uint64_t stream_len;
				struct _pdf_object *length_obj, *stream_obj;
				const uint8_t *stream_start;

				ptr += 6;

				if((eof - ptr) >= 2 && !memcmp(ptr, "\r\n", 2))
					ptr += 2;
				else if((eof - ptr) >= 1 && ptr[0] == '\n')
					ptr++;

				stream_start = ptr;

				length_obj =
					pdf_dict_lookup(object->u.indirect.object, "Length");
				RSCHECK(length_obj, "Indirect object without length");

				RSCHECK(length_obj->type == NUMBER &&
						!length_obj->u.number.is_float,
						"Stream length incorrect format");

				stream_len = length_obj->u.number.number;

				RSCHECK((uint64_t)(eof - stream_start) >= stream_len,
						"Stream length too large for file");

				rstate = phalloc(sizeof(struct _pdf_object), (void**)&stream_obj);
				RSCHECK_NESTED("Failed to allocate room for stream obj");

				stream_obj->type = STREAM;
				object->u.indirect.stream = stream_obj;

				rstate = phalloc(stream_len,
						(void**)&stream_obj->u.stream.payload);
				RSCHECK_NESTED("Failed to allocate room for stream");

				memcpy(stream_obj->u.stream.payload,
						stream_start, stream_len);
				stream_obj->u.stream.length = stream_len;

				object->u.indirect.stream = stream_obj;
			}

		} else if((eof - ptr) >= 7 && !memcmp(ptr, "trailer", 7)){
			if(!pdf_file->u.file.trailer){
				struct _pdf_object *trailer;

				ptr += 7;
				rstate = pdf_parse_object(ptr, eof - ptr, &ptr, &trailer);
				RSCHECK_NESTED("Failed to parse out trailer");

				if(pdf_dict_lookup(trailer, "Root")){
					pdf_file->u.file.trailer = trailer;
				}
			}
		}
	}

	RSCHECK(pdf_file->u.file.trailer,
			"Failed to find trailer with Root object");

	*out_object = pdf_file;

	rstate_ret = RSTATE_SUCCESS;
cleanup:
	if(rstate_ret != RSTATE_SUCCESS) pdf_free(pdf_file);
	RSTATE_RETURN;
}

