#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <limits.h>
#include <assert.h>

#define ROUND_UP(x, v)		((((v) - 1) | ((x) - 1)) + 1)

void run(void* program, size_t size)
{
	long page_size = sysconf(_SC_PAGESIZE);
	size_t allocated_size = ROUND_UP(size, page_size); 
	printf(
		"allocating buffer of %ld (rounded to page size %ld)\n",
		allocated_size,
		page_size
	);

	// allocate memory as RW, some OSes don't like having WX perms	
	void* allocated = mmap(
		NULL,
		allocated_size,
		PROT_READ | PROT_WRITE,
		MAP_ANONYMOUS | MAP_PRIVATE,
		-1,
		0
	);

	if (!allocated)
		perror("[run mmap] FATAL");

	memcpy(allocated, program, size);	

	// protect as exec so that we can run the code
	if (mprotect(allocated, allocated_size, PROT_READ | PROT_EXEC))
		perror("[run mprotect] FATAL");

	printf("starting execution\n");

	void (*program_entry)(void) = allocated;
	program_entry();

	printf("execution returned, cleaning up\n");
	// clean up removing the mapping
	munmap(allocated, allocated_size);
}

void print_int(long int i)
{
	printf("%ld ", i);
}

void newline()
{
	printf("\n");
}

void emit(unsigned char c)
{
	printf("%c", c);
}

bool valid_int(const char* token) {
	char* endptr;
	long int ival = strtol(token, &endptr, 0);
	return endptr != token && ival >= INT_MIN && ival <= INT_MAX;
}

// pop arguments for something off the stack in x86_64 calling convention order
size_t assemble_pops(uint8_t* buf, int num_args)
{
	assert(num_args <= 6);
	uint8_t* obuf = buf;
	uint8_t insns[] = { 0x5f, 0x5e, 0x5a, 0x59, 0x58, 0x59 };
	for (int i = 0; i < num_args; i++) {
		if (i > 3)
			*buf++ = 0x41;
		*buf++ = insns[i];
	}
	return buf - obuf;
}

// call with arguments taken from the stack
size_t assemble_stackcall(uint8_t* buf, void* func, int num_args)
{
	assert(num_args <= 6);
	uint8_t* obuf = buf;

	buf += assemble_pops(buf, num_args);	

	uint64_t fn_int = (uint64_t)func;
	// mov rax, fn_int
	*buf++ = 0x48;
	*buf++ = 0xb8;
	memcpy(buf, &fn_int, 8);
	buf += 8;

	// call rax
	*buf++ = 0xff; 
	*buf++ = 0xd0;

	return buf - obuf;
}

// call with immediate arguments
size_t assemble_immcall(uint8_t* buf, void* func, int num_args, ...)
{
	assert(num_args <= 6);

	va_list ap;
	va_start(ap, num_args);

	uint8_t* obuf = buf;
	uint64_t fn_int = (uint64_t)func;
		
	// arguments as per x86_64 sysv calling convention
	uint16_t prefixes[] = { 0xbf48, 0xbe48, 0xba48, 0xb948, 0xb849, 0xb949 };
	for (int i = 0; i < num_args; i++) {
		uint64_t ival = va_arg(ap, uint64_t);
		memcpy(buf, &prefixes[i], 2);
		buf += 2;
		memcpy(buf, &ival, 8);
		buf += 8;
	}

	// mov rax, fn_int
	*buf++ = 0x48;
	*buf++ = 0xb8;
	memcpy(buf, &fn_int, 8);
	buf += 8;

	*buf++ = 0xff; // call rax
	*buf++ = 0xd0;

	va_end(ap);

	return buf - obuf;
}

size_t assemble_push(uint8_t* buf, uint64_t val)
{
	uint8_t* obuf = buf;
	*buf++ = 0x48; // mov rax, val
	*buf++ = 0xb8;
	memcpy(buf, &val, 8);
	buf += 8;
	*buf++ = 0x50; // push rax
	return buf - obuf;
}

size_t assemble_token(uint8_t* buf, const char* token)
{
	uint8_t* obuf = buf;
	if (strcmp(token, "+") == 0) {
		// add
		buf += assemble_pops(buf, 2);
		*buf++ = 0x48; // add rsi, rdi
		*buf++ = 0x01;
		*buf++ = 0xfe;
		*buf++ = 0x56; // push rsi
		return buf - obuf;
	} else if (strcmp(token, "-") == 0) {
		// sub
		buf += assemble_pops(buf, 2);
		*buf++ = 0x48; // sub rsi, rdi
		*buf++ = 0x29;
		*buf++ = 0xfe;
		*buf++ = 0x56; // push rsi
		return buf - obuf;
	} else if (strcmp(token, ".") == 0) {
		return assemble_stackcall(buf, &print_int, 1);
	} else if (strcmp(token, "emit") == 0) {
		return assemble_stackcall(buf, &emit, 1);	
	} else if (strcmp(token, "cr") == 0) {
		return assemble_immcall(buf, &newline, 0);
	} else if (valid_int(token)) {
		long int ival = strtol(token, NULL, 0);
		return assemble_push(buf, (uint64_t)ival);
		return 0;
	} else {
		printf("Invalid token!\n");
		return -1;
	}
}

size_t assemble(uint8_t* buf, const char* program)
{
	char* progbuf = malloc(strlen(program) + 1);
	strcpy(progbuf, program);
	char* token = strtok(progbuf, " ");

	size_t len = 0;

	while (token) {
		size_t res = assemble_token(buf, token);
		if (res == -1) {
			free(progbuf);
			return -1;
		}
		buf += res;
		len += res;
		token = strtok(NULL, " ");
	}

	*buf++ = 0xc3; // ret
	len++;

	free(progbuf);
	return len;
}

int main(int argc, char** argv)
{
	uint8_t buf[512];
	size_t len = assemble(buf, "30 20 - . cr");
	printf("assembled, len: %ld\n", len);
	for (size_t i = 0; i < len; i++) {
		printf("%02X ", buf[i]);
		if ((i + 1) % 16 == 0)
			printf("\n");
	}
	printf("\n");
	run(buf, 512);
}
