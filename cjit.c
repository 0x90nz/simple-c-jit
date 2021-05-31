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
	return endptr != token;
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

	// the prologue and epilogue aren't a function prologue and epilogue
	// but more a guard for calls into C functions. these expect the stack
	// to be aligned on a 16-byte boundary, but we don't guarantee that internally
	// so set that up here.
	const char prologue[] = {
		0x55,			// push rbp
		0x48, 0x89, 0xe5,	// mov rbp, rsp
		0x48, 0x83, 0xe4, 0xf0	// and rsp, ~0x0f
	};
	const char epilogue[] = {
		0x48, 0x89, 0xec,	// mov rsp, rbp
		0x5d			// pop rbp
	};

	buf += assemble_pops(buf, num_args);	

	memcpy(buf, prologue, sizeof(prologue));
	buf += sizeof(prologue);

	uint64_t fn_int = (uint64_t)func;
	// mov rax, fn_int
	*buf++ = 0x48;
	*buf++ = 0xb8;
	memcpy(buf, &fn_int, 8);
	buf += 8;

	// call rax
	*buf++ = 0xff; 
	*buf++ = 0xd0;

	memcpy(buf, epilogue, sizeof(epilogue));
	buf += sizeof(epilogue);

	return buf - obuf;
}

size_t assemble_push(uint8_t* buf, uint64_t val)
{
	uint8_t* obuf = buf;
	if (val <= UINT32_MAX) {
		*buf++ = 0x68;
		uint32_t u32val = val;
		memcpy(buf, &u32val, 4);
		buf += 4;
	} else {
		*buf++ = 0x48; // mov rax, val
		*buf++ = 0xb8;
		memcpy(buf, &val, 8);
		buf += 8;
		*buf++ = 0x50; // push rax
	}
	return buf - obuf;
}

size_t assemble_equals(uint8_t* buf)
{
	uint8_t* obuf = buf;
	
	buf += assemble_pops(buf, 2);
	// essentially if the arguments are equal we move -1 to rdx
	// and push it otherwise we just push zero (rdx is cleared at
	// the start)
	const char assembly[] = { 
		0x48, 0x31, 0xd2,				// xor rdx, rdx
		0x48, 0xc7, 0xc0, 0xff, 0xff, 0xff, 0xff,	// mov rax, -1
		0x48, 0x39, 0xf7,				// cmp rdi, rsi
		0x48, 0x0f, 0x44, 0xd0,				// cmove rdx, rax
		0x52						// push rdx
	};
	memcpy(buf, assembly, sizeof(assembly));
	buf += sizeof(assembly);

	return buf - obuf;
}

size_t assemble_add(uint8_t* buf)
{
	uint8_t* obuf = buf;
	buf += assemble_pops(buf, 2);
	const char assembly[] = {
		0x48, 0x01, 0xfe,	// add rsi, rdi
		0x56			// push rsi
	};
	memcpy(buf, assembly, sizeof(assembly));
	buf += sizeof(assembly);
	return buf - obuf;
}

size_t assemble_sub(uint8_t* buf)
{
	uint8_t* obuf = buf;
	const char assembly[] = {
		0x48, 0x29, 0xfe,	// sub rsi, rdi
		0x56			// push rsi
	};
	buf += assemble_pops(buf, 2);
	memcpy(buf, assembly, sizeof(assembly));
	buf += sizeof(assembly);

	return buf - obuf;
}

size_t assemble_not(uint8_t* buf)
{
	uint8_t* obuf = buf;
	const char assembly[] = {
		0x58,			// pop rax
		0x48, 0xf7, 0xd0, 	// not rax
		0x50			// push rax
	};
	memcpy(buf, assembly, sizeof(assembly));
	buf += sizeof(assembly);
	return buf - obuf;
}

size_t assemble_dup(uint8_t* buf)
{
	uint8_t* obuf = buf;

	buf += assemble_pops(buf, 1);
	*buf++ = 0x57;	// push rdi (x2)
	*buf++ = 0x57;

	return buf - obuf;
}

size_t assemble_swap(uint8_t* buf)
{
	uint8_t* obuf = buf;

	buf += assemble_pops(buf, 2);
	*buf++ = 0x57;
	*buf++ = 0x56;

	return buf - obuf;
}

size_t assemble_token(uint8_t* buf, const char* token)
{
	uint8_t* obuf = buf;
	if (strcmp(token, "+") == 0) {
		buf += assemble_add(buf);
	} else if (strcmp(token, "-") == 0) {
		buf += assemble_sub(buf);
	} else if (strcmp(token, ".") == 0) {
		buf += assemble_stackcall(buf, &print_int, 1);
	} else if (strcmp(token, "=") == 0) {
		buf += assemble_equals(buf);
	} else if (strcmp(token, "not") == 0) {
		buf += assemble_not(buf);
	} else if (strcmp(token, "emit") == 0) {
		buf += assemble_stackcall(buf, &emit, 1);	
	} else if (strcmp(token, "cr") == 0) {
		buf += assemble_stackcall(buf, &newline, 0);
	} else if (strcmp(token, "dup") == 0) {
		buf += assemble_dup(buf);
	} else if (strcmp(token, "drop") == 0) {
		buf += assemble_pops(buf, 1);
	} else if (strcmp(token, "swap") == 0) {
		buf += assemble_swap(buf);
	} else if (valid_int(token)) {
		long int ival = strtol(token, NULL, 0);
		buf += assemble_push(buf, (uint64_t)ival);
	} else {
		printf("Invalid token '%s'!\n", token);
		return -1;
	}

	return buf - obuf;
}

struct label {
	char name[32];
	size_t offset;
};

size_t assemble_goto(uint8_t* buf, size_t place_to_go, size_t current_off)
{
	uint8_t* obuf = buf;
	const char assembly[] = {
		0x58, 				// pop rax
		0x48, 0x83, 0xf8, 0xff,		// cmp rax, -1
		0x0f, 0x84			// je offset (encoded below)
	};
	memcpy(buf, assembly, sizeof(assembly));
	buf += sizeof(assembly);

	// offset as address is relative to the start of the je immediate offset 
	uint32_t offset = current_off - place_to_go - 4 - sizeof(assembly);
	memcpy(buf, &offset, 4);
	buf += 4;

	return buf - obuf;
}

size_t assemble(uint8_t* buf, const char* program)
{
	uint8_t* obuf = buf;
	char* progbuf = malloc(strlen(program) + 1);
	strcpy(progbuf, program);
	char* token = strtok(progbuf, " ");

	struct label labels[32];	
	int num_labels = 0;

	const char prologue[] = {
		0x55,			// push rbp
		0x48, 0x89, 0xe5,	// mov rbp, rsp
	};
	const char epilogue[] = {
		0x48, 0x89, 0xec,	// mov rsp, rbp
		0x5d			// pop rbp
	};

	memcpy(buf, prologue, sizeof(prologue));
	buf += sizeof(prologue);

	while (token) {
		if (token[0] == '!') {
			struct label* label = &labels[num_labels++];
			assert(strlen(token + 1) < 32);
			strcpy(label->name, token + 1); 
			label->offset = buf - obuf;
		} else if (strncmp(token, "go!", 3) == 0) {
			size_t offset = -1;
			for (int i = 0; i < num_labels; i++) {
				if (strcmp(token + 3, labels[i].name) == 0) {
					offset = labels[i].offset;
					break;
				}
			}
			if (offset == -1) {
				printf("Unknown label '%s'\n", token + 3);
				return -1;
			}
			buf += assemble_goto(buf, buf - obuf, offset);
		} else {
			size_t res = assemble_token(buf, token);
			if (res == -1) {
				free(progbuf);
				return -1;
			}
			buf += res;
		}
		token = strtok(NULL, " ");
	}

	memcpy(buf, epilogue, sizeof(epilogue));
	buf += sizeof(epilogue);
	*buf++ = 0xc3; // ret

	free(progbuf);
	return buf - obuf;
}

void mem_dump(void* buffer, size_t len)
{
	uint8_t* buf = buffer;
	size_t i = 0;
	for (i = 0; i < len; i++) {
		printf("%02X ", buf[i]);
		if ((i + 1) % 16 == 0)
			printf("\n");
	}
	if (i % 16 != 0)
		printf("\n");
}

int main(int argc, char** argv)
{
	char* linebuf = malloc(4096);
	bool execute = true;

	printf("Simple C JIT demo. ^D, .q or .quit to exit.\n");
	while (true) {
		printf("> ");
		if (!fgets(linebuf, 512, stdin))
			break;

		linebuf[strcspn(linebuf, "\n")] = '\0'; // trim trailing newline

		if (strcmp(linebuf, ".q") == 0 || strcmp(linebuf, ".quit") == 0)
			break;

		if (strcmp(linebuf, ".e") == 0) {
			execute = !execute;
			continue;
		}

		char* program = malloc(4096);
		size_t length = assemble(program, linebuf);
		if (length != -1) {
			mem_dump(program, length);
			if (execute)
				run(program, 512);
		}
		free(program);
	}
	free(linebuf);
}

