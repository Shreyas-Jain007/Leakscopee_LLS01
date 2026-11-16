/* Parsed ELF: PT_LOAD segment images and a symbol table, independent of the
 * emulator.  Replaces pyelftools. */
#ifndef LEAKSCOPE_ELFLOAD_H
#define LEAKSCOPE_ELFLOAD_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define DYN_BIAS 0x555555554000ull   /* load bias applied to ET_DYN (PIE) */

typedef struct {
    uint64_t vaddr;      /* biased */
    uint8_t *data;       /* p_filesz bytes from the file */
    uint64_t filesz;
    uint64_t memsz;
} Segment;

typedef struct {
    char *name;
    uint64_t addr;       /* biased */
} Symbol;

typedef struct {
    char *path;
    Segment *segs;
    size_t nsegs;
    Symbol *syms;        /* insertion order: .symtab then .dynsym, first name wins */
    size_t nsyms;
    uint64_t load_bias;
} LoadedBinary;

/* Load an x86-64 ELF.  On failure returns false and fills err. */
bool elf_load(const char *path, LoadedBinary *out, char *err, size_t errlen);
void elf_free(LoadedBinary *b);

/* Resolve a manifest entry ("symbol" or "0xHEX"). Returns false if unknown. */
bool elf_resolve(const LoadedBinary *b, const char *entry, uint64_t *addr);

/* Nearest symbol at or below pc; returns false if none. */
bool elf_nearest_symbol(const LoadedBinary *b, uint64_t pc, const char **name, uint64_t *off);

#endif
