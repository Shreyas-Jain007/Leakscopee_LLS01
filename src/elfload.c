#include "elfload.h"

#include <elf.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"

#define ERR(...) do { snprintf(err, errlen, __VA_ARGS__); goto fail; } while (0)

/* true if [off, off+len) lies inside a file of size n (overflow-safe) */
static bool in_file(uint64_t off, uint64_t len, size_t n) {
    return off <= n && len <= n - off;
}

static void add_symbol(LoadedBinary *b, size_t *cap, const char *name, uint64_t addr) {
    for (size_t i = 0; i < b->nsyms; i++)
        if (strcmp(b->syms[i].name, name) == 0) return;   /* setdefault */
    if (b->nsyms == *cap) {
        *cap = *cap ? *cap * 2 : 64;
        b->syms = xrealloc(b->syms, *cap * sizeof(Symbol));
    }
    b->syms[b->nsyms].name = xstrdup(name);
    b->syms[b->nsyms].addr = addr;
    b->nsyms++;
}

bool elf_load(const char *path, LoadedBinary *out, char *err, size_t errlen) {
    memset(out, 0, sizeof *out);
    size_t n = 0;
    uint8_t *img = (uint8_t *)read_file(path, &n);
    if (!img) {
        snprintf(err, errlen, "cannot read %s: %s", path, strerror(errno));
        return false;
    }
    out->path = xstrdup(path);

    if (n < sizeof(Elf64_Ehdr) || memcmp(img, ELFMAG, SELFMAG) != 0)
        ERR("%s: not an ELF file", path);
    Elf64_Ehdr *eh = (Elf64_Ehdr *)img;
    if (eh->e_ident[EI_CLASS] != ELFCLASS64 || eh->e_ident[EI_DATA] != ELFDATA2LSB)
        ERR("%s: not a little-endian 64-bit ELF", path);
    if (eh->e_machine != EM_X86_64)
        ERR("%s: not an x86-64 ELF (e_machine=%u)", path, eh->e_machine);
    if (eh->e_type == ET_DYN) out->load_bias = DYN_BIAS;

    /* ---- program headers: PT_LOAD segments ---- */
    if (eh->e_phnum) {
        if (eh->e_phentsize != sizeof(Elf64_Phdr) ||
            !in_file(eh->e_phoff, (uint64_t)eh->e_phnum * sizeof(Elf64_Phdr), n))
            ERR("%s: bad program header table", path);
        Elf64_Phdr *ph = (Elf64_Phdr *)(img + eh->e_phoff);
        out->segs = xcalloc(eh->e_phnum, sizeof(Segment));
        for (int i = 0; i < eh->e_phnum; i++) {
            if (ph[i].p_type != PT_LOAD) continue;
            if (!in_file(ph[i].p_offset, ph[i].p_filesz, n))
                ERR("%s: PT_LOAD segment %d extends past end of file", path, i);
            Segment *s = &out->segs[out->nsegs++];
            s->vaddr = ph[i].p_vaddr + out->load_bias;
            s->filesz = ph[i].p_filesz;
            s->memsz = ph[i].p_memsz;
            s->data = xmalloc(ph[i].p_filesz ? ph[i].p_filesz : 1);
            memcpy(s->data, img + ph[i].p_offset, ph[i].p_filesz);
        }
    }

    /* ---- section headers: .symtab then .dynsym ---- */
    if (eh->e_shnum && eh->e_shoff) {
        if (eh->e_shentsize != sizeof(Elf64_Shdr) ||
            !in_file(eh->e_shoff, (uint64_t)eh->e_shnum * sizeof(Elf64_Shdr), n))
            ERR("%s: bad section header table", path);
        Elf64_Shdr *sh = (Elf64_Shdr *)(img + eh->e_shoff);
        const char *shstr = NULL;
        uint64_t shstr_sz = 0;
        if (eh->e_shstrndx < eh->e_shnum &&
            in_file(sh[eh->e_shstrndx].sh_offset, sh[eh->e_shstrndx].sh_size, n)) {
            shstr = (const char *)img + sh[eh->e_shstrndx].sh_offset;
            shstr_sz = sh[eh->e_shstrndx].sh_size;
        }
        size_t cap = 0;
        static const char *want[] = { ".symtab", ".dynsym" };
        for (int w = 0; w < 2 && shstr; w++) {
            for (int i = 0; i < eh->e_shnum; i++) {
                if (sh[i].sh_name >= shstr_sz) continue;
                const char *nm = shstr + sh[i].sh_name;
                if (strnlen(nm, shstr_sz - sh[i].sh_name) == shstr_sz - sh[i].sh_name) continue;
                if (strcmp(nm, want[w]) != 0) continue;
                if (sh[i].sh_entsize != sizeof(Elf64_Sym) ||
                    !in_file(sh[i].sh_offset, sh[i].sh_size, n) ||
                    sh[i].sh_link >= eh->e_shnum)
                    break;
                Elf64_Shdr *strsec = &sh[sh[i].sh_link];
                if (!in_file(strsec->sh_offset, strsec->sh_size, n)) break;
                const char *strtab = (const char *)img + strsec->sh_offset;
                uint64_t strsz = strsec->sh_size;
                Elf64_Sym *sym = (Elf64_Sym *)(img + sh[i].sh_offset);
                size_t count = sh[i].sh_size / sizeof(Elf64_Sym);
                for (size_t k = 0; k < count; k++) {
                    if (sym[k].st_name == 0 || sym[k].st_name >= strsz) continue;
                    const char *sname = strtab + sym[k].st_name;
                    if (strnlen(sname, strsz - sym[k].st_name) == strsz - sym[k].st_name)
                        continue;   /* unterminated */
                    if (!sname[0] || !sym[k].st_value) continue;
                    add_symbol(out, &cap, sname, sym[k].st_value + out->load_bias);
                }
                break;   /* get_section_by_name returns the first match */
            }
        }
    }
    free(img);
    return true;
fail:
    free(img);
    elf_free(out);
    return false;
}

void elf_free(LoadedBinary *b) {
    for (size_t i = 0; i < b->nsegs; i++) free(b->segs[i].data);
    free(b->segs);
    for (size_t i = 0; i < b->nsyms; i++) free(b->syms[i].name);
    free(b->syms);
    free(b->path);
    memset(b, 0, sizeof *b);
}

bool elf_resolve(const LoadedBinary *b, const char *entry, uint64_t *addr) {
    if (entry[0] == '0' && (entry[1] == 'x' || entry[1] == 'X')) {
        char *end;
        errno = 0;
        unsigned long long v = strtoull(entry + 2, &end, 16);
        if (errno || *end || end == entry + 2) return false;
        *addr = (uint64_t)v + b->load_bias;
        return true;
    }
    for (size_t i = 0; i < b->nsyms; i++) {
        if (strcmp(b->syms[i].name, entry) == 0) {
            *addr = b->syms[i].addr;
            return true;
        }
    }
    return false;
}

bool elf_nearest_symbol(const LoadedBinary *b, uint64_t pc, const char **name, uint64_t *off) {
    const Symbol *best = NULL;
    for (size_t i = 0; i < b->nsyms; i++) {
        const Symbol *s = &b->syms[i];
        if (s->addr <= pc && (!best || s->addr > best->addr)) best = s;
    }
    if (!best) return false;
    *name = best->name;
    *off = pc - best->addr;
    return true;
}
