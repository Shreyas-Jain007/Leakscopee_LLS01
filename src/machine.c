#include "machine.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unicorn/unicorn.h>

#include "taint.h"

/* System V AMD64 integer argument registers, in order. */
static const int ARG_REGS_UC[6] = {
    UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX,
    UC_X86_REG_RCX, UC_X86_REG_R8, UC_X86_REG_R9,
};
static const x86_reg ARG_REGS_CS[6] = {
    X86_REG_RDI, X86_REG_RSI, X86_REG_RDX, X86_REG_RCX, X86_REG_R8, X86_REG_R9,
};

/* Capstone -> Unicorn register ids for every general-purpose register width. */
typedef struct { x86_reg cs; int uc; } RegPair;
#define P(n) { X86_REG_##n, UC_X86_REG_##n }
static const RegPair REG_MAP[] = {
    P(RAX), P(EAX), P(AX), P(AH), P(AL),  P(RBX), P(EBX), P(BX), P(BH), P(BL),
    P(RCX), P(ECX), P(CX), P(CH), P(CL),  P(RDX), P(EDX), P(DX), P(DH), P(DL),
    P(RSI), P(ESI), P(SI), P(SIL),        P(RDI), P(EDI), P(DI), P(DIL),
    P(RBP), P(EBP), P(BP), P(BPL),        P(RSP), P(ESP), P(SP), P(SPL),
#define RN(n) P(R##n), P(R##n##D), P(R##n##W), P(R##n##B)
    RN(8), RN(9), RN(10), RN(11), RN(12), RN(13), RN(14), RN(15),
#undef RN
};
#undef P

static int cs_to_uc(x86_reg r) {
    for (size_t i = 0; i < sizeof REG_MAP / sizeof REG_MAP[0]; i++)
        if (REG_MAP[i].cs == r) return REG_MAP[i].uc;
    return -1;
}

static uint64_t align_down(uint64_t x) { return x & ~(PAGE_SIZE_EMU - 1); }
static uint64_t align_up(uint64_t x) { return (x + PAGE_SIZE_EMU - 1) & ~(PAGE_SIZE_EMU - 1); }

static uint64_t reg_read(uc_engine *uc, int id) {
    uint64_t v = 0;
    uc_reg_read(uc, id, &v);
    return v;
}

static void reg_write(uc_engine *uc, int id, uint64_t v) { uc_reg_write(uc, id, &v); }

/* ---- page set -> merged mapping ranges ------------------------------------ */
static int cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return x < y ? -1 : x > y;
}

static int cmp_cstr(const void *a, const void *b) {
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

static void add_pages(U64Vec *pages, uint64_t vaddr, uint64_t size) {
    for (uint64_t p = align_down(vaddr); p < align_up(vaddr + size); p += PAGE_SIZE_EMU)
        VEC_PUSH(pages, p);
}

bool machine_init(Machine *m, const Target *t, char *err, size_t errlen) {
    memset(m, 0, sizeof *m);
    m->target = t;
    if (!elf_load(t->binary_path, &m->bin, err, errlen)) return false;
    if (!elf_resolve(&m->bin, t->entry, &m->entry)) {
        /* list the alphabetically first 20 symbols as a hint */
        const char **names = xcalloc(m->bin.nsyms ? m->bin.nsyms : 1, sizeof(char *));
        for (size_t i = 0; i < m->bin.nsyms; i++) names[i] = m->bin.syms[i].name;
        qsort(names, m->bin.nsyms, sizeof(char *), cmp_cstr);
        size_t off = (size_t)snprintf(err, errlen, "entry '%s' not found; known symbols:", t->entry);
        for (size_t i = 0; i < m->bin.nsyms && i < 20 && off < errlen; i++)
            off += (size_t)snprintf(err + off, errlen - off, " %s", names[i]);
        free(names);
        elf_free(&m->bin);
        return false;
    }
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &m->cs) != CS_ERR_OK) {
        snprintf(err, errlen, "capstone: cs_open failed");
        elf_free(&m->bin);
        return false;
    }
    cs_option(m->cs, CS_OPT_DETAIL, CS_OPT_ON);
    m->cache_cap = 1024;
    m->cache = xcalloc(m->cache_cap, sizeof(DecodeSlot));

    /* Every page touched by a segment, the stack or the arena, mapped RWX
     * (we analyse, not enforce).  Merge into contiguous ranges. */
    U64Vec pages = {0};
    for (size_t i = 0; i < m->bin.nsegs; i++) {
        const Segment *s = &m->bin.segs[i];
        add_pages(&pages, s->vaddr, s->memsz > s->filesz ? s->memsz : s->filesz);
    }
    add_pages(&pages, STACK_BASE, STACK_SIZE);
    add_pages(&pages, ARENA_BASE, ARENA_SIZE);
    qsort(pages.data, pages.len, sizeof(uint64_t), cmp_u64);
    m->ranges = xcalloc(pages.len ? pages.len : 1, sizeof(MapRange));
    for (size_t i = 0; i < pages.len; i++) {
        if (i && pages.data[i] == pages.data[i - 1]) continue;
        if (m->nranges && m->ranges[m->nranges - 1].begin + m->ranges[m->nranges - 1].size == pages.data[i])
            m->ranges[m->nranges - 1].size += PAGE_SIZE_EMU;
        else
            m->ranges[m->nranges++] = (MapRange){ pages.data[i], PAGE_SIZE_EMU };
    }
    VEC_FREE(&pages);
    return true;
}

void machine_free(Machine *m) {
    for (size_t i = 0; i < m->cache_cap; i++)
        if (m->cache[i].insn) cs_free(m->cache[i].insn, 1);
    free(m->cache);
    free(m->ranges);
    if (m->cs) cs_close(&m->cs);
    elf_free(&m->bin);
    memset(m, 0, sizeof *m);
}

/* ---- disassembly cache ------------------------------------------------------ */
static size_t slot_of(uint64_t a, size_t cap) {
    a ^= a >> 29;
    a *= 0xbf58476d1ce4e5b9ull;
    a ^= a >> 32;
    return (size_t)a & (cap - 1);
}

static void cache_put(Machine *m, uint64_t addr, cs_insn *insn) {
    if ((m->cache_len + 1) * 2 > m->cache_cap) {
        size_t ncap = m->cache_cap * 2;
        DecodeSlot *n = xcalloc(ncap, sizeof(DecodeSlot));
        for (size_t i = 0; i < m->cache_cap; i++) {
            if (!m->cache[i].insn) continue;
            size_t j = slot_of(m->cache[i].addr, ncap);
            while (n[j].insn) j = (j + 1) & (ncap - 1);
            n[j] = m->cache[i];
        }
        free(m->cache);
        m->cache = n;
        m->cache_cap = ncap;
    }
    size_t j = slot_of(addr, m->cache_cap);
    while (m->cache[j].insn) j = (j + 1) & (m->cache_cap - 1);
    m->cache[j].addr = addr;
    m->cache[j].insn = insn;
    m->cache_len++;
}

static const cs_insn *decode(Machine *m, uc_engine *uc, uint64_t address) {
    size_t j = slot_of(address, m->cache_cap);
    while (m->cache[j].insn) {
        if (m->cache[j].addr == address) return m->cache[j].insn;
        j = (j + 1) & (m->cache_cap - 1);
    }
    uint8_t code[15];
    size_t n = sizeof code;
    /* read up to 15 bytes; shrink if the instruction sits at a mapping edge */
    while (n && uc_mem_read(uc, address, code, n) != UC_ERR_OK) n--;
    if (!n) return NULL;
    cs_insn *insn = NULL;
    if (cs_disasm(m->cs, code, n, address, 1, &insn) != 1) {
        if (insn) cs_free(insn, 1);
        return NULL;
    }
    cache_put(m, address, insn);
    return insn;
}

static bool is_cond_jump(Machine *m, const cs_insn *ins) {
    return cs_insn_group(m->cs, ins, X86_GRP_JUMP) && strcmp(ins->mnemonic, "jmp") != 0;
}

/* ---- machine construction ---------------------------------------------------- */
static uc_engine *new_uc(Machine *m) {
    uc_engine *uc;
    uc_err e = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
    if (e != UC_ERR_OK) die("unicorn: uc_open failed: %s", uc_strerror(e));
    for (size_t i = 0; i < m->nranges; i++) {
        e = uc_mem_map(uc, m->ranges[i].begin, m->ranges[i].size, UC_PROT_ALL);
        if (e != UC_ERR_OK)
            die("unicorn: cannot map 0x%llx+0x%llx: %s", (unsigned long long)m->ranges[i].begin,
                (unsigned long long)m->ranges[i].size, uc_strerror(e));
    }
    for (size_t i = 0; i < m->bin.nsegs; i++) {
        const Segment *s = &m->bin.segs[i];
        if (s->filesz) uc_mem_write(uc, s->vaddr, s->data, s->filesz);
    }
    return uc;
}

typedef struct {
    uint64_t addr, len;
} Region;

/* Place params per SysV AMD64.  Reports the secret memory regions and the
 * argument registers holding secrets (for taint seeding). */
static void place_inputs(Machine *m, uc_engine *uc, Bytes secret,
                         Region *regions, size_t *nregions, x86_reg *sregs, size_t *nsregs) {
    const Target *t = m->target;
    uint64_t rsp = STACK_BASE + STACK_SIZE - 0x1000;
    rsp &= ~0xFull;
    rsp -= 8;
    uint64_t sentinel = SENTINEL_RET;
    uc_mem_write(uc, rsp, &sentinel, 8);
    reg_write(uc, UC_X86_REG_RSP, rsp);
    reg_write(uc, UC_X86_REG_RBP, rsp);

    uint64_t arena = ARENA_BASE;
    size_t soff = 0;
    *nregions = *nsregs = 0;
    for (size_t i = 0; i < t->nparams; i++) {
        const Param *p = &t->params[i];
        int reg = ARG_REGS_UC[i];
        if (p->kind == KIND_INT) {
            uint64_t val = 0;
            if (p->is_secret) {
                uint8_t le[8] = {0};
                for (size_t k = 0; k < 8 && soff + k < secret.len; k++) le[k] = secret.data[soff + k];
                for (int k = 7; k >= 0; k--) val = val << 8 | le[k];
                soff += 8;
                sregs[(*nsregs)++] = ARG_REGS_CS[i];
            } else if (p->has_value) {
                val = p->value;
            }
            reg_write(uc, reg, val);
            continue;
        }
        /* inbuf / outbuf */
        uint64_t addr = arena;
        arena = align_up(arena + p->size + 0x40);
        if (arena > ARENA_BASE + ARENA_SIZE)
            die("input buffers exceed the %llu-byte input arena", (unsigned long long)ARENA_SIZE);
        uint8_t *chunk = xcalloc(p->size ? p->size : 1, 1);
        if (p->kind == KIND_INBUF) {
            if (p->is_secret) {
                for (size_t k = 0; k < p->size && soff + k < secret.len; k++) chunk[k] = secret.data[soff + k];
                soff += p->size;
                regions[(*nregions)++] = (Region){ addr, p->size };
            } else if (p->has_bytes) {
                memcpy(chunk, p->value_bytes.data,
                       p->value_bytes.len < p->size ? p->value_bytes.len : p->size);
            }
        }
        if (p->size) uc_mem_write(uc, addr, chunk, p->size);
        free(chunk);
        reg_write(uc, reg, addr);
    }
}

/* ---- architectural run ------------------------------------------------------- */
typedef struct {
    Machine *m;
    uc_engine *uc;
    Trace *tr;
    TaintState *ts;
    uint64_t pc;
    uint64_t count, budget;
    bool pending;                 /* a conditional branch awaits its outcome */
    uint64_t pend_pc, pend_target;
    bool pend_has_target;
} RunCtx;

static uint64_t taint_reader(void *vctx, int canon) {
    RunCtx *c = vctx;
    int id = canon >= 0 ? cs_to_uc((x86_reg)canon) : -1;
    /* only the 64-bit parents ever reach here (canonicalised) */
    return id >= 0 ? reg_read(c->uc, id) : 0;
}

/* Operand magnitude driving div/idiv latency: max(dividend RAX, divisor). */
static uint64_t div_magnitude(uc_engine *uc, const cs_insn *ins) {
    uint64_t divisor = 0;
    const cs_x86 *x = &ins->detail->x86;
    if (x->op_count > 0 && x->operands[0].type == X86_OP_REG) {
        int id = cs_to_uc(x->operands[0].reg);
        if (id >= 0) divisor = reg_read(uc, id);
    }
    uint64_t dividend = reg_read(uc, UC_X86_REG_RAX);
    return divisor > dividend ? divisor : dividend;
}

static void code_hook(uc_engine *uc, uint64_t address, uint32_t size, void *ud) {
    (void)size;
    RunCtx *c = ud;
    c->count++;
    if (c->count > c->budget) {
        c->tr->halted_reason = "budget";
        uc_emu_stop(uc);
        return;
    }
    /* resolve a pending branch decision now that we know the next pc */
    if (c->pending) {
        BranchEvent b = { c->pend_pc, c->pend_has_target && address == c->pend_target };
        VEC_PUSH(&c->tr->branches, b);
        c->pending = false;
    }
    c->pc = address;
    const cs_insn *ins = decode(c->m, uc, address);
    if (!ins) return;
    /* conditional branch? (any Jcc / loop / jrcxz, not plain jmp) */
    if (is_cond_jump(c->m, ins)) {
        const cs_x86 *x = &ins->detail->x86;
        c->pending = true;
        c->pend_pc = address;
        c->pend_has_target = x->op_count > 0 && x->operands[0].type == X86_OP_IMM;
        c->pend_target = c->pend_has_target ? (uint64_t)x->operands[0].imm : 0;
    }
    /* variable-latency instruction? */
    if (taint_is_variable_time(ins->mnemonic)) {
        TimingEvent te = { address, strcmp(ins->mnemonic, "div") == 0 ? "div" : "idiv",
                           div_magnitude(uc, ins) };
        VEC_PUSH(&c->tr->timing, te);
    }
    if (c->ts) taint_step(c->ts, c->m->cs, ins, taint_reader, c);
}

static void mem_hook(uc_engine *uc, uc_mem_type type, uint64_t address, int size,
                     int64_t value, void *ud) {
    (void)uc; (void)size; (void)value;
    RunCtx *c = ud;
    MemEvent e = { c->pc, address >> CACHE_LINE_BITS, type == UC_MEM_WRITE };
    VEC_PUSH(&c->tr->mem, e);
}

static bool unmapped_hook(uc_engine *uc, uc_mem_type type, uint64_t address, int size,
                          int64_t value, void *ud) {
    (void)type; (void)address; (void)size; (void)value;
    RunCtx *c = ud;
    c->tr->halted_reason = "unmapped";
    uc_emu_stop(uc);
    return false;
}

void machine_run(Machine *m, Bytes secret, bool with_taint, Trace *tr) {
    uc_engine *uc = new_uc(m);
    Region regions[6];
    x86_reg sregs[6];
    size_t nregions, nsregs;
    place_inputs(m, uc, secret, regions, &nregions, sregs, &nsregs);

    trace_init(tr, secret);
    RunCtx c = { .m = m, .uc = uc, .tr = tr, .pc = m->entry, .budget = m->target->instr_budget };
    if (with_taint) {
        c.ts = xcalloc(1, sizeof(TaintState));
        taint_init(c.ts);
        for (size_t i = 0; i < nregions; i++) taint_seed_mem(c.ts, regions[i].addr, regions[i].len);
        for (size_t i = 0; i < nsregs; i++) taint_seed_reg(c.ts, sregs[i]);
    }

    uc_hook h1, h2, h3;
    uc_hook_add(uc, &h1, UC_HOOK_CODE, (void *)code_hook, &c, 1, 0);
    uc_hook_add(uc, &h2, UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, (void *)mem_hook, &c, 1, 0);
    uc_hook_add(uc, &h3, UC_HOOK_MEM_UNMAPPED, (void *)unmapped_hook, &c, 1, 0);
    if (uc_emu_start(uc, m->entry, SENTINEL_RET, 0, c.budget + 1) != UC_ERR_OK)
        tr->halted_reason = "ucerror";
    tr->instr_count = c.count;
    tr->taint = c.ts;
    uc_close(uc);
}

/* ---- speculative probe ------------------------------------------------------- */
typedef struct {
    uint64_t pc;
    SpecAccesses *out;
} SpecCtx;

static void spec_code(uc_engine *uc, uint64_t address, uint32_t size, void *ud) {
    (void)uc; (void)size;
    ((SpecCtx *)ud)->pc = address;
}

static void spec_mem(uc_engine *uc, uc_mem_type type, uint64_t address, int size,
                     int64_t value, void *ud) {
    (void)uc; (void)type; (void)size; (void)value;
    SpecCtx *c = ud;
    /* registered for reads only, so every callback is a load */
    SpecAccess a = { c->pc, address >> CACHE_LINE_BITS };
    VEC_PUSH(c->out, a);
}

/* Run up to (not through) the conditional branch at bpc.  Returns the
 * instruction or NULL if it is never reached / not a conditional branch. */
static const cs_insn *run_to_branch(Machine *m, uc_engine *uc, Bytes secret, uint64_t bpc) {
    Region regions[6];
    x86_reg sregs[6];
    size_t nr, ns;
    place_inputs(m, uc, secret, regions, &nr, sregs, &ns);
    if (uc_emu_start(uc, m->entry, bpc, 0, m->target->instr_budget) != UC_ERR_OK) return NULL;
    if (reg_read(uc, UC_X86_REG_RIP) != bpc) return NULL;
    return decode(m, uc, bpc);
}

void machine_run_speculative(Machine *m, Bytes secret, uint64_t branch_pc,
                             uint64_t window, SpecAccesses *out) {
    memset(out, 0, sizeof *out);
    uc_engine *uc = new_uc(m);
    const cs_insn *ins = run_to_branch(m, uc, secret, branch_pc);
    if (!ins || !is_cond_jump(m, ins)) goto done;
    uint64_t fallthrough = branch_pc + ins->size;
    const cs_x86 *x = &ins->detail->x86;
    uint64_t target = (x->op_count > 0 && x->operands[0].type == X86_OP_IMM)
                          ? (uint64_t)x->operands[0].imm : fallthrough;
    /* execute the branch once to learn the architectural direction */
    if (uc_emu_start(uc, branch_pc, 0, 0, 1) != UC_ERR_OK) goto done;
    uint64_t arch_next = reg_read(uc, UC_X86_REG_RIP);
    uint64_t mispredict = arch_next == target ? fallthrough : target;
    reg_write(uc, UC_X86_REG_RIP, mispredict);

    SpecCtx c = { mispredict, out };
    uc_hook h1, h2;
    uc_hook_add(uc, &h1, UC_HOOK_CODE, (void *)spec_code, &c, 1, 0);
    uc_hook_add(uc, &h2, UC_HOOK_MEM_READ, (void *)spec_mem, &c, 1, 0);
    uc_emu_start(uc, mispredict, SENTINEL_RET, 0, window);   /* errors end the window */
done:
    uc_close(uc);
}

int machine_arch_direction(Machine *m, Bytes secret, uint64_t bpc) {
    uc_engine *uc = new_uc(m);
    int dir = -1;
    const cs_insn *ins = run_to_branch(m, uc, secret, bpc);
    if (!ins) goto done;
    uint64_t size = ins->size;
    if (uc_emu_start(uc, bpc, 0, 0, 1) != UC_ERR_OK) goto done;
    dir = reg_read(uc, UC_X86_REG_RIP) != bpc + size;   /* 1 = branch taken */
done:
    uc_close(uc);
    return dir;
}
