#include "taint.h"

#include <stdlib.h>
#include <string.h>

bool taint_is_variable_time(const char *m) {
    return strcmp(m, "div") == 0 || strcmp(m, "idiv") == 0;
}

int taint_canon(x86_reg r) {
    switch (r) {
    case X86_REG_INVALID: return -1;
    case X86_REG_RIP: case X86_REG_EFLAGS: return -1;
    case X86_REG_RAX: case X86_REG_EAX: case X86_REG_AX: case X86_REG_AH: case X86_REG_AL:
        return X86_REG_RAX;
    case X86_REG_RBX: case X86_REG_EBX: case X86_REG_BX: case X86_REG_BH: case X86_REG_BL:
        return X86_REG_RBX;
    case X86_REG_RCX: case X86_REG_ECX: case X86_REG_CX: case X86_REG_CH: case X86_REG_CL:
        return X86_REG_RCX;
    case X86_REG_RDX: case X86_REG_EDX: case X86_REG_DX: case X86_REG_DH: case X86_REG_DL:
        return X86_REG_RDX;
    case X86_REG_RSI: case X86_REG_ESI: case X86_REG_SI: case X86_REG_SIL: return X86_REG_RSI;
    case X86_REG_RDI: case X86_REG_EDI: case X86_REG_DI: case X86_REG_DIL: return X86_REG_RDI;
    case X86_REG_RBP: case X86_REG_EBP: case X86_REG_BP: case X86_REG_BPL: return X86_REG_RBP;
    case X86_REG_RSP: case X86_REG_ESP: case X86_REG_SP: case X86_REG_SPL: return X86_REG_RSP;
#define RN(n) case X86_REG_R##n: case X86_REG_R##n##D: case X86_REG_R##n##W: case X86_REG_R##n##B: \
        return X86_REG_R##n;
    RN(8) RN(9) RN(10) RN(11) RN(12) RN(13) RN(14) RN(15)
#undef RN
    default:
        return (r > 0 && r < X86_REG_ENDING) ? (int)r : -1;
    }
}

void taint_init(TaintState *st) {
    memset(st, 0, sizeof *st);
    u64set_init(&st->mem);
}

void taint_free(TaintState *st) {
    u64set_free(&st->mem);
    VEC_FREE(&st->branch_sites);
    VEC_FREE(&st->addr_sites);
    VEC_FREE(&st->timing_sites);
}

void taint_seed_reg(TaintState *st, x86_reg r) {
    int c = taint_canon(r);
    if (c >= 0) st->regs[c] = true;
}

void taint_seed_mem(TaintState *st, uint64_t addr, uint64_t len) {
    for (uint64_t a = addr; a < addr + len; a++) u64set_add(&st->mem, a);
}

static SiteEntry *site_find(SiteMap *m, uint64_t pc) {
    for (size_t i = 0; i < m->len; i++)
        if (m->data[i].pc == pc) return &m->data[i];
    return NULL;
}

static void site_bump(SiteMap *m, uint64_t pc) {
    SiteEntry *e = site_find(m, pc);
    if (e) { e->count++; return; }
    SiteEntry n = { pc, 1, NULL };
    VEC_PUSH(m, n);
}

static void site_set_mnemonic(SiteMap *m, uint64_t pc, const char *mn) {
    SiteEntry *e = site_find(m, pc);
    if (e) { e->mnemonic = mn; return; }
    SiteEntry n = { pc, 0, mn };
    VEC_PUSH(m, n);
}

static bool reg_tainted(const TaintState *st, x86_reg r) {
    int c = taint_canon(r);
    return c >= 0 && st->regs[c];
}

static void reg_set(TaintState *st, int c, bool v) {
    if (c >= 0) st->regs[c] = v;
}

static bool mem_bytes_tainted(const TaintState *st, uint64_t addr, unsigned size) {
    for (unsigned i = 0; i < size; i++)
        if (u64set_has(&st->mem, addr + i)) return true;
    return false;
}

static void taint_mem_bytes(TaintState *st, uint64_t addr, unsigned size, bool t) {
    for (unsigned i = 0; i < size; i++) {
        if (t) u64set_add(&st->mem, addr + i);
        else u64set_del(&st->mem, addr + i);
    }
}

/* Effective address of a MEM operand from live register values.
 * RIP-relative operands ([rip+disp], the usual way to reach globals) resolve
 * against the address of the next instruction, which is what RIP holds when
 * the instruction executes; EIP-relative (addr32) ones are truncated to 32
 * bits.  Segment bases (fs/gs) are not modelled. */
static uint64_t mem_operand_addr(const cs_insn *insn, const x86_op_mem *m,
                                 TaintRegReader rd, void *ctx) {
    uint64_t next_ip = insn->address + insn->size;
    uint64_t addr = (uint64_t)m->disp;
    bool addr32 = false;
    if (m->base == X86_REG_RIP) addr += next_ip;
    else if (m->base == X86_REG_EIP) { addr += next_ip; addr32 = true; }
    else if (m->base != X86_REG_INVALID) addr += rd(ctx, taint_canon(m->base));
    if (m->index != X86_REG_INVALID) addr += rd(ctx, taint_canon(m->index)) * (uint64_t)(int64_t)m->scale;
    return addr32 ? (addr & 0xFFFFFFFFull) : addr;
}

static bool mem_addr_tainted(const TaintState *st, const x86_op_mem *m) {
    if (m->base != X86_REG_INVALID && reg_tainted(st, m->base)) return true;
    if (m->index != X86_REG_INVALID && reg_tainted(st, m->index)) return true;
    return false;
}

void taint_step(TaintState *st, csh cs, const cs_insn *insn, TaintRegReader rd, void *ctx) {
    const char *mn = insn->mnemonic;
    const cs_x86 *x = &insn->detail->x86;
    const cs_x86_op *ops = x->operands;

    /* --- zeroing idioms clear taint: xor r,r / sub r,r ------------------- */
    if ((!strcmp(mn, "xor") || !strcmp(mn, "sub") || !strcmp(mn, "pxor") ||
         !strcmp(mn, "xorps") || !strcmp(mn, "xorpd")) &&
        x->op_count == 2 && ops[0].type == X86_OP_REG && ops[1].type == X86_OP_REG &&
        ops[0].reg == ops[1].reg) {
        reg_set(st, taint_canon(ops[0].reg), false);
        st->regs[TAINT_FLAGS] = false;
        return;
    }

    cs_regs regs_read, regs_write;
    uint8_t nread = 0, nwrite = 0;
    if (cs_regs_access(cs, insn, regs_read, &nread, regs_write, &nwrite) != CS_ERR_OK)
        return;   /* undecodable access info: leave state unchanged */

    /* --- gather source taint ------------------------------------------- */
    bool src_tainted = false;
    bool reads_flags = false;
    for (int i = 0; i < nread; i++) {
        if (reg_tainted(st, regs_read[i])) src_tainted = true;
        if (regs_read[i] == X86_REG_EFLAGS) reads_flags = true;
    }
    bool flags_tainted = st->regs[TAINT_FLAGS];

    for (int i = 0; i < x->op_count; i++) {
        if (ops[i].type != X86_OP_MEM || !(ops[i].access & CS_AC_READ)) continue;
        uint64_t addr = mem_operand_addr(insn, &ops[i].mem, rd, ctx);
        if (mem_addr_tainted(st, &ops[i].mem)) {
            /* secret-dependent *address*: a cache/address side channel */
            site_bump(&st->addr_sites, insn->address);
            src_tainted = true;
        }
        if (mem_bytes_tainted(st, addr, ops[i].size)) src_tainted = true;
    }

    /* --- variable-time instruction consuming a secret -------------------- */
    if (taint_is_variable_time(mn)) {
        /* div/idiv: divisor is the explicit operand; dividend is RDX:RAX */
        if (src_tainted || st->regs[X86_REG_RAX] || st->regs[X86_REG_RDX])
            site_set_mnemonic(&st->timing_sites, insn->address,
                              strcmp(mn, "div") == 0 ? "div" : "idiv");
    }

    /* --- conditional branch on secret flags ------------------------------ */
    if (cs_insn_group(cs, insn, X86_GRP_JUMP) && reads_flags && flags_tainted)
        site_bump(&st->branch_sites, insn->address);

    /* --- propagate to destination registers ----------------------------- */
    for (int i = 0; i < nwrite; i++) {
        x86_reg r = regs_write[i];
        if (r == X86_REG_RIP || r == X86_REG_EIP) continue;
        if (r == X86_REG_EFLAGS) {
            st->regs[TAINT_FLAGS] = src_tainted;
            continue;
        }
        reg_set(st, taint_canon(r), src_tainted);
    }

    /* --- propagate to destination memory -------------------------------- */
    for (int i = 0; i < x->op_count; i++) {
        if (ops[i].type != X86_OP_MEM || !(ops[i].access & CS_AC_WRITE)) continue;
        uint64_t addr = mem_operand_addr(insn, &ops[i].mem, rd, ctx);
        taint_mem_bytes(st, addr, ops[i].size, src_tainted);
    }
}
