# LeakScope

**LeakScope decides whether a compiled x86-64 Linux program's behaviour depends
on a secret** — and when it does, it tells you *where*, *what kind* of leak it
is, and hands you **two secret values that prove it**.

It analyses the binary, not the source, because the compiler is part of the
threat model: source that looks constant-time is routinely turned into leaky
machine code by the optimizer (LeakScope ships a target that demonstrates
exactly this).

```
$ leakscope targets/manifests/01_pw_check_bad.json
======================================================================
LeakScope report: pw_check_bad (secret-dependent branch)
binary: /path/to/targets/manifests/../bin/targets_gcc_O2
verdict: LEAKY   (66 secrets, ~36.2 instr/run)
======================================================================

[1] Secret-dependent branch
    where : pw_check_bad+0x25  (0x401245, file offset 0x401245)
    why   : branch decision depends on the secret
    proof : two secrets that make this channel differ:
            A = {'secret': '0000…0000'}
            B = {'secret': 'ffff…ffff'}
```

---

## What it detects

LeakScope watches the three things a microarchitectural side-channel attacker
can actually observe, plus transient execution:

| Leak kind | What it means | Example target |
|-----------|---------------|----------------|
| **Secret-dependent branch** | control flow changes with the secret (timing, branch predictor) | early-exit password compare |
| **Secret-dependent memory access** | a load/store *address* (cache line) changes with the secret | AES-style T-table lookup |
| **Variable-time instruction** | a data-dependent-latency instruction (`div`/`idiv`) consumes a secret | `secret % n` |
| **Speculative (Spectre-v1)** | a *mispredicted* branch transiently reads and transmits the secret, invisible in any normal run | bounds-check bypass gadget |

For every finding it reports the **instruction address** (and nearest symbol),
the leak **kind**, and a **witness pair** of secrets that makes that channel
diverge. Safe code — even code that *looks* dangerous (branches and table
lookups on public data) — is reported `SAFE`.

## How it works

LeakScope is a **dynamic** analyser written in C11 on top of the Unicorn CPU
emulator and the Capstone disassembler (both used through their native C APIs;
ELF loading and JSON parsing are built in, so there are no other dependencies). The analysis is original; it is not a fork or wrapper of
ctgrind, dudect, Microwalk, Binsec, angr, Spectector, Pitchfork or Teapot.

1. **Emulate, don't execute.** The target's ELF segments are mapped into an
   emulator; the chosen entry function is run to its return with its public and
   secret arguments placed per the System V AMD64 ABI. Nothing from the binary
   runs natively.
2. **Observe three channels per run** (`src/trace.c`): the ordered branch
   decisions, the ordered cache lines touched by loads/stores, and the ordered
   variable-latency instructions with their operand magnitudes.
3. **Differential comparison** (`src/analyze.c`): run many secrets with
   the public inputs held fixed, then look for divergence. A channel that
   differs between two secrets *is* a leak, and those two secrets are the proof.
   Each channel is compared only within the group of runs that agree on the
   previous channel, so a leak is attributed to its **root cause** (an address
   leak is not reported twice as a by-product of a branch leak).
4. **Taint tracking** (`src/taint.c`): a register + memory + flags taint
   engine seeded on the secret finds *candidate* sites — variable-time
   instructions with secret operands, secret-derived addresses, secret-derived
   branches — including ones a given secret pair didn't happen to expose. Taint
   never decides a leak on its own; it only tells the differential engine where
   to look, so over-tainting costs time, never soundness.
5. **Bounded mis-speculation** (`machine_run_speculative` in `src/machine.c`): at each
   conditional branch, LeakScope forces the *mispredicted* path for a bounded
   instruction window and records the cache lines it transiently touches. If two
   secrets that take the **same architectural direction** produce **different**
   transient accesses, that is a Spectre-v1 leak — reported with the branch to
   mispredict and the transmitting load.
6. **Self-verification.** Before reporting, LeakScope replays each finding's two
   witnesses and confirms the named channel really diverges (`verified: true` in
   the JSON). It checks its own proofs.

See [`docs/DESIGN.md`](docs/DESIGN.md) for the full method, the soundness
argument, and the known limitations.

## Install

Dependencies: a C11 compiler, `make`, `pkg-config`, and the Capstone (>= 4)
and Unicorn (>= 2) development packages.

```bash
sudo apt install build-essential pkg-config libcapstone-dev libunicorn-dev   # Debian / Ubuntu
make                     # builds build/leakscope, build/leakscope-bench and the benchmark targets
```

Pure userspace; no root, no kernel modules, no network. Works on any x86-64
Linux distribution that packages Capstone and Unicorn. Tested on Ubuntu 24.04
with both the distribution libraries (Capstone 4.0.2, Unicorn 2.0.1) and newer
ones (Capstone 5.0.7, Unicorn 2.1.4). To build against libraries outside the
pkg-config path, override `DEP_CFLAGS` / `DEP_LIBS` (see the top of the
`Makefile`).

## Build the benchmark targets

```bash
make -C targets          # builds targets/bin/targets_gcc_{O2,O0} and _clang_O2 if clang present
```

## Run it on a target

A *target* is an ELF plus a small JSON manifest that says which entry point to
analyse and which argument is secret (the "short description" the problem
statement says each target ships with). See
[`targets/manifests/`](targets/manifests) for the schema and examples.

```bash
leakscope PATH/TO/manifest.json [--json report.json] [--extra N] [--quiet]
# exit code 0 = SAFE, 1 = LEAKY  (usable as a CI gate), 2 = usage/input error
```

or without installing:

```bash
./build/leakscope targets/manifests/03_sbox_lookup_bad.json
```

## Evidence

Run the whole benchmark against ground truth (`targets/EXPECTATIONS.json`):

```bash
./build/leakscope-bench                                       # gcc -O2 (default)
./build/leakscope-bench --binary targets/bin/targets_gcc_O0
./build/leakscope-bench --binary targets/bin/targets_clang_O2
make bench-all                                                # all three
```

The whole ten-target benchmark runs in well under a second per build.

Unit + end-to-end tests (verdicts, self-verification, no false alarms,
cross-compiler robustness):

```bash
make test
```

The benchmark is ten targets: five leaky patterns (one per leak kind, plus a
compiler-introduced one), four safe counterparts, and one "suspicious but safe"
decoy. Every leaky verdict comes with a verified witness pair; every safe target
produces zero findings.

## Install as a command

```bash
sudo make install       # installs `leakscope` to /usr/local/bin (PREFIX=... to change)
```

## Limitations (honest scope)

LeakScope is a dynamic analyser: it reasons about the paths its secret samples
drive. It finds a leak whenever a sampled pair exposes it (and the taint engine
widens that reach to variable-time and speculative candidates), but it does not
claim a *proof of absence* for untested paths — `SAFE` means "no secret
dependence observed across a diverse, taint-guided sample set." The speculative
model explores a bounded window past branch mispredictions; it does not model
store-to-load forwarding or every predictor. These boundaries, and why they are
the right trade-off for a fast, offline, no-false-alarm tool, are discussed in
[`docs/DESIGN.md`](docs/DESIGN.md).

## Demo

A 5-minute walkthrough is in [`DEMO.md`](DEMO.md) (script + commands).

## Layout

```
src/            analyser (util, json, elfload, target, trace, taint, machine,
                analyze, report, cli; main.c is the `leakscope` entry point)
tools/bench.c   benchmark runner (`leakscope-bench`)
tests/          test suite (test_leakscope.c)
targets/        benchmark C sources, Makefile, manifests, ground-truth
docs/DESIGN.md  method, soundness argument, limitations
```

## License

MIT — see [LICENSE](LICENSE).
