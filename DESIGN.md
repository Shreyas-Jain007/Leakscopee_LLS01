# LeakScope — design, soundness, and limitations

## The threat model

An attacker who cannot read the program's memory can still recover a secret by
measuring *microarchitectural* side effects of the program running on that
secret:

* **time** — total runtime, dominated by how many instructions ran and which;
* **the branch predictor** — which way conditional branches went;
* **the cache** — which memory addresses (cache lines) were touched;
* **instruction latency** — some instructions (notably `div`/`idiv`) take a
  data-dependent number of cycles;
* **transient execution** — the CPU speculatively runs instructions past a
  mispredicted branch and, although it rolls back the architectural state, the
  cache footprint of that transient work survives (Spectre).

A program is *constant-time* (leak-free) with respect to a secret if none of
those observable effects depend on the secret. LeakScope's job is to decide that
property for a compiled binary and, when it fails, to localise and prove the
leak.

## Why observe the binary, not the source

The compiler is inside the threat model. An optimizer can:

* turn a branchless constant-time idiom into a conditional branch (our
  `spectre_masked_src` target: a source-level pointer mask becomes a
  secret-dependent transient access at `gcc -O2`, but stays safe at `clang -O2`
  and `gcc -O0`);
* pick a secret-dependent "fast path" (our `mod_bad` target under clang: an
  `or`/`shr 32`/`je` sequence chooses a 32-bit vs 64-bit `div` based on the
  magnitude of the secret dividend — a branch leak the source never wrote).

So the artifact that must be checked is the machine code that will actually run.

## The three architectural channels

For one concrete execution on one concrete secret, `src/trace.c` records:

* `branches` — `(pc, taken)` for every conditional branch, in order;
* `mem` — `(pc, cache_line, is_write)` for every load/store, in order, where
  `cache_line = address >> 6` (64-byte lines);
* `timing` — `(pc, mnemonic, operand_magnitude)` for every variable-latency
  instruction.

Each channel has an order-sensitive fingerprint. Two executions whose
fingerprints match on a channel are indistinguishable to an attacker on that
channel.

## Differential analysis: proof by construction

The core engine (`src/analyze.c`) runs the function on a diverse set of
secrets — structured (all-zeros, all-ones, single hot byte at each position,
boundary integers) and random — with **public inputs held fixed**. Then:

* **Branch channel.** If two secrets produce different branch fingerprints, the
  first differing branch is a *secret-dependent branch*. The two secrets are the
  witness.
* **Address channel.** Comparisons are made **only within a group of secrets
  that share the same branch fingerprint**, so an address difference is genuine
  data-dependent addressing, not a downstream effect of having taken a different
  path. The first differing access is a *secret-dependent memory access*.
* **Timing channel.** Compared **only within a group that shares both branch and
  address fingerprints**, isolating a pure latency leak. In addition the taint
  engine flags any `div`/`idiv` with a secret-tainted operand and the engine
  searches for a witness pair whose operand magnitude class differs.

This layering is what lets LeakScope attribute a leak to its *root cause* instead
of reporting one leak several times.

Because every reported leak is backed by two concrete secrets that demonstrably
diverge, **the false-positive rate of the architectural channels is driven to
zero by construction**: a finding that could not be reproduced by its own
witnesses is never emitted (and `verify()` in `src/analyze.c` re-checks exactly this).

## Taint tracking

`src/taint.c` is a forward taint engine over registers, memory bytes and
the flags register, seeded on the secret inputs at entry and propagated with a
conservative "any tainted source taints every destination" rule decoded from
Capstone operand metadata (with the standard `xor r,r` / `sub r,r` zeroing idiom
recognised). Memory-operand addresses are computed from live register values,
with RIP-relative operands (`[rip+disp]`, how position-independent code reaches
globals) resolved against the next instruction's address, so secrets passed
through global variables keep their taint. It exists to *find candidate sites* — especially variable-time
instructions and speculative gadgets that a particular secret pair might not
expose — and to attribute a leak to specific secret bytes. It never decides a
leak alone, so conservative over-tainting only widens the search; it cannot
create a false positive, because the differential engine still has to produce a
witness.

## Speculative (Spectre-v1) analysis

A Spectre-v1 gadget leaks *only* under misprediction, so it is invisible to any
architectural trace. `machine_run_speculative` (`src/machine.c`) models it directly:

1. run to the conditional branch;
2. learn the architectural direction by single-stepping the branch;
3. restart and force the **opposite** (mispredicted) direction;
4. execute a bounded window of instructions, recording the cache lines touched
   by transient loads.

A branch is reported as a speculative leak when two secrets that take the **same
architectural direction** (so the difference is purely speculative, not an
ordinary branch leak) produce **different** transient access lines. The report
names the branch to mispredict and the transmitting load — the "mispredictions
that trigger it" the problem statement asks for.

The window bound models the finite reorder buffer. The model deliberately flips
only control-flow speculation (the v1 case); it does not model store-to-load
forwarding (v4) or address speculation, which is noted below.

## Soundness and limitations

LeakScope is a **dynamic** analyser. Its guarantees:

* **Soundness of findings (no false alarms).** Every architectural finding has a
  reproduced witness pair; safe code, including code that merely *looks*
  suspicious, yields no findings. This is the property the benchmark's four safe
  targets and the "suspicious but safe" decoy check.
* **Completeness is bounded by coverage.** A leak is found when some sampled
  secret pair exposes it, widened by taint-guided candidate search. `SAFE`
  therefore means "no secret dependence observed across a diverse, taint-guided
  sample set," not a formal proof over all inputs and paths. For code with
  input-dependent path explosion, increase `--extra` or supply targeted public
  inputs via the manifest.
* **Speculative scope.** Bounded-window control-flow misprediction only; no v4 /
  store-forwarding, no modelling of a specific predictor's training.
* **Environment.** User-space x86-64 leaf-style entry points; the emulator maps
  the target's own segments and runs the entry function to return. Calls into
  uninstrumented external libraries are out of scope (compile targets so the
  analysed region is self-contained, as the benchmark does).

These are the right trade-offs for a tool that must be **fast, fully offline, and
free of false alarms**: it gives precise, proven, localised findings across
compilers and optimization levels in well under a second per target, rather than
a slower-or-unsound whole-program proof.

## A note on "go further": repair

The architecture makes binary repair a natural extension: a secret-dependent
`div` can be replaced by a constant-time reduction, a secret-indexed table read
by an oblivious full-table scan, and a Spectre gadget hardened by inserting a
speculation barrier after the guard. LeakScope already pinpoints the exact
instruction for each, which is the information a rewriter needs; wiring a patcher
onto the finding addresses is future work.
