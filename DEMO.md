# LeakScope — 5-minute demo script

Record this with any screen recorder (e.g. `asciinema`, OBS).

### 0:00 — Setup (20s)
```bash
sudo apt install libcapstone-dev libunicorn-dev
make                       # build leakscope + the benchmark across gcc -O2/-O0 (+ clang)
```
Say: *"LeakScope analyses a compiled binary and decides whether its behaviour
depends on a secret. No source, no running the target natively."*

### 0:30 — A branch leak, proven (50s)
```bash
./build/leakscope targets/manifests/01_pw_check_bad.json
```
Point out: verdict `LEAKY`, the exact address (`pw_check_bad+0x25`), the kind
(secret-dependent branch), and the **two secrets** that prove it. Show the source
(`targets/src/targets.c`, `pw_check_bad`) — the early-exit compare.

### 1:20 — An address (cache) leak and a timing leak (50s)
```bash
./build/leakscope targets/manifests/03_sbox_lookup_bad.json   # T-table cache leak
./build/leakscope targets/manifests/05_mod_bad.json           # variable-time div
```
Note the address leak points at the exact `movzbl (table,key)` load, and the
timing leak at the `div`.

### 2:10 — The speculative (Spectre-v1) leak (60s)
```bash
./build/leakscope targets/manifests/07_spectre_gadget.json
```
Stress: architecturally the bounds check is never taken — nothing secret is
touched in a normal run (`~4 instr/run`), yet LeakScope reports the leak, names
the **branch to mispredict** and the **transmitting load**. This is the leak that
"never shows up in a normal run."

### 3:10 — No false alarms (40s)
```bash
./build/leakscope targets/manifests/02_ct_eq.json          # constant-time compare
./build/leakscope targets/manifests/09_public_branch.json  # branches+tables on PUBLIC data
```
Both `SAFE`. Emphasise `09` *looks* dangerous (it has branches and a table
lookup) but every one is driven by public data.

### 3:50 — The compiler is the enemy (50s)
```bash
./build/leakscope-bench --binary targets/bin/targets_gcc_O2   | tail -3
./build/leakscope-bench --binary targets/bin/targets_clang_O2 | tail -3
```
Show `spectre_masked_src`: the *same source* is `LEAKY` at `gcc -O2` (the
optimizer rewrote a mask into a gadget) and `SAFE` at `clang -O2`. And clang's
`mod_bad` gains an extra secret-dependent branch from its div fast-path. This is
why you must check the binary.

### 4:40 — Evidence (20s)
```bash
make test
```
57 passing tests: every verdict, every finding self-verified by replaying its
own witnesses, no false alarms, cross-compiler robustness.

Close: *"Every leak comes with an address, a kind, and a proof. That's
LeakScope."*
