# Repository Guidelines

永远不要使用git checkout, 只能使用git stash作为替代

如果grep报错"指定了互相冲突的匹配器"，那是因为在 zcode 里 `grep` 是一个被重定义过的函数，与标准 GNU grep 行为不同。这时候需要 grep 时改用 `command grep ...`、`/usr/bin/grep ...`，或优先使用专门的搜索工具(rg)。

## Project Structure & Module Organization
- `main.cpp`: VM entry point, command-line parsing, signal setup.
- `insn.h`: core VM class (`vm`), abstract `SyscallHandler` interface, TLB, and instruction definitions.
- `insn.cpp`: BPF instruction execution (interpreter loop with JIT fallback).
- `elf_loader.h`, `elf_loader.cpp`: BPF ELF loading and library search (shared by `bpfvm` runtime and `bpfvm-ld`); runtime `.rela.dyn`/`.rela.plt` processing and PIE address allocation.
- `elf_linker.h`, `elf_linker.cpp`: offline BPF linker core (static / shared / dynamic modes); segment layout, relocations, PLT/GOT synthesis.
- `ld_main.cpp`: `bpfvm-ld` CLI (argument parsing, `-l`/`-L` resolution, mode dispatch).
- `posix_syscall.h`, `posix_syscall.cpp`: full POSIX syscall implementation (`PosixSyscall` class), fd management, signal queue, process control.
- `empty_syscall.h`: stub syscall handler (`EmptySyscall`) returning `-ENOSYS`, used for testing.
- `insn_test.cpp`: unit tests for instruction execution, built into `bpfvm_test`.
- `jit/`: JIT subsystem (compilers + architecture-specific emitters), compiled into `bpfvm_lib`.
    - `jit.h`: shared JIT data structures and type aliases.
    - `jit_compiler.h`, `jit_compiler.cpp`: architecture-independent JIT compiler template and implementation.
    - `jit_base_emitter.h`: architecture-independent code emission base class.
    - `x86_emitter.h`, `x86_emitter.cpp`: x86_64 JIT code emitter.
    - `aarch64_emitter.h`, `aarch64_emitter.cpp`: AArch64 JIT code emitter.
- `include/`: BPF-facing headers (syscall IDs, POSIX types) used by guest programs.
- `cmake/`: CMake helper scripts (e.g., `RunBpfProgram.cmake` for CTest integration).
- `passes/`: LLVM pass plugins (compiled into `build/lib*.so`, loaded by `clang -fpass-plugin=...`).
    - `BpfWideArgs.cpp`: lifts the BPF limit (5-arg, struct return, variadic, by-value aggregate params) + `BpfByvalTmpPass` (≤16B by-value double-free fix) + `BpfAtomicLowerPass` (lowers plain atomic load/store + deletes `atomic_thread_fence` — eBPF ISA only has RMW atomics, no fence instruction; `AtomicFence` makes ISel abort with "Cannot select"; unlocks static guards in locale/iostream). See the ABI workarounds section (函数调用约定突破) in README.
    - `BpfSoftFp.cpp`: rewrites floating-point IR into soft-float library calls, enabling `float`/`double` support. See the floating-point support section in README.
    - `BpfEmutls.cpp`: emulated TLS via `annotate("emutls")`. See the emulated TLS (emutls) section in README.
    - `BpfLibcallLower.cpp`: lowers memcpy/memmove/memset/trap + floor/ceil/trunc/round intrinsics into musl calls.
- `musl/`: default C library for BPF targets (musl 1.2.6 port); built via `sh musl/build.sh` → installs to `root/{include,lib}`. Porting internals in the musl porting section of README.
- `dash/`: shell sources for the BPF cross-build.
- `root/`: unified install root for the C/C++ toolchain + rootfs. `root/include` (musl headers + C++ headers in `c++/v1/`), `root/lib` (`libc.a`/`libc.so`/`ld-bpf.so`/`libcxx.a`/`libcxx.so`/`libcrypto.{a,so}`/`libssl.{a,so}`/...), `root/bin` (dash/busybox/openssl). Built by `./scripts/build_root.sh [components...]`.
- `test/`: small BPF test programs (`.c`) and expected outputs (`.out`), built via a local Makefile.
- `build/`: local build outputs (CMake and cross-build artifacts).
- `patches/`: out-of-tree patches for upstream dependencies this repo needs but cannot fix in-tree (e.g. `gdb-bpf-ptr-bit.patch` — see "Known GDB bugs" below). `patches/README.md` has per-patch usage + build instructions.

## Build, Test, and Development Commands
- `cmake -S . -B build && cmake --build build` — configure and build `bpfvm` and `bpfvm_test`.
- `./build/bpfvm <elf-file>` — run the VM on a BPF ELF file.
- `./build/bpfvm_test` — run the unit test executable (see `insn_test.cpp`).
- `cd build && ctest -j4` — run CTest with parallel jobs; tests are independent, so always pass `-j4` to run them concurrently instead of serially.
- `make -C test` — build BPF test programs into `.out` files using `clang` and `bpfvm-ld`.
- `./scripts/build_root.sh` — build base rootfs (musl libc + libcxx + busybox) into `root/`. Optional extra components via args: `./scripts/build_root.sh [dash sbase openssl ...]` (requires `clang`, `gcc`, and `libelf`).
- Disassemble BPF ELF binaries with `bpf-objdump` (from `binutils-bpf`), e.g. `bpf-objdump -d foo.out`. Prefer it over plain `objdump`, which does not understand the BPF target.

## Coding Style & Naming Conventions
- C++20 (`CMAKE_CXX_STANDARD 20`); keep code compatible with `clang`.
- Indentation: 4 spaces; braces on the same line as control statements/functions.
- Names: types use `CamelCase` or existing patterns (e.g., `vmOptions`), functions/variables use `lower_snake_case`, macros/constants use `UPPER_SNAKE_CASE`.
- Keep includes grouped: standard headers, then project headers.
- No numbered lists in comments (`1)`, `2)`, `a)`, or `5b`-style inserted items): inserting/removing an entry would force renumbering everything after it. Use dashes or descriptive headers instead.
- Keep comments concise and current-state only: no restating what the code plainly says, no redundancy, and no history ("previously…", "same as the old X", "moved from Y"). Describe what the code is, not what it was.
- Comments use ASCII and Chinese characters only: no other Unicode symbols (→, ≠, ×, ①, emoji, …) — they may render as garbage or blanks on some terminals/fonts and break greppability. Use plain ASCII equivalents (`->`, `!=`, `*`, `...`) instead. Exception: box-drawing characters (`─ │ ┌ ┐ └ ┘ ├ ┤ ┬ ┴ ┼ ═ ...`) may be used to draw diagrams and tables in comments.

## Testing Guidelines
- Unit tests live in `insn_test.cpp` and are built into `bpfvm_test`.
- BPF test programs live in `test/` and produce `.out` binaries; keep filenames aligned (`test_foo.c` -> `test_foo.out`).
- No coverage requirement is defined; add focused tests for new VM instructions or syscalls.

### CTest Cases
CMake registers the following CTest cases under the `BUILD_TESTING` option (run with `cd build && ctest`):

1. **`unit_tests`** — Runs the `bpfvm_test` executable (instruction-level unit tests from `insn_test.cpp`).
2. **`bpf_programs_build`** — Invokes `make -C test` to compile all BPF test programs (`test/*.c` → `test/*.out`). Marked as a fixture (`FIXTURES_SETUP bpf_programs_built`); all subsequent BPF program tests depend on it automatically.
3. **`test_*` series** — Auto-discovered from `test/test_*.c` files. Each test case runs the program through the `cmake/RunBpfProgram.cmake` runner in several variants (defined there) and checks the exit code against the expected value (default 0). Helper programs listed in `BPF_TEST_HELPERS` (e.g., `test_arg`, `test_cloexec_child`) are skipped and get no standalone entry. Members of `BPF_ROOT_TESTS` get an extra `<name>_chroot` entry (temp rootfs + `--root`); a test whose assertions require chroot (e.g., `test_root`) is listed in both so `_chroot` is its only entry.

**Adding a new BPF test case:** Simply create a `test/test_<name>.c` file; CTest will auto-discover and register it. If the program is a helper (invoked by other tests rather than run independently), add it to the `BPF_TEST_HELPERS` list in `CMakeLists.txt`. If it also needs a chroot (`--root`) variant, add it to `BPF_ROOT_TESTS`.

## JIT Compilation & Execution Model

The VM uses a hybrid interpreter/JIT execution model:
- **JIT-first**: hot functions are compiled to native code via `JitCompiler<EmitterT>`, with architecture-specific emitters for x86_64 and AArch64.
- **Interpreter fallback**: single-step execution or JIT errors fall back to the interpreter loop in `insn.cpp`.
- **TLB acceleration**: a software TLB caches guest-to-host address translations; misses go through `mmu_slow()` / `mmu_w_slow()`.
- **CoW support**: memory mappings support copy-on-write semantics (for `fork`); write faults trigger segment duplication.
- **Signal-aware frames**: normal call frames are 64 bytes; signal frames are 128 bytes with additional saved state.

### JIT Environment Variables
- `JIT_ENABLE`: set to `0` to disable JIT and force interpreter-only execution; defaults to enabled (any other value or unset enables JIT).
- `JIT_THRESHOLD`: hot-pc detection threshold (default `100`; `0` disables it, compiling every pc as before). A guest pc must be reached this many times (counted in `compile()`, which `step()` single-stepping and JIT `helper_call_bpf` both drive) before it is JIT-compiled. Loop back-edge targets reach the threshold quickly and get compiled at the loop header — an implicit OSR (the JIT prologue loads `vm->reg[]`, so it can enter at any pc and the interpreter's current state is preserved); cold pcs never reach it and stay in the interpreter, so compile time is not wasted on template-bloat cold code. The threshold trades OSR latency against compile savings: compute-bound programs (large loops) OSR after `threshold` iterations, so `test_compute` is unchanged; `test_stl_filesystem`-style programs (many cold functions) speed up ~25×. Higher values slow OSR (e.g. `test_compute` 0.16s at 100 → 1.0s at 2000).
- `BPF_DEBUG`: set to any value to print VM execution statistics (instruction counts, JIT compilation info, timing) to stderr at VM exit. Also enables instruction counting in JIT-compiled code.

### Instruction Budget
- The `--insn-limit N` (`-l N`) command-line option sets an upper bound on the total number of instructions the VM may execute (interpreter + JIT combined). When the limit is reached, the VM sets the `VM_BUDGET_EXCEEDED` flag, prints a diagnostic to stderr, and exits with code 255.
- In JIT code, the budget check is embedded in loop-header safepoints; the loop body size is estimated during compilation and added to `insn_count` at each back-edge.

## Syscall Implementation & C Library Wrappers
- Syscall handling is decoupled from the VM via the abstract `SyscallHandler` interface (defined in `insn.h`), with `PosixSyscall` (`posix_syscall.cpp`) as the main implementation and `EmptySyscall` (`empty_syscall.h`) as a stub for testing.
- Syscall IDs are defined in `include/bpf_syscall.h` and encoded via `BPF_CALL_BASE` / `BPF_CALL_ID()`; the VM dispatches them through the `SyscallHandler::syscall()` virtual method.
- The VM reads syscall arguments from registers (`r(1)`..`r(5)`), translates guest pointers with `mmu()`, and returns results in `r(0)`; errors are negative `errno` values.
- Signal handling uses a lock-free multi-producer-single-consumer queue (`MpscQueue`) in `PosixSyscall`, with support for `SIGKILL`/`SIGSTOP`/`SIGCONT` bypassing the queue via direct flags.
- C library wrappers (default musl) live in `musl/arch/bpf/syscall_arch.h` and the musl `src/` tree, mapping POSIX functions (`open`, `read`, `mmap`, `fork`, etc.) to `BPF_CALL_*` IDs. 
- The low-level `syscall()` path dispatches by casting the call ID to a function pointer with 0–5 args, so the VM sees a direct call to `BPF_CALL_*`.

## Commit & Pull Request Guidelines
- Commit messages are short and action-oriented; recent history uses concise Chinese phrases (e.g., “实现dup2”).
- Keep commits scoped to one change set and mention user-visible behavior when applicable.
- PRs should include a brief description, how you tested (commands + results), and links to relevant issues. Screenshots are only needed for UI changes (rare here).

## Configuration & Dependencies
- Requires `libelf` via `pkg-config` for the VM build.
- BPF toolchain: `clang` (>= 19) compiles `.c` → `.o`; `bpfvm-ld` (built from `src/ld_main.cpp`) links `.o` + archives into self-contained ET_EXEC or PIE ET_DYN; `bpfvm` runs the result. No `binutils-bpf` or `bpf-ld`.
- `bpfvm-ld` linking modes (static / shared / dynamic), DWARF debug-info preservation & strip, symbol-table generation: see the toolchain / bpfvm-ld section in README.

## Pass Rebuild (mandatory after editing a pass)
**Neither musl nor busybox tracks the timestamps of `libBpfWideArgs.so`/`libBpfSoftFp.so`/`libBpfEmutls.so` etc.** — they only look at `.c` source mtimes. After modifying any pass you must force a full rebuild, otherwise stale `.o` compiled with the old pass are reused:
- musl: `rm -rf musl/build`
- busybox: `find busybox/ -name *.o -delete`
they can all be rebuilt by `scripts/build_root.sh`.

## Build & CTest troubleshooting (stale artifacts after toolchain/env change)
Stale binaries compiled by a previous (newer) toolchain keep higher `GLIBC_*`/`GLIBCXX_*` version requirements and fail at load time with errors like `version 'GLIBC_2.38' not found` or `GLIBCXX_3.4.32 not found`. CMake/Make incremental builds only check source mtimes, so these stale artifacts are reused as-is when sources haven't changed. Two flavors:
- **`unit_tests` / `bpfvm`-built binaries (`build/`)** — caused by stale `.o` linked against a newer libstdc++/glibc. Fix: reconfigure so CMake re-runs compiler detection and rebuilds everything: `cmake -S . -B build && cmake --build build` (or `rm -rf build && cmake -S . -B build && cmake --build build` for a fully clean rebuild).
- **`*.host` variants under `test/`** — the CTest `host` variant runs native binaries (`test/*.host`) compiled by the Makefile with `HOST_CC := clang`. These are not rebuilt when their `.c`/`.cpp` sources are unchanged. Fix: `make -C test clean` then rebuild (the `bpf_programs_build` fixture rebuilds them on next `ctest`).
- **pass-plugin errors (`libBpf*.so`: missing headers / not found / stale)** — the pass `.so` is built into `build/` and loaded via `-fpass-plugin=`. If a pass fails to build or load, a plain reconfigure rebuilds it: `cmake -S . -B build` (re-runs CMake, regenerates the pass targets) then `cmake --build build`. No need to delete `build/`.

## BPF Architecture Constraints (summary + pointers)
The BPF backend has three hard limits that this repo lifts transparently at compile time via LLVM passes — **write guest code as standard C/C++, no manual rewriting needed**. For the full three-layer mechanism (pass / linker / VM execution), see the 架构设计与实现 (architecture & implementation) section of README:

1. **Floating point**: BPF has no hardware FPU. The `BpfSoftFp` pass rewrites FP IR into virtual instructions (`src_reg=2` channel); the VM/JIT runs them on the host's hardware FP. `long double == double` (64-bit). See the floating-point support section in README.
2. **Args / return values**: the native ABI limits to 5 args and disallows struct returns. The `BpfWideArgs` pass lifts this (incl. by-value aggregate params, variadic functions). See the ABI workarounds section in README.
3. **C++**: a language subset + libc++ STL (`-fno-exceptions -frtti`), incl. emutls, global ctors/dtors. See the C++ support section in README.

## Known upstream toolchain bugs (workarounds in this repo)
The BPF toolchain (LLVM/clang, binutils, gdb) has several upstream defects that this repo works around. For each: symptom → root cause → workaround → upstream issue, grouped by component. Other sections reference this one rather than repeating the details. (The 5-arg / no-FP / no-varargs limits in §BPF Architecture Constraints are by-design architecture constraints, not bugs.)

### LLVM BPF backend

- **Conditional branch into a zero-instruction successor → silent miscompile.** A conditional branch whose target lowers to zero instructions (an `unreachable` block, or a `barrier()`-only MBB that `MachineBlockPlacement` tail-duplicates with no terminator) gets an offset computed against that empty block's address, so it lands past the function end (or on the preceding instruction). Triggers in a ~13-instruction function; reproduces on clang 19/21/23 trunk; distinct from the 16-bit-offset overflow issues (#48509 etc.). **Hit by**: busybox `ash.c` `ash_main` (inlines `INT_ON`; the miscompiled branch forms an `exitreset`↔`INT_ON` loop → Ctrl+C exits the shell instead of returning to the prompt). **Workaround**: `scripts/build_busybox.sh` marks `popstackmark` `__attribute__((noinline))` (idempotent `perl` patch) so the trailing-barrier block is not inlined. **Upstream**: [#208984](https://github.com/llvm/llvm-project/issues/208984).

- **`-g` mangles member-function `declare`: `this` promoted to value, aggregate params lost ([#208141](https://github.com/llvm/llvm-project/issues/208141)).** With debug info, clang rewrites the `declare` of certain member functions so the `this` pointer becomes a value type and later by-value aggregate parameters disappear from the declaration, while the `call` keeps the right arg count → declare/call mismatch (clang 19/20 miscompile, 21/22 crash). Manifests on libc++ `<filesystem>` (`path::__compare(string_view)`). **Status**: no workaround in this repo currently needed — `test/test_stl_filesystem.cpp` compiles cleanly on clang 19 with `-g` (the trigger path is narrow); revisit if the test starts hitting the miscompiled `path` comparison. **Upstream**: [#208141](https://github.com/llvm/llvm-project/issues/208141), OPEN.

- **≤16B by-value non-trivially-destructible parameter double-free ([#207686](https://github.com/llvm/llvm-project/issues/207686)).** The BPF backend lowers a non-trivially-destructible by-value parameter that fits in 1–2 registers (≤16B) directly to `i64` (e.g. `std::unique_ptr`, 8B) or `[2 x i64]` (e.g. `std::shared_ptr`, 16B), bypassing byval/`ptr` invisible-reference. clang's caller still emits a backup temporary per the Itanium C++ ABI and destroys it after the call, but the callee (receiving the value, not a pointer) can't null the temp → double-free. Silent. (The original #207686 scope "≤8B only, shared_ptr 16B goes through byval/ptr" is wrong — verified by cross-version IR comparison clang 19/21/23 + end-to-end crash in `bpfvm-on-bpfvm`; see `test/test_sp_byvalue.cpp`.) **Workaround**: `BpfByvalTmpPass` in `src/passes/BpfWideArgs.cpp` inserts `store null/zeroinitializer, %tmp` before the destructor of identified backup temporaries. Runs at **two** EPs: (1) `PipelineStartEP` (right after `BpfWideArgsPass`) catches the call-form move-construct (`T::T(ptr %tmp, ptr %src)`, mangling `C1`/`C2` + `OS_`) — must run **before** `-O1` so the optimizer can't fold the backup temporary with its source and emit the wrong `atomicrmw -1` on the original control block; covers ≤16B (both unique_ptr and shared_ptr). (2) `OptimizerLastEP` as a fallback using the original baseline heuristic (size ≤8 + hasLoad + C++ dtor/reset call shape) for the case where `-O1` has inlined the move-construct into a store so no call-form move-ctor remains (16B shared_ptr is gone entirely by then, so this path only handles 8B unique_ptr). Detailed mechanism in the pass comments. **Upstream**: [#207686](https://github.com/llvm/llvm-project/issues/207686), OPEN (scope-correction comment posted).

- **`-target bpf -g` SIGSEGV in `CGDebugInfo::EmitFunctionDecl` ([#213714](https://github.com/llvm/llvm-project/issues/213714)).** With debug info, at `ActOnEndOfTranslationUnit` clang walks external function declarations it didn't codegen and builds their debug info; for some declaration shapes the BPF path segfaults creating the parameter `DILocalVariable` (`EmitFunctionDecl` → `DIBuilder::createParameterVariable` → `DILocalVariable::getImpl` → `MetadataTracking::track`, exit code 139). BPF-specific (same source + `--target=x86_64-linux-gnu -g` is fine); independent of any pass plugin (`-target bpf -g` alone reproduces). Only a minority of source files contain a triggering declaration, so under `make -j` it surfaces as sporadic single-file crashes. Reproduces on clang 19.1.7 / 21.1.8 / 23 trunk `cd3bfc1f9926` — **not fixed** as of clang 23 (one OpenSSL file, `encoder_lib.c`, incidentally stopped crashing on 21/23, but `rsa_sig.c` crashes consistently across all three; do not infer a fix from a single sample). **Hit by**: OpenSSL `crypto/encode_decode/encoder_lib.c`, `providers/implementations/signature/rsa_sig.c`, `providers/implementations/ciphers/cipher_aes.c`, etc. (≈6% of OpenSSL `.c` files). **Workaround**: the `build_openssl` function in `scripts/build_root.sh` strips `-g`/`-fstack-size-section` from `COMMON_CFLAGS` for the OpenSSL build (`${COMMON_CFLAGS//-g/}`) — the lost DWARF is acceptable (we don't debug OpenSSL internals). This is BPF-wide, not OpenSSL-specific; any large C codebase compiled with `-target bpf -g` may hit it. **Upstream**: [#213714](https://github.com/llvm/llvm-project/issues/213714), OPEN.

### binutils

- **`binutils-bpf` `bpf-ld` `.rodata.str1.1` merge bug (Debian [#1126689](https://bugs.debian.org/1126689)).** The historical `bpf-ld` mis-merged `.rodata.str1.1`, corrupting string constants. **Workaround**: this project ships its own linker `bpfvm-ld` (see above), fully replacing `bpf-ld`; the bug is no longer reachable. No source-level patch needed.

### gdb

- **GDB BPF target crashes on `info registers` after `backtrace` (missing `set_gdbarch_ptr_bit`).** `gdb/bpf-tdep.c`'s `bpf_gdbarch_init` never sets `ptr_bit`/`long_bit`/`int_bit` (every other target does). With `ptr_bit` defaulting to 32, `bpf_register_type` returns `builtin_data_ptr`/`builtin_func_ptr` (4 bytes) for r10/pc, so `sizeof_register[r10] == sizeof_register[pc] == 4` and the `g` packet lays them out as 4 bytes each. Frame unwinders, however, read SP/PC with an 8-byte buffer; the first `raw_read(r10)` after a `backtrace` trips the assertion `dst.size () == m_descr->sizeof_register[regnum]` in `regcache.c`. Reproduces on gdb 16.3 (Debian `gdb-multiarch` 16.3-1) and HEAD (commit 1fba9bb3, 2026-07-25) — never fixed upstream. BPF is a 64-bit ISA (r0..r10 all 64-bit), so the settings are simply missing. The `Target-supplied registers are not supported by the current architecture` warning means a target description cannot paper over this — the fix must be in `bpf-tdep.c`, and `bpfvm`'s GDB server (`src/gdb_server.cpp`) cannot work around it on its own. **Workaround**: build a patched GDB from upstream 16.3 with `patches/gdb-bpf-ptr-bit.patch` (adds `set_gdbarch_short/int/long/long_long/ptr/addr_bit`), then use that GDB against `bpfvm --gdb`. `bpfvm`'s `g` packet is laid out for the patched layout (r0..r10 + pc, all 8 bytes = 96 bytes) and so requires the patched GDB — an unpatched `gdb-multiarch` will reject it (`g packet reply too long: expected 88, got 96`). On an unpatched GDB the only way to avoid the crash is to not run a bare `info registers` after `bt` (use `info registers r0 .. r9` / `print $reg`, which don't trigger the 8-byte SP read). **Upstream**: [#34435](https://sourceware.org/bugzilla/show_bug.cgi?id=34435)

- **GDB BPF target rejects `catch syscall` + crashes on NULL syscall XML.** `bpf_gdbarch_init` never registers `get_syscall_number`, so `gdbarch_get_syscall_number_p()` is false and `catch_syscall_command` (break-catch-syscall.c) refuses with `The feature 'catch syscall' is not supported on this architecture yet` *before* consulting the remote stub — even though bpfvm's `--gdb` server advertises `QCatchSyscalls+` and emits `syscall_entry`/`syscall_return` stop reasons. On the remote path GDB takes the syscall number from the stop reply, not from this hook, so the hook is only needed to flip the feature gate. Enabling the hook alone then trips a second bug: with a NULL `xml_syscall_file`, `xml_fetch_content_from_file` opens the datadir as a file, `ftell` returns a bogus length, and GDB aborts `catch syscall` with `std::length_error: cannot create std::vector larger than max_size`. **Workaround**: the same `patches/gdb-bpf-ptr-bit.patch` also adds `bpf_get_syscall_number` (a placeholder reading r1) and sets `set_gdbarch_xml_syscall_file(gdbarch, "bpf-linux.xml")` (a nonexistent name so `gdb_fopen` fails cleanly — BPF uses its own `BPF_CALL_*` ID scheme, not Linux numbers, so no upstream XML applies). With the patched GDB, `catch syscall` / `catch syscall <N>` work against `bpfvm --gdb`; `N` is `BPF_CALL_TO_ID(call)` (e.g. `BPF_SYS_clock_gettime` = 38 = 0x26).


