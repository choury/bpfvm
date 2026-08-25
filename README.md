# bpfvm - 用户态 BPF 虚拟机

`bpfvm` 是一个基于 C++20 实现的 BPF (eBPF) 虚拟机，旨在在用户态加载并运行 BPF ELF 二进制文件。

与内核中的 BPF 运行时不同，本项目致力于提供一个类似 POSIX 的运行环境，通过集成 [musl](https://musl.libc.org/) libc，并模拟常见的系统调用 (syscalls)，使得标准的 C/C++ 程序（如 `dash` shell 和 `busybox` 工具集）能够通过交叉编译运行在此虚拟机上。

## 核心特性

*   **ELF 加载器**: 解析并加载标准 BPF ELF 可执行文件（支持静态链接与动态链接 PIE）。
*   **JIT 加速**: 混合解释器/JIT 执行模型，热函数编译为 x86_64 / AArch64 原生代码，配合软件 TLB 加速地址翻译。
*   **指令集支持**: 实现核心 eBPF 指令集解释执行。
*   **浮点支持**: 通过 `BpfSoftFp` LLVM pass 提供 `float`/`double` 支持（算术、类型转换、比较）。
*   **系统调用模拟**: 通过可插拔的 `SyscallHandler` 接口实现了 `open`, `read`, `write`, `fork`, `execve` 等核心 POSIX 系统调用，支持文件系统操作和进程控制。
*   **标准库支持**: 深度集成了 musl（默认）作为 C 库，并提供 libc++ 支持 C++ STL。
*   **信号支持**: 支持信号处理（`SIGKILL`/`SIGSTOP`/`SIGCONT` 等），使用无锁队列实现信号传递，支持信号打断系统调用。
*   **内存安全**: 提供内存越界检查机制。
*   **实际应用支持**: 能够运行 `dash` (Debian Almquist Shell) 和 `busybox` (coreutils) 等复杂程序。
*   **Demo Rootfs**: 提供脚本一键构建 `dash + busybox` 的最小 rootfs，并安装到 `root/`。

## 构建指南

### 依赖项

构建本项目需要以下工具和库：

*   **C++ 编译器**: 支持 C++20 标准 (推荐 Clang 或 GCC)。
*   **CMake**: 3.16 或更高版本。
*   **libelf**: 用于 ELF 文件解析 (`libelf-dev` 或 `elfutils-libelf-devel`)。
*   **BPF 工具链**: `clang >= 19` 编译 Guest 程序，`bpfvm-ld`（本项目自带）链接。无需 `binutils-bpf`。

### 编译虚拟机

```bash
# 配置并构建
cmake -S . -B build
cmake --build build

# 构建产物：
#   build/bpfvm / bpfvm-ld / bpfvm_test —— 虚拟机、链接器、单元测试
#   build/libBpfWideArgs.so / libBpfSoftFp.so —— LLVM pass 插件（Guest 编译用，
#     需 LLVM 开发头；缺失时跳过，不影响 VM 本体）
```

### 编译 Guest 标准库 (musl)

在编译任何 BPF Guest 程序之前，需要先构建针对 BPF 目标的 C 标准库（默认 musl）：

```bash
sh musl/build.sh     # → 安装到 root/{include,lib}（libc.a 含 _start，及头文件）
```
*默认安装前缀是项目根目录的 `root/`，所有构建脚本/Makefile 统一引用 `-Iroot/include`、`-Lroot/lib`。*

### 构建 Demo Rootfs

`scripts/build_root.sh` 统一构建 C/C++ 运行时（musl、libcxx）与可执行文件，安装到 `root/`（`root/include`、`root/lib`、`root/bin`）：

```bash
./scripts/build_root.sh                # 默认：musl libc + libc.so + libcxx + busybox
./scripts/build_root.sh dash sbase     # 额外构建 dash / sbase（可多选）
./scripts/build_root.sh openssl        # 额外构建 OpenSSL（库 + CLI）
# 运行 dash（示例）
./build/bpfvm root/bin/dash
```

### 构建 OpenSSL 3.0（库 + CLI）

`./scripts/build_root.sh openssl` 交叉编译 OpenSSL 3.0：产出 `root/lib/{libcrypto.a,libssl.a}`、`root/lib/{libcrypto.so,libssl.so}`、`root/include/openssl/` 头文件，以及 **`root/bin/openssl` CLI**（OpenSSL 自链的自包含静态 PIE，ssl/crypto/libc 全静态打入，无 DT_NEEDED，直接 `./build/bpfvm root/bin/openssl` 可跑）。Configure 经 `--config=cmake/openssl-bpf.conf` 注入 `bpf-unknown-none` 目标定义（`SIXTY_FOUR_BIT_LONG` bignum 启用 `__int128`（经 `BpfSoftFp` 软化）、`sys_id=BPFVM`、`thread_scheme=pthreads`），不改 OpenSSL 源码。

```bash
./scripts/build_root.sh openssl  # → root/lib/{libcrypto,libssl}.{a,so} + root/bin/openssl
./build/bpfvm root/bin/openssl version
# 实际用法（文件 I/O / 对称加密 / 公钥签名 / TLS 客户端都可用）：
printf 'abc' | ./build/bpfvm root/bin/openssl dgst -sha256
./build/bpfvm root/bin/openssl genrsa 512        # RSA（计算密集，大密钥较慢）
./build/bpfvm root/bin/openssl s_client -connect example.com:443 -servername example.com  # 真实 TLS 握手
```

## 运行与测试

### 运行 BPF 程序

使用编译好的虚拟机加载 ELF 文件：

```bash
./build/bpfvm <path-to-elf-file>
```

### 运行单元测试

VM 自身的指令集单元测试：

```bash
./build/bpfvm_test
```

### 运行集成测试

编译并运行 `test/` 目录下的简单 BPF 测试用例：

```bash
make -C test
```

## 项目结构

```
├── src/
│   ├── main.cpp              # VM 入口，命令行解析
│   ├── insn.h / insn.cpp     # VM 核心：指令定义、解释执行循环、浮点原语 do_softfp
│   ├── posix_syscall.h/cpp   # POSIX 系统调用实现 (PosixSyscall)
│   ├── empty_syscall.h       # 空系统调用桩 (EmptySyscall, 用于测试)
│   ├── elf_loader.h/cpp      # BPF ELF 加载与库搜索
│   ├── elf_linker.h/cpp      # 离线 BPF 链接器核心（静态/共享/动态三种模式）
│   ├── ld_main.cpp           # bpfvm-ld CLI
│   ├── jit/                  # JIT 子系统（编译器 + 各架构发射器）
│   │   ├── jit.h, jit_base_emitter.h     # JIT 共享结构与发射基类
│   │   ├── jit_compiler.h/cpp    # 架构无关的 JIT 编译器模板
│   │   ├── x86_emitter.h/cpp     # x86_64 JIT 代码发射
│   │   └── aarch64_emitter.h/cpp # AArch64 JIT 代码发射
│   ├── passes/               # LLVM pass 插件（编译为 build/lib*.so，由 clang -fpass-plugin= 加载）
│   │   ├── BpfWideArgs.cpp   #   突破 5 参数限制 + 返回结构体 + 变参函数 + by-value 聚合参数
│   │   ├── BpfSoftFp.cpp     #   把浮点 IR 改写为软浮点 call（启用 float/double）
│   │   ├── BpfEmutls.cpp     #   emutls（annotate("emutls") → 每线程存储）
│   │   └── BpfLibcallLower.cpp #  memcpy/memmove/memset/trap + floor/ceil/... → musl 调用
│   └── insn_test.cpp         # 指令集单元测试
├── include/              # BPF Guest 程序使用的头文件（syscall ID、POSIX 类型、浮点 call 编号）
├── cmake/                # CMake 辅助脚本（CTest 集成等）
├── musl/                 # musl 标准 C 库 (默认，含 BPF 移植)
├── dash/                 # dash shell (子模块)
├── busybox/              # busybox
├── test/                 # BPF 集成测试用例
└── root/                 # Demo rootfs 输出目录
```

VM 架构采用可插拔的 `SyscallHandler` 接口，将指令执行 (`insn.cpp`) 与系统调用处理 (`posix_syscall.cpp`) 解耦。`PosixSyscall` 提供完整的 POSIX 系统调用模拟，`EmptySyscall` 则作为测试用的空实现。

## 工具链 / bpfvm-ld

本项目自带 BPF 链接器 `bpfvm-ld`（`src/ld_main.cpp`），完全替代 `binutils-bpf` `bpf-ld`。

```bash
# 编译（clang 直接，无 wrapper）
clang -target bpf -mcpu=v4 -O1 -nostdinc -fno-builtin \
      -isystem root/include -isystem include -g \
      foo.c -c -o foo.o

# 链接（三种模式）
bpfvm-ld -static foo.o -L root/lib -l:libc.a -o foo.linked   # 静态：自包含 ET_EXEC
bpfvm-ld --shared --soname libc.so libc.a -o libc.so         # 共享库：PIE .so（实际由 build_root.sh 合成）
bpfvm-ld foo.o -L root/lib -l:libc.so -o foo.linked          # 动态（默认）：PIE + DT_NEEDED

# 运行
bpfvm foo.linked    # 或 foo.dyn
```

`bpfvm-ld` 兼容 clang/gcc 风格命令行（接受 `-target`、`-Wl,...`、`-isystem` 等），可作为 autoconf 项目的 `CCLD`。

### 三种链接模式

三种模式共享同一个 `Linker` 核心，与标准 `ld` 默认行为对齐：

- **静态** (`-static`)：把 `.o` + 归档合并成自包含的 ET_EXEC（固定地址）。例：`bpfvm-ld -static foo.o -l:libc.a -o foo.linked`。
- **共享库** (`-shared` / `--shared`)：从归档构建 `.so`，导出其 GLOBAL 符号表，PIE（`p_vaddr=0`，可加载到任意地址）。例：`bpfvm-ld --shared --soname libc.so libc.a -o libc.so`。
- **动态可执行**（默认）：构建引用 `.so` 依赖（`DT_NEEDED`）的 PIE ET_DYN。跨模块函数调用走 PLT/GOT；跨模块数据引用记录在 `.rela.dyn`。运行时 `bpfvm` 分配加载地址并应用重定位。例：`bpfvm-ld foo.o -l libc.so -o foo.linked`。

三种模式都输出**三个权限分离的 `PT_LOAD` 段**（W^X），由 `layout_segments`（`src/elf_linker.cpp`）按 section flags 分类：
- `text`（`SHF_EXECINSTR`）→ `PF_R|PF_X`（只读 + 可执行）
- `rodata`（只读数据）→ `PF_R`
- `data` + `.bss`（`SHF_WRITE`）→ `PF_R|PF_W`；`.bss` 是 `SHT_NOBITS`，故 `p_memsz > p_filesz`，加载时零填充

段在 guest 地址空间内页对齐且互不重叠。

入口符号默认 `_start`（标准 `ld` 行为）；用 `-e <name>` / `--entry <name>` 覆盖。

### 调试信息 (DWARF)

默认 `bpfvm-ld` 在输出中保留 DWARF 调试段（`.debug_info`、`.debug_line`、`.debug_str`、`.debug_abbrev`、`.debug_addr`、`.debug_frame`、...）作为 **non-ALLOC `SHT_PROGBITS`** 段，与标准 `ld` 行为一致。用 `-g` 编译（`test/Makefile`、`scripts/build_root.sh`、`scripts/build_busybox.sh` 已默认开启），链接后的二进制即带源码级调试信息：

```bash
bpfvm-ld -static foo.o -l:libc.a -o foo.linked     # .debug_* 保留（默认）
bpf-objdump -S foo.linked                           # 反汇编与 C 源码交错
llvm-dwarfdump --verify foo.linked                  # 校验 DWARF
```

- **仅静态模式**：调试段保留目前只在 `-static`（固定地址）启用。PIE 模式（`-shared`、默认动态）跳过调试输出，因为 `.debug_addr` 按绝对地址引用 `.text`，而该地址要到运行时 VM 选定加载基址后才确定（未来阶段可输出位置无关调试信息）。
- **Strip**：`--strip-debug` (`-S`) 仅丢弃 `.debug_*`；`-s` / `--strip-all` 同时丢弃 `.debug_*` 和 `.symtab`/`.strtab`（与标准 `ld` 语义一致）。`-g` 及其变体（`-g2`、`-gdwarf-4`、...）作为 no-op 接受（调试默认已开）。
- **重定位**：`.rel.debug_*` 重定位在链接期应用，**不**输出到产物（更干净；消费者看到的是预解析值）。处理两类地址引用：debug→debug 引用解析为段内偏移；debug→loadable 引用解析为最终 guest 地址。
- **符号表**：三种模式现在都输出静态 `.symtab`/`.strtab`，同时包含 GLOBAL 符号和 `STB_LOCAL` FUNC/OBJECT 符号（使 `objdump -d` 能标注本地函数边界）。`sh_info` 按 ELF 约定指向第一个 GLOBAL。PIE 模式下运行时符号解析仍用 `.dynsym`。
- `.BTF`/`.BTF.ext`（BPF 内核元数据）和 `.llvm_addrsig` 仍被丢弃（VM 用不到）。

#### 链接期修复 DWARF 栈变量偏移（clang BPF `frame-index` bug）

**症状**：clang BPF 后端为栈变量生成的 DWARF 定位是错的，任何 DWARF 调试器（gdb）读 spilled 到栈的局部变量 / 参数都读到垃圾。`gdb bt` 时，栈上参数显示错误值（常表现为多个无关帧共用同一个指针），而寄存器里的参数正确，回溯本身（函数名 / 返回地址）也正确。

  具体案例（busybox 在 `bpfvm --gdb` 下调试）：`read_key` 的 `fd` 被 `stxw [r10-8], r1` 写到 `[r10-8]`，但其 DWARF 定位读出来是 `DW_OP_breg10 +32` —— 即 gdb 去读 `[r10+32]`（帧头保存 r9 的槽）而非真实位置，于是显示 `fd=0x4034f5ec`（调用者的 r9）而非真实 fd。同类错误还影响 `ash_main::argc`（实际 `[r10-264]`，报成 `[r10+8]`），并让 `argv` 在很多帧里显示成同一个固定栈地址。

**根因**：`BPFFrameLowering` 没有重写 `TargetFrameLowering::getFrameIndexReference()`。通用实现按帧*底*用栈大小重算栈对象偏移，该模型假定帧指针会在 prologue 中移动；而 BPF 用的是固定、只读的帧指针 R10，永远指向帧*顶*（即 `DW_AT_frame_base = DW_OP_reg10` 的语义）。于是 `[r10-N]` 的变量被标成 `DW_OP_fbreg +(stacksize-N)` —— 只有当帧底为基准时才正确。帧顶为基准时，正偏移就落进帧头 / 保存寄存器区，调试器读到错误槽。内核 eBPF 里一直潜伏（内核程序从不用 DWARF 调试器查栈变量），但破坏任何 BPF 用户态代码的 DWARF 调试。寄存器变量一直正确，因为其定位是 `DW_OP_regN`，不走这条路。

**修复**：`bpfvm-ld` 在链接期修正错误的栈相对偏移。所有 BPF 构建都加 `-fstack-size-section`（`scripts/env.sh`、`musl/build.sh`、`test/Makefile`、`scripts/build_libcxx.sh`），让 clang 产出 `.stack_sizes` 段记录每个函数的栈大小。`bpfvm-ld` 消费它并改写 clang 输出 `+(stacksize-N)` 而非正确 `-N` 的两处（因为 BPF 帧基准 R10 是帧*顶*而非帧底）：

1. **`.debug_info` 内联 `DW_FORM_exprloc` 里的 `DW_OP_fbreg`**（`fix_fbreg_offsets`）：每条 `+N` → `+N − stacksize`。因为 SLEB128 重编码可能变长，CU 用两遍 buffer 重建（Pass A 逐 DIE 序列化、Pass B 回填 `DW_FORM_ref1/2/4/8` 的 DIE 偏移并修正 `unit_length` / exprloc 长度）。

2. **`.debug_loclists` 位置列表里的 `DW_OP_breg10`**（`fix_loclists_breg10` + `remap_loclists_base`）：函数中途被 spill 的参数 / 变量走 loclist，其 `breg10` 偏移有同样的 bug。所有 loclist 引用都用 `DW_FORM_loclistx`（索引形式），故每条 loclist 按修正后 SLEB128 的*真实*长度重建（不再 padding），再重算各贡献区的 `offset_table`，并把位移后的贡献区在 `.debug_info` 里的 `DW_AT_loclists_base`（sec_offset）定长改写（三阶段重写）。这处理了 stacksize > 64 时 loclist 变长的情况。

`.stack_sizes` 段从输出中丢弃。端到端验证：`test/test_gdb_fbreg.c`（`bpfvm --gdb` 下 GDB 在强制 spill 的函数里读出 `x=11,y=22,z=33`）、busybox `.debug_info`（3029 条 fbreg 全部修正）和 busybox `.debug_loclists`（7691/7691 条 breg10 全部修正），以及 `llvm-dwarfdump --verify` 通过。

**上游状态**：已在 `main` 由 [PR #204722](https://github.com/llvm/llvm-project/pull/204722) 修复（合并 `8140495e`，2026-06-22）。它落在 `release/22.x` 分支（2026-06-15）*之后*，故没有已发布的 clang 带它（截至 2026-07，19.x / 20.x / 21.x / 22.x 仍会 miscompile 调试信息）；一旦 clang 修复这个问题，`bpfvm-ld` 的改写就变成 no-op（没有错误偏移可修），但留着无害。

## 架构设计与实现

由于 BPF 架构的特殊性，为本虚拟机开发 C/C++ 程序时存在若干硬限制。本仓库通过一组 LLVM pass 在编译期透明解除，**写 guest 代码时按标准 C/C++ 直接用即可**。下面给出完整的三层实现机制（约束 → 方案 → pass / 链接器 / VM 执行）。

### 浮点数支持

**约束**：BPF 架构**没有硬件浮点单元或寄存器**。BPF LLVM 后端（`BPFISelLowering.cpp`）在 ISel 阶段拒绝任何浮点操作，报错如 `"A call to built-in function '__adddf3' is not supported"`——且该拒绝发生在后端把它 lower 成库调用**之前**，所以仅仅提供 `__adddf3` 实现并不够。

**方案：一批以 BPF `call` 编码的浮点「虚拟指令」**

核心思想是**通过 BPF `call` 机制模拟一批浮点指令**，然后在流水线的每一处都把它当作单条指令处理。具体地，每个浮点操作被赋予一个稳定的数字 ID——`include/bpf_fp.h` 中的 `BPF_FP_*` 族（如 `BPF_FP_ADD_D`、`BPF_FP_D2SI`、`BPF_FP_CMP_D`）——在 BPF 程序中最终变成一条 `call <imm>`，且 **`src_reg=2`（专用浮点通道）**。这刻意把浮点与系统调用（`src_reg=0`）分开：解释器和 JIT 把 `src_reg=2` 直接派发到浮点路径（`do_softfp` / `emit_call_softfp`），完全不碰 syscall handler。每条浮点指令自包含：从 `r1`/`r2` 读操作数（位模式），用宿主硬件 FP 计算结果，把位模式写回 `r0`。运行时没有函数调用、没有栈帧、操作数与结果之间没有 VM 状态穿梭——它就是一条恰好用 `call` 操作码承载的指令。

这跨三层实现（无 guest 侧胶水）：

1. **`BpfSoftFp` LLVM pass**（`src/passes/BpfSoftFp.cpp`，自动编进 `build/libBpfSoftFp.so`，由 `test/Makefile` 自动注入）——*IR* 阶段：把每条浮点 IR 指令（`fadd`/`fsub`/`fmul`/`fdiv`/`fneg`/`fcmp`、fp↔int 转换、`fpext`/`fptrunc`、以及 `fmuladd`/`fma`/`sqrt` 内联函数）改写为对 `extern __ksym` 函数 `__bpf_fp_<ID>`（段 `.ksyms`）的调用，其中 `<ID>` 是十进制 `BPF_FP_*` 值。后端把它当作普通的未解析外部调用 lower：参数按 BPF 调用约定落到 `r1`/`r2`/...、结果落到 `r0`（这是关键的稳定性属性——它用的是后端原生调用 lowering，而非 InlineAsm 那种 `"r"`/`"=r"` 约束无法钉住物理寄存器的把戏）。`fcmp` 展开成**两**次调用（`CMP` + `UNORD`），从而精确重建每个 IEEE-754 谓词。

2. **`bpfvm-ld` 链接器**——*字节码改写*阶段：clang 把它们发成 `call -1`（`src_reg=1` 占位）+ 指向 `__bpf_fp_<ID>` 的 `R_BPF_64_32` 重定位。链接器识别 `__bpf_fp_` 符号名，从名字解析 `<ID>`（无查表——ID 就在名字里），把指令改写为 `src_reg=2` + `imm=<ID>`。同时对这些名字抑制 "undefined symbol"（VM 在运行时解释它们），并跳过它们的 PLT/GOT 合成（它们不是真正的跨模块调用）。

3. **执行**——两条路径都解析同一个 `BPF_FP_*` ID（来自 `imm`），用宿主硬件 FP 执行（操作数为 `i64` 位模式，结果写 `r0`）：
   - **解释器**：`insn.cpp` 的 `do_softfp`——经 `src_reg=2` 派发分支直达，也是 JIT 的兜底。
   - **JIT**：`emit_call_softfp()` 识别 ID 并内联发射宿主原生 FP 代码。因为 JIT 把全部 11 个 BPF 寄存器常驻在物理寄存器中，r1/r2/r0 已就位（x86：R9/R10/R8；AArch64：X10/X11/X9）——无需 flush、无需 VM 退出，该操作只是指令流里又一条指令。各 arch 的细节与 bring-up 期间踩过的编码坑都注释在每个 `emit_call_softfp` 现场。这一层唯一要紧的架构差异：**AArch64 有原生 `FCVTZU`/`UCVTF`，每条 `BPF_FP_*` 都能原生处理；而 x86 缺少无符号 fp↔int 转换（需 AVX-512），故 x86 上无符号转换类 ID 回退到 `do_softfp`**（经 `emit_call_softfp_slow` → `helper_do_softfp`，一个与 syscall 路径解耦的专用 FP 兜底 helper）。

**ABI 细节**：浮点值以 IEEE-754 位模式存于 64 位 BPF 寄存器/栈槽——无精度损失。`printf("%f", x)` 之类的变参通过现有的 `BpfWideArgs` pass 工作（`va_list` 槽为 8 字节）。`printf %f` 格式化由默认 musl libc 提供（musl 的 printf 原生处理 `%f`/`%e`/`%g`）

**仍需注意**：
*   `long double` == `double`（64-bit）在本目标上；使用 128-bit `long double` 精度的代码应改为 `double`。
*   **数学函数：在 musl libm 与 VM 虚拟指令之间划分，分界线 = musl 函数体能否撑过 `instcombine`。** `floor`/`ceil`/`trunc`/`round`（+ `sin`/`cos`/`exp`/`log`/`pow`/...）来自 musl 的 `src/math/*.c`（通用纯 C；BPF 无 arch 专化）；`BpfLibcallLower` pass 把它们的*内联函数*形式（`@llvm.floor`、...）lower 成普通库调用（`call @floor`/`floorf`），并放行库调用形式让 libc 解析。`sqrt`/`fabs`/`copysign` 保留为 VM 虚拟指令（`BPF_FP_SQRT_*`/`FABS_*`/`COPYSIGN_*`）：`sqrt` 因为 JIT 发单条原生硬件指令（`sqrtsd`/`fsqrt`）；`fabs`/`copysign` 因为它们的 musl 函数体是单条按位 `and`/`or`，`-O1` instcombine 会把它*折叠回*同名内联函数（`@llvm.fabs`），所以 lower 成 `call @fabs` 会无限递归（`fabs` 调自己）——保留为 VM 指令绕开递归，无需在 pass 里写专门的按位逻辑。这三者（`sqrt`/`fabs`/`copysign`）在两个 `emit_call_softfp` 发射器里都有原生 JIT 用例（x86：xmm 上的 `sqrtsd`/`andps`/`orps`；AArch64：sqrt/fabs 用 `FSQRT`/`FABS`，copysign 用 GPR `and`/`or` 位掩码——它没有单条原生 FP 指令），故永不回退到解释器。它们的内联函数与库调用形式都被 `BpfSoftFp` 拦截并改写为对应 `BPF_FP_*`。VM 虚拟指令集因此保持：无 libc 对应物的 ISA 原语（算术/比较/转换）+ `sqrt` + `fabs`/`copysign`。（emutls 不走 VM 虚拟指令——它经 `BpfEmutls` pass 改写为普通 `__emutls_get_address` 调用，运行时在 musl，见下文「模拟 TLS (emutls)」。）

### 函数调用约定突破

**约束（原生 BPF ABI）**：原生 BPF 调用约定有三条严格限制：
1.  **参数个数**：函数参数不能超过 **5 个**（`"stack arguments are not supported"`）。
2.  **结构体返回**：函数**不能返回结构体**——后端拒绝 `sret` 属性（`"aggregate returns are not supported"`）。
3.  **变参函数**：后端在 ISel 阶段拒绝任何变参函数（`isVarArg = true`）（`"variadic functions are not supported"`，`BPFISelLowering.cpp`）。这也覆盖了使用 `va_arg`/`va_copy` 内联函数的非变参函数（如 `vfprintf`，它取 `va_list` 参数）。

**方案：BpfWideArgs pass**
本项目提供一个 LLVM pass 插件（`src/passes/BpfWideArgs.cpp`），在编译期透明解除**全部三条**限制，使你能写**标准 C**——任意参数个数、结构体返回、`...` 变参函数。它在 LLVM 开发头存在时自动编进 `build/libBpfWideArgs.so`，并由 `bpf-toolchain.cmake` / `test/Makefile` 自动注入。

**工作原理**（见 `src/passes/BpfWideArgs.cpp`）——四种变换独立且可组合（如返回结构体的 6 参函数也支持）：
*   **>5 个参数**：pass 把第 5 个参数起打包成 `__bpf_pack_<func>` 结构体，经 `r5` 中的指针传递。调用者在栈上分配该结构体（可重入/递归安全）；被调用者在入口加载额外参数。于是寄存器 `r1`–`r4` 持有前四个标量参数，`r5` 是 pack 指针。
*   **结构体返回**：LLVM 已把 `struct` 返回 lower 成 `sret` 指针约定（`void f(ptr sret, ...)`）；pass 只是剥离 BPF 后端拒绝的 `sret` 属性。语义不变。
*   **按值结构体参数**：clang 以两种方式 lower C++ 按值聚合参数，`lowerAggregateParams` 把两者都归一化为普通 `ptr`（各 1 个寄存器）：
    *   **大聚合（≥3 字，如 `std::string` 24B）**：clang 已发出 `ptr byval(%T) align N`——调用者把参数 memcpy 进栈临时并传其指针，被调用者把它当普通指针用（`getelementptr`/`load`）。BPF 后端拒绝 `byval` 属性（"pass by value not supported"），故 pass 从每个函数签名和调用点剥离 `byval`（覆盖直接/间接调用和外部 callee）。无类型/函数体改动——参数本就是指针。
    *   **小聚合（≤2 字，如 `std::pair`=`{i64,i64}`、`__bit_iterator`=`[2 x i64]`、`i128`）**：clang 直接用聚合**值类型**作参数类型（无 `byval`）。BPF 后端把它按元素/字段展开成多个寄存器，于是 `f(__bit_iterator, __bit_iterator, value, proj)` = 2+2+1+1 = 6 寄存器 > 5 寄存器限制 → "too many arguments"。pass 把签名重建为普通 `ptr`，搬移函数体，并改写函数体对值参数的使用及每个调用点的实参。按聚合是否平凡可拷贝分两种子情况：
        *   **平凡可拷贝**（标量的 `std::pair`、`i128`、...）：被调用者入口插入 `load T, ptr %arg`，调用点把值存入一个入口块新 alloca 并传其指针。按位拷贝正确。
        *   **非平凡可拷贝**（如 `std::shared_ptr` = `{ptr,ptr}` 16B，任何有用户自定义拷贝/移动构造或析构的）：clang 生成 `[2 x i64]` 值参数和形如 `store [2 x i64] %arg, ptr %local; ... move/copy %local ...` 的函数体。按位 `load`/`store` 会破坏移动语义——`move %local` 置空的是 `%local`（那份 load 拷贝），而非调用者的源对象，于是调用者拷贝构造的临时仍被析构、引用计数多减一次（静默：引用计数最终少一，调用者的 `shared_ptr` 悬空，下次 fork/访问 UAF；由 `test/test_sp_copy.cpp` 和 `bpfvm-on-bpfvm` 的 `test_waitid` 崩溃复现，其中 `do_clone` 的 `make_shared<PosixSyscall>(pgrp, session)` 少计了 `pgrp`）。修复镜像 x86 的 invisible-reference ABI：`rewriteValueParamUsesToPointer` 擦除 `store %arg, ptr %local`，把 `%local` RAUW 成指针参数，使函数体直接操作调用者的源对象；调用点在实参为 `load T, ptr %src`（clang 模式：调用者拷贝/移动构造一个临时 `%src` 再 load）时，传 `%src` 本身，使被调用者的移动置空调用者的临时、其析构变成 no-op。非 load 实参（罕见；如另一个调用的返回值）回退到平凡可拷贝的 alloca+store 路径。
    两种情况下语义都不变（按值 = 调用者交给被调用者一份独立拷贝）；每调用点的拷贝被保留（优化器无法证明被调用者不会写向这个现在无归属的指针，故保守保留它）。这解锁了 `f(std::string)` / `f(std::vector)` / `f(std::pair)` / 任意按值聚合——此前被拒绝。
*   **变参函数**——使用 clang 原生的 `VoidPtrBuiltinVaList`，`va_list` 是指向第一个 vararg 的单个 `void*`：
    *   **被调用者改写**：`R f(T0..Tn, ...)` → `R f(T0..Tn, ptr __va_base)`。`__va_base` 指向一块调用者分配的、持有 vararg 的内存区。函数原型（声明）同样改写。
    *   **调用者改写**：每个调用点在入口栈上分配 `__bpf_vapack_<func>` 结构体（packed，每槽按 `allocSize(T)` 定大小），把变参实参存入，并把其地址作为 `__va_base` 传入。
    *   **内联函数 lowering**（应用于*所有*函数，不只是变参的）：
        *   `va_start(ap)` → `store __va_base, ap`
        *   `va_arg(ap, T)` → `load T, ptr ap; ap += allocSize(T)`
        *   `va_copy(d, s)` → `*d = *s`（拷贝指针值）
        *   `va_end(ap)` → no-op

#### 历史 / 可选替代方案

> 以下内容是 `BpfWideArgs` pass 出现**之前**采用的技术，或 pass 关闭时（直接瞄准原生 BPF ABI）的备选方案。它们**不影响**现代 guest 程序的编写（pass 默认开启），保留作参考——想直接理解当前用法可跳过本节，直接看下一节 [C++ 支持](#c-支持)。

主要手法有二：强制内联、手搓 pseudo-`va_list`。

##### 强制内联（pass 关闭时的可选兜底）
通过内联函数绕过参数数/结构体返回限制，使调用约定不被触发：

```c
#define BPF_INLINE __attribute__((always_inline)) inline

// 例：>5 参数的函数
BPF_INLINE void complex_logic(int a, int b, int c, int d, int e, int f) {
    // 实现被内联，避开 5 寄存器限制
}
```
##### 手搓 pseudo-`va_list`
变参可完全在头文件里用一个调用者在每个调用点手工组装的 pseudo-`va_list` 模拟。pass 已取代该技术；本节保留作参考。

*   **把 `va_list` 定义为结构体**：
    ```c
    typedef struct {
        int pos;
        unsigned long long* data;
    } _va_list;
    ```
    `pos` 是运行索引，`data` 指向一个调用者分配的、持有 vararg 的 `uint64_t[]` 数组。
*   **参数计数**：数组长度与逐槽填充循环由一个预处理器参数计数器（`___bpf_narg`）驱动，使调用者无需手写计数。这是经典的占位符偏移技巧——一个前导哑参数，然后一个倒序编号列表，N 落在正确的槽上：
    ```c
    #define ___bpf_nth(_, _1, _2, _3, _4, _5, _6, _7, _8, _9, _a, _b, _c, N, ...) N
    #define ___bpf_narg(...) \
        ___bpf_nth(_, ##__VA_ARGS__, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)
    // ___bpf_narg(a, b)        → 2
    // ___bpf_narg(a, b, c, d)  → 4
    ```
    `___bpf_apply(fn, N)` 随后选择匹配的重载，故 `___bpf_fill(arr, a, b, c)` 展开为 `___bpf_fill3(arr, 0, a, b, c)`（每个 arity 都有一个 `___bpf_fillN` 重载，至 12）。同一计数器也定 size 数组本身：`unsigned long long data[___bpf_narg(args)]`。
*   **在调用点构建 list**：helper 宏分配一个局部 `uint64_t[]`（由 `___bpf_narg` 定 size），通过 `___bpf_fill` 逐槽逐参填充，并初始化结构体指向它。手动展开形如：
    ```c
    uint64_t ap_data[2] = { (uint64_t)(uintptr_t)"world", 42 };
    _va_list ap = { .pos = 0, .data = ap_data };
    ```
*   **访问宏**遍历数组：
    *   `_va_arg(ap, type)` → `{ ap.pos++; (type)ap.data[ap.pos-1]; }`
    *   `_va_copy(dest, src)` → `dest = src`（结构体拷贝，故两者共享数组）
    *   `_va_end(ap)` → no-op
    *   `_va_start` 被故意禁用（BPF 没有可 start 的 `...` 函数）。
*   **使用模式**：声明取真正 `va_list` 的*后端*函数，并在每个调用点构建 pseudo-`va_list` 的语句表达式宏中包装它：
    ```c
    int my_vprintf(const char *format, va_list ap);   // 后端，取 va_list

    #define my_printf(fmt, ...) ({ \
        /* 构建 ap：局部 uint64_t[] + init _va_list */ \
        my_vprintf(fmt, ap); \
    })
    ```

### C++ 支持

BPF VM 支持 **C++ 语言子集**：用 `clang++ -target bpf -fno-exceptions -frtti` 编译的程序，通过 `extern "C"` 使用 musl 的 C 运行时，并用 **libc++**（`libcxx.a`/`libcxx.so`）作为 C++ 标准库。由 `test/test_cpp_lang.cpp` 端到端验证（ctest 变体：dynamic × JIT/interp + host + 嵌套静态）；STL 覆盖由 `test/test_stl_*.cpp` 套件保证。

**无 C++ 运行时即可工作**（裸语言子集）：
- 模板、类/结构体、构造/析构、单继承、虚函数（vtable 分派）。
- 命名空间、`constexpr`、函数重载、引用、`auto`、lambda（带捕获）。
- `operator new` / `operator delete` 由 musl `malloc`/`free` 支撑（在 `.cpp` 里定义它们；mangle 为 `_Znwm`/`_ZdlPv`，无需 C++ 运行时库即可解析）。

**经 libc++ 的 STL**（`libcxx.a`/`libcxx.so`，由 `scripts/build_libcxx.sh` 构建）：标准库可用，含 RTTI（`typeid`/`dynamic_cast`）和 `<thread>`/`<mutex>`/`<future>`/`<barrier>`（musl pthread 之上的 libc++ pthread 后端）。构建完全从 LLVM 源码树出发（需解压 LLVM 源码 tarball 到 `/tmp/llvm-toolchain-*`，或设 `LLVM_SRC` 指向源码树）。

**已验证的编译期限制**（clang 19，`-target bpf -fno-exceptions -frtti`）：
- `throw` / `try`：`error: cannot use 'throw'/'try' with exceptions disabled`。RTTI已启用，故 `dynamic_cast` 和 `typeid` 可用（见 `test/test_stl_rtti.cpp`）；仅引用 `dynamic_cast` 失败（`bad_cast`）不可用，因为它需要异常。

**为本目标写 C++ 时要遵守的硬约束**：
- **无异常**：`throw`/`try` 编译期被拒（未移植 `__cxa_throw`/`__cxa_personality`/libunwind）。RTTI 已启用；`typeid`/`dynamic_cast` 可用。
- **`thread_local` 经 `annotate("emutls")`**（见下文「模拟 TLS (emutls)」）：C++ `thread_local` 关键字被 clang Sema 对 BPF 目标拒绝（无法用 `-femulated-tls`）。工具链经 `-Dthread_local='__attribute__((annotate("emutls")))'` 在预处理期把关键字替换成 `annotate` 属性（早于 Sema）。
- **`&thread_local_var`**：函数内可取地址（`return &var;`、作实参、`int *p = &var;` 等逃逸形式 pass 都会改写为 `__emutls_get_address` 返回的副本指针）；**全局初始化器里取地址 `int *gp = &var;` 不支持**，pass 编译期报错（没有函数上下文插入 `__emutls_get_address`）。

**全局构造/析构**：经 `bpfvm-ld` 的 `.init_array`/`.fini_array` 框架支持（见 `src/elf_linker.cpp` 与下文「全局构造/析构」）。有非平凡构造/析构的全局对象可用：构造在 `main` 之前运行（定义序），析构在 `exit` 时运行（逆序，经 `_GLOBAL__sub_I_*` 中注册的 `__cxa_atexit`）。由 `test/test_cpp_ctor.cpp` 验证。

**构建集成**（见 `test/Makefile`）：
- `test/test_cpp_*.cpp` 自动发现；`CXX_FLAGS` 镜像 C 的 `CC_FLAGS`（相同的 target/CPU/stack-size/isystem/pass-plugin 标志）加上 `-std=c++23 -nostdinc++ -fno-exceptions -frtti` 和 libc++ 绕过宏（`-D_LIBCPP_HAS_THREAD_API_PTHREAD -D_LIBCPP_HAS_MUSL_LIBC ...`）。C++ pass 插件（`libBpfWideArgs.so`/`libBpfSoftFp.so`/`libBpfLibcallLower.so`/`libBpfEmutls.so`）随 C 的一起注入。
- C++ 测试链接 `libcxx.a`（静态 `.out`）或 `libcxx.so`（动态 `.linked`），两者均由 `scripts/build_root.sh` 的 `build_libcxx` 产出（`scripts/build_libcxx.sh` → `libcxx.a`；`bpfvm-ld -shared` → `libcxx.so`，`DT_NEEDED libc.so`）。C 测试保持无任何 libcxx 依赖。
- C++ 测试经 `cmake/RunBpfProgram.cmake` 运行与 C 测试相同的 ctest 变体。
- musl `libc.a` **不**提供 C++ ABI 符号（仅 C 式 `__cxa_atexit`/`__cxa_finalize`）；C++ 运行时——`operator new`/`delete`、libc++abi typeinfo vtable + `__dynamic_cast` + `__cxa_*`，以及 libc++ 库本身——来自 `libcxx.a`/`libcxx.so`。

#### 模拟 TLS (emutls)

每线程存储通过「`-D` 注入 + LLVM pass + musl 运行时」三层支持，全程是普通函数调用，linker/JIT/VM 无 emutls 专属代码。

**用法**：直接写标准的 `thread_local`，工具链在 BPF 编译期注入 `-Dthread_local='__attribute__((annotate("emutls")))'`：
```cpp
thread_local int counter = 0;          // 零初始化
thread_local int init_val = 42;        // 非零初始化（首次访问时模板拷贝）
thread_local int arr[4] = {1,2,3,4};   // 数组（支持 GEP 访问）
struct Point { int x; int y; };
thread_local Point pt = {1, 2};        // 结构体（支持字段访问）
int *p = &counter;                     // 函数内取地址（支持，见下）
```
预处理期 `thread_local` 被替换成 `__attribute__((annotate("emutls")))`（早于 Sema，故绕过对 BPF `thread_local` 的拒绝；BPF.h `TLSSupported=false`，后端 `GlobalTLSAddress` ISel 会崩溃）。变量仍是普通 `addrspace(0)` 全局，clang 只是把它标进 `@llvm.global.annotations`，pass 解析该数组反查哪些是 emutls 变量。host 编译不注入该 `-D`，`thread_local` 保持原生语义，故同一源码在 `host` ctest 变体里充作基线。该 `-D` 仅注入 C++ flags（C 的 `thread_local` 来自 `<threads.h>` 宏，命令行 `-D` 会与之冲突；C 端 TLS 不在本方案覆盖范围）。

**机制**（见 `src/passes/BpfEmutls.cpp` + `musl/src/thread/bpf/emutls.c`）：
1. `BpfEmutls` pass（经 `-fpass-plugin=libBpfEmutls.so` 加载，在 `PipelineStartEPCallback` 运行，即优化 pipeline 最前——此时 `-O1` 常量折叠尚未执行）解析 `@llvm.global.annotations` 反查所有标注 `emutls` 的全局，为每个合成控制块 `@__emutls_v.<name> = { i64 size, i64 align, i64 index, ptr value, ptr dtor }`（value 为 null=零初始化，否则指向模板 `@__emutls_t.<name>`），并把对该全局的访问（含函数内取地址 `&var` 的 ret/call/store 逃逸形式）改写为 `call ptr @__emutls_get_address(ptr @__emutls_v.<name>)` + 访问返回的每线程副本指针。
2. bpfvm-ld 走普通 call 重定位 → PLT/GOT 合成，解析到 musl libc 的 `__emutls_get_address`。
3. musl 运行时（`musl/src/thread/bpf/emutls.c`）用一个 `pthread_key` 把本线程的副本指针数组经 `pthread_setspecific` 挂在 `struct pthread::tsd[]` 上，按控制块 `index` 懒分配/查表（`malloc`/`realloc` 增长，线程退出时由 key destructor `free`），首次访问按模板 `memcpy`（零初始化则清零）。每线程隔离由 musl 的 tp（每 vm 一个 `tp_`）保证——不侵入 `struct pthread` 定义，与 compiler-rt/libgcc 的通行做法一致。
4. 非平凡析构：clang 因 `thread_local` 被替换成 `annotate` 属性而走普通全局的进程级 `__cxa_atexit(dtor, &var, dso)`（仅析构主线程副本）。pass 的 `collectDtors` 从 init 函数里识别这条 `__cxa_atexit`（arg1 是某 emutls 全局），把 dtor 转移进控制块字段并删除原 call；`__emutls_get_address` 在每线程首次分配副本时若 `ctrl->dtor` 非空，调 `__cxa_thread_atexit(dtor, 本副本地址, NULL)` 注册本副本析构。dso 句柄不转移——BPF 无 dlopen/dlclose，运行时不按 DSO 过滤。每线程析构链由 `__pthread_run_cxa_dtors` 在 `__pthread_tsd_run_dtors` 开头（子线程）和 `exit()`（主线程）逆序调用——C++ ABI 要求 thread_local dtor 早于 pthread_key dtor（含 emutls 副本内存 `free`），故析构时副本内存仍有效。覆盖见 `test/test_thread_local_dtor.cpp`。

**fork 语义**：副本数组与副本内存经 `malloc` 落在 guest 可写堆（CoW 段），`pthread_key` 是进程级。子进程的 `tsd[]` 继承父的指针，任一方写入触发 CoW 分叉——自动达到 POSIX fork 的"继承父值、之后独立"。线程（`pthread_create`、带 `CLONE_VM` 的 clone）各获独立 `struct pthread`（空 `tsd`），即标准 `thread_local` 语义。

**限制**：
- 仅聚合初始化（无用户构造函数）：`thread_local T x{7};` / `thread_local T x;` 仅当 `T` 是聚合类型（或仅有隐式默认构造）时支持——其 initializer 直接进 GV。**带用户自定义构造函数的类型（如 `thread_local std::string s;`）pass 编译期报错**：pass 跑在 `-O1` 优化前，此时构造调用还在 init 函数里，pass 无法把它迁移成每线程执行，放行会丢构造且只构造一次。非平凡析构已支持，可用「聚合构造 + 用户析构」形态（`struct T { int v; ~T(){...} }; thread_local T x{7};`）。
- 全局初始化器里不能 `&var`：`int *gp = &tls_var;`（initializer 是编译期 Constant，无函数上下文插 `__emutls_get_address`）pass 编译期报错；函数内的 `&var` 完全支持（ret/call/store 均可）。
- TLS 变量必须定义并使用于单个翻译单元内；不支持跨 TU 的 `extern thread_local`（控制块用内部链接）。

#### 全局构造/析构

有非平凡构造/析构的全局对象经链接器合成符号支持，复用 musl 既有的 `__libc_start_init` / `__libc_exit_fini` 循环

**机制**（见 `src/elf_linker.cpp`）：
1. clang 发出 `.init_array`（SHT_INIT_ARRAY）持有函数指针（`_GLOBAL__sub_I_*`），每个构造一个全局对象并通过 `__cxa_atexit(dtor, obj, __dso_handle)` 注册其析构。
2. `bpfvm-ld` 把 `.init_array`/`.fini_array` 段收集进 SEG_DATA（在段内保持连续），并合成四个边界符号：`__init_array_start/end`、`__fini_array_start/end`（存于 `synthetic_globals_`，作为 `SHN_ABS` 同时发到 `.symtab` 和 `.dynsym`）。它还合成 `__dso_handle`。
3. 静态模式：`.init_array` 中的函数指针在链接期打补丁（R_BPF_64_ABS64）。PIE 模式：留作 `.rela.dyn` 条目，由 loader 在运行时解析（`_GLOBAL__sub_I_*` 是主程序中的已定义符号，收集进 `exports_`）。
4. musl 的 `__libc_start_main` → `__libc_start_init` 遍历 `[__init_array_start, __init_array_end)` 调用每个 ctor；`exit` → `__libc_exit_fini` 逆序遍历 `[__fini_array_start, __fini_array_end)`，加上 `__cxa_atexit` 链。

**顺序**：ctor 在一个 TU 内按定义序运行；dtor 逆序运行（LIFO），与 `__cxa_atexit` 注册的 dtor 交错。跨 TU 顺序遵循链接顺序（标准 `ld` 语义，无保证）。

## 标准库与移植

### musl 移植（`musl/`）

本项目附带 musl 1.2.6 的移植，作为 BPF 目标的**默认** C 库。用 `sh musl/build.sh`（默认前缀 `$TOP/root`）构建——产出 `root/lib/libc.a`（内含 `crt1.o`/`crti.o`/`crtn.o`，故含 `_start`）+ 独立的 `crt1.o`/`Scrt1.o`/`crti.o`/`crtn.o`，以及 `root/include/` 中的头文件，故 `-Iroot/include` 与 `-Lroot/lib` 解析到 musl 的头文件和 `libc.a`。`test/Makefile` 和 `scripts/build_root.sh` 直接基于此 musl 构建（静态 `.out` + 动态 `.linked`）。

#### musl 构建（`musl/build.sh`）
- **`--disable-shared`**：musl 的 `.so` 由 `bpfvm-ld -shared` 从 `libc.a` 合成（在 `scripts/build_root.sh` 的 `build_libc_bpfso` 中），而非由 musl 自己的构建产出。
- **`-mllvm -bpf-stack-size=16384`**：musl 的 `crypt_blowfish`（`BF_crypt`）有 ~8.5KB 局部结构；默认 4096 会溢出。
- **跳过 rcrt1.o / crti.o / crtn.o / Scrt1.o**：`make install` 编译 `rcrt1.o`（静态 PIE 自启动，依赖 `dlstart` 动态链接器逻辑——BPF 不支持；`_start_c` 签名不匹配 + `GETFUNCSYM` 无前向声明）并失败。脚本经 per-target `make obj/crt/crt1.o` **只构建 `crt1.o`**。其它 crt 对象在 BPF 上不必要：`crti.o`/`crtn.o` 编译成空 `.o`（BPF 无 `.init_array`/`.fini_array` 框架），且 `Scrt1.o` 在 BPF 上与 `crt1.o` 相同（clang 对地址引用总发重定位，故 `-fPIC` 不改变输出）。头文件手工拷到 `root/include/`（先 generic/bits，再 bpf/bits，使 BPF 专化覆盖胜出）。
- **crt1 合并进 libc.a**：BPF 的 `_start` 在 `crt1.o` 中（纯 C，`arch/bpf/crt_arch.h`）。脚本运行 `ar rcs lib/libc.a lib/crt1.o` 使 `libc.a` 自带 `_start`，链接器只需传 `libc.a`/`libc.so`，无需单独 crt 文件或排序。`crt1.o` 同时覆盖静态和 PIE/.so 模式（BPF `-fPIC` 不改变 crt1 输出）。
- **ldso 对象（`dlstart.lo`/`dynlink.lo`）单独构建；与 libc 合并进单二进制**：标准 musl 把 ldso 代码（`ldso/dlstart.c`、`ldso/dynlink.c`）放进 `libc.so` 而非 `libc.a`（静态链接的程序不需要动态链接器）。由于 BPF 的 `libc.so` 由 `bpfvm-ld -shared` 从 `libc.a` 合成（非 musl 自己的构建），这些对象本会丢失。脚本经 `make obj/ldso/dlstart.lo obj/ldso/dynlink.lo` 构建它们，并随 `libc.a` 一起安装到 `root/lib/`。
- **`libc.so` == `ld-bpf.so`（单二进制，镜像上游 musl `libc.so` == `ld.so`）**：ldso 必须在任何其它库被重定位之前工作，故它依赖的 libc（`malloc`/`memcpy`/TLS 设置/`__libc_start_main`/...）必须链接进它——它不能从单独的 `libc.so` 导入这些。`scripts/build_root.sh` 的 `build_libc_bpfso` 因此从 `libc.a + dlstart.lo + dynlink.lo` 构建**一个**二进制，`--soname libc.so`，入口 `_dlstart`（`-e _dlstart`），输出到 `root/lib/ld-bpf.so`，`root/lib/libc.so` 是指向它的相对符号链接。这不是浪费的重复：运行时 `load_library("libc.so")` 命中 musl ldso 的 `is_self` 短路（`ldso.name` 在 `__dls2` 中硬编码为 `"libc.so"`，且 `"libc"` 在保留名表中），故程序的 `DT_NEEDED libc.so` 复用已映射的 ldso 而非打开文件——磁盘上单独的 `libc.so` 会是死重。单文件服务三条路径：链接时（`-l:libc.so` 读其 dynsym + `DT_SONAME=libc.so`）、`DT_NEEDED libc.so`（→ `is_self`）、以及 `PT_INTERP=/lib/ld-bpf.so`（VM loader 解析 `ld-bpf.so`，入口 = `load_base + e_entry` → `_dlstart`）。ldso 自做 stage-1 自重定位（`dlstart.c` 的 `_dlstart_c`）；VM loader 只 mmap 段 + 设置 auxv。
- **安装布局**：`root/{include,lib}` 是与 libcxx 和 rootfs 共享的统一安装树；`root/lib` 持有 `libc.a`（含 crt1 合并）、`crt1.o`，以及 ldso 对象 `dlstart.lo`/`dynlink.lo`。

## 许可证

[待补充，如 MIT / GPL]
