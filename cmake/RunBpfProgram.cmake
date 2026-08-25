# 每个用例内部串行跑多变体：动态 x JIT 开/关 + host + bpfvm-on-bpfvm 嵌套。
# 不同用例之间由 ctest -j 并发。同用例的变体串行，不冲突文件。
#
# 参数：BPFVM / NAME / WORKDIR / ROOT（可选）/ BPFVM_BPF（可选）
#   ROOT 非空 -> chroot 模式：每个变体建临时 rootfs，prog 以 guest 路径（/<name>.<suffix>）
#   启动（bpfvm --root <rootfs>）。root/lib 一并拷入（动态变体的 PT_INTERP 解析）。
#   host 变体跳过（chroot 无宿主对照意义）。隔离正确性由 guest 程序自身断言
#
#   BPFVM_BPF 非空 -> 额外跑 1 个嵌套变体（nest_static）：
#   host bpfvm 跑 bpfvm.bpf，内层 bpfvm 再跑 prog。内层 bpfvm 交叉编译到 BPF 目标，
#   其 JIT 编译器在编译期被桩化（src/insn.cpp: StubJitCompiler，compile() 恒返回
#   nullptr），故内层恒为纯解释器——嵌套变体无 jit/interp 之分，只按程序类型区分。
#   chroot 模式下嵌套变体用 `bpfvm bpfvm.bpf -- --root <rootfs> /<name>.<suffix>`，
#   `--` 阻止 host bpfvm 的 getopt 把 --root 抢成自己的选项透传给内层。
#   耗时过长的用例跳过嵌套变体（见下方 BPF_NEST_SKIP 定义）。

if(NOT DEFINED BPFVM)
    message(FATAL_ERROR "BPFVM is required")
endif()
if(NOT DEFINED NAME)
    message(FATAL_ERROR "NAME is required")
endif()
if(NOT DEFINED WORKDIR)
    set(WORKDIR "${CMAKE_CURRENT_LIST_DIR}/..")
endif()

# IN_LIST 操作符需要 CMP0057 NEW（cmake -P 脚本模式下默认未开启）。
cmake_policy(SET CMP0057 NEW)

# 嵌套下耗时过长的用例：跳过其嵌套变体（普通变体照跑）。黑名单属运行时变体门控，
# 与消费者（下方 foreach 里的 IN_LIST 判断）同处一脚本，无需从 CMakeLists 传入，
# 也就免去了 "|" / ";" 转义那一套。
#   test_compute        计算密集，双重模拟下天量慢
#   test_pthread_create 嵌套 ~203s（原生 0.87s，futex 路径极慢）
#   test_pthread_mutex  嵌套 ~227s（原生 1.22s）
#   test_stl_thread     嵌套 ~70s（std::thread + futex/同步重路径放大）
set(BPF_NEST_SKIP
    test_compute
    test_pthread_create
    test_pthread_mutex
    test_stl_thread
)

# label|program_suffix|BPF_TEST_VARIANT|JIT_ENABLE|JIT_THRESHOLD|nest_flag  ("-" 占位空值)
# 前 2 个走 bpfvm（动态 x JIT/解释器）。静态程序不设非嵌套变体（控制用例
# 时长），其加载语义由 nest_static 覆盖。
# JIT 变体设 JIT_THRESHOLD=1：每个 pc 命中一次即编译，最大化 JIT 覆盖（暴露冷代码
# 路径里的 JIT 缺陷，而非只在热点循环上验证）。
# 第 3 个 host 变体直接运行宿主 gcc 原生二进制（test/Makefile 的 *.host），
# 作为 BPF/musl/bpfvm 实现的对照基线：同一测试逻辑在标准 glibc 下也应通过。
# 第 4 个 nest_static 变体跑 bpfvm-on-bpfvm 嵌套（仅当 BPFVM_BPF 可用）。
# 嵌套只跑静态：动态嵌套耗时显著增加且需额外环境变量，收益不大。
set(variants
    "dynamic_jit|linked|linked|-|1|-"
    "dynamic_interp|linked|linked|0|-|-"
    "host|host|host|-|-|-"
    "nest_static|out|-|-|-|1"
)

# chroot 模式下需要 root/lib（libc.so = ld-bpf.so，供动态变体 PT_INTERP 解析）。
if(DEFINED ROOT AND NOT ROOT STREQUAL "")
    set(ROOT_LIB "${WORKDIR}/root/lib")
endif()

# 嵌套变体可用性：BPFVM_BPF 未定义/文件不存在 -> 跳过（graceful，不影响普通变体）。
set(NEST_AVAILABLE OFF)
if(DEFINED BPFVM_BPF AND NOT BPFVM_BPF STREQUAL "" AND EXISTS "${BPFVM_BPF}")
    set(NEST_AVAILABLE ON)
endif()

foreach(v ${variants})
    string(REPLACE "|" ";" fields ${v})
    list(GET fields 0 label)
    list(GET fields 1 suffix)
    list(GET fields 2 variant_env)
    list(GET fields 3 jit_env)
    list(GET fields 4 threshold_env)
    list(GET fields 5 nest_flag)

    # chroot 模式跳过 host 变体（chroot 无宿主对照意义）。
    if(DEFINED ROOT AND label STREQUAL "host")
        continue()
    endif()

    # 嵌套变体跳过：bpfvm.bpf 不可用。
    if(nest_flag STREQUAL "1" AND NOT NEST_AVAILABLE)
        message("skip nest variant '${label}': bpfvm.bpf not available")
        continue()
    endif()
    # 嵌套变体跳过：已知耗时过长的用例（BPF_NEST_SKIP，脚本内定义见上文）。
    if(nest_flag STREQUAL "1" AND NAME IN_LIST BPF_NEST_SKIP)
        continue()
    endif()

    set(prog "${WORKDIR}/test/${NAME}.${suffix}")

    # 运行时库搜索路径（guest 用，经 -e 传给 bpfvm，再由 elf_loader 解析 LD_LIBRARY_PATH）：
    #   - root/lib：libc.so/libcxx.so（build_root.sh 复制到此，供 rootfs 与 ctest 共用）。
    #   - test：测试用 .so（如 GOT 的 libgot.so，构建产物落在 test/ 下）。
    # 不再设宿主 ENV{LD_LIBRARY_PATH}：bpfvm 自身的 elf_loader 现在用 -e 的 guest envp 搜库，
    # 宿主环境与 guest 库搜索彻底解耦。
    set(ldpath "${WORKDIR}/root/lib:${WORKDIR}/test")

    # bpfvm 不再从宿主 environ 自动透传环境变量，所有 guest 可见变量经 -e 显式传入。
    # 收集成 cmake list（"-e;K=V;-e;K2=V2"），execute_process 展开为独立 argv。
    # host 变体例外：直接跑宿主二进制不经 bpfvm，-e 无效，改设宿主 ENV。
    #
    # nest 变体（bpfvm-on-bpfvm）有两层 -e：
    #   - outer_env_args（${BPFVM_BPF} 之前，外层 bpfvm 消费）：注入 bpfvm.bpf 进程 environ，
    #     供 bpfvm.bpf 启动时其 ldso 加载 DT_NEEDED(libcxx.so) 用。只需 LD_LIBRARY_PATH。
    #   - inner_env_args（${BPFVM_BPF} 之后，bpfvm.bpf 消费）：bpfvm.bpf 的命令行 -e，注入给
    #     测试程序。nest_static 跑的是 -static 自包含 .out（无 DT_NEEDED），内层 load_elf 不搜库，
    #     故不需要 LD_LIBRARY_PATH；只需在 dynamic 变体下追加 BPF_TEST_VARIANT。
    set(guest_env_args "-e" "LD_LIBRARY_PATH=${ldpath}")  # 非 nest：直接给测试程序
    set(outer_env_args "-e" "LD_LIBRARY_PATH=${ldpath}")  # nest 外层：bpfvm.bpf 的 environ（ldso 用）
    set(inner_env_args)                                   # nest 内层：bpfvm.bpf 的 -e（见上注，默认空）
    # BPF_TEST_VARIANT 经 -e 注入给 guest（dynamic 系列变体需要它选 .linked）；
    # static 系列变体的 variant_env == "-"，清空宿主 ENV 避免残留。
    # host 变体特殊：它不经 bpfvm（直接跑宿主 gcc 二进制），-e 对它无效，故必须走宿主 ENV。
    # 其 variant_env == "host"（参见 variants 表），test 程序据此选 *.host 目标（如 test_arg.host）。
    if(label STREQUAL "host")
        set(ENV{BPF_TEST_VARIANT} "${variant_env}")
    elseif(variant_env STREQUAL "-")
        unset(ENV{BPF_TEST_VARIANT})
    else()
        list(APPEND guest_env_args "-e" "BPF_TEST_VARIANT=${variant_env}")
        list(APPEND inner_env_args "-e" "BPF_TEST_VARIANT=${variant_env}")
        unset(ENV{BPF_TEST_VARIANT})
    endif()
    if(jit_env STREQUAL "-")
        unset(ENV{JIT_ENABLE})
    else()
        set(ENV{JIT_ENABLE} "${jit_env}")
    endif()
    if(threshold_env STREQUAL "-")
        unset(ENV{JIT_THRESHOLD})
    else()
        set(ENV{JIT_THRESHOLD} "${threshold_env}")
    endif()

    if(label STREQUAL "host")
        # host 变体：直接运行宿主二进制，不经过 bpfvm。
        # 用 /bin/sh -c "umask 0022 && exec ..." 包装，对齐 bpfvm 启动时设置的 umask
        # （宿主 shell umask 可能不是 0022，如 0002，会导致 test_umask 误判失败）。
        execute_process(
            COMMAND /bin/sh -c "umask 0022 && exec \"$0\" \"$@\"" "${prog}"
            WORKING_DIRECTORY "${WORKDIR}"
            INPUT_FILE /dev/null
            RESULT_VARIABLE result
            OUTPUT_VARIABLE stdout
            ERROR_VARIABLE stderr
        )
    elseif(DEFINED ROOT)
        # chroot 变体：建临时 rootfs（CMAKE_PID+label 唯一，ctest 并发/同用例多变体不冲突），
        # 拷入 prog（guest 路径 = /<name>.<suffix>）与 root/lib，--root 启动。
        set(rootfs "${WORKDIR}/build/rootfs_${NAME}_${CMAKE_PID}_${label}")
        file(REMOVE_RECURSE "${rootfs}")
        file(MAKE_DIRECTORY "${rootfs}")
        file(COPY "${prog}" DESTINATION "${rootfs}")
        file(COPY "${ROOT_LIB}" DESTINATION "${rootfs}")
        if(nest_flag STREQUAL "1")
            # 嵌套 chroot：outer_env_args 注入 bpfvm.bpf 进程 environ（供其 ldso 启动加载
            # libcxx.so）；其后是 bpfvm.bpf 的 argv：--root chroot 到 rootfs，inner_env_args
            # 是 bpfvm.bpf 的 -e（其 load_elf 搜库 + 注入给测试程序），最后是 guest 路径。
            set(cmd "${BPFVM}" ${outer_env_args} "${BPFVM_BPF}" "--root" "${rootfs}" ${inner_env_args} "/${NAME}.${suffix}")
        else()
            set(cmd "${BPFVM}" "--root" "${rootfs}" ${guest_env_args} "/${NAME}.${suffix}")
        endif()
        execute_process(
            COMMAND ${cmd}
            WORKING_DIRECTORY "${WORKDIR}"
            INPUT_FILE /dev/null
            RESULT_VARIABLE result
            OUTPUT_VARIABLE stdout
            ERROR_VARIABLE stderr
        )
    else()
        if(nest_flag STREQUAL "1")
            # 嵌套非 chroot：outer_env_args 注入 bpfvm.bpf 进程 environ（供其 ldso 启动加载
            # libcxx.so）；其后是 bpfvm.bpf 的 argv：inner_env_args 是 bpfvm.bpf 的 -e
            # （其 load_elf 搜库 + 注入给测试程序），最后是 guest 路径。
            set(cmd "${BPFVM}" ${outer_env_args} "${BPFVM_BPF}" ${inner_env_args} "${prog}")
        else()
            set(cmd "${BPFVM}" ${guest_env_args} "${prog}")
        endif()
        execute_process(
            COMMAND ${cmd}
            WORKING_DIRECTORY "${WORKDIR}"
            INPUT_FILE /dev/null
            RESULT_VARIABLE result
            OUTPUT_VARIABLE stdout
            ERROR_VARIABLE stderr
        )
    endif()

    if(NOT result EQUAL 0)
        message("Variant '${label}' (${prog}) failed with exit ${result}:")
        message("stdout:\n${stdout}")
        message("stderr:\n${stderr}")
        message(FATAL_ERROR "${NAME} variant '${label}' exited with ${result}, expected 0")
    endif()

    # chroot 模式：清理临时 rootfs
    if(DEFINED ROOT)
        file(REMOVE_RECURSE "${rootfs}")
    endif()
endforeach()
