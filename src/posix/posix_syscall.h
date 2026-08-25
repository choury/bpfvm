#ifndef POSIX_SYSCALL_H__
#define POSIX_SYSCALL_H__
#include "insn.h"
#include "posix/fs.h"   // Fd/Path 多态层次及 GuestTty/PtySide 等（实现见 fs.cpp/procfs.cpp）

#include <unordered_map>
#include <array>
#include <deque>
#include <memory>
#include <mutex>
#include <optional>
#include <unistd.h>
#include <fcntl.h>   // AT_FDCWD（guest_abs_path/resolve_path 的 dirfd 默认值）
#include <sys/socket.h>   // sockaddr/socklen_t（sockaddr_to_host/to_guest 声明）

// 信号队列扫描上限（handle_signals 单轮最多处理的信号数，防止极端情况下死循环）。
// 原 MpscQueue 的固定容量；改 deque+锁后队列本身无界，此常量仅作单轮 drain 上限。
#define BPF_SIGNAL_QUE_SIZE 1024

// 会话（session）：setsid 创建，sid == leader->pid。
// 持有控制终端 ctty（shared_ptr<GuestTty>，nullptr = 无 ctty）。前台组挂在 GuestTty 上。
struct Session {
    uint64_t sid;
    std::shared_ptr<GuestTty> ctty;   // 控制终端；setsid 后置 nullptr（脱离），TIOCSCTTY 绑定
    explicit Session(uint64_t sid) : sid(sid) {}
};

// 进程组（process group）：setpgid/setsid 创建/修改，pgid == leader->pid。
// 同 pgid 必同 session。多个 task 通过 shared_ptr 共享同一 ProcessGroup 对象；
// setpgid 替换 shared_ptr 即"离组加组"，无需通知旧组。
struct ProcessGroup {
    uint64_t pgid;
    std::shared_ptr<Session> session;
    ProcessGroup(uint64_t pgid, std::shared_ptr<Session> session)
        : pgid(pgid), session(std::move(session)) {}
};

// 线程组生命周期状态（CLONE_THREAD 共享；fork 新建）。
// tgid = leader 的 tid。live_threads 归 0 时进程可被 waitpid 回收。
struct ThreadGroup {
    uint64_t tgid;
    // 父进程 pid（进程级：同组所有线程共享同一父进程，getppid 对所有线程返回同值）。
    // CLONE_THREAD 共享父 tg 自动继承；fork 新建 tg 时由 do_clone 显式 store 父 tgid；
    // 孤儿 reparent 时整组改。
    std::atomic<uint64_t> ppid{0};
    std::atomic<size_t> live_threads{1};
    std::atomic<bool> exited{false};
    // 整组对外报告的退出码（waitpid 读此值）。初值 -1 = 未设。
    // exit/exit_group/被信号杀（走 do_exit）均用 CAS(-1->code) 写入：首个正常退出者
    // 赢，后续不覆盖。被 exit_group 置 VM_KILLED 的线程不走 do_exit，fini 里不碰此值，
    // 故不会覆盖 winner 设的码。last 线程 fini 时若仍为 -1（整组无人正常退出，理论上
    // 不会发生——置 VM_KILLED 的调用方必先走过 do_exit_group），兜底置 137。
    std::atomic<int> exit_code{-1};
    // —— job-control 停止状态（thread-group 级，整组一致）——
    // stop 是进程级语义：SIGSTOP/SIGTSTP/SIGTTIN/SIGTTOU 停止整个线程组，故状态放tg而非vm
    // stopped       —— 整组处于停止态（waitpid WUNTRACED 查此位）
    // stop_sig      —— 停止信号号（WSTOPSIG 用；musl WIFSTOPPED 要求 status 低字节 0x7f、
    //                  高字节为信号号）
    // stop_reported —— SIGCHLD 去重：停止后给父进程投一次 SIGCHLD 后置 true，waitpid
    //                  消费（报告 WIFSTOPPED）后清零，使下次停止能再投。避免重复通知。
    std::atomic<bool> stopped{false};
    std::atomic<int>  stop_sig{-1};
    std::atomic<bool> stop_reported{false};
    std::mutex mtx;
    // 等待本组事件的 vm 列表（waitpid 的父进程 / exec 等同组线程收敛）。
    // 可报告事件（exit/stop）或同组线程退出时，wake_waiters 摘所有等待者并 wakeup(true)。
    std::vector<std::weak_ptr<vm>> waiters;
    // 摘除一个等待者（幂等：waker 路径已摘或已失效则空操作）。等待者正常退出 wait_for
    // 时自清，减少失效 weak_ptr 积压；析构兜底由 weak_ptr 失效保证。
    void remove_waiter(vm* v) {
        std::lock_guard<std::mutex> lk(mtx);
        std::erase_if(waiters, [v](const std::weak_ptr<vm>& w){
            return w.expired() || w.lock().get() == v;
        });
    }
    // 唤醒所有等待者并清空列表。摘取列表在锁内、wakeup 在锁外：wakeup 取 vm::wait_mutex，
    // 锁序 mtx -> wait_mutex 与 stop_process 既有约定一致；锁外 broadcast 避免长广播持锁。
    void wake_waiters() {
        std::vector<std::weak_ptr<vm>> to_wake;
        {
            std::lock_guard<std::mutex> lk(mtx);
            to_wake.swap(waiters);
        }
        for(auto& w : to_wake) {
            if(auto sp = w.lock()) sp->wakeup(true);
        }
    }
    std::vector<std::weak_ptr<vm>> threads;
    explicit ThreadGroup(uint64_t t) : tgid(t) {}
};

// 信号事件：既作 queue_signal 的入参，也作 SignalQueue 的元素。携带 siginfo 投递所需的字段。
//   sig     —— 信号号
//   sender  —— 发送方 pid（0 = kernel/host，对齐 Linux si_pid 语义）。pid 在
//              PosixSyscall 是 uint64_t，故此处用 uint64_t，免得调用方到处 cast。
//   code    —— si_code：SI_USER（kill/raise）、SI_KERNEL（kernel/tty）、CLD_*（SIGCHLD）
//   status  —— si_status：SIGCHLD 事件有效（CLD_EXITED=退出码、CLD_KILLED=信号号、
//              CLD_STOPPED=停止信号号），其余场景为 0
struct SigEvent {
    int sig;
    uint64_t sender;
    int32_t code;
    int32_t status;
};

// 信号队列：deque + 互斥锁。
//
// 容量上限 = BPF_SIGNAL_QUE_SIZE：push 满则丢弃（与原 MpscQueue 一致，
// 防止信号风暴下 deque 无限增长 OOM）。实现见 signal_queue.cpp。
class SignalQueue {
    std::deque<SigEvent> q_;
    std::mutex mtx_;
public:
    // 入队。满（size >= BPF_SIGNAL_QUE_SIZE）则丢弃，返回 false。调用方据此决定
    // 是否置 flag / wakeup（丢弃的信号不影响 VM_SIGNAL_PENDING 状态）。
    bool push(SigEvent v);
    // 出队。空则返回 false。
    bool pop(SigEvent& v);
    // 是否为空。供 waitpid/do_sigprocmask 等只需 peek 的调用方使用。
    bool empty();
    // 给 handle_signals 用：暴露锁让 drain + flag 维护原子化。
    // 调用方必须持 mtx() 后再访问 raw()。
    std::mutex& mtx() { return mtx_; }
    std::deque<SigEvent>& raw() { return q_; }
};

#ifndef NSIG
#define NSIG 32
#endif

class PosixSyscall: public SyscallHandler{
    struct signal_action {
        uint64_t handler = 0;
        uint64_t mask = 0;
        int flags = 0;
    };

    // CLONE_THREAD / CLONE_FILES / CLONE_SIGHAND / CLONE_FS 共享的进程级状态。
    // CLONE_THREAD: 整体共享。fork: 整体拷贝（make_shared + 复制内容）。
    struct SharedState {
        std::string cwd;
        std::array<signal_action, NSIG> signal_actions{};
        // chroot 根目录（宿主绝对路径，无尾斜杠）。空 = 不 chroot。
        // 随 fork/clone 自动传播（与 cwd 同级）。ps->cwd 存 guest 视角路径，
        // resolve_path 负责 cwd -> 宿主路径时拼上此 root。
        std::string root;
        // guest 程序路径（/proc/[pid]/exe symlink 目标，guest 视角绝对路径）。
        // 进程级（mm_struct::exe_file）：do_execveat 成功后更新；main.cpp 初次加载时补写。
        std::string exe_path;
        // 文件创建掩码（进程级，fs_struct::umask）。openat/mkdir 等按 mode & ~umask 生效。
        uint32_t umask = 0022;

        using FdMap = std::unordered_map<int, std::shared_ptr<Fd>>;
        // fds 表采用 Copy-on-Write 不可变快照：写整表复制 + 换入，读者持有不可变快照，
        // 阻塞调用（epoll_pwait/poll/read 等）任意久都不会和写冲突，避免"持锁调阻塞
        // host syscall"的死锁。被 close 的 Fd 随旧快照延迟析构（host fd 延迟关闭），
        // 对齐 Linux file 引用计数语义。
        //
        AtomicSharedPtr<const FdMap> fds;

        SharedState() : fds(std::make_shared<const FdMap>()) {}
        // AtomicSharedPtr 不可拷贝构造，手写 copy ctor：其它字段逐字段拷贝，fds 共享
        // 同一不可变快照（fork 语义：父子共享 fd 表，之后各自 COW 独立）。
        SharedState(const SharedState& o)
            : cwd(o.cwd), signal_actions(o.signal_actions), root(o.root),
              exe_path(o.exe_path), umask(o.umask),
              fds(AtomicSharedPtr<const FdMap>(o.fds.load())) {}
        SharedState& operator=(const SharedState&) = delete;

        // 单 fd 查找：返回 shared_ptr<Fd>（找不到为 nullptr）。持有返回值期间该 Fd
        // 存活，锁外调阻塞 host syscall 安全。
        std::shared_ptr<Fd> find_fd(int fd) const {
            auto snap = fds.load();
            auto it = snap->find(fd);
            return it == snap->end() ? nullptr : it->second;
        }
        std::shared_ptr<const FdMap> fds_snap() const {
            return fds.load();
        }
        // COW 写：f 必须是纯表修改（不可阻塞 / 投信号 / 调 host syscall）。
        template <class F>
        void fds_mutate(F&& f) {
            auto cur = fds.load();
            while(true) {
                auto next = std::make_shared<FdMap>(*cur);
                f(*next);
                if(fds.compare_exchange(cur, std::const_pointer_cast<const FdMap>(next))) {
                    break;
                }
            }
        }
        void fds_replace(std::shared_ptr<const FdMap> new_snap) {
            fds.store(std::move(new_snap));
        }
        int fds_emplace(std::shared_ptr<Fd> handle, int min_fd = 0) {
            int fd = min_fd;
            fds_mutate([&](FdMap& m){
                fd = min_fd;
                while(m.count(fd)) fd++;
                m[fd] = std::move(handle);
            });
            return fd;
        }
    };

    static std::atomic<uint64_t> next_pid;
    static std::unordered_map<uint64_t, std::shared_ptr<vm>> pid_map;
    static std::mutex pid_map_mutex;
    pthread_t tid = 0;
    // 信号掩码（POSIX sigprocmask）：bit (sig-1) 表示信号 sig 被阻塞（与 Linux 内核/
    // musl sigset_t ABI 一致）。SIGKILL/SIGSTOP 不可阻塞（do_sigprocmask 强制清对应位）。
    // 仅在 handle_signals 投递端过滤；queue_signal 无条件入队，被阻塞的信号留在
    // pending_signals 里，解锁后 safepoint 重扫时自然投出（实时信号统一模型）。
    std::atomic<uint64_t> sigmask{0};
    SignalQueue pending_signals;
    // set_tid_address / CLONE_CHILD_CLEARTID 设置；线程退出时清零并 futex_wake。
    uint64_t tid_address_ = 0;

    // 信号默认动作判定：是否为"可忽略"信号——即 SIG_IGN，或 SIG_DFL 且默认动作为
    // Ign(SIGCHLD/SIGURG/SIGWINCH)/Cont(SIGCONT)。这类信号投递给进程不会改变其状态，
    // 也不会打断阻塞中的系统调用（对齐 Linux：get_signal 不让 Ign/Cont 信号产生 EINTR）。
    // SIGKILL/SIGSTOP 调用方已特判，不会进入此函数。
    bool signal_ignorable(int sig);
    // 把信号投给指定 vm 的内部接口。
    void queue_signal(vm* v, const SigEvent& ev);
    // 停止整个线程组（SIGSTOP/SIGTSTP/SIGTTIN/SIGTTOU）：设 tg 级停止状态 + 组内每线程
    // VM_STOPPED + 给父进程投一次 SIGCHLD（去重）。stop 是进程级，整组一致
    void stop_process(int sig);
    // 给父进程（ppid 指向的 vm）投 SIGCHLD。find_task(ppid) 取父 vm -> sys()->queue_signal。
    // 父进程可能是 EmptySyscall（测试）或已退出，此时降级为 no-op。
    void notify_parent_sigchld();

public:
    const uint64_t pid;          // task id（== tid）。gettid 返回此值。
    // 程序名（/proc/[pid]/comm，basename(exe)，<=15 字节，Linux TASK_COMM_LEN-1）。
    std::string comm_;
    // —— 进程标识（procfs 自由函数直接读，字段 public 不加 getter 包装）——
    std::shared_ptr<SharedState> ps;
    std::shared_ptr<ThreadGroup> tg;  // 线程组生命周期（CLONE_THREAD 共享；fork 新建）。
    // 进程组/会话。fork 继承父的 shared_ptr（共享同一对象）；setpgid/setsid 替换为新对象。
    std::shared_ptr<ProcessGroup> pgrp;
    std::shared_ptr<Session> session;

    virtual void init(const std::shared_ptr<vm>& v) override;
    virtual void fini(const std::shared_ptr<vm>& v) override;
    virtual bool handle_signals(vm* v, sig_info* info) override;
    virtual int64_t (syscall)(vm* v, uint32_t call) override;
    virtual int id() override {
        return (int)pid;
    }
    static std::shared_ptr<PosixSyscall> sys(vm* v_);
    static std::shared_ptr<vm> find_task(uint64_t target_pid);
    // 枚举当前存活的所有 guest pid（pid_map 的 key 快照，持锁内拷贝）。
    // 供 procfs 枚举 /proc 顶层 [pid] 目录（pid_map 本身 private，不暴露内部表示）。
    static std::vector<uint64_t> list_pids();
    // futex 实现：等待者阻塞在 vm 自身 wait_cv 上，由 VM_BLOCKED 标志协调唤醒。
    // 见 posix/futex.cpp 中 futex_wait/futex_wake。
    static int futex_wait(vm* v, ThreadGroup* tg, uint64_t addr, uint32_t val,
                          const struct timespec* timeout);
    static int futex_wake(ThreadGroup* tg, uint64_t addr, int val);

    struct wait_event {
        std::shared_ptr<vm> child;
        bool exited = false;      // true=报告退出（WIFEXITED/WIFSIGNALED），false=报告停止
        int stop_sig = 0;         // 停止信号（仅 exited==false 有效）
        uint64_t exit_code = 0;   // 子 exit_code：<128=正常退出码，>=128=128+sig（信号致死）
    };
    int64_t do_wait_common(vm* v, int idtype, int64_t id, int options, wait_event& out);

    PosixSyscall();
    // fork/clone 子进程构造：继承父的 pgrp/session（shared_ptr 共享同一对象）。
    PosixSyscall(std::shared_ptr<ProcessGroup> pgrp, std::shared_ptr<Session> session);

    int allocate_fd(int min_fd = 0);
    bool read_c_string(vm* v, uint64_t addr, std::string& out, size_t max_len);
    bool read_c_string_array(vm* v, uint64_t addr, std::vector<std::string>& out, size_t max_count, size_t max_str_len);
    // 把任意 guest 路径（相对则用 dirfd 对应目录或 cwd）规范化为 guest 视角的绝对路径
    // 用于 Fd::path 存储与特殊设备（/dev/ptmx 等）匹配 —— 这些都应基于 guest 命名空间。
    std::string guest_abs_path(const std::string& path, int dirfd = AT_FDCWD);

    // AF_UNIX pathname 地址的 chroot 视角转换
    // 入向 guest sun_path -> 宿主路径，出向宿主写回的地址剥回 guest 视角。语义见 socket.cpp。
    const struct sockaddr* sockaddr_to_host(const struct sockaddr* addr, socklen_t len,
                                            struct sockaddr_storage* out, socklen_t* out_len);
    void sockaddr_to_guest(struct sockaddr* addr, socklen_t* len, socklen_t capacity);

    // 宿主侧信号（物理终端 ^C/^Z/^\ / 终端挂断 / 外部 kill 给 bpfvm）转交 handler 路由。
    // 凭本 handler 掌握的 session/ctty/前台组决定目标：有控制终端->发到 ctty 的前台
    // 进程组所有成员（tty 信号语义）；无 ctty->退化为投给该 vm 自身。
    virtual void host_signal(vm* v, int sig) override;

    // job-control 门控：检查对 fd 的后台 tty 访问是否需要投 SIGTTIN(read)/SIGTTOU(write)。
    // 返回 nullopt 表示放行真正 I/O；返回非空表示已拦截（已投信号），其值即 syscall 返回值。
    // 仅当 fd 是本 session ctty 且调用者非前台组时触发。
    std::optional<int64_t> tty_bg_check(vm* v, const std::shared_ptr<Fd>& fd, bool is_read);

    // 向控制终端的前台进程组（tty->fg_pgrp）投递 tty 信号。tty==nullptr 时退化为按
    // 调用者 session 选目标组。host_signal（宿主->guest 路由）与 do_close 的 pty master
    // 关闭发 SIGHUP（对齐 Linux tty_vhangup 语义）共用此路径。
    void deliver_to_ctty_fg(vm* v, GuestTty* tty, int sig);


    // —— SyscallHandler protected 静态访问器的公开转发：procfs 自由函数要读 vm* 的
    //    options/maps/flags（protected），非成员够不到，经此转发。——
    static auto& options_of(vm* v) { return options(v); }
    static auto& maps_of(vm* v) { return maps(v); }
    static auto& maps_mutex_of(vm* v) { return maps_mutex(v); }

    int64_t do_clock_gettime(vm* v);
    int64_t do_mmap(vm* v);
    int64_t do_munmap(vm* v);
    int64_t do_exit(vm* v);
    int64_t do_nanosleep(vm* v);
    int64_t do_openat(vm* v);
    int64_t do_read(vm* v);
    int64_t do_write(vm* v);
    int64_t do_lseek(vm* v);
    int64_t do_truncate(vm* v);
    int64_t do_ftruncate(vm* v);
    int64_t do_close(vm* v);
    int64_t do_unlinkat(vm* v);
    int64_t do_mkdirat(vm* v);
    int64_t do_symlinkat(vm* v);
    int64_t do_linkat(vm* v);
    int64_t do_renameat2(vm* v);
    int64_t do_readlinkat(vm* v);
    int64_t do_execveat(vm* v);
    int64_t do_clone(vm* v);
    int64_t do_getpid(vm*);
    int64_t do_getppid(vm*);
    int64_t do_getuid(vm*);
    int64_t do_geteuid(vm*);
    int64_t do_getgid(vm*);
    int64_t do_getegid(vm*);
    int64_t do_getgroups(vm* v);
    int64_t do_wait4(vm* v);
    int64_t do_waitid(vm* v);
    int64_t do_dup(vm* v);
    int64_t do_dup3(vm* v);
    int64_t do_pipe2(vm* v);
    int64_t do_fchdir(vm* v);
    int64_t do_getcwd(vm* v);
    int64_t do_statx(vm* v);
    int64_t do_fchmodat(vm* v);
    int64_t do_utimensat(vm* v);
    int64_t do_faccessat(vm* v);
    int64_t do_kill(vm* v);
    int64_t do_tkill(vm* v);
    int64_t do_tgkill(vm* v);
    int64_t do_sigaction(vm* v);
    int64_t do_sigprocmask(vm* v);
    int64_t do_setpgid(vm* v);
    int64_t do_getpgid(vm* v);
    int64_t do_getpgrp(vm*);
    int64_t do_setsid(vm*);
    int64_t do_getsid(vm* v);
    int64_t do_fcntl(vm* v);
    int64_t do_ioctl(vm* v);
    int64_t do_umask(vm* v);
    int64_t do_sigsetjmp(vm* v);
    int64_t do_siglongjmp(vm* v);
    int64_t do_mprotect(vm* v);
    int64_t do_readv(vm* v);
    int64_t do_writev(vm* v);
    int64_t do_pread(vm* v);
    int64_t do_pwrite(vm* v);
    int64_t do_getrandom(vm* v);
    int64_t do_getdents64(vm* v);
    int64_t do_set_tid_address(vm* v);
    int64_t do_exit_group(vm* v);
    int64_t do_madvise(vm*);
    int64_t do_sched_yield(vm*);
    int64_t do_gettid(vm*);
    int64_t do_set_tls(vm* v);
    int64_t do_get_tls(vm* v);
    int64_t do_futex(vm* v);
    int64_t do_alloca(vm* v);
    int64_t do_poll(vm* v);
    int64_t do_pselect6(vm* v);
    int64_t do_socket(vm* v);
    int64_t do_socketpair(vm* v);
    int64_t do_bind(vm* v);
    int64_t do_listen(vm* v);
    int64_t do_connect(vm* v);
    int64_t do_accept4(vm* v);
    int64_t do_sendto(vm* v);
    int64_t do_recvfrom(vm* v);
    int64_t do_sendmsg(vm* v);
    int64_t do_recvmsg(vm* v);
    int64_t do_shutdown(vm* v);
    int64_t do_setsockopt(vm* v);
    int64_t do_getsockopt(vm* v);
    int64_t do_getsockname(vm* v);
    int64_t do_getpeername(vm* v);
    int64_t do_epoll_create1(vm* v);
    int64_t do_epoll_ctl(vm* v);
    int64_t do_epoll_pwait(vm* v);
    int64_t do_signalfd4(vm* v);
};

#endif
