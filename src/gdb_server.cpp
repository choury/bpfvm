//
// GDB Remote Serial Protocol (RSP) server 实现。详见 gdb_server.h。
//

#include "gdb_server.h"
#include "posix/posix_syscall.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>

#include <cstring>
#include <cstdio>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

GdbServer::GdbServer(std::shared_ptr<vm> main_vm, uint16_t port, bool stop_at_start)
    : main_vm(main_vm),current_vm(main_vm), port_(port), stop_at_start_(stop_at_start){}

GdbServer::~GdbServer() {
    // 关闭 listen fd 拒绝新连接；client fd 由 server_loop 在 GDB 断开或 vm 退出后自行关闭。
    // server_loop 用带超时的 recv（SO_RCVTIMEO）周期性检查 running_，从而在收到停止信号后能及时退出。
    //
    // 注意：不能用 `if(!running_.exchange(false)) return;` 提前返回——server_loop 的 LoopExitGuard
    // 在退出时会把 running_ 置 false（如 GDB 断开后自然退出），此时析构再走 exchange 返回 false 会
    // 直接 return，跳过下面的 thread_.join()，导致 std::thread 析构时仍 joinable -> std::terminate
    // （kill 场景必现崩溃）。是否要 join 只取决于 thread_.joinable()，与 running_ 的值无关。
    running_ = false;
    if(listen_fd_ >= 0) {
        shutdown(listen_fd_, SHUT_RDWR);
        close(listen_fd_);
        listen_fd_ = -1;
    }
    if(thread_.joinable()) {
        // 轮询等待 server_loop 自然退出（GDB 断开或 vm 退出），最多 ~6 秒。
        // running_ 已 false，server 应在 <=0.2s（一个 recv 超时周期）内退出；超时则
        // 强制关 client fd 让阻塞中的 recv 返回后再 join。
        for(int i = 0; i < 60 && !loop_done_.load(std::memory_order_acquire); i++) {
            timespec ts{0, 100000000};  // 0.1s
            nanosleep(&ts, nullptr);
        }
        if(!loop_done_.load(std::memory_order_acquire)) {
            if(client_fd_ >= 0) { ::shutdown(client_fd_, SHUT_RDWR); ::close(client_fd_); client_fd_ = -1; }
        }
        thread_.join();
    }
}

void GdbServer::start() {
    // 装 debug hooks（create/syscall/breakpoint）到 main_vm。必须在 run() 前：hooks 在 fork 时由
    // 子快照继承（notify_create），run 后才装则 attach 前 fork 出的进程树拿不到 hook，后续 vAttach
    // 也无法跟踪它们的 fork。钩子常驻各 vm，attach/detach 只用 VM_DEBUG_ATTACHED flag 当开关——未
    // attach 时 create 回调因父无 ATTACHED 提前返回、breakpoint 钩子查空 tasks_ 查不到，均无副作用。
    auto hooks = std::make_shared<DebugHooks>();
    hooks->create = [this](vm* p, vm* c, bool t){ this->on_create_vm(p, c, t); };
    hooks->syscall_entry = make_syscall_cb(true);
    hooks->syscall_return = make_syscall_cb(false);
    // breakpoint 钩子：命中断点或消费单步请求时 set VM_DEBUG_STOP。已被请求停则早返保持 flag。
    hooks->breakpoint = [this](vm* v) -> void {
        if(v->get_flags() & vm::VM_DEBUG_STOP) return;
        uint64_t pc = v->pc();
        // vm 不在表里（未 attach）则不停。命中断点或 stepping 即 set flag 当生产者。
        with_task(v, [&](TaskEntry& e){
            if(e.stepping) {
                e.stepping = false;              // 消费单步/step-over 请求
                v->set_flags(vm::VM_DEBUG_STOP);
            } else if(e.breakpoints.count(pc)) {
                v->set_flags(vm::VM_DEBUG_STOP);
            }
        });
    };
    main_vm->set_debug_hooks(hooks);

    if(stop_at_start_) {
        // --stop（对齐 QEMU -S）：run() 前冻结主 vm 在入口。必须在 run() 启动前设置，否则与首条指令
        // 竞态。此处不能调 register_task/request_stop——它们内部用 v->sys()->id() 取 pid，而
        // vm::run() 才会把 options（含 sys）赋给 vm（run 前 vm->options.sys 是空 shared_ptr）。
        // 根进程 pid 恒为 1，直接用字面量建 entry。GDB 连上后 attach_on_connect 会用 sys() 重新
        // register（insert_or_assign 覆盖此临时 entry）。
        main_vm->set_flags(vm::VM_DEBUG_ATTACHED | vm::VM_DEBUG_STOP);
        std::lock_guard<std::mutex> lk(tasks_mutex_);
        tasks_[1] = TaskEntry{main_vm, {}, {}};
    }
    // 默认（不带 --stop）：不在 start 登记 main_vm——它是 GDB attach 后才接管的调试簿记，
    // 由 attach_on_connect() 首次连接时 register + 停在当前 pc。主 vm 全速 JIT 跑到那时。
    running_ = true;
    thread_ = std::thread([this] { server_loop(); });
}

// ── hex 工具 ──────────────────────────────────────────────────────────────
int GdbServer::hex_val(char c) {
    if(c >= '0' && c <= '9') return c - '0';
    if(c >= 'a' && c <= 'f') return c - 'a' + 10;
    if(c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

std::string GdbServer::to_hex2(uint8_t v) {
    static const char* d = "0123456789abcdef";
    std::string s;
    s += d[(v >> 4) & 0xF];
    s += d[v & 0xF];
    return s;
}

std::string GdbServer::reg_to_hex(uint64_t v) {
    // 小端：低字节在前
    std::string s;
    for(int i = 0; i < 8; i++) s += to_hex2((v >> (i * 8)) & 0xFF);
    return s;
}

uint64_t GdbServer::hex_to_reg(const std::string& s) {
    uint64_t v = 0;
    for(int i = 0; i < 8 && (size_t)(i * 2) < s.size(); i++) {
        int hi = hex_val(s[i * 2]);
        int lo = hex_val(s[i * 2 + 1]);
        if(hi < 0 || lo < 0) break;
        v |= (uint64_t)((hi << 4) | lo) << (i * 8);
    }
    return v;
}

std::string GdbServer::hex_encode(const void* data, size_t len) {
    auto* p = static_cast<const unsigned char*>(data);
    std::string s;
    s.reserve(len * 2);
    for(size_t i = 0; i < len; i++) s += to_hex2(p[i]);
    return s;
}

bool GdbServer::hex_decode(const std::string& s, void* out, size_t len) {
    if(s.size() < len * 2) return false;
    auto* p = static_cast<unsigned char*>(out);
    for(size_t i = 0; i < len; i++) {
        int hi = hex_val(s[i * 2]);
        int lo = hex_val(s[i * 2 + 1]);
        if(hi < 0 || lo < 0) return false;
        p[i] = (unsigned char)((hi << 4) | lo);
    }
    return true;
}

// ── RSP 包 I/O ────────────────────────────────────────────────────────────
// 单字节可靠接收：SO_RCVTIMEO 超时（EAGAIN/EWOULDBLOCK）和被信号打断（EINTR）时
// 重试——GDB 握手时会流水线连发多个包，单字节 recv 可能在包中间超时，若直接当
// 错误返回会截断包导致校验和失败。仅以下情况返回 false：EOF、硬错误、或 running_
// 被外部（stop()）置 false（此时不再重试，让 recv_packet 返回，server 退出）。
bool GdbServer::recv_byte(char& out) {
    for(;;) {
        if(!running_) return false;
        ssize_t n = recv(client_fd_, &out, 1, 0);
        if(n == 1) return true;
        if(n == 0) return false;  // EOF
        if(errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) continue;
        return false;  // 硬错误
    }
}

bool GdbServer::recv_packet(std::string& out) {
    // 略过 ack '+'/'-'（no_ack 模式下理论上不会来，但容错跳过）和 Ctrl-C (0x03)
    char c;
    for(;;) {
        if(!recv_byte(c)) return false;
        if(c == '$') break;
        // 其余（+, -, 0x03）忽略
    }
    std::string data;
    uint8_t cksum = 0;
    for(;;) {
        if(!recv_byte(c)) return false;
        if(c == '#') break;
        data += c;
        cksum += (uint8_t)c;
    }
    // 校验和两 hex
    char cs[2];
    if(!recv_byte(cs[0])) return false;
    if(!recv_byte(cs[1])) return false;
    int hi = hex_val(cs[0]), lo = hex_val(cs[1]);
    if(!no_ack_) {
        char ack = (hi < 0 || lo < 0 || (uint8_t)((hi << 4) | lo) != cksum) ? '-' : '+';
        send(client_fd_, &ack, 1, 0);
    }
    out = data;
    return true;
}

void GdbServer::send_packet(const std::string& payload) {
    uint8_t cksum = 0;
    for(char c : payload) cksum += (uint8_t)c;
    std::string pkt = "$" + payload + "#";
    pkt += to_hex2(cksum);
    // 简单发送（payload 小，TCP 缓冲足够）
    size_t off = 0;
    while(off < pkt.size()) {
        ssize_t n = send(client_fd_, pkt.data() + off, pkt.size() - off, 0);
        if(n <= 0) break;
        off += (size_t)n;
    }
}

// ── vm 状态访问 ──────────────────────────────────────────────────────────

// tasks_ helper 实现。接口语义与约束见 gdb_server.h。tasks_ 内部仍以 pid 为 key，
// with_task/has_breakpoint/mark_stepping/register_task 用 v->sys()->id() 取 key。
void GdbServer::for_each_task(std::function<void(TaskEntry&)> fn) {
    std::lock_guard<std::mutex> lock(tasks_mutex_);
    for(auto& kv : tasks_) fn(kv.second);
}

bool GdbServer::with_task(vm* v, std::function<void(TaskEntry&)> fn) {
    std::lock_guard<std::mutex> lock(tasks_mutex_);
    auto it = tasks_.find(v->sys()->id());
    if(it == tasks_.end()) return false;
    fn(it->second);
    return true;
}

// 退出后的 vm 仍在表里（直到 send_exit_reply/detach_vm 移除），故可读 r(0)/tgid 发退出回复。
// 仅 wire 入口（H/vAttach/vKill/T/D，只有 pid 字符串）走此 pid 重载；其余手头有 vm 的路径用 with_task。
std::shared_ptr<vm> GdbServer::find_task(uint64_t pid) {
    std::lock_guard<std::mutex> lock(tasks_mutex_);
    auto it = tasks_.find(pid);
    if(it == tasks_.end()) return nullptr;
    return it->second.vmp;
}

void GdbServer::register_task(std::shared_ptr<vm> v,
                              std::unordered_set<uint64_t> bps) {
    // 必须先算出 key（v->sys()->id()），再 std::move(v) 进 TaskEntry：二者同属一个全表达式，
    // C++ 里函数实参的求值顺序未排序（unsequenced），若写成
    //   tasks_.insert_or_assign(v->sys()->id(), TaskEntry{std::move(v), ...});
    // 编译器可能先执行 TaskEntry{std::move(v)}（把 v 移空），再求值 v->sys()，
    // 解引用已移空的 shared_ptr -> SIGSEGV（gcc 14 实测就是这么排的）。
    uint64_t pid = v->sys()->id();
    std::lock_guard<std::mutex> lock(tasks_mutex_);
    tasks_.insert_or_assign(pid, TaskEntry{std::move(v), std::move(bps), {}});
}

bool GdbServer::has_breakpoint(vm* v, uint64_t addr) const {
    std::lock_guard<std::mutex> lock(tasks_mutex_);
    auto it = tasks_.find(v->sys()->id());
    return it != tasks_.end() && it->second.breakpoints.count(addr) != 0;
}

// 取 vm 所属线程组 id（tgid）。multiprocess 线程 id 形如 pPID.TID，其中 PID 是进程级
// 标识（tgid）、TID 是线程级标识（vm 的 pid）。leader 线程的 pid==tgid；非 leader 线程
// pid!=tgid。sys 为非 PosixSyscall（测试 EmptySyscall）时退化为 pid。
uint64_t GdbServer::vm_tgid(vm* v) {
    if(auto s = PosixSyscall::sys(v)) return s->tg->tgid;
    return (uint64_t)v->sys()->id();
}

// 把 vm 编码成 RSP 线程 id 字符串。multiprocess 关闭：裸 hex pid（如 "1"）；
// 开启：pPID.TID（如 "p1.1"，PID=tgid、TID=pid）。调用方手边有 vm 时直接传，省一次查表。
std::string GdbServer::encode_tid(vm* v) {
    uint64_t pid = v->sys()->id();
    char buf[64];
    if(!multiprocess_) {
        std::snprintf(buf, sizeof(buf), "%lx", (unsigned long)pid);
        return buf;
    }
    uint64_t tgid = vm_tgid(v);
    std::snprintf(buf, sizeof(buf), "p%lx.%lx", (unsigned long)tgid, (unsigned long)pid);
    return buf;
}

// 解析 RSP 线程 id 字符串为 vm（内部 find_task 查表）。
//   裸 hex（"1"/"2a"）：按裸 pid 处理。
//   pPID.TID（"p1.1"）：multiprocess 格式，取 TID 段作为 pid。
//   "0"/"-1"/"p0.0"/"p-1.-1"：RSP 特殊值（任意/所有）-> pid 0；pid 0 或查表不到均返回 nullptr。
std::shared_ptr<vm> GdbServer::decode_tid(const std::string& s, bool search_pid_map) {
    uint64_t pid = 0;
    if(!s.empty()) {
        if(s[0] == 'p') {
            std::string rest = s.substr(1);
            auto dot = rest.find('.');
            std::string tid_str = (dot == std::string::npos) ? rest : rest.substr(dot + 1);
            if(tid_str != "0" && tid_str != "-1")
                pid = std::strtoull(tid_str.c_str(), nullptr, 16);
        } else if(s != "0" && s != "-1") {
            pid = std::strtoull(s.c_str(), nullptr, 16);
        }
    }
    if(pid == 0) return nullptr;
    auto v = find_task(pid);
    if(!v && search_pid_map) v = PosixSyscall::find_task(pid);
    return v;
}

bool GdbServer::is_vm_exited(vm* v) {
    return v->get_flags() & (vm::VM_EXITED | vm::VM_KILLED);
}

void GdbServer::mark_stepping(vm* v) {
    // 单步/step-over 的放行信号（一次性，breakpoint 钩子查中即清 + set VM_DEBUG_STOP）。
    with_task(v, [](TaskEntry& e){ e.stepping = true; });
}

void GdbServer::request_stop(vm* v) {
    // 置 VM_DEBUG_STOP + wakeup（踢 debug_park / wait_for）+ host_signal（让 host 阻塞 syscall EINTR）。
    v->set_flags(vm::VM_DEBUG_STOP);
    v->wakeup(false);
    auto Sys = v->sys();
    if(Sys) Sys->host_signal(v, 0);
}

void GdbServer::attach_on_connect() {
    if(main_vm->get_flags() & vm::VM_DEBUG_ATTACHED) return;
    register_task(main_vm);
    main_vm->set_flags(vm::VM_DEBUG_ATTACHED);
    request_stop(main_vm.get());  // 停在当前 pc（set flag + wakeup + host_signal）
}

void GdbServer::end_session() {
    // 锁内收集 vmp 引用后 clear（for_each_task 的 fn 内不能 erase 当前迭代器）。
    std::vector<std::shared_ptr<vm>> to_release;
    {
        std::lock_guard<std::mutex> lk(tasks_mutex_);
        to_release.reserve(tasks_.size());
        for(auto& kv : tasks_) to_release.push_back(kv.second.vmp);
        tasks_.clear();
    }
    // 锁外清存活 vm 的调试态 + wakeup（exited 的随后析构；get_flags 原子读，锁外判 exited 安全）。
    // 不清 VM_STOPPED（POSIX 停止位，由 guest SIGCONT 恢复）。
    for(auto& v : to_release) {
        if(v->get_flags() & (vm::VM_EXITED | vm::VM_KILLED)) continue;
        v->clear_flags(vm::VM_DEBUG_ATTACHED | vm::VM_DEBUG_STOP);
        v->wakeup(false);
    }
    // 复位 RSP 协商态：每条连接是全新会话，上一会话的协商结果不应带过来（否则未协商的新 GDB
    // 会收到 pPID.TID 格式的 tid 但按裸 hex 解析，错乱）。在会话结束时清，下次连接进来即干净。
    // syscall_catch_ 也清：gap 期间 vm 的 syscall 钩子被 VM_DEBUG_ATTACHED 守卫拦住不会触发，
    // 但仍复位以免残留配置影响下次会话。
    no_ack_ = false;
    multiprocess_ = false;
    report_fork_events_ = false;
    report_exec_events_ = false;
    current_vm = main_vm;
    syscall_catch_.store(std::make_shared<const SyscallCatchCfg>());
}

// continue 即放弃本次协调：清所有 stepping/syscall_event（stop_all_vms 对运行中 vm mark 的
// stepping 若没被消费会残留，放行后下回解释器会误停；同时停下的 vm 的 pending syscall 事件也
// 需清，否则下次该 vm 因任何原因停下会被 try_send_syscall_stop 误当 syscall 停上报）。
void GdbServer::continue_all_vms() {
    for_each_task([](TaskEntry& e){
        e.stepping = false;
        e.syscall_event = {0, false};
        e.exec_path.clear();
        if(e.vmp->get_flags() & vm::VM_DEBUG_ATTACHED) {
            e.vmp->clear_flags(vm::VM_DEBUG_STOP);
            e.vmp->wakeup(false);
        }
    });
}

// host_signal 的必要性见文件头。
void GdbServer::stop_all_vms() {
    for_each_task([](TaskEntry& e){
        auto& v = e.vmp;
        uint32_t f = v->get_flags();
        if(!(f & vm::VM_DEBUG_ATTACHED)) return;
        if(f & (vm::VM_DEBUG_STOP | vm::VM_STOPPED | vm::VM_EXITED | vm::VM_KILLED)) return;
        v->set_flags(vm::VM_DEBUG_STOP);
        v->wakeup(false);   // 唤醒可能阻塞在 VM_BLOCKED / wait_for 的 vm（mask 含 VM_DEBUG_STOP）
        v->sys()->host_signal(v.get(), 0);
    });
}

void GdbServer::detach_vm(vm* v) {
    // 锁内取 vmp 引用 + erase entry（连断点/stepping/事件一并释放）。
    std::shared_ptr<vm> keep;
    {
        std::lock_guard<std::mutex> lk(tasks_mutex_);
        auto it = tasks_.find(v->sys()->id());
        if(it == tasks_.end()) return;
        keep = it->second.vmp;
        tasks_.erase(it);
    }
    if(keep->get_flags() & (vm::VM_EXITED | vm::VM_KILLED)) return;
    keep->clear_flags(vm::VM_DEBUG_ATTACHED | vm::VM_DEBUG_STOP);
    // 不清 VM_STOPPED（POSIX 停止位，由 guest SIGCONT 恢复）。
    keep->wakeup(false);
}

// 由父 vm 在 do_clone 内同步调用（父 vm 线程）。父未被 trace 时直接返回。
// 子继承父的断点集快照（拷贝）——对齐 gdb per-pspace：fork 时子继承父的断点位置，之后父子各自
// 独立增删。CLONE_THREAD 线程不报 fork 事件（靠 qfThreadInfo 发现）。
void GdbServer::on_create_vm(vm* parent, vm* child, bool is_thread) {
    if(!(parent->get_flags() & vm::VM_DEBUG_ATTACHED)) return;

    child->set_flags(vm::VM_DEBUG_ATTACHED);
    bool want_fork_event = (!is_thread && report_fork_events_);

    // 一次锁内完成：register 子 -> set VM_DEBUG_STOP(子 停首条) -> [fork-events: 写父 fork_child +
    // set VM_DEBUG_STOP(父 停)]。子停首条是 all-stop 正确性要求：派生的子必须立即停下纳入协调，
    // 否则会在父命中断点时自由跑完，破坏 all-stop。
    std::lock_guard<std::mutex> lk(tasks_mutex_);
    std::unordered_set<uint64_t> child_bps;
    auto pit = tasks_.find(parent->sys()->id());
    if(pit != tasks_.end()) child_bps = pit->second.breakpoints;

    auto& ce = tasks_[child->sys()->id()];
    ce.vmp = child->shared_from_this();
    ce.breakpoints = std::move(child_bps);
    child->set_flags(vm::VM_DEBUG_STOP);   // 子停首条指令

    if(want_fork_event && pit != tasks_.end()) {
        pit->second.fork_child = child;   // 存子 vm*（子已 register 进表），供 send_stop_reply 上报
        parent->set_flags(vm::VM_DEBUG_STOP);   // 父停 fork
    }
}

// syscall 钩子回调：在 vm 线程内同步执行（do_syscall 前后）。命中 catch 配置 / exec 事件则记待
// 上报事件 + set_flags(VM_DEBUG_STOP)（do_syscall 据此 debug_park）。return 钩子（is_entry=false）
// 额外处理 exec 事件。
std::function<void(vm*, uint32_t)> GdbServer::make_syscall_cb(bool is_entry) {
    return [this, is_entry](vm* v, uint32_t call) -> void {
        // exec 事件：仅 return 钩子、仅 EXECVEAT、仅成功时（r(0)==0，do_execveat 已替换地址空间）。
        // 先于 catch 配置判定——exec 是独立功能，不依赖 QCatchSyscalls。未 attach 则跳过。
        // call 是编码后的 BPF_CALL_ID(sysno)（含 0x10000 基址），用 BPF_CALL_TO_ID 还原后比较。
        if(!is_entry && BPF_CALL_TO_ID(call) == BPF_SYS_EXECVEAT
           && (v->get_flags() & vm::VM_DEBUG_ATTACHED)
           && (int64_t)v->r(0) == 0) {
            std::lock_guard<std::mutex> lk(tasks_mutex_);
            auto it = tasks_.find(v->sys()->id());
            if(it != tasks_.end() && report_exec_events_) {
                it->second.breakpoints.clear();  // 旧程序地址空间已失效
                it->second.exec_path = v->image()->exe;  // 宿主路径（GDB open 用）
                v->set_flags(vm::VM_DEBUG_STOP);  // 停新程序首条指令（all-stop 协调要求）
                return;  // debug_park：停住等 GDB continue
            }
        }
        auto cfg = syscall_catch_.load();
        if(!cfg->enabled) return;
        uint32_t sysno = BPF_CALL_TO_ID(call);
        bool hit = cfg->sysnos->empty() || cfg->sysnos->count(sysno) != 0;
        if(!hit) return;
        // 记待上报事件。pid 对应的 task 必已 register（fork 子经 on_create_vm 登记，主 vm 在 start）。
        {
            std::lock_guard<std::mutex> lk(tasks_mutex_);
            auto it = tasks_.find(v->sys()->id());
            if(it != tasks_.end()) it->second.syscall_event = {sysno, is_entry};
        }
        v->set_flags(vm::VM_DEBUG_STOP);  // 命中 catch：当生产者
    };
}

void GdbServer::resume(vm* v, bool single_step) {
    bool need_step_over = (!single_step) && has_breakpoint(v, v->pc());
    v->clear_flags(vm::VM_DEBUG_STOP);
    if(single_step || need_step_over) {
        // 单步/step-over：清 STOP 放行（debug_park 退出）+ 设 stepping；breakpoint 钩子消费 stepping
        // 并 set STOP 落实停。
        mark_stepping(v);
        v->wakeup(false);
        wait_stopped(v);
        if(is_vm_exited(v)) return;
    }
    if(single_step) return;  // 单步请求到此为止（已停）
    v->clear_flags(vm::VM_DEBUG_STOP);
    v->wakeup(false);
    wait_stopped(v);
}

// 越过断点（若命中）后放行，不阻塞等下次停下（交给调用方的 wait_any_stopped）。
void GdbServer::resume_continue(vm* v) {
    if(has_breakpoint(v, v->pc())) {
        // step-over：清 STOP 放行 + 设 stepping，钩子消费 stepping 落实停。
        v->clear_flags(vm::VM_DEBUG_STOP);
        mark_stepping(v);
        v->wakeup(false);
        wait_stopped(v);
        if(is_vm_exited(v)) return;
    }
    v->clear_flags(vm::VM_DEBUG_STOP);
    v->wakeup(false);
}

// 等待期间并发窥探 client socket 的 async Ctrl-C（裸 0x03，不带 $...# 框）。SIGUSR1 打断
// host 阻塞 syscall 的机制见文件头。
void GdbServer::wait_stopped(vm* v) {
    for(;;) {
        uint32_t f = v->get_flags();
        if(f & (vm::VM_DEBUG_STOP | vm::VM_EXITED | vm::VM_KILLED)) return;
        if(client_fd_ >= 0) {
            char peek;
            ssize_t n = recv(client_fd_, &peek, 1, MSG_PEEK | MSG_DONTWAIT);
            if(n == 1 && peek == '\x03') {
                recv(client_fd_, &peek, 1, MSG_DONTWAIT);  // 消费 0x03
                request_stop(v);  // set flag + wakeup + host_signal
                continue;
            }
        }
        struct timespec ts{0, 2000000};  // 2ms
        nanosleep(&ts, nullptr);
    }
}

// 向 GDB 报告 vm 退出（W 包，每个 vm 只发一次）。
// 幂等靠 tasks_ 表本身：发完即 erase，下次查不到该 vm 直接返回——无需独立计数/标记，
// 且天然 per-vm（多进程下各 vm 各自 erase，互不影响）。v 由调用方持 shared_ptr 保证存活，
// 故读 v->r(0)/vm_tgid 安全。
void GdbServer::send_exit_reply(vm* v) {
    uint64_t pid = v->sys()->id();
    {
        std::lock_guard<std::mutex> lk(tasks_mutex_);
        if(tasks_.find(pid) == tasks_.end()) return;  // 已上报过（已 erase）则不重复
    }
    unsigned long code = (unsigned long)(v->r(0) & 0xFF);
    char buf[64];
    // multiprocess 下 W 包带 ;process:<pid>（pPID.TID 的 PID 段）
    if(multiprocess_) {
        std::snprintf(buf, sizeof(buf), "W%02lx;process:%lx",
                      code, (unsigned long)vm_tgid(v));
    } else {
        std::snprintf(buf, sizeof(buf), "W%02lx", code);
    }
    send_packet(buf);
    // 上报退出后从 tracee 表移除（释放 shared_ptr 引用）。vm 对象若再无其它引用即析构。
    // 对齐 ptrace：tracer 上报 tracee 退出后即释放 task_struct 引用。
    std::lock_guard<std::mutex> lk(tasks_mutex_);
    tasks_.erase(pid);
}

// T<sig> + thread:<tid>（multiprocess 用 pPID.TID）。fork_child 非 null 时改发 fork 事件
// （T<sig>fork:<child>;thread:<tid>;，GDB 据此应用 follow-fork-mode / detach-on-fork）。
// 发送时把焦点设为命中的 vm：stop reply 隐式设置 server 端 general thread（后续无 Hg 的
// g/G/p/P 包操作目标），不更新则多 inferior 场景下 g 包会读到旧焦点的寄存器。
void GdbServer::send_stop_reply(vm* v, int sig, vm* fork_child) {
    current_vm = v->shared_from_this();
    char buf[80];
    std::snprintf(buf, sizeof(buf), "T%02x", (unsigned)(sig & 0xFF));
    std::string pkt = buf;
    if(fork_child) {
        // fork 事件直接用子的 vm* 上报 tid（on_create_vm 已把子 vm* 存进父 TaskEntry::fork_child）。
        pkt += "fork:" + encode_tid(fork_child) + ";";
    }
    pkt += "thread:" + encode_tid(v) + ";";
    send_packet(pkt);
}

// 查 pid 对应 task 的 syscall_event 字段是否有待上报事件。有则发 syscall 停止回复
// 并清字段（一次性消费），返回 true（已发）。无则返回 false（调用方发普通断点/fork回复）。
// 被 continue/step/vCont 在 wait_any_stopped 命中后调用：先 try_send_syscall_stop，
// 失败再 send_stop_reply/send_exit_reply，这样 syscall 停与断点/fork 停共用同一 all-stop
// 协调路径（wait_any_stopped 统一检测 VM_DEBUG_STOP 阻塞位），仅停止回复内容不同。
bool GdbServer::try_send_syscall_stop(vm* v) {
    uint64_t pid = v->sys()->id();
    uint32_t sysno;
    bool is_entry;
    {
        std::lock_guard<std::mutex> lk(tasks_mutex_);
        auto it = tasks_.find(pid);
        if(it == tasks_.end() || it->second.syscall_event.first == 0) return false;
        sysno = it->second.syscall_event.first;
        is_entry = it->second.syscall_event.second;
        it->second.syscall_event = {0, false};  // 一次性消费
    }
    // 锁外发送：send_packet 可能阻塞，不应持锁
    current_vm = v->shared_from_this();
    char snobuf[32];
    std::snprintf(snobuf, sizeof(snobuf), "%x", (unsigned)sysno);
    std::string reason = is_entry ? "syscall_entry:" : "syscall_return:";
    send_packet("T05" + reason + snobuf + ";thread:" + encode_tid(v) + ";");
    return true;
}

// 查 pid 对应 task 的 exec_path 字段是否有待上报事件。有则发 exec 停止回复
// 并清字段（一次性消费），返回 true（已发）。无则返回 false（调用方发普通断点/fork 回复）。
// 优先级见各 resume 入口：先 send_exec_stop，再 send_syscall_stop
bool GdbServer::try_send_exec_stop(vm* v) {
    uint64_t pid = v->sys()->id();
    std::string path;
    {
        std::lock_guard<std::mutex> lk(tasks_mutex_);
        auto it = tasks_.find(pid);
        if(it == tasks_.end() || it->second.exec_path.empty()) return false;
        path = std::move(it->second.exec_path);
    }
    // 锁外发送：send_packet 可能阻塞，不应持锁
    current_vm = v->shared_from_this();
    // exec 停止回复：T05exec:<hex-host-path>;thread:<tid>;（路径整体 hex 编码，非小端寄存器格式）。
    send_packet("T05exec:" + hex_encode(path.data(), path.size()) + ";thread:" + encode_tid(v) + ";");
    return true;
}

void GdbServer::wait_any_stopped(std::shared_ptr<vm>& out_hit_vm, vm* preferred,
                                 const std::vector<vm*>& watch_vms,
                                 vm** out_fork_child) {
    out_hit_vm.reset();
    if(out_fork_child) *out_fork_child = nullptr;
    bool propagated = false;
    // 快照本次观察目标。仅观察 VM_DEBUG_ATTACHED 的 vm——已 detach 进程的停止/退出绝不上报，
    // 否则 GDB 对已移除的 inferior 取状态会 internal-error。
    std::set<vm*> running_watch;
    if(watch_vms.empty()) {
        for_each_task([&](TaskEntry& e){
            if(e.vmp->get_flags() & vm::VM_DEBUG_ATTACHED)
                running_watch.insert(e.vmp.get());
        });
    } else {
        for(vm* v : watch_vms) running_watch.insert(v);
    }
    auto is_settled = [](uint32_t f) {
        return (f & (vm::VM_DEBUG_STOP | vm::VM_EXITED | vm::VM_KILLED)) != 0;
    };
    auto is_bp_hit = [](uint32_t f) {
        return (f & vm::VM_DEBUG_STOP) != 0;
    };
    auto is_exited = [](uint32_t f) {
        return (f & (vm::VM_EXITED | vm::VM_KILLED)) != 0;
    };
    for(;;) {
        // 每轮一次 for_each_task：找首个命中 vm 并判 all-stop 收敛。
        // 命中优先级：preferred(已停) > 断点停 > 退出。断点停优先于退出，避免子进程退出
        // 把父的断点命中吞掉（父命中更可操作，子退出可下一轮报）。
        enum { NONE, EXITED, BP, PREF } hit_phase = NONE;
        std::shared_ptr<vm> hit_vm;
        vm* hit_fork_child = nullptr;
        bool all_settled = true;
        for_each_task([&](TaskEntry& e){
            vm* v = e.vmp.get();
            uint32_t f = e.vmp->get_flags();
            bool in_watch = running_watch.count(v) != 0;
            if(v == preferred && in_watch && is_settled(f) && hit_phase < PREF) {
                hit_phase = PREF; hit_vm = e.vmp; hit_fork_child = e.fork_child;
            } else if(in_watch && is_bp_hit(f) && hit_phase < BP) {
                hit_phase = BP; hit_vm = e.vmp; hit_fork_child = e.fork_child;
            } else if(in_watch && is_exited(f) && hit_phase < EXITED) {
                hit_phase = EXITED; hit_vm = e.vmp; hit_fork_child = e.fork_child;
            }
            // all-settled 判定：已停（VM_DEBUG_STOP/VM_STOPPED/EXITED/KILLED）或已放行单步
            // （stepping）均视为就绪。stepping 覆盖单步放行后到 vm 在下个 step() 钩子消费 stepping
            // 置 STOP 之间的窗口（含被步进的指令进入阻塞 syscall、暂不回钩子的情形）。
            if(!(f & vm::VM_DEBUG_ATTACHED)) return;
            bool settled = (f & (vm::VM_DEBUG_STOP | vm::VM_STOPPED
                                 | vm::VM_EXITED | vm::VM_KILLED)) || e.stepping;
            if(!settled) all_settled = false;
        });
        if(hit_vm) {
            if(!propagated) {
                stop_all_vms();
                propagated = true;
            }
            if(all_settled) {
                out_hit_vm = hit_vm;
                // fork 事件一次性消费；表里其它 vm 的 fork 事件保留（合法的待上报事件）。
                if(out_fork_child && report_fork_events_ && hit_fork_child) {
                    *out_fork_child = hit_fork_child;
                    with_task(hit_vm.get(), [](TaskEntry& e){ e.fork_child = nullptr; });
                }
                return;
            }
        }
        // async Ctrl-C（0x03，不带 $...# 框）
        if(client_fd_ >= 0) {
            char peek;
            ssize_t n = recv(client_fd_, &peek, 1, MSG_PEEK | MSG_DONTWAIT);
            if(n == 1 && peek == '\x03') {
                recv(client_fd_, &peek, 1, MSG_DONTWAIT);
                stop_all_vms();
                propagated = true;
            }
        }
        struct timespec ts{0, 2000000};  // 2ms
        nanosleep(&ts, nullptr);
    }
}

// vCont 处理。包形如 vCont[;action[:tid]]...，每个 action：
//   c / C<hexsig>   继续该 tid（C 带信号，bpfvm 无 ptrace-stop 信号投递，按 c 处理）
//   s / S<hexsig>   单步该 tid（S 带信号，按 s 处理）
//   t               保持该 tid 停止（不动作）
//   :tid            可选，指定该 action 的目标线程；省略则代表「其余所有线程」(default action)
// all-stop 语义：按 action 优先级（显式单线程 > 进程作用域 pPID.-1 > 全局 default）
// 决定每个 attached vm 的动作（c/s/t/无），再统一越步+放行。至少要有一个 action。
// 完成后 self_replied_=true，发送停止/退出回复。
std::string GdbServer::handle_vcont(const std::string& pkt) {
    self_replied_ = true;
    // 切分 ';'：首段是 "vCont"，其后每段一个 action。
    // 例：vCont;c:1;s:2  -> ["vCont", "c:1", "s:2"]
    std::vector<std::string> actions;
    size_t start = 0;
    for(;;) {
        auto semi = pkt.find(';', start);
        if(semi == std::string::npos) {
            actions.push_back(pkt.substr(start));
            break;
        }
        actions.push_back(pkt.substr(start, semi - start));
        start = semi + 1;
    }
    if(actions.size() < 2) {
        // vCont 无 action（仅 "vCont"）：按 continue 处理
        actions.push_back("c");
    }

    struct ParsedAction {
        char act;          // 'c' / 's' / 't'
        vm* target = nullptr;  // 单线程目标（has_tid=true 时有效）；wire pid 已桥成 vm*
        bool has_tid;      // 是否作用于单个线程
        vm* scope = nullptr;   // 进程作用域目标（pPID.-1 形式，桥成该 pid 的 vm*）；nullptr=全局
    };
    std::vector<ParsedAction> parsed;
    char default_act = 'c';   // 无 :tid 的 action 决定 default（取最后一个）
    bool has_default = false; // 是否存在无 :tid 的 action（全局 default）
    vm* step_vm = nullptr;    // 单步的目标 vm（用于 preferred）

    for(size_t i = 1; i < actions.size(); i++) {
        const std::string& a = actions[i];
        if(a.empty()) continue;
        char act = a[0];
        // 归一化：C<c> -> c（带信号继续），S<c> -> s（带信号单步）。信号当前不投递。
        char norm;
        if(act == 'c' || act == 'C') norm = 'c';
        else if(act == 's' || act == 'S') norm = 's';
        else if(act == 't') norm = 't';
        else continue;  // 未知 action 跳过

        // 解析可选 :tid。tid 形如 pid / pPID.TID / pPID.-1 / pPID.0 / -1 / 0。
        //   pPID.TID    -> 单线程（has_tid=true, target=该 tid 的 vm*）
        //   pPID.-1/0   -> 该 PID 的所有线程（scope=该 pid 的 vm*，has_tid=false）
        //   -1/0/p-1.-1 -> 所有线程（全局 default，has_tid=false, scope=nullptr）
        // wire pid 经 find_task 桥成 vm*；桥不到（已退出/detach）存 nullptr，后续 set_action 跳过。
        auto colon = a.find(':');
        bool has_tid = false;
        vm* target = nullptr;
        vm* scope = nullptr;
        if(colon != std::string::npos) {
            std::string tidstr = a.substr(colon + 1);
            if(tidstr.size() > 1 && tidstr[0] == 'p') {
                // pPID.TID / pPID.-1
                std::string rest = tidstr.substr(1);
                auto dot = rest.find('.');
                std::string pid_str = (dot == std::string::npos) ? rest : rest.substr(0, dot);
                std::string tid_str = (dot == std::string::npos) ? "" : rest.substr(dot + 1);
                if(tid_str == "-1" || tid_str == "0" || tid_str.empty()) {
                    uint64_t pid_val = std::strtoull(pid_str.c_str(), nullptr, 16);
                    scope = find_task(pid_val).get();  // 该 PID 所有线程（pid_val 桥成 vm*）
                } else {
                    uint64_t tid_val = std::strtoull(tid_str.c_str(), nullptr, 16);
                    target = find_task(tid_val).get();
                    has_tid = true;
                }
            } else if(tidstr == "-1" || tidstr == "0") {
                // 全局 default（所有线程）
            } else {
                uint64_t tid_val = std::strtoull(tidstr.c_str(), nullptr, 16);
                if(tid_val != 0) {
                    target = find_task(tid_val).get();
                    has_tid = true;
                }
            }
        }
        if(!has_tid && scope == nullptr) {
            default_act = norm;
            has_default = true;
        }
        if(norm == 's' && has_tid) step_vm = target;
        parsed.push_back({norm, target, has_tid, scope});
    }

    // 三阶段执行（三阶段都用 for_each_task；step-over 的 wait_stopped 阻塞需锁外，在 fn 里
    // 收集目标后锁外逐个做）：
    //   -  决定每个 attached vm 的最终动作（显式单线程 > 进程作用域 pPID.-1 > 全局 default）。
    //   -  对 c 动作且 pc 命中断点的 vm 串行 step-over（必须越过，否则放行后首条 step 又命中
    //      同一断点死循环）。s/t 不需越步。
    //   -  按动作统一放行，wait_any_stopped 仅观察本次释放的 vm 停下。
    // 跳过非 VM_DEBUG_ATTACHED 的 vm（已 detach 的停止/退出绝不上报，否则 GDB 对已移除
    // inferior 取状态会 internal-error）。
    auto is_attached = [](vm* v) { return (v->get_flags() & vm::VM_DEBUG_ATTACHED) != 0; };

    // 收集有显式 action 的 vm* 集合（nullptr 跳过——桥不到的已退出/detach 进程不操作）
    std::set<vm*> explicit_targets;
    for(auto& pa : parsed) if(pa.has_tid && pa.target) explicit_targets.insert(pa.target);

    // ── 第一阶段：决定每个 attached vm 的最终动作。
    //   vCont;c           -> 所有线程 'c'（全局 default）
    //   vCont;c:p1.-1     -> inferior 1 的线程 'c'（进程作用域）
    //   vCont;c:p1.1      -> 线程 1 'c'（显式单线程）
    //   vCont;c:p1.-1;t:p1.1 -> 线程 1 't'，inferior 1 其余线程 'c'（显式优先于作用域）
    std::unordered_map<vm*, char> action_of;
    auto set_action = [&](vm* v, char act) {
        if(!v) return;  // 桥不到的 vm 跳过（已退出/detach）
        auto [it, ins] = action_of.try_emplace(v, act);
        if(!ins) it->second = act;
    };
    if(has_default) {
        for_each_task([&](TaskEntry& e){
            if(!is_vm_exited(e.vmp.get()) && is_attached(e.vmp.get()))
                set_action(e.vmp.get(), default_act);
        });
    }
    for(auto& pa : parsed) {
        if(pa.has_tid || pa.scope == nullptr) continue;
        if(explicit_targets.count(pa.scope)) continue;
        set_action(pa.scope, pa.act);
    }
    for(auto& pa : parsed) {
        if(!pa.has_tid) continue;
        set_action(pa.target, pa.act);
    }

    // ── 第二阶段：c 动作 pc 命中断点的 vm 串行 step-over（step-over 用 stepping 放行信号）。
    std::vector<std::shared_ptr<vm>> need_step;
    for_each_task([&](TaskEntry& e){
        if(is_vm_exited(e.vmp.get()) || !is_attached(e.vmp.get())) return;
        auto it = action_of.find(e.vmp.get());
        if(it == action_of.end() || it->second != 'c') return;
        if(e.breakpoints.count(e.vmp->pc()) != 0) {
            need_step.push_back(e.vmp);
        }
    });
    for(auto& v : need_step) {
        // step-over：清 STOP 放行 + 设 stepping，钩子消费 stepping 落实停。
        v->clear_flags(vm::VM_DEBUG_STOP);
        mark_stepping(v.get());
        v->wakeup(false);
        wait_stopped(v.get());
        if(is_vm_exited(v.get())) action_of.erase(v.get());
    }

    // ── 第三阶段：按动作统一放行：c 动作清 STOP + wakeup；s 动作清 STOP + 设 stepping；t 动作
    // 保持 stopped。released 给 wait_any_stopped 的 watch_vms。
    std::vector<vm*> released;
    std::vector<std::shared_ptr<vm>> release_vms;
    for_each_task([&](TaskEntry& e){
        if(is_vm_exited(e.vmp.get()) || !is_attached(e.vmp.get())) return;
        auto it = action_of.find(e.vmp.get());
        if(it == action_of.end()) return;
        char act = it->second;
        if(act == 't') return;  // 保持 stopped
        released.push_back(e.vmp.get());
        release_vms.push_back(e.vmp);
    });
    for(auto& v : release_vms) {
        char act = action_of[v.get()];
        v->clear_flags(vm::VM_DEBUG_STOP);  // 清上轮停止状态
        if(act == 's') {
            mark_stepping(v.get());  // 单步：放行后跑一条，钩子消费 stepping 落实停
        }
        v->wakeup(false);
    }

    // 阻塞等待任一「本次释放的」vm 停下（断点命中/单步完成/异常/fork），all-stop 传播到其余 vm
    std::shared_ptr<vm> hit_vm;
    vm* fork_child = nullptr;
    wait_any_stopped(hit_vm, step_vm, released, &fork_child);
    if(!hit_vm || is_vm_exited(hit_vm.get())) {
        send_exit_reply(hit_vm ? hit_vm.get() : current_vm.get());
    } else if(!try_send_exec_stop(hit_vm.get())) {
        // 非 exec 停：再查 syscall，最后普通断点/fork
        if(!try_send_syscall_stop(hit_vm.get()))
            send_stop_reply(hit_vm.get(), 5, fork_child);  // SIGTRAP（fork_child!=null 时为 fork 事件）
    }
    return "";
}

// ── server 主循环 ────────────────────────────────────────────────────────
void GdbServer::server_loop() {
    // 退出守卫：任何 return 路径（含 socket/bind/listen/accept 失败）都置 running_=false
    // 并通知 stop() 可立即 join，避免它空等满 6 秒超时。
    struct LoopExitGuard {
        GdbServer* s;
        ~LoopExitGuard() {
            s->running_ = false;
            s->loop_done_.store(true, std::memory_order_release);
        }
    } guard{this};

    // 阻塞 SIGPIPE（client 断开时 send 不触发进程终止）
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGPIPE);
    pthread_sigmask(SIG_BLOCK, &mask, nullptr);

    listen_fd_ = socket(AF_INET, SOCK_STREAM, 0);
    if(listen_fd_ < 0) return;
    int yes = 1;
    setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);  // 仅本地，安全
    addr.sin_port = htons(port_);
    if(bind(listen_fd_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        std::fprintf(stderr, "[gdb] bind port %u failed: %s\n", port_, std::strerror(errno));
        close(listen_fd_);
        listen_fd_ = -1;
        return;
    }
    if(listen(listen_fd_, 1) < 0) {
        close(listen_fd_);
        listen_fd_ = -1;
        return;
    }
    std::fprintf(stderr, "[gdb] listening on 127.0.0.1:%u (entry=0x%lx)\n",
                 port_, (unsigned long)main_vm->image()->entry);

    // 外层 accept 循环：每来一个 GDB 连接就是一次会话，会话结束（断开 / detach all）后 detach
    // 并回 accept 等下次连接——支持重复 attach。单线程 accept 串行化保证同时只服务一个会话
    // （会话期间不调 accept，第二个连接在 listen backlog=1 里排队）。主 vm 退出后不再接会话。
    while(running_ && !is_vm_exited(main_vm.get())) {
        client_fd_ = accept(listen_fd_, nullptr, nullptr);
        if(client_fd_ < 0) {
            // accept 失败：被 stop() 关 listen_fd 打断（running_ 已 false），或临时错误。
            // running_/vm 退出则整体退出，否则继续等下次连接。
            if(!running_ || is_vm_exited(main_vm.get())) break;
            continue;
        }
        // 新会话：协议协商态已由上一会话的 end_session 复位（首次连接时为构造函数初值），直接 attach。
        // --stop 与默认模式都走 attach_on_connect：它内部 :319 守卫已处理"main 已 ATTACHED"的首次
        // 连接（--stop 时 main 在 start 被冻在入口、已 ATTACHED，守卫跳过避免重复 mark），重复连接
        // （end_session 清过 flag）则正常重新 attach。
        attach_on_connect();
        // 关闭 Nagle，减少小包延迟
        int one = 1;
        setsockopt(client_fd_, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        // recv 超时：让内层循环周期性醒来检查 running_ 与 vm 退出，避免永久阻塞
        struct timeval tv{0, 200000};  // 0.2s
        setsockopt(client_fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        // 内层包循环：处理本会话的 RSP 包，直到 GDB 断开 / detach all / stop() / vm 退出。
        while(running_) {
            std::string pkt;
            bool got = recv_packet(pkt);
            if(!got) {
                // recv_packet 返回 false：对端关闭(EOF)/硬错误，或 running_ 被 stop() 置 false。
                // 对端关闭时，若主 vm 已退出但还没发 W（例如断点停后用户直接断开），补发一次。
                // send_exit_reply 自身按 tasks_ 表幂等，已发过则不重复。
                if(is_vm_exited(main_vm.get())) {
                    send_exit_reply(main_vm.get());
                }
                break;
            }
            if(pkt.empty()) {
                send_packet("");
                continue;
            }
            // handle_packet 返回值：空串=未识别/空回复（需发空包 $#00，GDB 视为"不支持"）；
            // 非空=正常回复。c/s 等已自行 send 的命令会置 self_replied_ 且返回空串——此时跳过。
            self_replied_ = false;
            std::string reply = handle_packet(pkt);
            if(!self_replied_) send_packet(reply);
        }
        // 会话结束：detach 让被 trace 的 vm 恢复全速，清空 tasks_。
        // 下次 GDB 连上由 attach_on_connect 从 main_vm 重新登记（hooks 一直在各 vm 身上，无需重装）。
        end_session();
        if(client_fd_ >= 0) {
            close(client_fd_);
            client_fd_ = -1;
        }
    }
    // server 整体退出（主 vm 已退出 / stop()）：最终 detach，清空 tasks_（连 pid 1 一起）。
    // end_session 已是「detach 全部 vm + clear tasks_」的批量实现，语义等价且幂等。
    end_session();
    if(client_fd_ >= 0) {
        close(client_fd_);
        client_fd_ = -1;
    }
}

// ── 包处理 ───────────────────────────────────────────────────────────────
std::string GdbServer::handle_packet(const std::string& pkt) {
    char cmd = pkt[0];
    switch(cmd) {
    case 'q': {
        if(pkt.rfind("qSupported", 0) == 0) {
            // 协商：GDB 发的 qSupported 里若含 multiprocess+ 表示它支持，我们也广告之。
            // 仅在双方都支持时切到 pPID.TID 线程 id 格式（encode_tid/decode_tid 据此切换）。
            if(pkt.find("multiprocess+") != std::string::npos) multiprocess_ = true;
            std::string r = "PacketSize=4096;swbreak+;vContSupported+;QStartNoAckMode+";
            // QCatchSyscalls：广告支持 catch syscall。GDB 据此发 QCatchSyscalls:0/1 配置，
            // 我们在 syscall 钩子命中时发 T05syscall_entry/return:<hex>; 停止回复。无 multiprocess
            // 依赖（单进程也支持 catch syscall），故无条件广告。带 + 后缀对齐 QEMU 实践，
            // GDB 16.3 解析 qSupported 期望带 +/- 的可探测项（裸 token 被判 "unrecognized item"）。
            r += ";QCatchSyscalls+";
            if(multiprocess_) {
                r += ";multiprocess+";
                // fork-events+/vfork-events+：让 GDB 在 fork 时收到 T05fork:<child>，按
                // follow-fork-mode / detach-on-fork 决策（跟父或子、是否 detach 另一个）。
                // 关键：被 GDB detach 的进程（如 detach-on-fork=on 时的非跟随方）后续的
                // 停止/退出绝不通过 qfThreadInfo/wait_any_stopped 上报，否则 GDB 对已移除的
                // inferior 取状态会 internal-error（已在 wait_any_stopped/continue_all_vms/
                // stop_all_vms 中过滤 VM_DEBUG_ATTACHED）。
                if(pkt.find("fork-events+") != std::string::npos) {
                    r += ";fork-events+;vfork-events+";
                    report_fork_events_ = true;
                }
                // exec-events+：让 GDB 在 execveat 后收到 T05exec:<hex-path>，据此重载符号
                // TaskEntry::exec_path，经同一 all-stop 协调路径上报。
                if(pkt.find("exec-events+") != std::string::npos) {
                    r += ";exec-events+";
                    report_exec_events_ = true;
                }
            }
            return r;
        }
        if(pkt == "qAttached") return "1";
        if(pkt.rfind("qfThreadInfo", 0) == 0) {
            // 枚举线程：m<tid>,<tid>,... 随后 qsThreadInfo 回 l 终止。
            // tid 格式由 multiprocess_ 决定（裸 hex 或 pPID.TID）。
            // 仅枚举 VM_DEBUG_ATTACHED 的 vm（已 detach 的进程若出现，GDB 见到已移除 inferior
            // 会 set_current_inferior(NULL) 崩）。
            std::string r = "m";
            bool first = true;
            for_each_task([&](TaskEntry& e){
                if(!(e.vmp->get_flags() & vm::VM_DEBUG_ATTACHED)) return;
                if(!first) r += ",";
                r += encode_tid(e.vmp.get());
                first = false;
            });
            // 无 attached vm 时回 l（空列表结束）——裸 m 是非法格式，GDB 会解析错误。
            return first ? "l" : r;
        }
        if(pkt.rfind("qsThreadInfo", 0) == 0) return "l";
        if(pkt.rfind("qThreadExtraInfo", 0) == 0) return "";
        if(pkt.rfind("qC", 0) == 0) {
            // 返回当前线程 id。current_vm 恒非空，绝不返回 QC0（线程 id 0 是 RSP 特殊值，
            // GDB 会 switch_to_thread(NULL) 触发 assertion）。
            return "QC" + encode_tid(current_vm.get());
        }
        if(pkt.rfind("qOffsets", 0) == 0) {
            // PIE 程序的 .text/.data 运行时基址偏移。GDB 拿到后把符号/DWARF 文件内地址
            // +偏移重定位到运行时地址，否则 PIE 断点命中不了（文件内 main@0xbc728 vs
            // 运行时 0x401ce728）。静态/ET_EXEC 的 load_base 为 0。
            // 注意值是纯十六进制，不能带 0x 前缀（GDB 报 "Invalid hex digit"）。
            uint64_t base = current_vm->image()->load_base;
            char buf[64];
            std::snprintf(buf, sizeof(buf), "Text=%lx;Data=%lx;Bss=%lx",
                          (unsigned long)base, (unsigned long)base, (unsigned long)base);
            return buf;
        }
        return "";
    }
    case 'Q': {
        if(pkt == "QStartNoAckMode") {
            no_ack_ = true;
            return "OK";
        }
        // QCatchSyscalls:0 禁用 / :1 catch 全部 / :1;<hex>;<hex>;... catch 列表。
        // sysno 为小写变长十六进制。构造新 const SyscallCatchCfg 后原子 store（所有 vm 共用，
        // 回调闭包 load 拿不可变快照）。
        // 注意：钩子已在 start() 装到 main_vm 并经 fork 继承到所有派生 vm，这里只更新
        // syscall_catch_，回调闭包查它。
        if(pkt.rfind("QCatchSyscalls:", 0) == 0) {
            std::string rest = pkt.substr(strlen("QCatchSyscalls:"));
            auto cfg = std::make_shared<SyscallCatchCfg>();
            if(rest == "0") {
                cfg->enabled = false;  // 禁用（sysnos 保持空集）
            } else if(rest == "1") {
                cfg->enabled = true;   // catch 全部（sysnos 空集=catch全部）
            } else if(rest.size() >= 2 && rest[0] == '1' && rest[1] == ';') {
                // 形如 "1;5;6;e8"：catch 列表（首段恒为 "1"，必须紧跟 ';'）
                cfg->enabled = true;
                auto set = std::make_shared<std::unordered_set<uint32_t>>();
                size_t pos = 2;  // 跳过 "1;"
                for(;;) {
                    size_t semi = rest.find(';', pos);
                    std::string tok = (semi == std::string::npos) ? rest.substr(pos) : rest.substr(pos, semi - pos);
                    if(!tok.empty()) {
                        char* endp = nullptr;
                        unsigned long val = std::strtoul(tok.c_str(), &endp, 16);
                        if(endp == tok.c_str() || *endp != '\0') return "E01";  // 非法 hex
                        set->insert((uint32_t)val);
                    }
                    if(semi == std::string::npos) break;
                    pos = semi + 1;
                }
                cfg->sysnos = set;  // shared_ptr<T> -> shared_ptr<const T> 隐式转换
            } else {
                return "E01";  // 格式错误（如 "1abc"）
            }
            syscall_catch_.store(std::move(cfg));  // shared_ptr<T> -> shared_ptr<const T>
            return "OK";
        }
        return "";
    }
    case '?': {
        // 报告停止原因。T05 = SIGTRAP（断点/单步/attach），带 thread:<tid> 让 GDB 切到该线程。
        auto v = current_vm;
        if(is_vm_exited(v.get())) {
            char buf[32];
            std::snprintf(buf, sizeof(buf), "W%02lx", (unsigned long)(v->r(0) & 0xFF));
            return buf;
        }
        return "T05thread:" + encode_tid(v.get()) + ";";
    }
    case 'H': {
        // H<op><thread>：选择后续操作的目标线程。<thread> 形如 pid、pPID.TID、0、-1。
        // '0'/'-1'/'p0.0'/'p-1.-1' 是 RSP 特殊值（任意/所有线程）——必须映射到一个真实 vm，
        // 否则后续 qC 返回 0 会让 GDB switch_to_thread(NULL) 触发 assertion。
        // tid==0 或查表失败均回退 main vm（current_vm 恒非空）。
        if(pkt.size() < 2) return "E01";
        std::string t = pkt.substr(2);
        if(auto v = decode_tid(t)) { current_vm = v; return "OK"; }
        current_vm = main_vm;  // tid==0 / 查表失败 -> 回退主 vm（current_vm 恒非空）
        return "OK";
    }
    case 'g': {
        // 读全部寄存器：r0..r10 + pc 全部 8 字节小端（共 96 字节 = 192 hex）。
        auto v = current_vm;
        std::string r;
        for(int i = 0; i < 11; i++) r += reg_to_hex(v->r(i));          // r0..r10 (8B)
        r += reg_to_hex(v->pc());                                      // pc (8B)
        return r;
    }
    case 'G': {
        // 写全部寄存器：96 字节（192 hex 字符），布局同 g。
        auto v = current_vm;
        std::string h = pkt.substr(1);
        for(int i = 0; i < 11; i++) {
            v->r(i) = hex_to_reg(h.substr(i * 16, 16));
        }
        v->pc() = hex_to_reg(h.substr(11 * 16, 16));
        return "OK";
    }
    case 'p': {
        // p<n> 读单寄存器。索引 0-10=r0-r10，11=pc，全部 8 字节（与 g 包布局一致）。
        auto v = current_vm;
        unsigned long n = std::strtoul(pkt.substr(1).c_str(), nullptr, 16);
        if(n <= 10) return reg_to_hex(v->r((int)n));
        if(n == 11) return reg_to_hex(v->pc());
        return "E01";
    }
    case 'P': {
        // P<n>=<hex> 写单寄存器（尺寸同 p）
        auto v = current_vm;
        auto eq = pkt.find('=');
        if(eq == std::string::npos) return "E02";
        unsigned long n = std::strtoul(pkt.substr(1, eq - 1).c_str(), nullptr, 16);
        std::string h = pkt.substr(eq + 1);
        if(n <= 10) v->r((int)n) = hex_to_reg(h);
        else if(n == 11) v->pc() = hex_to_reg(h);
        return "OK";
    }
    case 'm': {
        // m<addr>,<len> 读内存。跨段时按段切分；单次 mmu 请求会校验 [addr,addr+size)
        // 整段在同一映射内，请求越大越易失败，故先按剩余整段请求，失败则降到逐字节。
        auto v = current_vm;
        auto comma = pkt.find(',');
        if(comma == std::string::npos) return "E02";
        uint64_t addr = std::strtoull(pkt.substr(1, comma - 1).c_str(), nullptr, 16);
        uint64_t len = std::strtoull(pkt.substr(comma + 1).c_str(), nullptr, 16);
        if(len == 0) return "";
        std::string out;
        out.reserve(len * 2);
        uint64_t off = 0;
        while(off < len) {
            size_t want = (size_t)(len - off);
            void* p = v->mmu(addr + off, want);
            size_t step = want;
            if(!p) { p = v->mmu(addr + off, 1); step = 1; }
            if(!p) return "E14";
            out += hex_encode(p, step);
            off += step;
        }
        return out;
    }
    case 'M': {
        // M<addr>,<len>:<hex> 写内存
        auto v = current_vm;
        auto comma = pkt.find(',');
        auto colon = pkt.find(':');
        if(comma == std::string::npos || colon == std::string::npos) return "E02";
        uint64_t addr = std::strtoull(pkt.substr(1, comma - 1).c_str(), nullptr, 16);
        uint64_t len = std::strtoull(pkt.substr(comma + 1, colon - comma - 1).c_str(), nullptr, 16);
        std::string h = pkt.substr(colon + 1);
        if(h.size() < len * 2) return "E03";
        uint64_t off = 0;
        while(off < len) {
            size_t want = (size_t)(len - off);
            void* p = v->mmu_w(addr + off, want);
            size_t step = want;
            if(!p) {
                p = v->mmu_w(addr + off, 1);
                step = 1;
            }
            if(!p) return "E14";
            if(!hex_decode(h.substr(off * 2, step * 2), p, step)) return "E03";
            off += step;
        }
        return "OK";
    }
    case 'c': {
        // continue [addr]（addr 忽略，从当前 pc 继续）
        auto v = current_vm;
        self_replied_ = true;
        if(is_vm_exited(v.get())) {
            send_exit_reply(v.get());
            return "";
        }
        // all-stop：当前 vm 先越过断点并放行（resume_continue 读 v->pc()/设 flags，必须在
        // v 被放行前完成——否则 v 解释器线程并发写 pc_ 构成数据竞争），再放行其余 vm。
        // continue 不能只等当前 vm（旧 resume 路径的 bug：若另一 vm 先命中断点而当前 vm
        // 无断点长循环，wait_stopped(current) 永不返回 -> all-stop 失效）。改由 wait_any_stopped
        // 统一协调：放行所有 vm 后等任一命中并传播 stop 到其余 vm。
        resume_continue(v.get());
        continue_all_vms();
        // 阻塞等待任一 vm 命中（断点/异常/fork），命中后 stop_all_vms 让其余 vm 也停
        std::shared_ptr<vm> hit_vm;
        vm* fork_child = nullptr;
        wait_any_stopped(hit_vm, v.get(), {}, &fork_child);
        if(!hit_vm || is_vm_exited(hit_vm.get()))
            send_exit_reply(hit_vm ? hit_vm.get() : v.get());
        else if(!try_send_exec_stop(hit_vm.get())) {
            if(!try_send_syscall_stop(hit_vm.get()))
                send_stop_reply(hit_vm.get(), 5, fork_child);  // SIGTRAP（fork_child!=null 时为 fork 事件）
        }
        return "";
    }
    case 's': {
        // step [addr]：单步当前线程。其余 vm 保持 stopped（all-stop：单步是局部动作，
        // 但若单步期间有其他 vm 已先命中断点，wait_any_stopped 会回报那个 vm）。
        auto v = current_vm;
        self_replied_ = true;
        if(is_vm_exited(v.get())) {
            send_exit_reply(v.get());
            return "";
        }
        resume(v.get(), true);
        // 单步完成后当前 vm 已停（resume 内 wait_stopped）；优先回报当前线程（preferred）。
        std::shared_ptr<vm> hit_vm;
        vm* fork_child = nullptr;
        wait_any_stopped(hit_vm, v.get(), {}, &fork_child);
        if(!hit_vm || is_vm_exited(hit_vm.get()))
            send_exit_reply(hit_vm ? hit_vm.get() : v.get());
        else if(!try_send_exec_stop(hit_vm.get())) {
            if(!try_send_syscall_stop(hit_vm.get()))
                send_stop_reply(hit_vm.get(), 5, fork_child);  // SIGTRAP（fork_child!=null 时为 fork 事件）
        }
        return "";
    }
    case 'Z':   // 设置断点
    case 'z': { // 清除断点
        // Z/z<type>,<addr>,<kind>
        auto comma1 = pkt.find(',');
        auto comma2 = pkt.rfind(',');
        if(comma1 == std::string::npos) return "E02";
        unsigned long type = std::strtoul(pkt.substr(1, comma1 - 1).c_str(), nullptr, 16);
        uint64_t addr = std::strtoull(pkt.substr(comma1 + 1, comma2 - comma1 - 1).c_str(), nullptr, 16);
        // kind 不用（BPF 指令固定 8 字节）
        if(type != 0) return "";  // 仅支持软断点(type 0)
        // per-vm 断点：操作焦点 vm 对应 inferior 的集（对齐 gdb per-pspace 模型）。
        // Z0/z0 由 gdb 对当前操作的 inferior 发（set_general_process 切到该 inferior），
        // 故改焦点 vm 对应 task 的集；fork 时子已继承父的集快照，detach 子只动子的集，
        // 父的不受影响（detach-on-fork on 下父仍命中）。pid 取焦点 vm 的派生属性。
        uint64_t pid = current_vm->sys()->id();
        {
            std::lock_guard<std::mutex> lk(tasks_mutex_);
            auto it = tasks_.find(pid);
            if(it == tasks_.end()) return "E01";  // 无该 task，拒绝
            auto& bps = it->second.breakpoints;
            if(cmd == 'Z') bps.insert(addr);
            else           bps.erase(addr);
        }
        return "OK";
    }
    case 'k': {
        // kill：置 VM_KILLED 让 vm 在下个 safepoint 退出（r(0)=128+SIGKILL）。
        // 回 OK：GDB 期望 kill 收到确认；vm 真正退出后由 server_loop 的断开路径
        // （recv 返回 false）补发 W 包。返回空串会被 server_loop 当作未识别回复发空包。
        // host_signal（pthread_kill SIGUSR1）踢开阻塞在 host syscall 的 vm，否则它要等
        // syscall 自然返回才走到 safepoint 检查 VM_KILLED（与 vKill 行为一致）。
        auto v = current_vm;
        v->set_flags(vm::VM_KILLED);
        v->wakeup(false);
        v->sys()->host_signal(v.get(), 0);
        return "OK";
    }
    case 'D': {
        // detach。D=detach 所有进程结束会话（GDB quit，走 end_session）；D;pid=仅 detach 该 pid
        // （fork 后按 follow/detach 决策，该进程随后自由运行，会话继续）。
        auto semi = pkt.find(';');
        if(semi == std::string::npos) {
            end_session();
        } else {
            if(auto v = decode_tid(pkt.substr(semi + 1))) detach_vm(v.get());
            else          end_session();
        }
        return "OK";
    }
    case 'v': {
        // vCont[;action[:tid]]...
        if(pkt.rfind("vCont?", 0) == 0) return "vCont;c;C;s;S;t";
        if(pkt.rfind("vCont", 0) == 0) return handle_vcont(pkt);
        if(pkt.rfind("vAttach", 0) == 0) {
            // vAttach;pid：attach 到指定 pid。decode_tid 查 tasks_（已 trace 的 vm），查不到则从
            // syscall 层 pid_map 兜底（search_pid_map=true，找尚未被 trace 的存活 vm）。登记后若未
            // attached 则置 attach + request_stop 停在当前 pc。
            auto semi = pkt.find(';');
            if(semi == std::string::npos) return "E01";
            std::shared_ptr<vm> v = decode_tid(pkt.substr(semi + 1), /*search_pid_map=*/true);
            if(!v) return "E01";  // 该 pid 既不在 tasks_ 也不在 pid_map（不存在 / 特殊值）
            register_task(v);
            if(!(v->get_flags() & vm::VM_DEBUG_ATTACHED)) {
                v->set_flags(vm::VM_DEBUG_ATTACHED);
                request_stop(v.get());
            }
            current_vm = v;
            return multiprocess_ ? ("T05thread:" + encode_tid(v.get()) + ";") : "S05";
        }
        if(pkt.rfind("vKill", 0) == 0) {
            // vKill;pid：kill 指定 pid（无 pid 参数则 kill 当前 vm）。
            // 置 VM_KILLED，vm 在下个 safepoint 退出（r(0)=128+SIGKILL）。回 OK。
            std::shared_ptr<vm> v = current_vm;
            auto semi = pkt.find(';');
            if(semi != std::string::npos) {
                if(auto found = decode_tid(pkt.substr(semi + 1))) v = found;
            }
            v->set_flags(vm::VM_KILLED);
            v->wakeup(false);
            v->sys()->host_signal(v.get(), 0);  // EINTR 阻塞中的 vm 让它尽快退出
            return "OK";
        }
        // vMustReplyEmpty / 其它未识别 v 包：回空串（GDB 视为不支持）
        return "";
    }
    case 'T': {
        // T<thread> 线程是否存活。<thread> 形如 pid 或 pPID.TID。
        // decode_tid 查到（在 tasks_）即存活；特殊值（0/-1/p0.0 等"任意/主线程"）视为存活。
        auto v = decode_tid(pkt.substr(1));
        if(v) return "OK";
        // decode_tid 返回 nullptr：可能是特殊值或查不到。特殊值判存活。
        std::string t = pkt.substr(1);
        bool special = (t == "0" || t == "-1" ||
                        (t.size() > 1 && t[0] == 'p' &&
                         (t.find(".0") != std::string::npos || t.find(".-1") != std::string::npos)));
        return special ? "OK" : "E01";
    }
    default:
        return "";  // 未识别，回空让 GDB 忽略
    }
}
