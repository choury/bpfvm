#include "posix_internal.h"

#include <sys/un.h>

int64_t PosixSyscall::do_socket(vm* v) {
    int domain   = arg_s32(v->r(1));
    int type     = arg_s32(v->r(2));
    int protocol = arg_s32(v->r(3));

    int host_fd = ::socket(domain, type, protocol);
    if(host_fd < 0) {
        return -errno;
    }
    auto handle = std::make_shared<HostFd>(host_fd);
    // cloexec 仅是 VM 的 fd 表属性，同步登记以便 execve 时关闭。
    if(type & SOCK_CLOEXEC) {
        handle->cloexec = true;
    }
    return ps->fds_emplace(handle);
}

int64_t PosixSyscall::do_socketpair(vm* v) {
    int domain   = arg_s32(v->r(1));
    int type     = arg_s32(v->r(2));
    int protocol = arg_s32(v->r(3));
    int* sv = static_cast<int*>(v->mmu_w(v->r(4), 2 * sizeof(int)));
    if(sv == nullptr) {
        return -EFAULT;
    }

    int host_fds[2] = {-1, -1};
    if(::socketpair(domain, type, protocol, host_fds) < 0) {
        return -errno;
    }

    auto handle0 = std::make_shared<HostFd>(host_fds[0]);
    if(type & SOCK_CLOEXEC) {
        handle0->cloexec = true;
    }
    auto handle1 = std::make_shared<HostFd>(host_fds[1]);
    if(type & SOCK_CLOEXEC) {
        handle1->cloexec = true;
    }
    // 两端在同一 mutate 内分配，保证不抢同号。
    int guest_fd0 = -1, guest_fd1 = -1;
    ps->fds_mutate([&](SharedState::FdMap& m){
        guest_fd0 = 0;
        while(m.count(guest_fd0)) guest_fd0++;
        guest_fd1 = guest_fd0 + 1;
        while(m.count(guest_fd1)) guest_fd1++;
        m[guest_fd0] = handle0;
        m[guest_fd1] = handle1;
    });

    sv[0] = guest_fd0;
    sv[1] = guest_fd1;
    return 0;
}

// ===========================================================================
// bind / listen / connect / shutdown —— 单 fd + 可选 sockaddr
// ===========================================================================

// AF_UNIX pathname 地址与文件 syscall 共用同一套路径视角（ps->root 前缀），
// 否则 chroot 模式下 bind("/tmp/x.sock") 会落到宿主 /tmp 而非 rootfs 内。
// 抽象命名空间（sun_path[0]=='\0'）不经文件系统，Linux chroot 同样不隔离，不转换。
const struct sockaddr* PosixSyscall::sockaddr_to_host(const struct sockaddr* addr, socklen_t len,
                                                      struct sockaddr_storage* out, socklen_t* out_len) {
    if(len <= offsetof(struct sockaddr_un, sun_path) || addr->sa_family != AF_UNIX) {
        return addr;
    }
    const struct sockaddr_un* un = reinterpret_cast<const struct sockaddr_un*>(addr);
    if(un->sun_path[0] == '\0') {
        return addr;
    }
    char path[sizeof(un->sun_path) + 1];
    size_t avail = len - offsetof(struct sockaddr_un, sun_path);
    if(avail > sizeof(un->sun_path)) {
        avail = sizeof(un->sun_path);
    }
    memcpy(path, un->sun_path, avail);
    path[avail] = '\0';   // 内核允许 sun_path 108 字节全满不 NUL 终止

    std::string host = guest_abs_path(path);
    if(!ps->root.empty() && ps->root != "/") {
        host = std::filesystem::path(ps->root + host).lexically_normal().string();
    }
    socklen_t host_len = offsetof(struct sockaddr_un, sun_path) + host.size() + 1;
    if(host_len > sizeof(struct sockaddr_un)) {
        return nullptr;   // 加前缀后超出 sun_path 容量，调用方返回 -EINVAL
    }
    struct sockaddr_un* hun = reinterpret_cast<struct sockaddr_un*>(out);
    memset(hun, 0, sizeof(*hun));
    hun->sun_family = AF_UNIX;
    memcpy(hun->sun_path, host.c_str(), host.size() + 1);
    *out_len = host_len;
    return reinterpret_cast<const struct sockaddr*>(hun);
}

// 原地改写（只会变短，安全）。capacity 是调用方映射 addr 时的缓冲容量：内核只写
// min(容量, 记录地址长度) 字节，*len 却报完整记录长度（move_addr_to_user 语义），
// 扫描与清零须以实际写入范围为上限——越过会破坏缓冲外 guest 内存。
void PosixSyscall::sockaddr_to_guest(struct sockaddr* addr, socklen_t* len, socklen_t capacity) {
    if(addr == nullptr || len == nullptr || capacity <= offsetof(struct sockaddr_un, sun_path)) {
        return;
    }
    if(*len <= offsetof(struct sockaddr_un, sun_path) || addr->sa_family != AF_UNIX) {
        return;
    }
    struct sockaddr_un* un = reinterpret_cast<struct sockaddr_un*>(addr);
    if(un->sun_path[0] == '\0') {
        return;
    }
    if(ps->root.empty() || ps->root == "/") {
        return;
    }
    size_t written = std::min(capacity, *len) - offsetof(struct sockaddr_un, sun_path);
    std::string host_path(un->sun_path, strnlen(un->sun_path, written));
    const std::string prefix = ps->root + "/";
    if(host_path.compare(0, prefix.size(), prefix) != 0) {
        return;   // 无 root 前缀的路径原样保留
    }
    std::string guest_path = "/" + host_path.substr(prefix.size());
    memset(un->sun_path, 0, written);
    memcpy(un->sun_path, guest_path.c_str(), guest_path.size() + 1);
    *len = offsetof(struct sockaddr_un, sun_path) + guest_path.size() + 1;
}

int64_t PosixSyscall::do_bind(vm* v) {
    int guest_fd = arg_s32(v->r(1));
    auto h = ps->find_fd(guest_fd);
    if(!h) {
        return -EBADF;
    }
    socklen_t addrlen = (socklen_t)arg_u32(v->r(3));
    const struct sockaddr* addr = static_cast<const struct sockaddr*>(v->mmu(v->r(2), addrlen));
    if(addr == nullptr) {
        return -EFAULT;
    }
    struct sockaddr_storage haddr;
    socklen_t haddrlen = addrlen;
    const struct sockaddr* host_addr = sockaddr_to_host(addr, addrlen, &haddr, &haddrlen);
    if(host_addr == nullptr) {
        return -EINVAL;
    }
    if(::bind(h->host_fd(), host_addr, haddrlen) < 0) {
        return -errno;
    }
    return 0;
}

int64_t PosixSyscall::do_listen(vm* v) {
    int guest_fd = arg_s32(v->r(1));
    auto h = ps->find_fd(guest_fd);
    if(!h) {
        return -EBADF;
    }
    int backlog = arg_s32(v->r(2));
    if(::listen(h->host_fd(), backlog) < 0) {
        return -errno;
    }
    return 0;
}

int64_t PosixSyscall::do_connect(vm* v) {
    int guest_fd = arg_s32(v->r(1));
    auto h = ps->find_fd(guest_fd);
    if(!h) {
        return -EBADF;
    }
    socklen_t addrlen = (socklen_t)arg_u32(v->r(3));
    const struct sockaddr* addr = static_cast<const struct sockaddr*>(v->mmu(v->r(2), addrlen));
    if(addr == nullptr) {
        return -EFAULT;
    }
    struct sockaddr_storage haddr;
    socklen_t haddrlen = addrlen;
    const struct sockaddr* host_addr = sockaddr_to_host(addr, addrlen, &haddr, &haddrlen);
    if(host_addr == nullptr) {
        return -EINVAL;
    }
    if(::connect(h->host_fd(), host_addr, haddrlen) < 0) {
        // EINPROGRESS（非阻塞 socket，连接建立中）按 errno 透传；
        return (errno == EINTR) ? SYSCALL_RESTART : -errno;
    }
    return 0;
}

int64_t PosixSyscall::do_shutdown(vm* v) {
    int guest_fd = arg_s32(v->r(1));
    auto h = ps->find_fd(guest_fd);
    if(!h) {
        return -EBADF;
    }
    int how = arg_s32(v->r(2));
    if(::shutdown(h->host_fd(), how) < 0) {
        return -errno;
    }
    return 0;
}

// ===========================================================================
// accept4 —— 返回新 fd；addr/addrlen 可空（in-out）
// ===========================================================================

int64_t PosixSyscall::do_accept4(vm* v) {
    int guest_fd = arg_s32(v->r(1));
    auto h = ps->find_fd(guest_fd);
    if(!h) {
        return -EBADF;
    }
    uint64_t addr_arg = v->r(2);
    uint64_t addrlen_arg = v->r(3);
    int flags = arg_s32(v->r(4));

    struct sockaddr* addr = nullptr;
    socklen_t* addrlen = nullptr;
    socklen_t curlen = 0;   // 入参：缓冲区容量
    if(addr_arg != 0 && addrlen_arg != 0) {
        addrlen = static_cast<socklen_t*>(v->mmu_w(addrlen_arg, sizeof(socklen_t)));
        if(addrlen == nullptr) {
            return -EFAULT;
        }
        curlen = *addrlen;
        if(curlen > 0) {
            addr = static_cast<struct sockaddr*>(v->mmu_w(addr_arg, curlen));
            if(addr == nullptr) {
                return -EFAULT;
            }
        }
    }

    int new_host = ::accept4(h->host_fd(), addr, addrlen, flags);
    if(new_host < 0) {
        return (errno == EINTR) ? SYSCALL_RESTART : -errno;
    }
    // addrlen 已被 host 写回（实际对端地址长度），host 直接写进了 guest 内存。
    sockaddr_to_guest(addr, addrlen, curlen);

    auto handle = std::make_shared<HostFd>(new_host);
    if(flags & SOCK_CLOEXEC) {
        handle->cloexec = true;
    }
    return ps->fds_emplace(handle);
}

// ===========================================================================
// sendto / recvfrom —— buf 必填；addr/sendto 的 addr 为入参，recvfrom 的 addr 出参
// ===========================================================================

int64_t PosixSyscall::do_sendto(vm* v) {
    int guest_fd = arg_s32(v->r(1));
    auto h = ps->find_fd(guest_fd);
    if(!h) {
        return -EBADF;
    }
    size_t len = arg_size(v->r(3));
    const void* buf = v->mmu(v->r(2), len);
    if(buf == nullptr) {
        return -EFAULT;
    }
    int flags = arg_s32(v->r(4));

    const struct sockaddr* addr = nullptr;
    socklen_t addrlen = 0;
    if(v->r(5) != 0) {
        addrlen = (socklen_t)arg_u32(v->r(0));
        addr = static_cast<const struct sockaddr*>(v->mmu(v->r(5), addrlen));
        if(addr == nullptr) {
            return -EFAULT;
        }
    }
    struct sockaddr_storage haddr;
    socklen_t haddrlen = addrlen;
    const struct sockaddr* host_addr = addr;
    if(addr != nullptr) {
        host_addr = sockaddr_to_host(addr, addrlen, &haddr, &haddrlen);
        if(host_addr == nullptr) {
            return -EINVAL;
        }
    }

    ssize_t rc = ::sendto(h->host_fd(), buf, len, flags, host_addr, haddrlen);
    if(rc < 0) {
        return (errno == EINTR) ? SYSCALL_RESTART : -errno;
    }
    return rc;
}

int64_t PosixSyscall::do_recvfrom(vm* v) {
    int guest_fd = arg_s32(v->r(1));
    auto h = ps->find_fd(guest_fd);
    if(!h) {
        return -EBADF;
    }
    size_t len = arg_size(v->r(3));
    void* buf = v->mmu_w(v->r(2), len);
    if(buf == nullptr) {
        return -EFAULT;
    }
    int flags = arg_s32(v->r(4));

    struct sockaddr* addr = nullptr;
    socklen_t* addrlen = nullptr;
    socklen_t curlen = 0;   // 入参：缓冲区容量
    if(v->r(5) != 0) {
        addrlen = static_cast<socklen_t*>(v->mmu_w(v->r(0), sizeof(socklen_t)));
        if(addrlen == nullptr) {
            return -EFAULT;
        }
        curlen = *addrlen;
        if(curlen > 0) {
            addr = static_cast<struct sockaddr*>(v->mmu_w(v->r(5), curlen));
            if(addr == nullptr) {
                return -EFAULT;
            }
        }
    }

    ssize_t rc = ::recvfrom(h->host_fd(), buf, len, flags, addr, addrlen);
    if(rc < 0) {
        return (errno == EINTR) ? SYSCALL_RESTART : -errno;
    }
    // addrlen 已被 host 写回（实际来源地址长度）。
    sockaddr_to_guest(addr, addrlen, curlen);
    return rc;
}

// ===========================================================================
// sendmsg / recvmsg —— scatter-gather + cmsg 辅助数据
// ===========================================================================
//
// msghdr 不能整体 cast 给 host：msg_name/msg_iov/msg_control 三个字段都是 guest
// 虚拟地址，host 内核解引用会访问错误地址。必须逐字段重建 host msghdr，把 guest
// 指针经 mmu()/mmu_w() 翻译成 host 指针。msghdr/cmsghdr/iovec 的结构体布局 guest
// 与 host 二进制兼容（都是 Linux 64 位标准布局），但内部指针和 cmsg 里的 fd 要翻译。
//
// SCM_RIGHTS（fd 传递）：
// VM 只在边界翻译 fd 编号——cmsg 里 guest 塞的是 guest fd，host 内核认 host fd：
//   sendmsg: guest cmsg 的 SCM_RIGHTS fd -> 查 fd 表得 host fd -> 写进 cmsg -> host 内核
//   recvmsg: host 内核在本进程安装 host fd -> VM 分配 guest fd 登记进接收方 fd 表
//            -> 得 guest fd -> 写回 guest cmsg
//
// FIXME: 目前只翻译 SCM_RIGHTS 的 fd，其余 cmsg 类型原样透传（如 SCM_TIMESTAMP 的
// timeval/timespec 纯数据，host 直接读写 guest 的 control 缓冲区即可）。但以下需要类似
// 边界翻译、尚未实现：
//   - SCM_CREDENTIALS（ucred{pid,uid,gid}）：send 侧 guest pid 是 VM 内 guest 编号，host 内核
//     不认；recv 侧 host 内核填的是 VM 进程的 host pid（恒定），guest 期望对端 guest pid。
//     两侧都需 guest pid <-> host pid 翻译。uid/gid 在无 user namespace 时一致，可不翻译。
//   - SO_PEERCRED（getsockopt 获取对端凭据）有同样的 pid 问题。

// 把 guest 的 msghdr 翻译成 host msghdr。writable=true 时 iov/control/name 的缓冲区
// 用 mmu_w（recvmsg 需要写回）；false 用 mmu（sendmsg 只读）。返回 host msghdr；
// hmsg.msg_iov 指向 caller 提供的 vector<iovec>（已填好翻译后的 iov_base）。
// 失败（指针越界/iov 过多）返回 false 并设 *err 为负 errno。
static bool translate_msghdr(vm* v, const struct msghdr* gmsg, struct msghdr* hmsg,
                             std::vector<iovec>& hiov, bool writable, int64_t* err) {
    memset(hmsg, 0, sizeof(*hmsg));
    // msg_name + msg_namelen
    hmsg->msg_namelen = gmsg->msg_namelen;
    if(gmsg->msg_name != 0 && gmsg->msg_namelen > 0) {
        hmsg->msg_name = writable
            ? v->mmu_w(reinterpret_cast<uint64_t>(gmsg->msg_name), gmsg->msg_namelen)
            : v->mmu(reinterpret_cast<uint64_t>(gmsg->msg_name), gmsg->msg_namelen);
        if(hmsg->msg_name == nullptr) { *err = -EFAULT; return false; }
    }
    // msg_iov + msg_iovlen（guest 的 iovec 数组，逐个翻译 iov_base）
    int niov = gmsg->msg_iovlen;
    if(niov < 0) { *err = -EINVAL; return false; }
    if(niov > 1024) { *err = -EMSGSIZE; return false; }   // UIO_MAXIOV
    if(niov > 0 && gmsg->msg_iov != 0) {
        const iovec* giov = static_cast<const iovec*>(
            v->mmu(reinterpret_cast<uint64_t>(gmsg->msg_iov), sizeof(iovec) * (size_t)niov));
        if(giov == nullptr) { *err = -EFAULT; return false; }
        hiov.resize(niov);
        for(int i = 0; i < niov; ++i) {
            hiov[i].iov_len = giov[i].iov_len;
            if(giov[i].iov_base != 0 && giov[i].iov_len > 0) {
                hiov[i].iov_base = writable
                    ? v->mmu_w(reinterpret_cast<uint64_t>(giov[i].iov_base), giov[i].iov_len)
                    : v->mmu(reinterpret_cast<uint64_t>(giov[i].iov_base), giov[i].iov_len);
                if(hiov[i].iov_base == nullptr) { *err = -EFAULT; return false; }
            } else {
                hiov[i].iov_base = nullptr;
            }
        }
        hmsg->msg_iov = hiov.data();
        hmsg->msg_iovlen = niov;
    }
    // msg_control + msg_controllen（cmsg 缓冲区，send 用 mmu / recv 用 mmu_w）
    hmsg->msg_controllen = gmsg->msg_controllen;
    if(gmsg->msg_control != 0 && gmsg->msg_controllen > 0) {
        hmsg->msg_control = writable
            ? v->mmu_w(reinterpret_cast<uint64_t>(gmsg->msg_control), gmsg->msg_controllen)
            : v->mmu(reinterpret_cast<uint64_t>(gmsg->msg_control), gmsg->msg_controllen);
        if(hmsg->msg_control == nullptr) { *err = -EFAULT; return false; }
    }
    return true;
}

int64_t PosixSyscall::do_sendmsg(vm* v) {
    int guest_fd = arg_s32(v->r(1));
    auto h = ps->find_fd(guest_fd);
    if(!h) {
        return -EBADF;
    }
    const struct msghdr* gmsg = static_cast<const struct msghdr*>(
        v->mmu(v->r(2), sizeof(struct msghdr)));
    if(gmsg == nullptr) {
        return -EFAULT;
    }

    struct msghdr hmsg;
    std::vector<iovec> hiov;
    int64_t err;
    if(!translate_msghdr(v, gmsg, &hmsg, hiov, /*writable=*/false, &err)) {
        return err;
    }
    // msg_name 的 AF_UNIX pathname 同样过 chroot 前缀转换（同 bind/connect）；
    // haddr 需存活到 ::sendmsg 之后。
    struct sockaddr_storage haddr;
    if(hmsg.msg_name != nullptr && hmsg.msg_namelen > 0) {
        socklen_t hlen = hmsg.msg_namelen;
        const struct sockaddr* host_addr = sockaddr_to_host(
            static_cast<const struct sockaddr*>(hmsg.msg_name), hmsg.msg_namelen, &haddr, &hlen);
        if(host_addr == nullptr) {
            return -EINVAL;
        }
        hmsg.msg_name = const_cast<struct sockaddr*>(host_addr);
        hmsg.msg_namelen = hlen;
    }
    // cmsg 缓冲区需可写（SCM_RIGHTS 要把 guest fd 改写成 host fd），但 translate_msghdr
    // 用 mmu（只读语义）翻译的。拷一份到本地再改，避免污染 guest 的 cmsg（guest 的 fd
    // 原样保留，重复 sendmsg 时还能用）。
    std::vector<char> cmsg_buf;
    if(hmsg.msg_control != nullptr && hmsg.msg_controllen > 0) {
        cmsg_buf.resize(hmsg.msg_controllen);
        memcpy(cmsg_buf.data(), hmsg.msg_control, hmsg.msg_controllen);
        hmsg.msg_control = cmsg_buf.data();
        // SCM_RIGHTS: guest fd -> host fd（在本地副本上改）
        for(struct cmsghdr* cmsg = CMSG_FIRSTHDR(&hmsg); cmsg; cmsg = CMSG_NXTHDR(&hmsg, cmsg)) {
            if(cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS) {
                continue;
            }
            int* fds = reinterpret_cast<int*>(CMSG_DATA(cmsg));
            int nfds = static_cast<int>((cmsg->cmsg_len - sizeof(struct cmsghdr)) / sizeof(int));
            for(int i = 0; i < nfds; ++i) {
                auto fd_h = ps->find_fd(fds[i]);
                if(!fd_h) {
                    return -EBADF;
                }
                fds[i] = fd_h->host_fd();   // guest fd -> host fd
            }
        }
    }

    ssize_t rc = ::sendmsg(h->host_fd(), &hmsg, arg_s32(v->r(3)));
    if(rc < 0) {
        return (errno == EINTR) ? SYSCALL_RESTART : -errno;
    }
    return rc;
}

int64_t PosixSyscall::do_recvmsg(vm* v) {
    int guest_fd = arg_s32(v->r(1));
    auto h = ps->find_fd(guest_fd);
    if(!h) {
        return -EBADF;
    }
    struct msghdr* gmsg = static_cast<struct msghdr*>(
        v->mmu_w(v->r(2), sizeof(struct msghdr)));
    if(gmsg == nullptr) {
        return -EFAULT;
    }

    struct msghdr hmsg;
    std::vector<iovec> hiov;
    int64_t err;
    if(!translate_msghdr(v, gmsg, &hmsg, hiov, /*writable=*/true, &err)) {
        return err;
    }

    ssize_t rc = ::recvmsg(h->host_fd(), &hmsg, arg_s32(v->r(3)));
    if(rc < 0) {
        return (errno == EINTR) ? SYSCALL_RESTART : -errno;
    }
    // 容量取 guest 传入的 msg_namelen（此刻 gmsg 尚未被写回，仍是原值）。
    sockaddr_to_guest(static_cast<struct sockaddr*>(hmsg.msg_name), &hmsg.msg_namelen,
                      gmsg->msg_namelen);
    // host 写回的状态拷给 guest msghdr
    gmsg->msg_flags = hmsg.msg_flags;
    gmsg->msg_namelen = hmsg.msg_namelen;
    gmsg->msg_controllen = hmsg.msg_controllen;
    // SCM_RIGHTS: host fd -> guest fd（host 内核已在本进程安装 host fd，登记进接收方 fd 表）。
    for(struct cmsghdr* cmsg = CMSG_FIRSTHDR(&hmsg); cmsg; cmsg = CMSG_NXTHDR(&hmsg, cmsg)) {
        if(cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS) {
            continue;
        }
        int* fds = reinterpret_cast<int*>(CMSG_DATA(cmsg));
        int nfds = static_cast<int>((cmsg->cmsg_len - sizeof(struct cmsghdr)) / sizeof(int));
        for(int i = 0; i < nfds; ++i) {
            int host_fd = fds[i];
            int new_guest = ps->fds_emplace(std::make_shared<HostFd>(host_fd));
            fds[i] = new_guest;   // host fd -> guest fd，写回 guest 的 cmsg 缓冲区
        }
    }
    return rc;
}

// ===========================================================================
// setsockopt / getsockopt —— optval；getsockopt 的 optlen 是 in-out
// ===========================================================================

int64_t PosixSyscall::do_setsockopt(vm* v) {
    int guest_fd = arg_s32(v->r(1));
    auto h = ps->find_fd(guest_fd);
    if(!h) {
        return -EBADF;
    }
    int level   = arg_s32(v->r(2));
    int optname = arg_s32(v->r(3));
    socklen_t optlen = (socklen_t)arg_u32(v->r(5));
    const void* optval = v->mmu(v->r(4), optlen);
    if(optval == nullptr && optlen > 0) {
        return -EFAULT;
    }
    if(::setsockopt(h->host_fd(), level, optname, optval, optlen) < 0) {
        return -errno;
    }
    return 0;
}

int64_t PosixSyscall::do_getsockopt(vm* v) {
    int guest_fd = arg_s32(v->r(1));
    auto h = ps->find_fd(guest_fd);
    if(!h) {
        return -EBADF;
    }
    int level   = arg_s32(v->r(2));
    int optname = arg_s32(v->r(3));

    socklen_t* optlen = static_cast<socklen_t*>(v->mmu_w(v->r(5), sizeof(socklen_t)));
    if(optlen == nullptr) {
        return -EFAULT;
    }
    socklen_t curlen = *optlen;
    void* optval = nullptr;
    if(curlen > 0) {
        optval = v->mmu_w(v->r(4), curlen);
        if(optval == nullptr) {
            return -EFAULT;
        }
    }
    if(::getsockopt(h->host_fd(), level, optname, optval, optlen) < 0) {
        return -errno;
    }
    // optlen 已被 host 写回（实际选项值长度）。
    return 0;
}

// ===========================================================================
// getsockname / getpeername —— addr + in-out addrlen（同 accept4 模式）
// ===========================================================================

// getsockname / getpeername：addr 缓冲区按入参 *addrlen 容量映射（而非固定
// sizeof(struct sockaddr)=16B）。否则 AF_UNIX（sockaddr_un=110B）等大地址族会让
// host 内核按 *addrlen 写越界。模式同 do_accept4。
static inline int64_t do_sockname_common(vm* v, PosixSyscall* self, int host_fd,
        int (*host_call)(int, struct sockaddr*, socklen_t*)) {
    socklen_t* addrlen = static_cast<socklen_t*>(v->mmu_w(v->r(3), sizeof(socklen_t)));
    if(addrlen == nullptr) {
        return -EFAULT;
    }
    socklen_t curlen = *addrlen;   // 入参：缓冲区容量
    struct sockaddr* addr = nullptr;
    if(curlen > 0) {
        addr = static_cast<struct sockaddr*>(v->mmu_w(v->r(2), curlen));
        if(addr == nullptr) {
            return -EFAULT;
        }
    }
    if(host_call(host_fd, addr, addrlen) < 0) {
        return -errno;
    }
    self->sockaddr_to_guest(addr, addrlen, curlen);
    return 0;
}

int64_t PosixSyscall::do_getsockname(vm* v) {
    auto h = ps->find_fd(arg_s32(v->r(1)));
    if(!h) {
        return -EBADF;
    }
    return do_sockname_common(v, this, h->host_fd(), ::getsockname);
}

int64_t PosixSyscall::do_getpeername(vm* v) {
    auto h = ps->find_fd(arg_s32(v->r(1)));
    if(!h) {
        return -EBADF;
    }
    return do_sockname_common(v, this, h->host_fd(), ::getpeername);
}

// ===========================================================================
// epoll
// ===========================================================================
//

int64_t PosixSyscall::do_epoll_create1(vm* v) {
    int flags = arg_s32(v->r(1));
    int host_fd = ::epoll_create1(flags);
    if(host_fd < 0) {
        return -errno;
    }
    auto handle = std::make_shared<HostFd>(host_fd);
    // EPOLL_CLOEXEC == O_CLOEXEC；host 已处理，VM 登记 cloexec 属性。
    if(flags & EPOLL_CLOEXEC) {
        handle->cloexec = true;
    }
    return ps->fds_emplace(handle);
}

int64_t PosixSyscall::do_epoll_ctl(vm* v) {
    int epfd = arg_s32(v->r(1));
    auto ep_h = ps->find_fd(epfd);
    if(!ep_h) {
        return -EBADF;
    }
    int op = arg_s32(v->r(2));
    int target_guest = arg_s32(v->r(3));
    auto tg_h = ps->find_fd(target_guest);
    if(op != EPOLL_CTL_DEL && !tg_h) {
        return -EBADF;
    }

    // 读 guest 的 16B 非紧凑 epoll_event，转成 host 12B 紧凑。
    bpf::epoll_event* gev = static_cast<bpf::epoll_event*>(
        v->mmu(v->r(4), sizeof(bpf::epoll_event)));
    if(gev == nullptr) {
        return -EFAULT;
    }
    epoll_event hev;
    hev.events = gev->events;
    // bpf::epoll_data_t 与 host epoll_data_t 是不同类型（分属 bpf:: 与全局命名空间），
    // 但都是 8B opaque union、布局一致。按 u64 整体搬运，不解析 data 语义。
    hev.data.u64 = gev->data.u64;

    int target_host = tg_h ? tg_h->host_fd() : -1;
    if(::epoll_ctl(ep_h->host_fd(), op, target_host,
                   reinterpret_cast<struct epoll_event*>(&hev)) < 0) {
        return -errno;
    }
    return 0;
}

int64_t PosixSyscall::do_epoll_pwait(vm* v) {
    int epfd = arg_s32(v->r(1));
    auto h = ps->find_fd(epfd);
    if(!h) {
        return -EBADF;
    }
    int maxev = arg_s32(v->r(3));
    int timeout = arg_s32(v->r(4));
    if(maxev <= 0) {
        return -EINVAL;
    }

    // sigset 可空（epoll_wait 经 epoll_pwait(...,NULL) 调来）。sigsetsize（第 6 参，走
    // r0）host epoll_pwait 不需要 VM 显式传，host 内核按自身 _NSIG 处理，忽略。
    const sigset_t* sigs = nullptr;
    if(v->r(5) != 0) {
        sigs = static_cast<const sigset_t*>(v->mmu(v->r(5), sizeof(sigset_t)));
        if(sigs == nullptr) {
            return -EFAULT;
        }
    }

    std::vector<epoll_event> hev(maxev);
    // h 是 find_fd 拷贝出的 shared_ptr<Fd>，::epoll_pwait 阻塞期间持有者不释放，
    // 与并发 dup/open/close 不冲突（fds COW 快照语义）。
    int n = ::epoll_pwait(h->host_fd(), reinterpret_cast<struct epoll_event*>(hev.data()),
                          maxev, timeout, sigs);
    if(n < 0) {
        return (errno == EINTR) ? SYSCALL_RESTART : -errno;
    }

    bpf::epoll_event* gev = static_cast<bpf::epoll_event*>(
        v->mmu_w(v->r(2), sizeof(bpf::epoll_event) * (size_t)maxev));
    if(gev == nullptr) {
        return -EFAULT;
    }
    for(int i = 0; i < n; ++i) {
        gev[i].events = hev[i].events;
        // 同 do_epoll_ctl：data 按 u64 整体搬运（bpf::epoll_data_t 与 host epoll_data_t
        // 是不同类型但同布局的 8B opaque union）。
        gev[i].data.u64 = hev[i].data.u64;
        // _pad 字段保持为 0（mmu_w 的内存不保证已清零；显式写更安全）
        gev[i]._pad   = 0;
    }
    return n;
}
