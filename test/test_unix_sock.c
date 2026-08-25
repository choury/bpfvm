// test_unix_sock.c — 验证 bpfvm 的 AF_UNIX pathname socket。
// 覆盖：socket/bind/listen/connect/accept/send/recv + getsockname/getpeername 的
// 地址往返（sun_path 应与 bind 时一致——chroot 前缀转换对称性的回归）、小缓冲
// getsockname 的越界回归，以及抽象命名空间（sun_path[0]='\0'）的透传。
// 另注册 chroot 变体（CMakeLists 的 BPF_ROOT_TESTS），rootfs 相关适配见各节注释。

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stddef.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>

/* chroot rootfs 可能没有 /tmp：bind 落在 rootfs/tmp，遇 ENOENT 先建目录再试。
 * 非 chroot 时 /tmp 已存在，首次 bind 直接成功，不会走到 mkdir。 */
static int bind_or_mkdir(int fd, const struct sockaddr_un *addr)
{
    if (bind(fd, (const struct sockaddr *)addr, sizeof(*addr)) == 0) {
        return 0;
    }
    if (errno == ENOENT && (mkdir("/tmp", 0777) == 0 || errno == EEXIST)
        && bind(fd, (const struct sockaddr *)addr, sizeof(*addr)) == 0) {
        return 0;
    }
    return -1;
}

int main(void)
{
    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    /* 路径要短：chroot 变体的 rootfs 前缀约 80 字符，加本路径后须仍在
     * sun_path(108) 内。 */
    snprintf(addr.sun_path, sizeof(addr.sun_path), "/tmp/tus_%d", getpid());
    unlink(addr.sun_path);

    int lfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (lfd < 0) { perror("socket l"); return 1; }
    if (bind_or_mkdir(lfd, &addr) < 0) {
        fprintf(stderr, "bind main failed: path=%s errno=%d\n", addr.sun_path, errno);
        return 1;
    }
    if (listen(lfd, 1) < 0) { perror("listen"); return 1; }

    int cfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (cfd < 0) { perror("socket c"); return 1; }
    if (connect(cfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) { perror("connect"); return 1; }

    struct sockaddr_un mine = {0}, peer = {0};
    socklen_t mlen = sizeof(mine), plen = sizeof(peer);
    if (getsockname(lfd, (struct sockaddr*)&mine, &mlen) < 0) { perror("getsockname"); return 1; }
    if (strcmp(mine.sun_path, addr.sun_path) != 0) {
        fprintf(stderr, "FAIL: getsockname='%s' want '%s'\n", mine.sun_path, addr.sun_path);
        return 1;
    }
    if (getpeername(cfd, (struct sockaddr*)&peer, &plen) < 0) { perror("getpeername"); return 1; }
    if (strcmp(peer.sun_path, addr.sun_path) != 0) {
        fprintf(stderr, "FAIL: getpeername='%s' want '%s'\n", peer.sun_path, addr.sun_path);
        return 1;
    }

    const char *msg = "ping";
    if (send(cfd, msg, strlen(msg), 0) != (ssize_t)strlen(msg)) { perror("send"); return 1; }
    struct sockaddr_un from = {0};
    socklen_t flen = sizeof(from);
    int afd = accept(lfd, (struct sockaddr*)&from, &flen);
    if (afd < 0) { perror("accept"); return 1; }

    char buf[64] = {0};
    if (recv(afd, buf, sizeof(buf) - 1, 0) < 0) { perror("recv"); return 1; }
    if (strcmp(buf, "ping") != 0) {
        fprintf(stderr, "FAIL: server got '%s'\n", buf);
        return 1;
    }
    const char *reply = "pong";
    if (send(afd, reply, strlen(reply), 0) != (ssize_t)strlen(reply)) { perror("send reply"); return 1; }
    memset(buf, 0, sizeof(buf));
    if (recv(cfd, buf, sizeof(buf) - 1, 0) < 0) { perror("recv client"); return 1; }
    if (strcmp(buf, "pong") != 0) {
        fprintf(stderr, "FAIL: client got '%s'\n", buf);
        return 1;
    }
    close(afd);
    close(cfd);
    close(lfd);
    unlink(addr.sun_path);

    /* 回归：getsockname 传入小于 sockaddr_un(110) 但装得下 root 前缀的缓冲。
     * chroot 下宿主路径长于缓冲：内核只写 min(容量,记录长度) 字节而 *len 报
     * 完整记录长度，VM 剥前缀时的扫描/清零越过写入范围会破坏缓冲外内存。
     * 定长 21 字符路径保证各变体的 rootfs 前缀下必然截断（recorded = 前缀+24
     * > 96，且前缀 <= 94 装得进可见区）。 */
    struct sockaddr_un saddr = {0};
    saddr.sun_family = AF_UNIX;
    snprintf(saddr.sun_path, sizeof(saddr.sun_path), "/tmp/tusb_%07d_pad", getpid());
    unlink(saddr.sun_path);
    int sfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sfd < 0) { perror("socket sb"); return 1; }
    if (bind_or_mkdir(sfd, &saddr) < 0) { perror("bind sb"); return 1; }

    struct { char buf[96]; unsigned char guard[96]; } sb;
    memset(sb.guard, 0xAA, sizeof(sb.guard));
    socklen_t slen = sizeof(sb.buf);
    if (getsockname(sfd, (struct sockaddr*)&sb.buf, &slen) < 0) { perror("getsockname sb"); return 1; }
    sa_family_t fam = AF_UNIX;
    if (memcmp(sb.buf, &fam, sizeof(fam)) != 0 || sb.buf[sizeof(fam)] != '/') {
        fprintf(stderr, "FAIL: small-buffer getsockname family/path\n");
        return 1;
    }
    for (size_t i = 0; i < sizeof(sb.guard); i++) {
        if (sb.guard[i] != 0xAA) {
            fprintf(stderr, "FAIL: small-buffer getsockname clobbered adjacent memory\n");
            return 1;
        }
    }
    close(sfd);
    unlink(saddr.sun_path);

    /* 抽象名不经文件系统、宿主全局（chroot 不隔离）：普通/chroot 两个 ctest 条目
     * 并发跑，guest pid 在各 VM 里都从小号起、无法去重，用单调钟纳秒做唯一后缀。 */
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    struct sockaddr_un aaddr = {0};
    aaddr.sun_family = AF_UNIX;
    snprintf(aaddr.sun_path + 1, sizeof(aaddr.sun_path) - 1, "test_unix_sock_abs_%lld",
             (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec);
    socklen_t alen = offsetof(struct sockaddr_un, sun_path) + 1 + strlen(aaddr.sun_path + 1);
    int alf = socket(AF_UNIX, SOCK_STREAM, 0);
    if (alf < 0) { perror("socket abstract"); return 1; }
    if (bind(alf, (struct sockaddr*)&aaddr, alen) < 0) { perror("bind abstract"); return 1; }
    if (listen(alf, 1) < 0) { perror("listen abstract"); return 1; }
    int acf = socket(AF_UNIX, SOCK_STREAM, 0);
    if (acf < 0) { perror("socket abstract c"); return 1; }
    if (connect(acf, (struct sockaddr*)&aaddr, alen) < 0) { perror("connect abstract"); return 1; }
    if (send(acf, "a", 1, 0) != 1) { perror("send abstract"); return 1; }
    int aaf = accept(alf, NULL, NULL);
    if (aaf < 0) { perror("accept abstract"); return 1; }
    if (recv(aaf, buf, 1, 0) != 1) { perror("recv abstract"); return 1; }
    close(aaf);
    close(acf);
    close(alf);

    printf("test_unix_sock OK\n");
    return 0;
}
