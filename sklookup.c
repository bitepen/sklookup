#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "sklookup.skel.h"

#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif

#ifndef SYS_pidfd_getfd
#define SYS_pidfd_getfd 438
#endif

static volatile sig_atomic_t g_stop = 0;

static void sig_handler(int sig) {
    (void)sig;
    g_stop = 1;
}

/* 遍历目标 PID 的所有 FD，精准寻找监听指定端口的 TCP 套接字 */
static int get_listening_socket(pid_t target_pid, int target_port) {
    char path[128];
    snprintf(path, sizeof(path), "/proc/%d/fd", target_pid);

    DIR *dir = opendir(path);
    if (!dir) {
        perror("[-] 打开 /proc/<pid>/fd 失败");
        return -1;
    }

    int pidfd = syscall(SYS_pidfd_open, target_pid, 0);
    if (pidfd < 0) {
        perror("[-] pidfd_open 失败");
        closedir(dir);
        return -1;
    }

    int matched_fd = -1;
    struct dirent *entry;

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.')
            continue;

        int fd = atoi(entry->d_name);
        if (fd <= 2)
            continue; // 跳过标准输入输出

        int local_fd = syscall(SYS_pidfd_getfd, pidfd, fd, 0);
        if (local_fd < 0)
            continue;

        // 1. 严格校验 Socket 类型：必须是 SOCK_STREAM (TCP)
        int sock_type = 0;
        socklen_t optlen = sizeof(sock_type);
        if (getsockopt(local_fd, SOL_SOCKET, SO_TYPE, &sock_type, &optlen) < 0 || sock_type != SOCK_STREAM) {
            close(local_fd);
            continue;
        }

        // 2. 严格校验监听状态：必须处于 LISTEN 状态（避免误抓主动连出的 TCP 客户端套接字）
        int accepting = 0;
        optlen = sizeof(accepting);
        if (getsockopt(local_fd, SOL_SOCKET, SO_ACCEPTCONN, &accepting, &optlen) < 0 || !accepting) {
            close(local_fd);
            continue;
        }

        // 3. 校验端口：同时兼容 IPv4 (AF_INET) 和 IPv6 双栈 (AF_INET6)
        struct sockaddr_storage ss;
        socklen_t slen = sizeof(ss);
        if (getsockname(local_fd, (struct sockaddr *)&ss, &slen) == 0) {
            int bound_port = 0;
            if (ss.ss_family == AF_INET) {
                bound_port = ntohs(((struct sockaddr_in *)&ss)->sin_port);
            } else if (ss.ss_family == AF_INET6) {
                bound_port = ntohs(((struct sockaddr_in6 *)&ss)->sin6_port);
            }

            if (bound_port == target_port) {
                matched_fd = local_fd;
                break; // 成功匹配，终止扫描
            }
        }

        close(local_fd);
    }

    close(pidfd);
    closedir(dir);
    return matched_fd;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "用法: %s <mihomo_pid> <listen_port>\n", argv[0]);
        return 1;
    }

    pid_t target_pid = (pid_t)atoi(argv[1]);
    int target_port = atoi(argv[2]);

    // 注册信号捕获，确保退出的原子性与优雅清理
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("[*] 正在从 PID %d 探测端口 %d 的 TCP 监听套接字...\n", target_pid, target_port);
    int sock_fd = get_listening_socket(target_pid, target_port);
    if (sock_fd < 0) {
        fprintf(stderr, "[-] 未找到匹配的监听套接字，请确认 Mihomo 已就绪。\n");
        return 1;
    }
    printf("[+] 成功获取套接字！本地副本 FD: %d\n", sock_fd);

    // 加载 BPF Skeleton
    struct sklookup_bpf *skel = sklookup_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "[-] BPF skeleton 加载失败\n");
        close(sock_fd);
        return 1;
    }

    // 更新 SOCKMAP
    __u32 key = 0;
    __u64 val = (__u64)sock_fd;
    int map_fd = bpf_map__fd(skel->maps.redir_map);
    if (bpf_map_update_elem(map_fd, &key, &val, BPF_ANY) < 0) {
        perror("[-] bpf_map_update_elem 失败");
        sklookup_bpf__destroy(skel);
        close(sock_fd);
        return 1;
    }
    printf("[+] 套接字成功注入 SOCKMAP\n");

    // 打开当前网络命名空间并挂载
    int netns_fd = open("/proc/self/ns/net", O_RDONLY);
    if (netns_fd < 0) {
        perror("[-] 打开 netns 失败");
        sklookup_bpf__destroy(skel);
        close(sock_fd);
        return 1;
    }

    struct bpf_link *link = bpf_program__attach_netns(skel->progs.lookup_tcp, netns_fd);
    if (!link) {
        fprintf(stderr, "[-] bpf_program__attach_netns 挂载失败\n");
        close(netns_fd);
        sklookup_bpf__destroy(skel);
        close(sock_fd);
        return 1;
    }

    printf("[+] sk_lookup 挂载成功！正在守护监听...\n");

    // 挂起主线程，避免空转占用 CPU
    while (!g_stop) {
        sleep(1);
    }

    printf("\n[*] 接收到退出信号，正在安全卸载与清理...\n");
    bpf_link__destroy(link);
    close(netns_fd);
    sklookup_bpf__destroy(skel);
    close(sock_fd);

    printf("[+] 卸载完成，干净退出。\n");
    return 0;
}