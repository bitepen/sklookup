#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <dirent.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "sklookup.skel.h"

#ifndef __NR_pidfd_open
#define __NR_pidfd_open 434
#endif
#ifndef __NR_pidfd_getfd
#define __NR_pidfd_getfd 438
#endif

static volatile sig_atomic_t running = 1;

static void sig_handler(int sig)
{
    (void)sig;
    running = 0;
}

/* 
 * 借助 Linux 6.6 的 pidfd_getfd，克隆 Mihomo 的监听 Socket
 * 增加了 SO_TYPE == SOCK_STREAM 严格校验，防止错抓 UDP 导致断网
 */
static int get_mihomo_socket_fd(int pid, int target_port)
{
    int pidfd = syscall(__NR_pidfd_open, pid, 0);
    if (pidfd < 0) {
        perror("pidfd_open failed");
        return -1;
    }

    char fd_dir_path[64];
    snprintf(fd_dir_path, sizeof(fd_dir_path), "/proc/%d/fd", pid);
    DIR *dir = opendir(fd_dir_path);
    if (!dir) {
        perror("opendir /proc/[pid]/fd failed");
        close(pidfd);
        return -1;
    }

    struct dirent *entry;
    int target_sock = -1;

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.')
            continue;

        int remote_fd = atoi(entry->d_name);
        if (remote_fd <= 2)
            continue;

        int local_fd = syscall(__NR_pidfd_getfd, pidfd, remote_fd, 0);
        if (local_fd < 0)
            continue;

        // 核心修复：必须是 TCP (SOCK_STREAM)，坚决排除 UDP
        int sock_type = 0;
        socklen_t type_len = sizeof(sock_type);
        if (getsockopt(local_fd, SOL_SOCKET, SO_TYPE, &sock_type, &type_len) < 0 || sock_type != SOCK_STREAM) {
            close(local_fd);
            continue;
        }

        struct sockaddr_storage ss;
        socklen_t len = sizeof(ss);

        if (getsockname(local_fd, (struct sockaddr *)&ss, &len) == 0) {
            int port = 0;
            if (ss.ss_family == AF_INET) {
                port = ntohs(((struct sockaddr_in *)&ss)->sin_port);
            } else if (ss.ss_family == AF_INET6) {
                port = ntohs(((struct sockaddr_in6 *)&ss)->sin6_port);
            }

            if (port == target_port) {
                target_sock = local_fd;
                break;
            }
        }
        close(local_fd);
    }

    closedir(dir);
    close(pidfd);
    return target_sock;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <mihomo_pid> [target_port]\n", argv[0]);
        return 1;
    }

    int mihomo_pid = atoi(argv[1]);
    int target_port = (argc >= 3) ? atoi(argv[2]) : 7891;

    struct sklookup_bpf *skel = NULL;
    struct bpf_link *link_sklookup = NULL;
    struct bpf_link *link_dns_c4 = NULL;
    struct bpf_link *link_dns_s4 = NULL;
    struct bpf_link *link_dns_c6 = NULL;
    struct bpf_link *link_dns_s6 = NULL;

    int mihomo_fd = -1;
    int netns_fd = -1;
    int cgroup_fd = -1;
    __u32 key = 0;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("[+] Fetching listening TCP socket for port %d from PID %d...\n", target_port, mihomo_pid);
    mihomo_fd = get_mihomo_socket_fd(mihomo_pid, target_port);
    if (mihomo_fd < 0) {
        fprintf(stderr, "[-] Could not find listening TCP socket on port %d in PID %d\n", target_port, mihomo_pid);
        return 1;
    }
    printf("[+] Grabbed TCP socket successfully! Local cloned FD: %d\n", mihomo_fd);

    netns_fd = open("/proc/self/ns/net", O_RDONLY);
    if (netns_fd < 0) {
        perror("open netns failed");
        close(mihomo_fd);
        return 1;
    }

    printf("[+] Loading BPF skeleton...\n");
    skel = sklookup_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "[-] Failed to load BPF skeleton\n");
        goto cleanup;
    }

    // 1. 注册 Mihomo PID 到配置表（防 DNS 自身死锁）
    __u32 cfg_val = (__u32)mihomo_pid;
    if (bpf_map_update_elem(bpf_map__fd(skel->maps.config_map), &key, &cfg_val, BPF_ANY) < 0) {
        perror("[-] Failed to register Mihomo PID in config_map");
        goto cleanup;
    }
    printf("[+] Mihomo PID %d registered to config_map\n", mihomo_pid);

    // 2. 注册 TCP 监听 Socket 到 SOCKMAP
    if (bpf_map_update_elem(bpf_map__fd(skel->maps.redirect_socket), &key, &mihomo_fd, BPF_ANY) < 0) {
        perror("[-] Failed to register socket in SOCKMAP");
        goto cleanup;
    }
    printf("[+] TCP Socket registered to SOCKMAP\n");

    // 3. 挂载 sk_lookup 钩子
    link_sklookup = bpf_program__attach_netns(skel->progs.sk_lookup_redirect, netns_fd);
    if (!link_sklookup) {
        fprintf(stderr, "[-] Failed to attach SK_LOOKUP: %s (errno=%d)\n", strerror(errno), errno);
        goto cleanup;
    }
    printf("[+] SK_LOOKUP attached to netns\n");

    // 4. 打开根 cgroup 并挂载 4 个 DNS 系统调用拦截钩子
    cgroup_fd = open("/sys/fs/cgroup", O_RDONLY | O_CLOEXEC);
    if (cgroup_fd < 0) {
        perror("[-] Failed to open /sys/fs/cgroup");
        goto cleanup;
    }

    link_dns_c4 = bpf_program__attach_cgroup(skel->progs.dns_connect4, cgroup_fd);
    link_dns_s4 = bpf_program__attach_cgroup(skel->progs.dns_sendmsg4, cgroup_fd);
    link_dns_c6 = bpf_program__attach_cgroup(skel->progs.dns_connect6, cgroup_fd);
    link_dns_s6 = bpf_program__attach_cgroup(skel->progs.dns_sendmsg6, cgroup_fd);

    if (!link_dns_c4 || !link_dns_s4 || !link_dns_c6 || !link_dns_s6) {
        fprintf(stderr, "[-] Failed to attach one or more cgroup DNS hooks\n");
        goto cleanup;
    }
    printf("[+] cgroup DNS interception active!\n");

    printf("\n[+] ==========================================\n");
    printf("[+] Pure eBPF Proxy is now ACTIVE!\n");
    printf("[+] TCP Traffic -> Mihomo (Port %d)\n", target_port);
    printf("[+] DNS Queries -> Rewritten to 127.0.0.1:1053\n");
    printf("[+] IPv6 DNS 53 -> Instantly Rejected\n");
    printf("[+] Zero iptables rules required!\n");
    printf("[+] ==========================================\n\n");

    while (running) {
        sleep(1);
    }

    printf("\n[+] Detaching all hooks and exiting...\n");

cleanup:
    if (link_dns_s6) bpf_link__destroy(link_dns_s6);
    if (link_dns_c6) bpf_link__destroy(link_dns_c6);
    if (link_dns_s4) bpf_link__destroy(link_dns_s4);
    if (link_dns_c4) bpf_link__destroy(link_dns_c4);
    if (link_sklookup) bpf_link__destroy(link_sklookup);
    if (cgroup_fd >= 0) close(cgroup_fd);
    if (skel) sklookup_bpf__destroy(skel);
    if (netns_fd >= 0) close(netns_fd);
    if (mihomo_fd >= 0) close(mihomo_fd);

    printf("[+] Completed. Exited cleanly.\n");
    return 0;
}