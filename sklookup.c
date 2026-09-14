#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

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

/* 根据端口号与 PID，抓取对应的监听 Socket FD */
static int get_mihomo_socket_fd(int pid, int target_port) {
    int pidfd = syscall(__NR_pidfd_open, pid, 0);
    if (pidfd < 0) return -1;

    char fd_dir_path[64];
    snprintf(fd_dir_path, sizeof(fd_dir_path), "/proc/%d/fd", pid);
    DIR *dir = opendir(fd_dir_path);
    if (!dir) { close(pidfd); return -1; }

    struct dirent *entry;
    int target_sock = -1;

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;
        int remote_fd = atoi(entry->d_name);
        
        // 利用 pidfd_getfd 将 Mihomo 的 FD 复制到当前进程
        int local_fd = syscall(__NR_pidfd_getfd, pidfd, remote_fd, 0);
        if (local_fd < 0) continue;

        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        if (getsockname(local_fd, (struct sockaddr *)&addr, &len) == 0) {
            if (ntohs(addr.sin_port) == target_port) {
                target_sock = local_fd;
                break; // 成功找到 Mihomo 的监听 Socket
            }
        }
        close(local_fd);
    }
    closedir(dir);
    close(pidfd);
    return target_sock;
}

int main(void)
{
    struct sklookup_bpf *skel = NULL;
    struct bpf_link *link = NULL;
    int listener_fd = -1;
    int netns_fd = -1;
    __u32 key = 0;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("[+] creating listener on 31337...\n");
    listener_fd = create_listener();
    if (listener_fd < 0)
        return 1;

    netns_fd = open("/proc/self/ns/net", O_RDONLY);
    if (netns_fd < 0) {
        perror("open netns");
        return 1;
    }

    printf("[+] opening BPF skeleton...\n");
    skel = sklookup_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "[-] failed to load BPF program\n");
        return 1;
    }

    if (bpf_map_update_elem(
            bpf_map__fd(skel->maps.redirect_socket),
            &key,
            &listener_fd,
            BPF_ANY) < 0) {
        perror("bpf_map_update_elem");
        return 1;
    }

    printf("[+] listener registered in SOCKMAP\n");

    link = bpf_program__attach_netns(skel->progs.sk_lookup_redirect, netns_fd);
    if (!link) {
        fprintf(stderr, "[-] failed to attach SK_LOOKUP: %s (errno=%d)\n", strerror(errno), errno);
        return 1;
    }

    printf("\n[+] SK_LOOKUP successfully attached!\n");
    printf("[+] TCP 127.0.0.1:9999 -> 127.0.0.1:31337\n");
    printf("[+] press Ctrl+C to stop\n\n");

    serve(listener_fd);

    bpf_link__destroy(link);
    sklookup_bpf__destroy(skel);
    close(netns_fd);
    close(listener_fd);

    return 0;
}