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

        // 仅抓取 TCP (SOCK_STREAM) 套接字，规避同端口 UDP
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
    struct bpf_link *link = NULL;
    int mihomo_fd = -1;
    int netns_fd = -1;
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
        fprintf(stderr, "[-] Failed to load BPF program\n");
        close(mihomo_fd);
        close(netns_fd);
        return 1;
    }

    if (bpf_map_update_elem(
            bpf_map__fd(skel->maps.redirect_socket),
            &key,
            &mihomo_fd,
            BPF_ANY) < 0) {
        perror("bpf_map_update_elem failed");
        goto cleanup;
    }
    printf("[+] TCP Socket registered to SOCKMAP\n");

    link = bpf_program__attach_netns(skel->progs.sk_lookup_redirect, netns_fd);
    if (!link) {
        fprintf(stderr, "[-] Failed to attach SK_LOOKUP: %s (errno=%d)\n", strerror(errno), errno);
        goto cleanup;
    }

    printf("\n[+] ==========================================\n");
    printf("[+] SK_LOOKUP is now ACTIVE!\n");
    printf("[+] All Outbound TCP -> Mihomo (Port %d)\n", target_port);
    printf("[+] Press Ctrl+C to stop and detach\n");
    printf("[+] ==========================================\n\n");

    while (running) {
        pause();
    }

    printf("\n[+] Detaching and cleaning up...\n");

cleanup:
    if (link)
        bpf_link__destroy(link);
    if (skel)
        sklookup_bpf__destroy(skel);
    if (netns_fd >= 0)
        close(netns_fd);
    if (mihomo_fd >= 0)
        close(mihomo_fd);

    printf("[+] Completed. Exited cleanly.\n");
    return 0;
}