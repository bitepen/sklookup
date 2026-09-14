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

static volatile sig_atomic_t running = 1;

static void sig_handler(int sig)
{
    (void)sig;
    running = 0;
}

static int create_listener(void)
{
    int fd;
    int opt = 1;

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
        .sin_port = htons(31337),
    };

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind 31337");
        close(fd);
        return -1;
    }

    if (listen(fd, 16) < 0) {
        perror("listen");
        close(fd);
        return -1;
    }

    return fd;
}

static void serve(int fd)
{
    printf("[server] listening on 127.0.0.1:31337\n");

    while (running) {
        int client;
        char buf[4096];

        client = accept(fd, NULL, NULL);
        if (client < 0) {
            if (errno == EINTR)
                continue;
            perror("accept");
            break;
        }

        printf("[server] connection received via sk_lookup!\n");

        const char *msg = "HELLO FROM SK_LOOKUP\n";
        send(client, msg, strlen(msg), 0);

        ssize_t n = recv(client, buf, sizeof(buf) - 1, 0);
        if (n > 0) {
            buf[n] = '\0';
            printf("[server] received:\n%s\n", buf);
        }

        close(client);
    }
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