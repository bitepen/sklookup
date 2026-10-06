#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

#define MIHOMO_PORT 7891

/* 扩充为 2 个槽位：
 * Key 0: TCP 7891 (常规 TCP 透明代理)
 * Key 1: UDP 7891 (TPROXY UDP，承载 DNS 劫持与常规 UDP)
 */
struct {
    __uint(type, BPF_MAP_TYPE_SOCKMAP);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u32);
} redirect_socket SEC(".maps");

SEC("sk_lookup")
int sk_lookup_redirect(struct bpf_sk_lookup *ctx)
{
    __u32 key = 0;
    struct bpf_sock *sk;

    /* 1. 保护机制：排除发往 127.0.0.0/8 回环地址的连接 */
    if ((bpf_ntohl(ctx->local_ip4) >> 24) == 127)
        return SK_PASS;

    /* 2. TCP 流量分支 */
    if (ctx->protocol == IPPROTO_TCP) {
        /* 防死锁：排除发往 Mihomo 监听端口自身的流量 */
        if (ctx->local_port == MIHOMO_PORT)
            return SK_PASS;

        key = 0; /* 取 TCP 7891 socket */
    }
    /* 3. UDP 流量分支：仅拦截发往 53 端口的 DNS 查询 */
    else if (ctx->protocol == IPPROTO_UDP && ctx->local_port == 53) {
        key = 1; /* 取 UDP 7891 TPROXY socket */
    }
    /* 其他未纳管流量直接放行 */
    else {
        return SK_PASS;
    }

    /* 4. 查找目标套接字并分派 */
    sk = bpf_map_lookup_elem(&redirect_socket, &key);
    if (!sk)
        return SK_PASS;

    bpf_sk_assign(ctx, sk, BPF_SK_LOOKUP_F_REPLACE);
    bpf_sk_release(sk);

    return SK_PASS;
}