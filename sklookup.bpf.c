#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

#define MIHOMO_PORT 7891

struct {
    __uint(type, BPF_MAP_TYPE_SOCKMAP);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} redirect_socket SEC(".maps");

SEC("sk_lookup")
int sk_lookup_redirect(struct bpf_sk_lookup *ctx)
{
    __u32 key = 0;
    struct bpf_sock *sk;

    /* 1. 仅处理 TCP 连接请求 */
    if (ctx->protocol != IPPROTO_TCP)
        return SK_PASS;

    /* 2. 排除发往 Mihomo 监听端口自身的流量，防止死锁 */
    if (ctx->local_port == MIHOMO_PORT)
        return SK_PASS;

    /* 3. 排除发往 127.0.0.0/8 回环地址的连接，保护本地 Web 面板与本地服务 */
    if ((bpf_ntohl(ctx->local_ip4) >> 24) == 127)
        return SK_PASS;

    /* 4. 放开端口限制：将全端口（含 HMS 5228 等）正常派发给 Mihomo */
    sk = bpf_map_lookup_elem(&redirect_socket, &key);
    if (!sk)
        return SK_PASS;

    bpf_sk_assign(ctx, sk, BPF_SK_LOOKUP_F_REPLACE);
    bpf_sk_release(sk);

    return SK_PASS;
}