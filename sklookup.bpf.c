#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

/* 
 * 存储用户态 31337 监听套接字
 * key = 0, value = listening socket fd
 */
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

    /* 仅处理 TCP */
    if (ctx->protocol != IPPROTO_TCP)
        return SK_PASS;

    /* local_port 为主机字节序，直接比对 9999 端口 */
    if (ctx->local_port != 9999)
        return SK_PASS;

    sk = bpf_map_lookup_elem(&redirect_socket, &key);
    if (!sk)
        return SK_PASS;

    /* 覆盖目标套接字并立即释放引用 */
    bpf_sk_assign(ctx, sk, BPF_SK_LOOKUP_F_REPLACE);
    bpf_sk_release(sk);

    return SK_PASS;
}