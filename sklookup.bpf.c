#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

#define MIHOMO_PORT 7893

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

    /* 仅处理 TCP 连接请求 */
    if (ctx->protocol != IPPROTO_TCP)
        return SK_PASS;

    /* 绝对排除发往 Mihomo 监听端口自身的流量，防止内核死锁 */
    if (ctx->local_port == MIHOMO_PORT)
        return SK_PASS;

    /* 
     * 流量放行过滤：
     * 现阶段可先指定只劫持 80 和 443 进行安全验证；
     * 验证通过后即可取消注释放行所有端口。
     */
    if (ctx->local_port != 80 && ctx->local_port != 443)
        return SK_PASS;

    sk = bpf_map_lookup_elem(&redirect_socket, &key);
    if (!sk)
        return SK_PASS;

    bpf_sk_assign(ctx, sk, BPF_SK_LOOKUP_F_REPLACE);
    bpf_sk_release(sk);

    return SK_PASS;
}