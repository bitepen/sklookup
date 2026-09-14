#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* SOCKMAP 用于存放 Mihomo 监听套接字 */
struct {
    __uint(type, BPF_MAP_TYPE_SOCKMAP);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} redir_map SEC(".maps");

SEC("sk_lookup")
int lookup_tcp(struct bpf_sk_lookup *ctx)
{
    /* 1. 协议过滤：仅处理 TCP 握手流量 */
    if (ctx->protocol != IPPROTO_TCP)
        return BPF_OK;

    /* 2. 防自环短路：如果目标端口本来就是 Mihomo 监听端口 (7891)，绝不重定向 */
    /* 注：在 bpf_sk_lookup 上下文中，local_port 内核已转换为主机字节序 (Host Byte Order) */
    if (ctx->local_port == 7891)
        return BPF_OK;

    /* 3. 从 SOCKMAP 提取套接字 */
    __u32 key = 0;
    struct bpf_sock *sk = bpf_map_lookup_elem(&redir_map, &key);
    if (!sk)
        return BPF_OK;

    /* 4. 分配 Socket 并完成重定向 */
    /* BPF_SK_LOOKUP_F_REPLACE 确保覆盖内核默认查找结果 */
    int err = bpf_sk_assign(ctx, sk, BPF_SK_LOOKUP_F_REPLACE);

    /* 5. 核心：配对释放引用计数！
     * bpf_map_lookup_elem 返回的套接字持有内核引用计数，
     * 无论 assign 成功与否，BPF 程序必须显式调用 bpf_sk_release 归还引用，
     * 否则内核 verifier 会拦截，强行跳过会导致严重内核内存泄漏。
     */
    bpf_sk_release(sk);

    return err == 0 ? BPF_OK : BPF_DROP;
}

char _license[] SEC("license") = "GPL";