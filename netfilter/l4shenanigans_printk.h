#ifndef L4SHENANIGANS_PRINTK_H
#define L4SHENANIGANS_PRINTK_H

#include <linux/ip.h>
#include <linux/printk.h>
#include <linux/skbuff.h>

#define PR_ERR_RATELIMITED(skb, fmt, ...) {     \
        struct iphdr *iph = ip_hdr(skb);        \
        pr_err_ratelimited("[%pI4 -> %pI4]" fmt,                     \
                           &iph->saddr, &iph->daddr, ##__VA_ARGS__); \
}

#endif /* L4SHENANIGANS_PRINTK_H */
