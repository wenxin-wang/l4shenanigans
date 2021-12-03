#ifndef L4SHENANIGANS_PROTOCOL_H
#define L4SHENANIGANS_PROTOCOL_H

#include <linux/ip.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <uapi/linux/in.h>

#define ENCAP_LEN (2 + 4 + 2) // bytes

int encap_adjust_headroom(struct sk_buff *skb, int nhead, int payloadoff,
                          int csum_offset);

void update_iphdr_len(struct sk_buff *skb, int nhead);
void update_udp_len(struct sk_buff *skb, struct udphdr *udph, int nhead);
void update_tcp_len(struct sk_buff *skb, struct tcphdr *tcph, int old_len,
                    int nhead);

void udp_fill_encap(struct sk_buff *skb, struct udphdr *udph);
void udp_unfill_encap(struct sk_buff *skb, struct udphdr *udph,
                      __be32 encap_daddr, __be16 encap_dport);
int udp_load_encap(struct udphdr *udph, __be32 *encap_daddr,
                   __be16 *encap_dport);

void tcp_fill_encap(struct sk_buff *skb, struct tcphdr *tcph, int tcp_hdrl);
void tcp_unfill_encap(struct sk_buff *skb, struct tcphdr *tcph,
                      __be32 encap_daddr, __be16 encap_dport);
int tcp_load_encap(struct tcphdr *tcph, int tcp_hdrl, __be32 *encap_daddr,
                   __be16 *encap_dport);

#endif /* L4SHENANIGANS_PROTOCOL_H */
