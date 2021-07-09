#include <linux/ip.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter/x_tables.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <uapi/linux/in.h>

#include "compat/conntrack.h"
#ifdef COMPAT_NAT_CORE_HEADER
#include <net/netfilter/nf_nat_core.h>
#else
#include <net/netfilter/nf_nat.h>
#endif

#include "l4shenanigans_protocol.h"
#include "l4shenanigans_uapi.h"

static int l4shenanigan_dnat_parse_udp(struct sk_buff *skb,
                                       unsigned int udphoff,
                                       __be32 *encap_daddr,
                                       __be16 *encap_dport) {
  struct udphdr *udph;
  int ret;

  ret = skb_ensure_writable(skb, udphoff + (int)sizeof(struct udphdr));
  if (ret) {
    pr_err_ratelimited("l4shenanigan_dnat_udp: failed to ensure udp "
                       "header writable %d\n",
                       ret);
    return ret;
  }

  udph = (struct udphdr *)(skb_network_header(skb) + udphoff);
  if (ntohs(udph->len) < sizeof(struct udphdr)) {
    pr_info_ratelimited("l4shenanigan_dnat_udp: udp header too small %d\n",
                        ntohs(udph->len));
    return -1;
  }

  return udp_load_encap(udph, encap_daddr, encap_dport);
}

static int l4shenanigan_dnat_parse_tcp(struct sk_buff *skb,
                                       unsigned int tcphoff,
                                       __be32 *encap_daddr,
                                       __be16 *encap_dport) {
  struct tcphdr *tcph;
  int ret, tcp_hdrlen;

  ret = skb_ensure_writable(skb, tcphoff + (int)sizeof(struct tcphdr));
  if (ret) {
    pr_err_ratelimited("l4shenanigan_dnat_tcp: failed to ensure base tcp "
                       "header writable %d\n",
                       ret);
    return ret;
  }

  tcph = (struct tcphdr *)(skb_network_header(skb) + tcphoff);
  if (!tcph->syn) {
    return 0;
  }

  tcp_hdrlen = tcph->doff * 4;

  if (tcp_hdrlen < sizeof(struct tcphdr)) {
    pr_err_ratelimited("l4shenanigan_dnat_tcp: tcp header too small %d\n",
                       tcp_hdrlen);
    return -1;
  }

  ret = skb_ensure_writable(skb, tcphoff + tcp_hdrlen);
  if (ret) {
    pr_err_ratelimited("l4shenanigan_dnat_tcp: failed to ensure full tcp "
                       "header writable %d\n",
                       ret);
    return ret;
  }

  return tcp_load_encap(tcph, encap_daddr, encap_dport);
}

static unsigned int l4shenanigan_dnat_tg4(struct sk_buff *skb,
                                          const struct xt_action_param *par) {
  struct iphdr *iph = ip_hdr(skb);
#ifndef COMPAT_NAT_NO_RANGE2
  struct nf_nat_range2 range;
#else
  struct nf_nat_range range;
#endif
  enum ip_conntrack_info ctinfo;
  struct nf_conn *ct;
  int ret = 0;

  // This is a fragment, no header is available.
  // This should not happen as conntrack will be used together, which handles
  // defragmentation.
  if (unlikely(par->fragoff != 0)) {
    return XT_CONTINUE;
  }

  switch (iph->protocol) {
  case IPPROTO_UDP:
    ret = l4shenanigan_dnat_parse_udp(
        skb, iph->ihl * 4, &range.max_addr.in.s_addr, &range.max_proto.all);
    break;
  case IPPROTO_TCP:
    ret = l4shenanigan_dnat_parse_tcp(
        skb, iph->ihl * 4, &range.max_addr.in.s_addr, &range.max_proto.all);
    break;
  default:
    return XT_CONTINUE;
  }
  if (ret) {
    pr_err_ratelimited("l4shenanigan_dnat_tg4: failed to parse encap %d\n",
                       ret);
    return NF_DROP;
  }

  ct = nf_ct_get(skb, &ctinfo);
  WARN_ON(!(ct != NULL && (ctinfo == IP_CT_NEW || ctinfo == IP_CT_RELATED ||
                           ctinfo == IP_CT_RELATED_REPLY)));

  range.flags = NF_NAT_RANGE_MAP_IPS | NF_NAT_RANGE_PROTO_SPECIFIED;
  range.min_addr.in = range.max_addr.in;
  range.min_proto.all = range.max_proto.all;
  return nf_nat_setup_info(ct, &range, NF_NAT_MANIP_DST);
}

static int l4shenanigan_dnat_tg4_check(const struct xt_tgchk_param *par) {
#ifndef COMPAT_CT_NO_NETNS_GETPUT
  nf_ct_netns_get(par->net, par->family);
#endif
  return 0;
}

static void l4shenanigan_dnat_tg4_destroy(const struct xt_tgdtor_param *par) {
#ifndef COMPAT_CT_NO_NETNS_GETPUT
  nf_ct_netns_put(par->net, par->family);
#endif
}

static struct xt_target l4shenanigan_dnat_tg4_regs[] __read_mostly = {{
    .name = DNAT_TARGET_NAME,
    .family = NFPROTO_IPV4,
    .target = l4shenanigan_dnat_tg4,
    .targetsize = 0,
    .checkentry = l4shenanigan_dnat_tg4_check,
    .destroy = l4shenanigan_dnat_tg4_destroy,
    .table = "nat",
    .hooks = (1 << NF_INET_PRE_ROUTING),
    .me = THIS_MODULE,
}};

static int __init l4shenanigan_dnat_tg4_init(void) {
  return xt_register_targets(l4shenanigan_dnat_tg4_regs,
                             ARRAY_SIZE(l4shenanigan_dnat_tg4_regs));
}

static void __exit l4shenanigan_dnat_tg4_exit(void) {
  xt_unregister_targets(l4shenanigan_dnat_tg4_regs,
                        ARRAY_SIZE(l4shenanigan_dnat_tg4_regs));
}

module_init(l4shenanigan_dnat_tg4_init);
module_exit(l4shenanigan_dnat_tg4_exit);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("L4SHENANIGAN_DNAT for iptables");
MODULE_AUTHOR("Wenxin Wang <i@wenxinwang.me>");
