#include <linux/ip.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter/x_tables.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/netfilter/ipv4/nf_defrag_ipv4.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <uapi/linux/in.h>

#include "compat/conntrack.h"
#include "l4shenanigans_protocol.h"
#include "l4shenanigans_uapi.h"

static int l4shenanigan_encap_udp(struct sk_buff *skb, unsigned int udphoff) {
  struct udphdr *udph;
  int ret;

  ret = skb_ensure_writable(skb, udphoff + (int)sizeof(struct udphdr));
  if (ret) {
    return ret;
  }

  udph = (struct udphdr *)(skb_network_header(skb) + udphoff);
  if (ntohs(udph->len) < sizeof(struct udphdr)) {
    return -1;
  }

  ret = encap_adjust_headroom(skb, ENCAP_LEN,
                              udphoff + (int)sizeof(struct udphdr),
                              udphoff + offsetof(struct udphdr, check));
  if (ret) {
    return ret;
  }

  update_iphdr_len(skb, ENCAP_LEN);

  udph = (struct udphdr *)(skb_network_header(skb) + udphoff);
  update_udp_len(skb, udph, ENCAP_LEN);

  udp_fill_encap(skb, udph);
  return 0;
}

static int l4shenanigan_encap_tcp(struct sk_buff *skb, unsigned int tcphoff) {
  struct tcphdr *tcph;
  int ret, tcp_hdrlen;

  ret = skb_ensure_writable(skb, tcphoff + (int)sizeof(struct tcphdr));
  if (ret) {
    pr_err_ratelimited("l4shenanigan_encap_tcp: failed to ensure base tcp "
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
    pr_err_ratelimited("l4shenanigan_encap_tcp: tcp header too small %d\n",
                       tcp_hdrlen);
    return -1;
  }
  if (tcp_hdrlen + TCPOLEN_ENCAP > 15 * 4) {
    pr_info_ratelimited("l4shenanigan_encap_tcp: no room for encap %d\n",
                        tcp_hdrlen);
    return 0;
  }

  ret = encap_adjust_headroom(skb, TCPOLEN_ENCAP,
                              tcphoff + (int)sizeof(struct tcphdr),
                              tcphoff + offsetof(struct tcphdr, check));
  if (ret) {
    return ret;
  }

  update_iphdr_len(skb, TCPOLEN_ENCAP);

  tcph = (struct tcphdr *)(skb_network_header(skb) + tcphoff);
  update_tcp_len(skb, tcph, skb->len - tcphoff - TCPOLEN_ENCAP, TCPOLEN_ENCAP);

  tcp_fill_encap(skb, tcph);
  return 0;
}

static unsigned int l4shenanigan_encap_tg4(struct sk_buff *skb,
                                           const struct xt_action_param *par) {
  struct iphdr *iph = ip_hdr(skb);
  int ret = 0;

  // This is a fragment, no header is available.
  // This should not happen as conntrack will be used together, which handles
  // defragmentation. See nf_defrag_ipv4_enable and nf_defrag_ipv4_disable
  if (unlikely(par->fragoff != 0)) {
    return XT_CONTINUE;
  }

  switch (iph->protocol) {
  case IPPROTO_UDP:
    ret = l4shenanigan_encap_udp(skb, iph->ihl * 4);
    break;
  case IPPROTO_TCP:
    ret = l4shenanigan_encap_tcp(skb, iph->ihl * 4);
    break;
  default:
    break;
  }
  return ret < 0 ? NF_DROP : XT_CONTINUE;
}

static int l4shenanigan_encap_tg4_check(const struct xt_tgchk_param *par) {
  int err = nf_defrag_ipv4_enable(par->net);
  if (err) {
    return err;
  }
  return 0;
}

static void l4shenanigan_encap_tg4_destroy(const struct xt_tgdtor_param *par) {
#ifndef COMPAT_CT_NO_DISABLE_DEFRAG_NS
  nf_defrag_ipv4_disable(par->net);
#endif
}

static struct xt_target l4shenanigan_encap_tg4_regs[] __read_mostly = {{
    .name = ENCAP_TARGET_NAME,
    .family = NFPROTO_IPV4,
    .target = l4shenanigan_encap_tg4,
    .targetsize = 0,
    .checkentry = l4shenanigan_encap_tg4_check,
    .destroy = l4shenanigan_encap_tg4_destroy,
    .me = THIS_MODULE,
}};

static int __init l4shenanigan_encap_tg4_init(void) {
  return xt_register_targets(l4shenanigan_encap_tg4_regs,
                             ARRAY_SIZE(l4shenanigan_encap_tg4_regs));
}

static void __exit l4shenanigan_encap_tg4_exit(void) {
  xt_unregister_targets(l4shenanigan_encap_tg4_regs,
                        ARRAY_SIZE(l4shenanigan_encap_tg4_regs));
}

module_init(l4shenanigan_encap_tg4_init);
module_exit(l4shenanigan_encap_tg4_exit);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("L4SHENANIGAN_ENCAP for iptables");
MODULE_AUTHOR("Wenxin Wang <i@wenxinwang.me>");
