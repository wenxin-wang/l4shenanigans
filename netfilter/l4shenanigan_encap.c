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
#include <net/netfilter/nf_conntrack_seqadj.h>

#include "l4shenanigans_printk.h"
#include "l4shenanigans_protocol.h"
#include "l4shenanigans_uapi.h"

static int l4shenanigan_encap_udp(struct sk_buff *skb, unsigned int udphoff) {
  struct udphdr *udph;
  int ret;

  ret = skb_ensure_writable(skb, udphoff + (int)sizeof(struct udphdr));
  if (ret) {
    PR_ERR_RATELIMITED(skb, "l4shenanigan_encap_udp: failed to ensure base udp "
                       "header writable %d\n",
                       ret);
    return ret;
  }

  udph = (struct udphdr *)(skb_network_header(skb) + udphoff);
  if (ntohs(udph->len) < sizeof(struct udphdr)) {
    PR_ERR_RATELIMITED(skb, "l4shenanigan_encap_udp: udp header too small %d\n",
                       ntohs(udph->len));
    return -1;
  }

  ret = encap_adjust_headroom(skb, ENCAP_LEN,
                              udphoff + (int)sizeof(struct udphdr),
                              udphoff + offsetof(struct udphdr, check));
  if (ret) {
    PR_ERR_RATELIMITED(skb, "l4shenanigan_encap_udp: failed to adjust headroom %d\n",
                       ret);
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
  int ret, tcp_hdrl;
  enum ip_conntrack_info ctinfo;
  struct nf_conn *ct;

  ret = skb_ensure_writable(skb, tcphoff + (int)sizeof(struct tcphdr));
  if (ret) {
    PR_ERR_RATELIMITED(skb, "l4shenanigan_encap_tcp: failed to ensure base tcp "
                       "header writable %d\n",
                       ret);
    return ret;
  }

  tcph = (struct tcphdr *)(skb_network_header(skb) + tcphoff);

  tcp_hdrl = tcph->doff * 4;
  if (tcp_hdrl < sizeof(struct tcphdr)) {
    PR_ERR_RATELIMITED(skb, "l4shenanigan_encap_tcp: tcp header too small %d\n",
                       tcp_hdrl);
    return -1;
  }

  if (!tcph->syn) {
    return 0;
  }

  ret = encap_adjust_headroom(skb, ENCAP_LEN, tcphoff + tcp_hdrl,
                              tcphoff + offsetof(struct tcphdr, check));
  if (ret) {
    PR_ERR_RATELIMITED(skb, "l4shenanigan_encap_tcp: failed to adjust headroom %d\n",
                       ret);
    return ret;
  }

  update_iphdr_len(skb, ENCAP_LEN);

  tcph = (struct tcphdr *)(skb_network_header(skb) + tcphoff);
  update_tcp_len(skb, tcph, skb->len - tcphoff - ENCAP_LEN, ENCAP_LEN);

  tcp_fill_encap(skb, tcph, tcp_hdrl);

  ct = nf_ct_get(skb, &ctinfo);
  if (ct != NULL && (ctinfo == IP_CT_NEW || ctinfo == IP_CT_RELATED ||
                           ctinfo == IP_CT_RELATED_REPLY)) {
    if (!nfct_seqadj(ct) && !nfct_seqadj_ext_add(ct)) {
      PR_ERR_RATELIMITED(skb, "l4shenanigan_encap_tcp: nfct_seqadj_ext_add failed\n");
      return -1;
    }
    nf_ct_seqadj_set(ct, ctinfo, tcph->seq, ENCAP_LEN);
  } else {
    PR_ERR_RATELIMITED(skb, "l4shenanigan_encap_tcp: nfct_seqadj_ext_add skipped\n");
  }
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
#ifndef COMPAT_CT_NO_NETNS_GETPUT
  nf_ct_netns_get(par->net, par->family);
#endif
  return 0;
}

static void l4shenanigan_encap_tg4_destroy(const struct xt_tgdtor_param *par) {
#ifndef COMPAT_CT_NO_NETNS_GETPUT
  nf_ct_netns_put(par->net, par->family);
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
