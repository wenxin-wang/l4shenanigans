#include <linux/highmem.h>
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
#include "compat/highmem.h"
#include "l4shenanigan_printk.h"
#include "l4shenanigan_uapi.h"

#ifdef __LP64__
/* 64-bit */
#define XOR_MASK_PTR 0xffffffffffffffff
#else
/* 32-bit */
#define XOR_MASK_PTR 0xffffffff
#endif

#define XOR_MASK_BYTE 0xff

// static char invert_char_at_base(char c, char base, char range) {
//   return base + range - (c - base);
// }
//
// static char invert_char(char c) {
//   if (c >= '0' && c <= '9') {
//     return invert_char_at_base(c, '0', '9' - '0');
//   } else if (c >= 'a' && c <= 'z') {
//     return invert_char_at_base(c, 'a', 'z' - 'a');
//   } else if (c >= 'A' && c <= 'Z') {
//     return invert_char_at_base(c, 'A', 'Z' - 'A');
//   } else {
//     return c;
//   }
// }

static uintptr_t get_ptr_xmask(char xmask) {
  uintptr_t ptr_xmask;
  memset(&ptr_xmask, xmask, sizeof(ptr_xmask));
  return ptr_xmask;
}

static uintptr_t invert_uintptr(uintptr_t val, uintptr_t ptr_xmask) { return ptr_xmask ^ val; }

static char invert_char(char val, char xmask) { return xmask ^ val; }

static void invert_buf(char *buf, char *end, char xmask) {
  uintptr_t ptr_xmask = get_ptr_xmask(xmask);
  for (; buf + sizeof(uintptr_t) - 1 < end; buf += sizeof(uintptr_t)) {
    *(uintptr_t *)buf = invert_uintptr(*(uintptr_t *)buf, ptr_xmask);
  }
  if (buf >= end) {
    return;
  }
  for (; buf < end; ++buf) {
    *buf = invert_char(*buf, xmask);
  }
}

static __wsum uintptr_csum_add(__wsum csum, uintptr_t val) {
#ifdef __LP64__
  /* 64-bit */
  __wsum *val32 = (__wsum *)&val;
  return csum_add(csum_add(csum, val32[0]), val32[1]);
#else
  /* 32-bit */
  return csum_add(csum, val);
#endif
}

static void invert_buf_with_csum(__sum16 *csum, struct sk_buff *skb, char *buf,
                                 char *end, char xmask) {
  uintptr_t from = 0, to = 0, ptr_xmask = get_ptr_xmask(xmask);
  char *p_from = (char *)&from, *p_to = (char *)&to;
  __be32 from_csum = 0, to_csum = 0;
  for (; buf + sizeof(uintptr_t) - 1 < end; buf += sizeof(uintptr_t)) {
    from = *(uintptr_t *)buf;
    to = invert_uintptr(from, ptr_xmask);
    *(uintptr_t *)buf = to;
    from_csum = uintptr_csum_add(from_csum, from);
    to_csum = uintptr_csum_add(to_csum, to);
  }
  if (buf >= end) {
    inet_proto_csum_replace4(csum, skb, from_csum, to_csum, false);
    return;
  }
  from = 0;
  to = 0;
  for (; buf < end; ++buf, ++p_from, ++p_to) {
    *p_from = *buf;
    *p_to = *buf = invert_char(*buf, xmask);
  }
  from_csum = uintptr_csum_add(from_csum, from);
  to_csum = uintptr_csum_add(to_csum, to);
  inet_proto_csum_replace4(csum, skb, from_csum, to_csum, false);
}

static void invert_skb_unpaged_frags(struct sk_buff *skb, __sum16 *csum, char xmask) {
  int i, len = skb->len;
  int seg_len = min_t(int, skb_headlen(skb), len);
  len -= seg_len;

  for (i = 0; len && i < skb_shinfo(skb)->nr_frags; i++) {
    skb_frag_t *frag = &skb_shinfo(skb)->frags[i];
    u32 p_off, p_len, copied;
    struct page *p;
    char *vaddr;

    skb_frag_foreach_page(frag, skb_frag_off(frag), skb_frag_size(frag), p,
                          p_off, p_len, copied) {
      seg_len = min_t(int, p_len, len);
#ifndef COMPAT_HIGHMEM_NO_KMAP_LOCAL_PAGE
      vaddr = kmap_local_page(p);
#else
      vaddr = kmap_atomic(p);
#endif
      if (!csum) {
        invert_buf(vaddr + p_off, vaddr + p_off + seg_len, xmask);
      } else {
        invert_buf_with_csum(csum, skb, vaddr + p_off, vaddr + p_off + seg_len, xmask);
      }
#ifndef COMPAT_HIGHMEM_NO_KMAP_LOCAL_PAGE
      kunmap_local(vaddr);
#else
      kunmap_atomic(vaddr);
#endif
      len -= seg_len;
      if (!len)
        break;
    }
  }
}

static int invert_frag_list_skb(struct sk_buff *skb, __sum16 *csum, char xmask) {
  char *payload = skb->data;
  int headlen;

  headlen = skb_headlen(skb);
  if (!csum) {
    invert_buf(payload, payload + headlen, xmask);
    invert_skb_unpaged_frags(skb, NULL, xmask);
  } else {
    invert_buf_with_csum(csum, skb, payload, payload + headlen, xmask);
    invert_skb_unpaged_frags(skb, csum, xmask);
  }

  if (skb_has_frag_list(skb)) {
    struct sk_buff *list_skb;
    skb_walk_frags(skb, list_skb) { invert_frag_list_skb(list_skb, csum, xmask); }
  }

  return 0;
}

static int l4shenanigan_invert_udp(struct sk_buff *skb, unsigned int udphoff, int xmask) {
  struct udphdr *udph;
  char *payload;
  int ret, headlen;
  bool no_csum_update;

  ret = skb_ensure_writable(skb, udphoff + (int)sizeof(struct udphdr));
  if (ret) {
    return ret;
  }

  udph = (struct udphdr *)(skb_network_header(skb) + udphoff);
  if (ntohs(udph->len) < sizeof(struct udphdr)) {
    return -1;
  }

  headlen = skb_headlen(skb) - udphoff -
            sizeof(struct udphdr); // udp payload length in skb header
  payload = ((char *)udph) + sizeof(struct udphdr);

  no_csum_update = skb->ip_summed == CHECKSUM_PARTIAL || udph->check == 0;
  if (no_csum_update) {
    // gso/gro enabled or udp zero checksum, no need to checksum
    invert_buf(payload, payload + headlen, xmask);
    invert_skb_unpaged_frags(skb, NULL, xmask);
  } else {
    invert_buf_with_csum(&udph->check, skb, payload, payload + headlen, xmask);
    invert_skb_unpaged_frags(skb, &udph->check, xmask);
    if (udph->check == 0) {
      udph->check = 0xffff;
    }
  }

  if (skb_has_frag_list(skb)) {
    struct sk_buff *list_skb;
    skb_walk_frags(skb, list_skb) {
      invert_frag_list_skb(list_skb, no_csum_update ? NULL : &udph->check, xmask);
    }
  }

  return 0;
}

static int l4shenanigan_invert_tcp(struct sk_buff *skb, unsigned int tcphoff, char xmask) {
  struct tcphdr *tcph;
  char *payload;
  int ret, headlen, tcp_hdrl;
  bool no_csum_update;

  ret = skb_ensure_writable(skb, tcphoff + (int)sizeof(struct tcphdr));
  if (ret) {
    return ret;
  }

  tcph = (struct tcphdr *)(skb_network_header(skb) + tcphoff);
  tcp_hdrl = tcph->doff * 4;

  if (tcp_hdrl < sizeof(struct tcphdr)) {
    return -1;
  }

  ret = skb_ensure_writable(skb, tcphoff + tcp_hdrl);
  if (ret) {
    return ret;
  }

  headlen = skb_headlen(skb) - tcphoff -
            tcp_hdrl; // tcp payload length in skb header
  payload = ((char *)tcph) + tcp_hdrl;
  no_csum_update = skb->ip_summed == CHECKSUM_PARTIAL;
  if (no_csum_update) {
    // gso/gro enabled, no need to checksum
    invert_buf(payload, payload + headlen, xmask);
    invert_skb_unpaged_frags(skb, NULL, xmask);
  } else {
    invert_buf_with_csum(&tcph->check, skb, payload, payload + headlen, xmask);
    invert_skb_unpaged_frags(skb, &tcph->check, xmask);
  }

  if (skb_has_frag_list(skb)) {
    struct sk_buff *list_skb;
    skb_walk_frags(skb, list_skb) {
      invert_frag_list_skb(list_skb, no_csum_update ? NULL : &tcph->check, xmask);
    }
  }

  return 0;
}

static unsigned int l4shenanigan_invert_tg4(struct sk_buff *skb,
                                            const struct xt_action_param *par) {
  const struct l4shenanigan_invert_info *invert_info = par->targinfo;
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
    ret = l4shenanigan_invert_udp(skb, iph->ihl * 4, invert_info->xmask);
    break;
  case IPPROTO_TCP:
    ret = l4shenanigan_invert_tcp(skb, iph->ihl * 4, invert_info->xmask);
    break;
  default:
    break;
  }
  return ret < 0 ? NF_DROP : XT_CONTINUE;
}

static int l4shenanigan_invert_tg4_check(const struct xt_tgchk_param *par) {
  int err = nf_defrag_ipv4_enable(par->net);
  if (err) {
    return err;
  }
  return 0;
}

static void l4shenanigan_invert_tg4_destroy(const struct xt_tgdtor_param *par) {
#ifndef COMPAT_CT_NO_DISABLE_DEFRAG_NS
  nf_defrag_ipv4_disable(par->net);
#endif
}

static struct xt_target l4shenanigan_invert_tg4_regs[] __read_mostly = {{
    .name = INVERT_TARGET_NAME,
    .family = NFPROTO_IPV4,
    .target = l4shenanigan_invert_tg4,
    .targetsize = sizeof(struct l4shenanigan_invert_info),
    .checkentry = l4shenanigan_invert_tg4_check,
    .destroy = l4shenanigan_invert_tg4_destroy,
    .me = THIS_MODULE,
}};

static int __init l4shenanigan_invert_tg4_init(void) {
  return xt_register_targets(l4shenanigan_invert_tg4_regs,
                             ARRAY_SIZE(l4shenanigan_invert_tg4_regs));
}

static void __exit l4shenanigan_invert_tg4_exit(void) {
  xt_unregister_targets(l4shenanigan_invert_tg4_regs,
                        ARRAY_SIZE(l4shenanigan_invert_tg4_regs));
}

module_init(l4shenanigan_invert_tg4_init);
module_exit(l4shenanigan_invert_tg4_exit);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("L4SHENANIGAN_INVERT for iptables");
MODULE_AUTHOR("Wenxin Wang <i@wenxinwang.me>");
